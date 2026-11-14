//
//  I2PSAMServer.swift
//  The SAMv3.3 bridge: a TCP listener on localhost that exposes the router
//  to SAM clients — sessions (transient destinations + per-session tunnel
//  pools + LeaseSet publication), streams (CONNECT/ACCEPT over garlic'd
//  tunnels), datagrams (repliable/anonymous, UDP or TCP delivery), naming
//  and destination utilities. One connection runs the HELLO → SESSION CREATE
// → operational state machine; QUIT or socket close tears it down.
//

import Foundation
import Network
import CryptoKit

/// The router surface SAM needs. The running router context provides the real
/// components; test rigs provide a loopback router network.
struct I2PSAMRouterCore {
    let routerHash: Data
    let netDB: I2PNetworkDatabase
    let participant: I2PTunnelParticipant
    let buildTransport: I2PTunnelBuildTransport
    let peerProvider: I2PTunnelPeerProvider
    let delivery: I2PDeliveryTransport
    let i2npRouter: I2NPMessageRouter
    /// Routers whose gateway handlers this process can program directly
    /// (loopback test rigs). Live-network hops run standard IBGW/OBEP behavior.
    let controlledRouter: (Data) -> I2NPMessageRouter?
}

extension I2PTunnelPool.Config {
    /// SAM pools: single-hop tunnels, fast staggered fills.
    static var samDefault: I2PTunnelPool.Config {
        var config = I2PTunnelPool.Config()
        config.hopCount = 1
        config.staggerInterval = 0.05
        config.buildTimeout = 10
        config.maintenanceInterval = 5
        return config
    }
}

/// Sends SAM datagrams to a client's UDP endpoint (SAM v3 datagram replies).
final class I2PSAMUDPDatagramSender {
    private let connection: NWConnection

    init(host: String, port: UInt16) {
        let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host(host),
                                           port: NWEndpoint.Port(rawValue: port) ?? .any)
        connection = NWConnection(to: endpoint, using: .udp)
        connection.start(queue: .global(qos: .utility))
    }

    func send(_ data: Data) {
        connection.send(content: data, completion: .contentProcessed { _ in })
    }

    func shutdown() { connection.cancel() }
}

/// Routes inbound garlic messages to every registered SAM session; only the
/// session whose destination key decrypts a payload consumes it.
final class I2PSAMGarlicDispatcher {
    private let lock = NSLock()
    private var sessions: [I2PSAMSession] = []

    func register(_ session: I2PSAMSession) {
        lock.lock(); sessions.append(session); lock.unlock()
    }

    func unregister(_ session: I2PSAMSession) {
        lock.lock(); sessions.removeAll { $0 === session }; lock.unlock()
    }

    func hasSession(_ nickname: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return sessions.contains { $0.nickname == nickname }
    }

    func handle(_ message: I2NPMessage, from source: Data) {
        guard message.type == .garlic else { return }
        lock.lock()
        let snapshot = sessions
        lock.unlock()
        snapshot.forEach { $0.garlicHandler.handle(message, from: source) }
    }
}

/// The SAM bridge itself.
final class I2PSAMServer {
    enum State: Equatable {
        case stopped
        case listening(port: UInt16)
        case failed(String)
    }

    let core: I2PSAMRouterCore
    private let configuredPort: UInt16
    private let poolConfig: I2PTunnelPool.Config
    let queue = DispatchQueue(label: "i2p.sam.server")
    private let lock = NSLock()
    private var listener: NWListener?
    private(set) var state: State = .stopped
    private var connections: [I2PSAMConnection] = []
    private var sessions: [String: I2PSAMSession] = [:]
    private(set) var addressbook: [String: I2PDestination] = [:]
    private(set) var log: [String] = []
    var onChange: (() -> Void)?
    let transport: I2PSAMGarlicTransport
    /// Optional session key persistence for PERSISTENT=true sessions.
    let keyStore = I2PSAMKeyStore()
    private let dispatcher: I2PSAMGarlicDispatcher
    private var renewalTask: Task<Void, Never>?

    init(core: I2PSAMRouterCore, port: UInt16 = 7656,
         poolConfig: I2PTunnelPool.Config = .samDefault) {
        self.core = core
        self.configuredPort = port
        self.poolConfig = poolConfig
        self.transport = I2PSAMGarlicTransport(core: core)
        self.dispatcher = I2PSAMGarlicDispatcher()
        self.transport.onEvent = { [weak self] line in self?.note(line) }
        // Inbound garlic for SAM destinations flows through the router's body
        // handlers; the dispatcher fans out to every session (only the right
        // destination key decrypts).
        core.i2npRouter.addBodyHandler { [dispatcher] message, source in
            dispatcher.handle(message, from: source)
        }
    }

    // MARK: Listener lifecycle

    func start() {
        lock.lock()
        guard listener == nil else { lock.unlock(); return }
        lock.unlock()
        do {
            let listener = try NWListener(using: .tcp, on: NWEndpoint.Port(rawValue: configuredPort) ?? .any)
            listener.newConnectionHandler = { [weak self] connection in
                guard let self else { return }
                let sam = I2PSAMConnection(connection: connection, server: self)
                self.lock.lock(); self.connections.append(sam); self.lock.unlock()
                sam.start()
            }
            listener.stateUpdateHandler = { [weak self] state in
                guard let self else { return }
                switch state {
                case .ready:
                    self.lock.lock()
                    let bound = self.listener?.port?.rawValue ?? self.configuredPort
                    self.state = .listening(port: bound)
                    self.lock.unlock()
                    self.note("SAM listener ready on 127.0.0.1:\(bound)")
                    self.startRenewalLoop()
                case .failed(let error):
                    self.lock.lock(); self.state = .failed(String(describing: error)); self.lock.unlock()
                    self.note("SAM listener failed: \(error)")
                default: break
                }
                self.onChange?()
            }
            lock.lock(); self.listener = listener; lock.unlock()
            listener.start(queue: queue)
        } catch {
            lock.lock(); state = .failed(String(describing: error)); lock.unlock()
            note("SAM listener error: \(error)")
        }
        onChange?()
    }

    /// Graceful shutdown: listener, connections, sessions, renewal loop.
    func stop() {
        lock.lock()
        let listener = self.listener
        self.listener = nil
        let connections = self.connections
        self.connections = []
        let sessions = self.sessions
        self.sessions = [:]
        let renewal = self.renewalTask
        self.renewalTask = nil
        lock.unlock()
        listener?.cancel()
        connections.forEach { $0.shutdown() }
        sessions.values.forEach { $0.shutdown() }
        renewal?.cancel()
        lock.lock(); state = .stopped; lock.unlock()
        note("SAM listener stopped")
        onChange?()
    }

    private func startRenewalLoop() {
        renewalTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(300))
                guard let self, !Task.isCancelled else { return }
                for session in self.sessionSnapshot() {
                    if session.publishesEncryptedLeaseSet {
                        // b33 entries re-publish as their leases rotate.
                        await session.refreshEncryptedPublication()
                    } else {
                        _ = await session.publishLeaseSet()
                    }
                }
            }
        }
    }

    // MARK: Sessions

    /// Creates a session: transient (or imported) destination keys, its own
    /// tunnel pool, and LeaseSet publication under the session identity —
    /// plain, or encrypted under the destination's blinded b33 key when the
    /// session asked for encrypted publication.
    func createSession(nickname: String, style: I2PSAMStyle,
                       keys: I2PSAMDestinationKeys,
                       encryptedPublication: Bool = false) async throws -> I2PSAMSession {
        guard dispatcher.hasSession(nickname) == false else { throw I2PSAMError.duplicatedID }
        let pool = I2PTunnelPool(localRouterHash: core.routerHash,
                                 participant: core.participant,
                                 transport: core.buildTransport,
                                 peerProvider: core.peerProvider,
                                 config: poolConfig)
        let session = I2PSAMSession(nickname: nickname, style: style, keys: keys,
                                    pool: pool, transport: transport, delivery: core.delivery,
                                    encryptedPublication: encryptedPublication)
        session.onEvent = { [weak self] line in self?.note("\(nickname): \(line)") }
        dispatcher.register(session)
        pool.start()
        await pool.fillPools()
        await session.publishLeaseSet()
        for tunnel in pool.inboundTunnels {
            transport.installInboundGlueIfNeeded(tunnel)
        }
        lock.lock(); sessions[nickname] = session; lock.unlock()
        let b33Note = session.b33Address.map { " · b33 \($0.prefix(12))…" } ?? ""
        note("session \(nickname) (\(style.rawValue)) created · dest \(session.destinationHash.hex.prefix(8))\(b33Note)")
        onChange?()
        return session
    }

    func closeSession(_ nickname: String) {
        lock.lock()
        let session = sessions.removeValue(forKey: nickname)
        lock.unlock()
        guard let session else { return }
        dispatcher.unregister(session)
        session.shutdown()
        note("session \(nickname) closed")
        onChange?()
    }

    func session(named nickname: String) -> I2PSAMSession? {
        lock.lock(); defer { lock.unlock() }
        return sessions[nickname]
    }

    func sessionSnapshot() -> [I2PSAMSession] {
        lock.lock(); defer { lock.unlock() }
        return Array(sessions.values)
    }

    func sessionSummaries() -> [I2PSAMSessionSummary] {
        sessionSnapshot().map { $0.summary() }
    }

    // MARK: b33 hosts

    /// One live b33 host a session publishes under, with the destination
    /// credentials that unlock its encrypted LeaseSet2.
    struct I2PSAMB33Host {
        let address: String
        let nickname: String
        let credentials: I2PB33Credentials
    }

    /// Every live encrypted-publication host this bridge holds credentials
    /// for — the resolvable rows of the b33 host book.
    func b33Hosts() -> [I2PSAMB33Host] {
        sessionSnapshot().compactMap { session in
            guard let host = session.b33Host else { return nil }
            return I2PSAMB33Host(address: host.address,
                                 nickname: session.nickname,
                                 credentials: host.credentials)
        }
    }

    func connectionClosed(_ connection: I2PSAMConnection, sessionNickname: String?) {
        lock.lock()
        connections.removeAll { $0 === connection }
        lock.unlock()
        if let sessionNickname { closeSession(sessionNickname) }
    }

    // MARK: Naming / destinations

    /// Resolves a b33 blinded address for a querying session's credentials:
    /// decodes and validates the address through the b33 codec (checksum,
    /// flag/scheme/encType bytes), checks it against the blinded key the
    /// session's own destination credentials (Ed25519 seed + ECIES X25519
    /// private key) derive, and resolves through the encrypted-LS2 blinding
    /// path. A b33 the credentials do not derive is a stranger host — its
    /// encrypted inner body stays opaque, so nothing resolves and nothing
    /// leaks: the caller surfaces the spec resolution failure. Returns nil
    /// when the address does not resolve.
    func resolveB33(_ address: String, credentials: I2PB33Credentials) async -> I2PDestination? {
        guard let blindedPublicKey = I2PB33Blinding.b33Decode(address),
              let encryptionPublicKey = I2PB33Blinding.destinationEncryptionPublicKey(credentials),
              let blinded = try? I2PB33Blinding.blind(destinationSeed: credentials.ed25519Seed,
                                                      encryptionPublicKey: encryptionPublicKey,
                                                      secret: credentials.secret),
              blinded.blindedPublicKey == blindedPublicKey else {
            return nil
        }
        return await core.netDB.resolveEncryptedDestination(credentials: credentials)?.destination
    }

    /// Resolves a SAM destination spec: base64 destination, `.b32.i2p` host
    /// (DHT LeaseSet lookup), B64: prefix, or an addressbook entry.
    func resolveDestination(_ spec: String) async throws -> I2PDestination {
        let trimmed = spec.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { throw I2PSAMError.invalidDestination }
        if trimmed.hasPrefix("B64:") || trimmed.hasPrefix("B64.") {
            return try destination(fromBase64: String(trimmed.dropFirst(4)))
        }
        if trimmed.lowercased().hasSuffix(".b32.i2p") {
            let base32 = String(trimmed.dropLast(8))
            guard let hash = I2PSAMEncoding.base32Decode(base32), hash.count == 32 else {
                throw I2PSAMError.invalidDestination
            }
            guard let entry = await core.netDB.lookup(hash), let leaseSet = entry.leaseSet else {
                throw I2PSAMError.destinationNotFound
            }
            return leaseSet.destination
        }
        if let destination = try? destination(fromBase64: trimmed) {
            return destination
        }
        lock.lock()
        let entry = addressbook[trimmed.lowercased()]
        lock.unlock()
        guard let entry else { throw I2PSAMError.destinationNotFound }
        return entry
    }

    private func destination(fromBase64 text: String) throws -> I2PDestination {
        guard let data = I2PSAMEncoding.normalizedBase64(text) else {
            throw I2PSAMError.invalidDestination
        }
        var reader = I2PReader(data)
        guard let destination = try? I2PKeysAndCert.parse(&reader), data.count >= 384 else {
            throw I2PSAMError.invalidDestination
        }
        return destination
    }

    func addressbookEntry(name: String, destination: I2PDestination) {
        lock.lock()
        addressbook[name.lowercased()] = destination
        lock.unlock()
        note("addressbook entry added: \(name)")
        onChange?()
    }

    // MARK: Activity log

    func note(_ line: String) {
        lock.lock()
        log.append("[\(Date().formatted(date: .omitted, time: .standard))] \(line)")
        if log.count > 40 { log.removeFirst(log.count - 40) }
        lock.unlock()
    }
}

// MARK: - Per-connection state machine

/// One TCP client connection: HELLO → SESSION CREATE → operational, with a
/// single active stream (CONNECT/ACCEPT) or datagram traffic. The connection
/// owns the session it created and tears it down on close/QUIT.
final class I2PSAMConnection {
    private enum Phase { case awaitingHello; case operational; case closed }
    private enum StreamPhase {
        case idle
        case connecting(I2PSAMStreamContext)
        case established(I2PSAMStreamContext)
        case accepting
    }
    private enum ReadUnit {
        case line(String)
        case rawPayload(Data)
        case streamData(Data)
    }

    private let connection: NWConnection
    // Strong, not unowned: a connection's async drain chain can outlive the
    // owner that tore the server down (a test rig deallocating while a
    // session-create chain is still inside pool filling). Resuming that chain
    // and touching an unowned server trap-killed the process with a runtime
    // assertion (unowned-retain failure → fatalError → SIGABRT). The server
    // holds its connections in an array and drops them on close, so the cycle
    // always breaks exactly once per connection.
    private let server: I2PSAMServer
    private let lock = NSLock()
    private var phase: Phase = .awaitingHello
    private var streamPhase: StreamPhase = .idle
    private var buffer = Data()
    private var draining = false
    private var awaitingRawRemaining = 0
    private var pendingDatagram: (id: String, destination: String)?
    private var pendingClientBytes = Data()
    private var pendingConnectReply: (id: String, silent: Bool)?
    private var pendingAcceptReply: (id: String, silent: Bool)?
    private var connectTimeoutTask: Task<Void, Never>?
    private var acceptTimeoutTask: Task<Void, Never>?
    private var session: I2PSAMSession?
    private(set) var closed = false

    init(connection: NWConnection, server: I2PSAMServer) {
        self.connection = connection
        self.server = server
    }

    func start() {
        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready: self?.receiveNext()
            case .failed, .cancelled: self?.handleTransportClose()
            default: break
            }
        }
        connection.start(queue: server.queue)
    }

    func shutdown() { handleTransportClose() }

    private func receiveNext() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, _, isComplete, error in
            guard let self, !self.closed else { return }
            if let data, !data.isEmpty { self.handleData(data) }
            if isComplete || error != nil { self.handleTransportClose(); return }
            self.receiveNext()
        }
    }

    private func handleData(_ data: Data) {
        lock.lock()
        buffer += data
        let wasDraining = draining
        draining = true
        lock.unlock()
        guard !wasDraining else { return }
        Task { [weak self] in await self?.drainUntilIdle() }
    }

    private func drainUntilIdle() async {
        while true {
            guard let unit = nextUnit() else {
                lock.lock()
                draining = false
                let more = hasCompleteUnitLocked()
                if more { draining = true }
                lock.unlock()
                if !more { return }
                continue
            }
            switch unit {
            case .line(let line): await handle(line: line)
            case .rawPayload(let payload): await handle(rawPayload: payload)
            case .streamData(let data): pumpClientBytes(data)
            }
        }
    }

    /// Line mode for commands; raw mode while a stream is connecting or
    /// established; fixed-size raw reads after a DATAGRAM SEND command line.
    private func nextUnit() -> ReadUnit? {
        lock.lock()
        defer { lock.unlock() }
        var rawMode = false
        if case .established = streamPhase { rawMode = true }
        if case .connecting = streamPhase { rawMode = true }
        if rawMode {
            guard !buffer.isEmpty else { return nil }
            let data = buffer
            buffer = Data()
            return .streamData(data)
        }
        if awaitingRawRemaining > 0 {
            guard buffer.count >= awaitingRawRemaining else { return nil }
            let payload = Data(Array(buffer.prefix(awaitingRawRemaining)))
            buffer = Data(Array(buffer.dropFirst(awaitingRawRemaining)))
            awaitingRawRemaining = 0
            return .rawPayload(payload)
        }
        guard let newline = buffer.firstIndex(of: 0x0A) else { return nil }
        let lineData = Data(Array(buffer[buffer.startIndex..<newline]))
        buffer = Data(Array(buffer[buffer.index(after: newline)...]))
        return .line(String(decoding: lineData, as: UTF8.self))
    }

    private func hasCompleteUnitLocked() -> Bool {
        var rawMode = false
        if case .established = streamPhase { rawMode = true }
        if case .connecting = streamPhase { rawMode = true }
        if rawMode { return !buffer.isEmpty }
        if awaitingRawRemaining > 0 { return buffer.count >= awaitingRawRemaining }
        return buffer.contains(0x0A)
    }

    private func send(reply: String) {
        server.note("← \(reply.prefix(96))")
        connection.send(content: Data((reply + "\n").utf8), completion: .contentProcessed { _ in })
    }

    /// Sends a reply and then closes the stream gracefully: the final line must
    /// reach the client before the FIN (a bare cancel can drop the last reply).
    private func sendAndClose(reply: String) {
        server.note("← \(reply.prefix(96))")
        connection.send(content: Data((reply + "\n").utf8),
                        contentContext: .finalMessage,
                        isComplete: true,
                        completion: .contentProcessed { [weak self] _ in
                            self?.connection.cancel()
                        })
    }

    private func boundSession() -> I2PSAMSession? {
        lock.lock(); defer { lock.unlock() }
        return session
    }

    // MARK: Command handling

    private func handle(line rawLine: String) async {
        let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !line.isEmpty else { return }
        server.note("→ \(line.prefix(96))")
        do {
            switch try I2PSAMGrammar.parse(line) {
            case .hello(let minVersion, let maxVersion):
                let compatible = Self.versionCompatible(min: minVersion, max: maxVersion)
                if compatible {
                    lock.lock(); phase = .operational; lock.unlock()
                    send(reply: I2PSAMReply.hello(ok: true))
                } else {
                    // No common version ends the connection, but the client
                    // still has to receive the NO_VERSION line first.
                    sendAndClose(reply: I2PSAMReply.hello(ok: false))
                }
            case .sessionCreate(let style, let id, let destinationSpec, let options):
                try await createSession(style: style, id: id, destinationSpec: destinationSpec, options: options)
            case .sessionQuit:
                if let session = boundSession() { server.closeSession(session.nickname) }
                connection.cancel()
            case .streamConnect(let id, let destinationSpec, let silent):
                await streamConnect(id: id, destinationSpec: destinationSpec, silent: silent)
            case .streamAccept(let id, let silent):
                await streamAccept(id: id, silent: silent)
            case .datagramSend(let id, let destinationSpec, let size):
                stageDatagramSend(id: id, destination: destinationSpec, size: size)
            case .namingLookup(let name):
                await namingLookup(name)
            case .namingAdd(let name, let destinationSpec):
                namingAdd(name: name, destinationSpec: destinationSpec)
            case .destGenerate:
                destGenerate()
            }
        } catch {
            send(reply: I2PSAMReply.error(error, prefix: "SESSION STATUS"))
        }
    }

    private static func versionCompatible(min: String, max: String) -> Bool {
        func parse(_ text: String) -> (Int, Int)? {
            let parts = text.split(separator: ".").compactMap { Int($0) }
            guard parts.count >= 2 else { return nil }
            return (parts[0], parts[1])
        }
        guard let minimum = parse(min), let maximum = parse(max) else { return false }
        return minimum <= (3, 3) && maximum >= (3, 0)
    }

    private func createSession(style: I2PSAMStyle, id: String,
                               destinationSpec: String, options: [String: String]) async throws {
        lock.lock()
        guard case .operational = phase else {
            lock.unlock()
            throw I2PSAMError.invalidCommand("hello_required")
        }
        lock.unlock()
        // Optional session persistence: PERSISTENT=true saves the destination's
        // private keys under the nickname and restores them on re-creation.
        // Session parameters: signature and encryption types are validated
        // against the router's modern-only destination stack (Ed25519 SigType 7
        // + X25519 EncType 4/5); legacy crypto types are rejected outright.
        if let requested = options["SIGNATURE_TYPE"], !requested.isEmpty {
            let supported = ["7", "eddsa_sha512_ed25519"]
            guard supported.contains(requested.lowercased()) else {
                throw I2PSAMError.invalidCommand("unsupported_signature_type_\(requested)")
            }
        }
        if let requested = options["ENCRYPTION_TYPE"], !requested.isEmpty {
            let supported = ["4", "5", "x25519", "ecies_x25519"]
            guard supported.contains(requested.lowercased()) else {
                throw I2PSAMError.invalidCommand("unsupported_encryption_type_\(requested)")
            }
        }
        // Encrypted (b33) LeaseSet2 publication: the session seals its leases
        // to its own destination, stores the entry under the destination's
        // blinded netdb key, and hands out its b33 address.
        let encryptedPublication = options["ENCRYPTED_LEASESET"]?.lowercased() == "true"
        let keys: I2PSAMDestinationKeys
        let persistent = options["PERSISTENT"] == "true"
        if destinationSpec == "TRANSIENT" {
            if persistent, let saved = server.keyStore.load(nickname: id),
               let restored = try? I2PSAMDestinationKeys.parse(saved) {
                keys = restored
            } else {
                keys = I2PSAMDestinationKeys.generate()
                if persistent {
                    server.keyStore.save(nickname: id, privateKey: keys.privateKeyData)
                }
            }
        } else if let data = I2PSAMEncoding.normalizedBase64(destinationSpec),
                  let parsed = try? I2PSAMDestinationKeys.parse(data) {
            keys = parsed
            if persistent {
                server.keyStore.save(nickname: id, privateKey: keys.privateKeyData)
            }
        } else {
            throw I2PSAMError.invalidDestination
        }
        let session = try await server.createSession(nickname: id, style: style, keys: keys,
                                                     encryptedPublication: encryptedPublication)
        // One session per connection: replacing the binding tears down the
        // previous session (duplicate IDs are rejected before this point).
        lock.lock()
        let previous = self.session
        self.session = session
        session.owner = self
        lock.unlock()
        if let previous, previous !== session {
            server.closeSession(previous.nickname)
        }
        if let portText = options["PORT"], let port = UInt16(portText) {
            session.udpEndpoint = (options["HOST"] ?? "127.0.0.1", port)
        }
        send(reply: I2PSAMReply.sessionStatus(result: "OK",
                                             destination: session.destinationBase64,
                                             b33: session.b33Address))
    }

    // MARK: Streams

    private func streamConnect(id: String, destinationSpec: String, silent: Bool) async {
        do {
            guard let session = boundSession() else {
                throw I2PSAMError.invalidCommand("no_session")
            }
            lock.lock()
            guard case .idle = streamPhase else {
                lock.unlock()
                throw I2PSAMError.invalidCommand("stream_in_progress")
            }
            lock.unlock()
            let remote = try await server.resolveDestination(destinationSpec)
            server.note("connect: destination \(remote.hash.hex.prefix(8))")
            let lease = try await session.transport.resolveLease(remote.hash)
            server.note("connect: lease tunnel \(lease.tunnelID)")
            let context = I2PSAMStreamContext(localID: UInt32.random(in: 1...UInt32.max),
                                              remote: remote, lease: lease,
                                              garlic: try session.garlicSession(toward: remote))
            lock.lock()
            streamPhase = .connecting(context)
            pendingConnectReply = (id, silent)
            lock.unlock()
            let syn = I2PSAMFrame(streamID: context.localID, flags: [.syn], sequence: 0,
                                  fromPort: 0, toPort: 0, chunkIndex: 0, chunkCount: 1,
                                  chunk: Data(), attached: session.keys.destination.raw)
            try await session.send(syn, to: lease, remote: remote)
            server.note("connect: SYN sent")
            startConnectTimeout()
        } catch {
            lock.lock(); streamPhase = .idle; lock.unlock()
            server.note("stream connect failed: \(error)")
            if silent {
                closeClient()
            } else {
                send(reply: I2PSAMReply.error(error, prefix: "STREAM STATUS"))
            }
        }
    }

    private func streamAccept(id: String, silent: Bool) async {
        do {
            guard let session = boundSession() else {
                throw I2PSAMError.invalidCommand("no_session")
            }
            lock.lock()
            guard case .idle = streamPhase else {
                lock.unlock()
                throw I2PSAMError.invalidCommand("stream_in_progress")
            }
            streamPhase = .accepting
            pendingAcceptReply = (id, silent)
            lock.unlock()
            session.pendingAccept = self
            startAcceptTimeout()
            // Accept-after-connect race: a SYN may already be buffered.
            if let buffered = session.takeBufferedSyn() {
                completeAccept(streamID: buffered.frame.streamID, sender: buffered.sender)
            }
        } catch {
            send(reply: I2PSAMReply.error(error, prefix: "STREAM STATUS"))
        }
    }

    /// Inbound garlic stream/datagram messages land here via the session.
    func handleStreamMessage(streamID: UInt32, sequence: UInt32,
                             flags: I2PSAMFrame.Flags, sender: I2PDestination?, data: Data) {
        lock.lock()
        let phase = streamPhase
        lock.unlock()
        switch phase {
        case .accepting:
            guard flags.contains(.syn), let sender else { return }
            server.note("accept: inbound SYN from \(sender.hash.hex.prefix(8))")
            completeAccept(streamID: streamID, sender: sender)
        case .connecting(let context):
            guard streamID == context.localID else { return }
            if flags.contains(.rst) {
                replyConnectError()
            } else if flags.contains(.syn) {
                establish(context)
            }
        case .established(let context):
            guard streamID == context.localID else { return }
            if flags.contains(.fin) || flags.contains(.rst) {
                closeClient()
            } else if !data.isEmpty {
                connection.send(content: data, completion: .contentProcessed { _ in })
            }
        case .idle:
            break
        }
    }

    private func completeAccept(streamID: UInt32, sender: I2PDestination) {
        guard let session = boundSession() else { return }
        session.pendingAccept = nil
        Task { [weak self] in
            guard let self, let session = self.boundSession() else { return }
            do {
                let lease = try await session.transport.resolveLease(sender.hash)
                let context = I2PSAMStreamContext(localID: streamID, remote: sender, lease: lease,
                                                  garlic: try session.garlicSession(toward: sender))
                // SYN-ACK back to the connector (carries our destination).
                let syn = I2PSAMFrame(streamID: streamID, flags: [.syn], sequence: 0,
                                      fromPort: 0, toPort: 0, chunkIndex: 0, chunkCount: 1,
                                      chunk: Data(), attached: session.keys.destination.raw)
                try await session.send(syn, to: lease, remote: sender)
                server.note("accept: SYN-ACK sent")
                self.lock.lock()
                self.streamPhase = .established(context)
                let reply = self.pendingAcceptReply
                self.pendingAcceptReply = nil
                self.lock.unlock()
                self.acceptTimeoutTask?.cancel()
                if let reply, !reply.silent {
                    self.send(reply: I2PSAMReply.streamStatus(result: "OK", id: reply.id))
                }
            } catch {
                self.lock.lock(); self.streamPhase = .idle; self.lock.unlock()
                self.send(reply: I2PSAMReply.error(error, prefix: "STREAM STATUS"))
            }
        }
    }

    private func establish(_ context: I2PSAMStreamContext) {
        lock.lock()
        guard case .connecting = streamPhase else { lock.unlock(); return }
        streamPhase = .established(context)
        let buffered = pendingClientBytes
        pendingClientBytes = Data()
        let reply = pendingConnectReply
        pendingConnectReply = nil
        lock.unlock()
        server.note("connect: established")
        connectTimeoutTask?.cancel()
        if let reply, !reply.silent {
            send(reply: I2PSAMReply.streamStatus(result: "OK", id: reply.id))
        }
        if !buffered.isEmpty { pumpClientBytes(buffered) }
    }

    private func replyConnectError() {
        lock.lock()
        let reply = pendingConnectReply
        pendingConnectReply = nil
        streamPhase = .idle
        lock.unlock()
        connectTimeoutTask?.cancel()
        if let reply, !reply.silent {
            send(reply: I2PSAMReply.streamStatus(result: "CANT_REACH_PEER", id: reply.id))
        } else if reply?.silent == true {
            closeClient()
        }
    }

    private func startConnectTimeout() {
        connectTimeoutTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(I2PSAMLimits.handshakeTimeout))
            await self?.connectTimedOut()
        }
    }

    private func connectTimedOut() {
        lock.lock()
        guard case .connecting = streamPhase else { lock.unlock(); return }
        streamPhase = .idle
        let reply = pendingConnectReply
        pendingConnectReply = nil
        lock.unlock()
        if let reply, !reply.silent {
            send(reply: I2PSAMReply.streamStatus(result: "TIMEOUT", id: reply.id))
        }
    }

    private func startAcceptTimeout() {
        acceptTimeoutTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(I2PSAMLimits.handshakeTimeout))
            await self?.acceptTimedOut()
        }
    }

    private func acceptTimedOut() {
        lock.lock()
        guard case .accepting = streamPhase else { lock.unlock(); return }
        streamPhase = .idle
        let reply = pendingAcceptReply
        pendingAcceptReply = nil
        lock.unlock()
        if let reply, !reply.silent {
            send(reply: I2PSAMReply.streamStatus(result: "TIMEOUT", id: reply.id))
        }
    }

    /// Client bytes: pumped as garlic'd stream chunks, buffered while the
    /// handshake completes.
    private func pumpClientBytes(_ data: Data) {
        lock.lock()
        guard case .established(let context) = streamPhase else {
            if case .connecting = streamPhase {
                pendingClientBytes += data
                if pendingClientBytes.count > I2PSAMLimits.maxStreamBuffer {
                    pendingClientBytes = Data()
                }
            }
            lock.unlock()
            return
        }
        lock.unlock()
        let chunks = I2PSAMChunker.split(data)
        // One write is one framed message: every chunk of it carries the same
        // sequence number and a distinct chunk index. The receiver reassembles
        // by (stream, sequence) and waits for all `chunkCount` chunks of that
        // message before delivering it; numbering the chunks as separate
        // messages left each one waiting for chunks that never came, so any
        // client write larger than one chunk (the load test's 8 KiB bulk
        // transfer) stalled forever.
        let sequence = context.nextSequence()
        for (index, chunk) in chunks.enumerated() {
            let frame = I2PSAMFrame(streamID: context.localID, flags: [], sequence: sequence,
                                    fromPort: 0, toPort: 0,
                                    chunkIndex: UInt16(index), chunkCount: UInt16(chunks.count),
                                    chunk: chunk, attached: Data())
            Task { [weak self] in
                guard let self, let session = self.boundSession() else { return }
                do {
                    try await session.send(frame, to: context.lease, remote: context.remote)
                } catch {
                    // A dropped chunk leaves a permanent sequence gap, so the
                    // peer would hold every later frame forever. Fail the
                    // stream loudly instead of hanging.
                    self.abortStream("send of \(chunk.count)B chunk \(index)/\(chunks.count) failed: \(error)")
                }
            }
        }
    }

    /// Tears the connection down after a transport failure, so the peer's
    /// ordered reassembly does not wait on a frame that will never arrive.
    private func abortStream(_ reason: String) {
        server.note("stream aborted: \(reason)")
        closeClient()
    }

    // MARK: Datagrams

    private func stageDatagramSend(id: String, destination: String, size: Int) {
        // The payload follows the command line: it is consumed no matter what
        // so the framing stays in sync, then the send is validated/executed.
        let consume = min(max(size, 0), 1_048_576)
        lock.lock()
        awaitingRawRemaining = consume
        pendingDatagram = (id, destination)
        lock.unlock()
    }

    private func handle(rawPayload payload: Data) async {
        lock.lock()
        let command = pendingDatagram
        pendingDatagram = nil
        lock.unlock()
        guard let command else { return }
        await executeDatagramSend(id: command.id, destinationSpec: command.destination, payload: payload)
    }

    private func executeDatagramSend(id: String, destinationSpec: String, payload: Data) async {
        do {
            guard let session = boundSession() else {
                throw I2PSAMError.invalidCommand("no_session")
            }
            guard payload.count <= I2PSAMLimits.maxDatagramSize else {
                throw I2PSAMError.invalidCommand("datagram_too_large")
            }
            let remote = try await server.resolveDestination(destinationSpec)
            let lease = try await session.transport.resolveLease(remote.hash)
            // Anonymous (RAW) datagrams carry no return address, so no
            // destination attachment is added to the first chunk.
            let attachment = session.style != .raw && !payload.isEmpty
                ? session.keys.destination.raw.count : 0
            let chunks = I2PSAMChunker.split(payload, attachmentLength: attachment)
            let messageID = UInt32.random(in: 1...UInt32.max)
            for (index, chunk) in chunks.enumerated() {
                // Anonymous (RAW) datagrams carry no return address.
                let attached = (session.style != .raw && index == 0) ? session.keys.destination.raw : Data()
                let frame = I2PSAMFrame(streamID: session.datagramStreamID, flags: [.datagram],
                                        sequence: messageID, fromPort: 0, toPort: 0,
                                        chunkIndex: UInt16(index), chunkCount: UInt16(chunks.count),
                                        chunk: chunk, attached: attached)
                server.note("datagram chunk \(index)/\(chunks.count): \(chunk.count)B + \(attached.count)B attach")
                try await session.send(frame, to: lease, remote: remote)
            }
        } catch {
            server.note("datagram send failed: \(I2PSAMReply.resultCode(for: error)) — \(error)")
        }
    }

    /// Inbound datagram delivery: UDP endpoint per SAM v3, TCP line fallback.
    func deliverDatagram(sender: I2PDestination?, payload: Data) {
        server.note("datagram received: \(payload.count)B from \(sender.map { $0.hash.hex.prefix(8) } ?? "anonymous")")
        guard let session = boundSession() else { return }
        if session.udpEndpoint != nil {
            let data: Data
            if session.style == .raw {
                data = payload
            } else {
                let senderText = sender?.raw.base64EncodedString() ?? ""
                data = Data((senderText + " ").utf8) + payload
            }
            session.enqueueUDPDelivery(data)
        } else {
            let line = I2PSAMReply.datagramReceived(destination: sender?.raw.base64EncodedString(),
                                                    size: payload.count)
            connection.send(content: Data((line + "\n").utf8) + payload + Data([0x0A]),
                            completion: .contentProcessed { _ in })
        }
    }

    // MARK: Naming / destination tools

    private func namingLookup(_ name: String) async {
        do {
            let value = try await resolveName(name)
            send(reply: I2PSAMReply.namingReply(result: "OK", name: name, value: value))
        } catch {
            send(reply: I2PSAMReply.namingReply(result: I2PSAMReply.resultCode(for: error), name: name))
        }
    }

    private func resolveName(_ name: String) async throws -> String {
        if name == "ME" {
            guard let session = boundSession() else { throw I2PSAMError.destinationNotFound }
            return session.destinationBase64
        }
        if name.hasPrefix("B64:") || name.hasPrefix("B64.") {
            let destination = try serverDestination(fromBase64: String(name.dropFirst(4)))
            return destination.raw.base64EncodedString()
        }
        // b33 blinded addresses: resolve through the encrypted-LS2 blinding
        // path when this session holds the destination's credentials (its
        // Ed25519 seed + ECIES X25519 private key). A b33 the credentials
        // cannot derive is a stranger host — the encrypted inner body stays
        // opaque, so the lookup answers the spec resolution failure without
        // leaking anything. Without a session there are no credentials at all.
        if let b33 = Self.b33Spec(address: name) {
            guard let session = boundSession() else {
                throw I2PSAMError.destinationNotFound
            }
            let credentials = I2PB33Credentials(
                ed25519Seed: session.keys.signingSeed,
                x25519PrivateKey: session.keys.encryptionKey.rawRepresentation)
            guard let destination = await server.resolveB33(b33, credentials: credentials) else {
                throw I2PSAMError.destinationNotFound
            }
            return destination.raw.base64EncodedString()
        }
        let destination = try await server.resolveDestination(name)
        return destination.raw.base64EncodedString()
    }

    /// Extracts a b33 address from a SAM name spec: the raw 57-character
    /// blinded address or a "b33:"-prefixed form. Returns nil for anything
    /// else so plain hosts fall through to the ordinary naming path.
    private static func b33Spec(address name: String) -> String? {
        var candidate = name.lowercased().trimmingCharacters(in: .whitespaces)
        if candidate.hasPrefix("b33:") { candidate.removeFirst(4) }
        return I2PB33Blinding.b33Decode(candidate) != nil ? candidate : nil
    }

    private func namingAdd(name: String, destinationSpec: String) {
        do {
            let destination = try serverDestination(fromBase64: destinationSpec)
            server.addressbookEntry(name: name, destination: destination)
            send(reply: I2PSAMReply.namingReply(result: "OK", name: name))
        } catch {
            send(reply: I2PSAMReply.namingReply(result: I2PSAMReply.resultCode(for: error), name: name))
        }
    }

    private func destGenerate() {
        let keys = I2PSAMDestinationKeys.generate()
        send(reply: I2PSAMReply.destReply(pub: keys.destination.raw.base64EncodedString(),
                                          priv: keys.privateKeyData.base64EncodedString()))
    }

    private func serverDestination(fromBase64 text: String) throws -> I2PDestination {
        guard let data = I2PSAMEncoding.normalizedBase64(text) else {
            throw I2PSAMError.invalidDestination
        }
        var reader = I2PReader(data)
        guard let destination = try? I2PKeysAndCert.parse(&reader), data.count >= 384 else {
            throw I2PSAMError.invalidDestination
        }
        return destination
    }

    // MARK: Teardown

    private func closeClient() {
        connection.cancel()
    }

    private func handleTransportClose() {
        // Check-and-set under the lock: close callbacks and server teardown
        // can arrive concurrently, and a double-close would tear the session
        // down twice and race the stream phase.
        lock.lock()
        guard !closed else { lock.unlock(); return }
        closed = true
        let phase = streamPhase
        let nickname = session?.nickname
        let boundAtClose = session
        session?.pendingAccept = nil
        lock.unlock()
        if case .established(let context) = phase, let boundAtClose {
            let fin = I2PSAMFrame(streamID: context.localID, flags: [.fin], sequence: context.nextSequence(),
                                  fromPort: 0, toPort: 0, chunkIndex: 0, chunkCount: 1,
                                  chunk: Data(), attached: Data())
            // The FIN must leave through the session's tunnels BEFORE the
            // session is torn down: closing the session here first (the
            // transport-close path of a one-stream-per-connection bridge)
            // raced the send and dropped the FIN, so the peer never saw the
            // stream end.
            Task { [weak self] in
                try? await boundAtClose.send(fin, to: context.lease, remote: context.remote)
                guard let self else { return }
                self.server.connectionClosed(self, sessionNickname: nickname)
                self.connection.cancel()
            }
            return
        }
        server.connectionClosed(self, sessionNickname: nickname)
        connection.cancel()
    }
}

/// One direction of an established stream: the local stream ID, the remote
/// destination and lease to route frames through, and its sequence counter.
final class I2PSAMStreamContext {
    let localID: UInt32
    let remote: I2PDestination
    let lease: I2PGarlicLease
    let garlic: I2PGarlicSession
    private let lock = NSLock()
    private var sequence: UInt32 = 0

    init(localID: UInt32, remote: I2PDestination, lease: I2PGarlicLease, garlic: I2PGarlicSession) {
        self.localID = localID
        self.remote = remote
        self.lease = lease
        self.garlic = garlic
    }

    func nextSequence() -> UInt32 {
        lock.lock()
        defer { lock.unlock() }
        sequence += 1
        return sequence
    }
}