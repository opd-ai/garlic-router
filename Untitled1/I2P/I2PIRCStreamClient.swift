//
//  I2PIRCStreamClient.swift
//  The I2P side of the IRC client: one client destination with its own tunnel
//  pool and published leases, a garlic session toward the IRC server, and a
//  long-lived stream framed the way the router's SAM stream layer frames them.
//
//  Where the eepsite browser fetches one page per stream, this connection
//  stays open: lines arrive through the inbound assembler as the server sends
//  them, sends are serialized through one outbound path, and the destination's
//  leases are re-published on a cadence so a chat that lasts longer than a
//  tunnel does not lose its reply path.
//

import Foundation
import CryptoKit

// MARK: - Client (connection factory)

/// The IRC client's connection: one client destination, reused across server
/// connections so the nick the server sees keeps the same destination and the
/// router does not grow a body handler per reconnect.
final class I2PIRCClient {
    private let core: I2PSAMRouterCore
    private let credentials: (String) -> I2PB33Credentials?
    private let addressBook: (String) -> I2PDestination?

    private let lock = NSLock()
    private var shared: I2PIRCStreamConnection?

    init(core: I2PSAMRouterCore,
         credentials: @escaping (String) -> I2PB33Credentials?,
         addressBook: @escaping (String) -> I2PDestination?) {
        self.core = core
        self.credentials = credentials
        self.addressBook = addressBook
    }

    /// The connection this client talks through. Created on first use.
    func connection() -> I2PIRCStreamConnection {
        lock.lock()
        defer { lock.unlock() }
        if let shared { return shared }
        let created = I2PIRCStreamConnection(core: core,
                                             credentials: credentials,
                                             addressBook: addressBook)
        shared = created
        return created
    }
}

// MARK: - Stream connection

/// One IRC connection over an I2P stream. `connect` resolves the server,
/// fills the client's pool, publishes the client's leases and opens the stream;
/// `send` writes one line; inbound lines reach `onLine` and an unexpected end
/// of stream reaches `onClosed` with the reason.
final class I2PIRCStreamConnection {
    private let core: I2PSAMRouterCore
    private let credentials: (String) -> I2PB33Credentials?
    private let addressBook: (String) -> I2PDestination?

    private let keys: I2PSAMDestinationKeys
    private let pool: I2PTunnelPool
    private let transport: I2PSAMGarlicTransport
    private let garlicHandler: I2PGarlicMessageHandler
    private let assembler: I2PSAMInboundAssembler

    private let lock = NSLock()
    private var destination: I2PDestination?
    private var garlic: I2PGarlicSession?
    private var lease: I2PGarlicLease?
    private var streamID: UInt32 = 0
    private var sequence: UInt32 = 0
    private var port: UInt16 = I2PIRCServerEntry.defaultPort
    private var established = false
    private var resetReason: String?
    private var closed = false
    private var publishedAt = Date.distantPast

    private var receiveBuffer = Data()
    private var refreshTask: Task<Void, Never>?

    /// One inbound line, without its CRLF.
    var onLine: ((String) -> Void)?
    /// The stream ended without this client asking it to.
    var onClosed: ((String) -> Void)?

    /// A netdb lookup round; two rounds let the DHT iterate.
    private static let lookupTimeout: TimeInterval = 2.0
    private static let lookupRounds = 2
    private static let poolWaitTimeout: TimeInterval = 45
    private static let handshakeTimeout: TimeInterval = 45
    /// How long a published LeaseSet stands before the refresh re-publishes it.
    private static let republishInterval: TimeInterval = 240
    /// The lease lifetime each published entry is capped at.
    private static let leaseWindow: TimeInterval = 600
    /// How much of an unterminated line is buffered before it is dropped.
    private static let maxLineBuffer = 64 * 1024

    init(core: I2PSAMRouterCore,
         credentials: @escaping (String) -> I2PB33Credentials?,
         addressBook: @escaping (String) -> I2PDestination?) {
        self.core = core
        self.credentials = credentials
        self.addressBook = addressBook
        let keys = I2PSAMDestinationKeys.generate()
        self.keys = keys
        self.pool = I2PTunnelPool(localRouterHash: core.routerHash,
                                  participant: core.participant,
                                  transport: core.buildTransport,
                                  peerProvider: core.peerProvider,
                                  config: .ircDefault)
        self.transport = I2PSAMGarlicTransport(core: core)
        self.garlicHandler = I2PGarlicMessageHandler(
            sessionManager: I2PGarlicInboundSessionManager(localKey: keys.encryptionKey),
            deliveryTransport: core.delivery)
        self.assembler = I2PSAMInboundAssembler(ordered: true)

        assembler.onCompleted = { [weak self] completed in
            self?.handle(completed)
        }
        garlicHandler.addLocalConsumer { [weak self] message, _ in
            guard let self,
                  message.type == .dataMessage,
                  // The Data body carries its own 4-byte length; the stream frame
                  // starts after it.
                  let body = try? I2NPDataMessage.parse(message.payload),
                  let frame = I2PSAMFrame.parse(body) else { return }
            self.assembler.ingest(frame)
        }
        core.i2npRouter.addBodyHandler { [weak self] message, source in
            self?.garlicHandler.handle(message, from: source)
        }
    }

    // MARK: Connect

    /// Runs one connection: address → resolve → pool → stream SYN. Returns once
    /// the server has answered the stream, so the caller can register.
    func connect(host: String,
                 port typedPort: UInt16,
                 onStage: @escaping (I2PIRCStage) -> Void) async throws {
        onStage(.address)
        let parsed = try I2PIRCHost.parse(host)
        let resolvedPort = parsed.port ?? typedPort
        guard resolvedPort > 0 else {
            throw I2PIRCFailure(stage: .address,
                                message: "The server has no usable port — I2P IRC servers usually listen on 6667.")
        }
        resetForConnect(port: resolvedPort)
        pool.start()

        let target = try await resolve(parsed, onStage: onStage)
        if Task.isCancelled {
            abort()
            throw CancellationError()
        }

        try await prepareTunnelPool(onStage: onStage)
        if Task.isCancelled {
            abort()
            throw CancellationError()
        }

        onStage(.connect)
        let garlicSession: I2PGarlicSession
        do {
            garlicSession = try I2PGarlicSession(
                peerPublicKey: Curve25519.KeyAgreement.PublicKey(
                    rawRepresentation: target.destination.encryptionPublicKey),
                tagsPerHandshake: 16)
        } catch {
            abort()
            throw I2PIRCFailure(stage: .connect,
                                message: "The server advertises an encryption key the stream cannot use: \(error)")
        }
        guard let chosen = target.leases.first else {
            abort()
            throw I2PIRCFailure(stage: .leases,
                                message: "The server's lease set carried no usable lease.")
        }
        let garlicLease = I2PGarlicLease(gatewayRouterHash: chosen.gatewayHash,
                                         tunnelID: chosen.tunnelId,
                                         expiration: chosen.expiration)
        transport.registry.register(garlicLease)
        let newStreamID = UInt32.random(in: 1...UInt32.max)
        setRoute(destination: target.destination,
                 garlic: garlicSession,
                 lease: garlicLease,
                 streamID: newStreamID)

        do {
            try await sendFrame(payload: Data(),
                                flags: [.syn],
                                sequence: 0,
                                attached: keys.destination.raw)
        } catch {
            abort()
            throw I2PIRCFailure(stage: .connect,
                                message: "The stream SYN could not leave the outbound tunnel pool: \(Self.describe(error))")
        }

        try await waitForEstablished(lease: chosen)
        startLeaseRefresh()
    }

    /// Sends one IRC line (CRLF appended, line breaks inside it removed).
    func send(_ line: String) async throws {
        let payload = Data((I2PIRCText.stripLineBreaks(line) + "\r\n").utf8)
        guard let sequence = nextSequence() else {
            throw I2PSAMError.invalidCommand("the IRC stream is not open")
        }
        try await sendFrame(payload: payload, flags: [], sequence: sequence, attached: Data())
    }

    /// Closes the stream on the user's behalf: a best-effort FIN, then the pool
    /// stops. No close callback fires, since the client asked for it.
    func close() {
        Task { [weak self] in
            guard let self else { return }
            if let sequence = self.nextSequence() {
                try? await self.sendFrame(payload: Data(), flags: [.fin],
                                          sequence: sequence, attached: Data())
            }
            self.stop(reason: nil)
        }
    }

    /// Stops everything after a failed attempt, without reporting a close.
    func abort() {
        stop(reason: nil)
    }

    // MARK: Resolution

    private struct Target {
        let destination: I2PDestination
        let leases: [I2PLease]
    }

    private func resolve(_ parsed: I2PIRCHost.Parsed,
                         onStage: @escaping (I2PIRCStage) -> Void) async throws -> Target {
        switch parsed.target {
        case .b33(let blinded):
            onStage(.blinding)
            guard let credentialSet = credentials(blinded) else {
                throw I2PIRCFailure(stage: .blinding,
                                    message: "This b33 host is a stranger: the router holds no credentials for its blinded key, so its encrypted LeaseSet2 can never be opened. Credentialled hosts come from a SAM session publishing an encrypted LeaseSet2 (see the b33 Hosts screen).")
            }
            onStage(.lookup)
            guard let resolved = await core.netDB.resolveEncryptedDestination(
                credentials: credentialSet,
                timeoutPerRound: Self.lookupTimeout,
                maxRounds: Self.lookupRounds) else {
                throw I2PIRCFailure(stage: .blinding,
                                    message: "No encrypted LeaseSet2 came back from the floodfills for this host's blinded netdb key. The server may not be publishing right now.")
            }
            onStage(.leases)
            let leases = Self.liveLeases(resolved.leases)
            guard !leases.isEmpty else { throw expiredFailure(resolved.leases) }
            return Target(destination: resolved.destination, leases: leases)

        case .b32(let hash):
            return try await resolveByKey(hash, hint: nil, onStage: onStage)

        case .destination(let destination):
            return try await resolveByKey(destination.hash, hint: destination, onStage: onStage)

        case .name(let name):
            guard let destination = addressBook(name) else {
                throw I2PIRCFailure(stage: .lookup,
                                    message: "\(name) is not in the router's address book. I2P has no global name service — add the destination with NAMING ADD on the SAM screen, or connect with its b32 host or base64 destination.")
            }
            return try await resolveByKey(destination.hash, hint: destination, onStage: onStage)
        }
    }

    private func resolveByKey(_ key: Data,
                              hint: I2PDestination?,
                              onStage: @escaping (I2PIRCStage) -> Void) async throws -> Target {
        onStage(.lookup)
        guard let entry = await core.netDB.lookup(key,
                                                  timeoutPerRound: Self.lookupTimeout,
                                                  maxRounds: Self.lookupRounds) else {
            throw I2PIRCFailure(stage: .lookup,
                                message: "No netdb entry for \(Self.shortHash(key)) at any floodfill — the server is not currently published, or the router has no floodfill sessions yet.")
        }
        onStage(.leases)
        if let leaseSet = entry.leaseSet {
            let leases = Self.liveLeases(leaseSet.leases)
            guard !leases.isEmpty else { throw expiredFailure(leaseSet.leases) }
            return Target(destination: hint ?? leaseSet.destination, leases: leases)
        }
        if let leaseSet2 = entry.leaseSet2, let resolved = leaseSet2.resolvedLeaseSet() {
            let leases = Self.liveLeases(resolved.leases)
            guard !leases.isEmpty else { throw expiredFailure(resolved.leases) }
            return Target(destination: hint ?? resolved.destination, leases: leases)
        }
        throw I2PIRCFailure(stage: .lookup,
                            message: "The netdb entry for \(Self.shortHash(key)) carries no lease set the client can route to.")
    }

    private func expiredFailure(_ leases: [I2PLease]) -> I2PIRCFailure {
        let newest = leases.map(\.expiration).max()
        let age = newest.map { Self.ageText(Date().timeIntervalSince($0)) } ?? "an unknown time"
        return I2PIRCFailure(stage: .leases,
                             message: "Every lease in the server's lease set has expired (the newest ran out \(age) ago) — the server is not republishing, so a stream cannot reach it.")
    }

    // MARK: Tunnel pool

    private func prepareTunnelPool(onStage: @escaping (I2PIRCStage) -> Void) async throws {
        onStage(.tunnels)
        pool.start()
        if pool.outboundTunnels.isEmpty || pool.inboundTunnels.isEmpty {
            let candidates = core.peerProvider.peers(count: 1, excluding: [core.routerHash])
            guard !candidates.isEmpty else {
                throw I2PIRCFailure(stage: .tunnels,
                                    message: "The router has no tunnel hops yet — its netdb holds no usable peer RouterInfos, so no tunnel can be built. Open the Router tab and let the bootstrap cycle connect to floodfills, then connect again.")
            }
            await pool.fillPools()
        }
        let deadline = Date().addingTimeInterval(Self.poolWaitTimeout)
        while Date() < deadline {
            if Task.isCancelled { throw CancellationError() }
            if !pool.outboundTunnels.isEmpty && !pool.inboundTunnels.isEmpty { break }
            try await Task.sleep(for: .milliseconds(250))
        }
        guard !pool.outboundTunnels.isEmpty else {
            throw I2PIRCFailure(stage: .tunnels,
                                message: "No outbound tunnel could be built. The client needs live peers — open the Router tab, let the pool fill, then connect again.")
        }
        guard !pool.inboundTunnels.isEmpty else {
            throw I2PIRCFailure(stage: .tunnels,
                                message: "The client has an outbound tunnel but no inbound tunnel, so the server could not send anything back. The pool keeps building; try again in a moment.")
        }
        if needsRepublish() {
            await publishLeases()
        }
        guard !currentLeases().isEmpty else {
            throw I2PIRCFailure(stage: .tunnels,
                                message: "No inbound leases could be published for the client's own destination — the reply path needs at least one live inbound tunnel.")
        }
    }

    /// The leases the client publishes: one per live inbound tunnel, capped at
    /// a ten-minute window like any other destination's publication.
    private func currentLeases(now: Date = Date()) -> [I2PLease] {
        pool.inboundTunnels.filter { !$0.isExpired(now: now) }.compactMap { tunnel in
            guard let gateway = tunnel.hops.first else { return nil }
            return I2PLease(gatewayHash: gateway.routerHash,
                            tunnelId: tunnel.gatewayTunnelID,
                            expiration: min(tunnel.expiresAt,
                                            now.addingTimeInterval(Self.leaseWindow)))
        }
    }

    @discardableResult
    private func publishLeases() async -> Bool {
        let now = Date()
        let leases = currentLeases(now: now)
        guard !leases.isEmpty else { return false }
        var leaseSet = I2PLeaseSet(destination: keys.destination, published: now, leases: leases)
        do {
            try leaseSet.sign(withSeed: keys.signingSeed)
        } catch {
            return false
        }
        _ = await core.netDB.publish(leaseSet: leaseSet)
        lock.lock()
        publishedAt = now
        lock.unlock()
        return true
    }

    private func needsRepublish(now: Date = Date()) -> Bool {
        let leases = currentLeases(now: now)
        guard !leases.isEmpty else { return false }
        let last = publishedDate()
        if last == Date.distantPast { return true }
        if now.timeIntervalSince(last) >= Self.republishInterval { return true }
        let soonest = leases.map(\.expiration).min() ?? now
        return soonest.timeIntervalSince(now) < 60
    }

    /// Keeps the client's reply path alive for a chat that outlasts the leases
    /// it published: a lease set that runs out would silently mute the server.
    private func startLeaseRefresh() {
        lock.lock()
        guard refreshTask == nil else {
            lock.unlock()
            return
        }
        refreshTask = Task { [weak self] in
            while let self, !Task.isCancelled {
                try? await Task.sleep(for: .seconds(Self.republishInterval))
                guard !Task.isCancelled else { break }
                await self.refreshLeasesIfNeeded()
            }
        }
        lock.unlock()
    }

    private func refreshLeasesIfNeeded() async {
        guard needsRepublish() else { return }
        await publishLeases()
    }

    // MARK: Stream

    private func waitForEstablished(lease: I2PLease) async throws {
        let deadline = Date().addingTimeInterval(Self.handshakeTimeout)
        while Date() < deadline {
            if Task.isCancelled { throw CancellationError() }
            if isEstablished() { return }
            if let reason = failureReason() {
                throw I2PIRCFailure(stage: .connect, message: reason)
            }
            if Date() > lease.expiration {
                throw I2PIRCFailure(stage: .connect,
                                    message: "The server's lease (tunnel \(lease.tunnelId)) expired before it answered the stream. Reconnect to resolve its lease set again.")
            }
            try await Task.sleep(for: .milliseconds(100))
        }
        throw I2PIRCFailure(stage: .connect,
                            message: "The server did not answer the stream SYN within \(Int(Self.handshakeTimeout))s. The connection left through the outbound tunnel pool; either the server is offline or its inbound tunnels are not forwarding.")
    }

    /// Sends one logical message as the frames the stream layer expects: all
    /// chunks share the sequence number, and the attachment rides chunk zero.
    private func sendFrame(payload: Data,
                           flags: I2PSAMFrame.Flags,
                           sequence: UInt32,
                           attached: Data) async throws {
        guard let route = currentRoute() else {
            throw I2PSAMError.invalidCommand("the IRC stream is not open")
        }
        let chunks = I2PSAMChunker.split(payload, attachmentLength: attached.count)
        for (index, chunk) in chunks.enumerated() {
            let frame = I2PSAMFrame(streamID: route.streamID,
                                    flags: flags,
                                    sequence: sequence,
                                    fromPort: 0,
                                    toPort: UInt32(route.port),
                                    chunkIndex: UInt16(index),
                                    chunkCount: UInt16(chunks.count),
                                    chunk: chunk,
                                    attached: index == 0 ? attached : Data())
            try await transport.send(I2NPMessage(type: .dataMessage,
                                                 payload: I2NPDataMessage(
                                                    payload: frame.serialize()).serialize()),
                                     to: route.lease,
                                     garlicSession: route.garlic,
                                     pool: pool)
        }
    }

    private func handle(_ completed: I2PSAMInboundAssembler.Completed) {
        if completed.flags.contains(.rst) {
            stop(reason: "The server reset the stream.")
            return
        }
        if completed.flags.contains(.syn) {
            markEstablished()
        }
        if !completed.data.isEmpty {
            ingest(completed.data)
        }
        if completed.flags.contains(.fin) {
            stop(reason: "The server closed the stream.")
        }
    }

    /// Splits the inbound bytes into CRLF-terminated lines and hands each one on.
    private func ingest(_ data: Data) {
        var lines: [String] = []
        lock.lock()
        receiveBuffer.append(data)
        while let newline = receiveBuffer.firstIndex(of: 0x0A) {
            var lineData = Data(receiveBuffer[receiveBuffer.startIndex..<newline])
            if lineData.last == 0x0D { lineData.removeLast() }
            let consumed = receiveBuffer.distance(from: receiveBuffer.startIndex, to: newline) + 1
            receiveBuffer.removeFirst(consumed)
            lines.append(String(decoding: lineData, as: UTF8.self))
        }
        if receiveBuffer.count > Self.maxLineBuffer {
            // A peer that never terminates a line must not grow the buffer.
            receiveBuffer.removeAll()
        }
        lock.unlock()
        for line in lines {
            onLine?(line)
        }
    }

    // MARK: State

    private struct Route {
        let garlic: I2PGarlicSession
        let lease: I2PGarlicLease
        let streamID: UInt32
        let port: UInt16
    }

    private func resetForConnect(port: UInt16) {
        lock.lock()
        closed = false
        established = false
        resetReason = nil
        receiveBuffer.removeAll()
        sequence = 0
        streamID = 0
        garlic = nil
        lease = nil
        destination = nil
        // A fresh connection publishes its own leases rather than trusting an
        // earlier session's entry.
        publishedAt = Date.distantPast
        self.port = port
        lock.unlock()
    }

    private func setRoute(destination: I2PDestination,
                          garlic: I2PGarlicSession,
                          lease: I2PGarlicLease,
                          streamID: UInt32) {
        lock.lock()
        self.destination = destination
        self.garlic = garlic
        self.lease = lease
        self.streamID = streamID
        self.sequence = 0
        lock.unlock()
    }

    private func currentRoute() -> Route? {
        lock.lock()
        defer { lock.unlock() }
        guard let garlic, let lease else { return nil }
        return Route(garlic: garlic, lease: lease, streamID: streamID, port: port)
    }

    private func nextSequence() -> UInt32? {
        lock.lock()
        defer { lock.unlock() }
        guard garlic != nil, lease != nil, !closed else { return nil }
        sequence += 1
        return sequence
    }

    private func markEstablished() {
        lock.lock()
        established = true
        lock.unlock()
    }

    private func isEstablished() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return established
    }

    private func failureReason() -> String? {
        lock.lock()
        defer { lock.unlock() }
        return resetReason
    }

    private func publishedDate() -> Date {
        lock.lock()
        defer { lock.unlock() }
        return publishedAt
    }

    /// Stops the connection once. A reason is reported to `onClosed`; nil means
    /// the client itself hung up.
    private func stop(reason: String?) {
        lock.lock()
        guard !closed else {
            lock.unlock()
            return
        }
        closed = true
        established = false
        resetReason = reason
        let task = refreshTask
        refreshTask = nil
        garlic = nil
        lease = nil
        receiveBuffer.removeAll()
        lock.unlock()
        task?.cancel()
        pool.stop()
        if let reason {
            onClosed?(reason)
        }
    }

    // MARK: Formatting

    private static func liveLeases(_ leases: [I2PLease], now: Date = Date()) -> [I2PLease] {
        leases.filter { $0.expiration > now }
            .sorted { $0.expiration > $1.expiration }
    }

    private static func shortHash(_ key: Data) -> String {
        let hex = key.hex
        guard hex.count > 12 else { return hex }
        return "\(hex.prefix(12))…"
    }

    private static func ageText(_ seconds: TimeInterval) -> String {
        let total = Int(max(0, seconds))
        if total < 60 { return "\(total)s" }
        if total < 3_600 { return "\(total / 60)m" }
        return "\(total / 3_600)h"
    }

    private static func describe(_ error: Error) -> String {
        if let samError = error as? I2PSAMError {
            switch samError {
            case .noTunnels: return "the outbound tunnel pool is empty"
            case .timeout: return "the peer timed out"
            case .destinationNotFound: return "the lease could not be resolved"
            case .unreachable: return "the peer is unreachable"
            case .invalidCommand(let reason): return reason
            case .invalidDestination: return "the destination is malformed"
            case .duplicatedID: return "a duplicate session id"
            }
        }
        return String(describing: error)
    }
}

// MARK: - IRC pool

extension I2PTunnelPool.Config {
    /// The IRC client's pool: a small, fast-filling pair of one-hop tunnels.
    /// The inbound side exists so the server's lines have a path back.
    static var ircDefault: I2PTunnelPool.Config {
        var config = I2PTunnelPool.Config()
        config.outboundTarget = 2
        config.inboundTarget = 2
        config.hopCount = 1
        config.staggerInterval = 0.2
        config.buildTimeout = 15
        config.maintenanceInterval = 5
        return config
    }
}
