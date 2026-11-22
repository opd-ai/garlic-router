//
//  I2PSAMConformanceTest.swift
//  SAMv3.3 conformance: a real loopback TCP client speaks the protocol to
//  a bridge wired to an in-memory router network (tunnel hops, netdb, garlic
//  pipeline). Covers the HELLO/SESSION/STREAM/DATAGRAM/NAMING/DEST command set,
//  end-to-end streams through tunnels, fragmented datagrams, and edge cases.
//

import Foundation
import Network
import CryptoKit

// MARK: - Test rig (loopback router network)

/// Keeps the most recent bridges' activity logs so a failed case reports the
/// commands and replies of the connection it lost, not just "timeout".
private enum SAMTestLog {
    private static let lock = NSLock()
    private static var servers: [I2PSAMServer] = []
    private static var trace: [String] = []

    static func register(_ server: I2PSAMServer) {
        lock.lock()
        servers.append(server)
        if servers.count > 8 { servers.removeFirst(servers.count - 8) }
        lock.unlock()
    }

    static func note(_ line: String) {
        lock.lock()
        trace.append(line)
        if trace.count > 200 { trace.removeFirst(trace.count - 200) }
        lock.unlock()
    }

    static func reset() {
        lock.lock()
        trace.removeAll()
        lock.unlock()
    }

    static func recent(_ limit: Int = 3) -> String {
        lock.lock()
        let snapshot = Array(servers.suffix(limit))
        let route = Array(trace.suffix(120))
        lock.unlock()
        let logs = snapshot.flatMap { $0.log.suffix(14) }
        return (logs + route).joined(separator: " | ")
    }
}

private final class SAMTestNode {
    let routerHash = I2PCrypto.randomBytes(32)
    let encryptionKey = Curve25519.KeyAgreement.PrivateKey()
    let participant: I2PTunnelParticipant
    let router: I2NPMessageRouter
    /// Strongly held: `I2NPMessageRouter.deliveryTransport` is weak, so a
    /// transport kept only there is deallocated and every hop-to-hop forward
    /// (the message-path end handing the payload on) silently goes nowhere.
    let deliveryTransport: I2NPLoopbackDeliveryTransport

    init(buildHub: I2PTunnelBuildHub, deliveryHub: I2NPLoopbackDeliveryHub) {
        participant = I2PTunnelParticipant(
            localRouterHash: routerHash,
            localEncryptionKey: encryptionKey,
            transport: I2PTunnelLoopbackTransport(hub: buildHub, localRouterHash: routerHash)
        )
        buildHub.register(participant)
        router = I2NPMessageRouter(localRouterHash: routerHash)
        // The router must know the participant, or an arriving TunnelData
        // message finds no hop state and the whole tunnel silently drops it —
        // exactly what every cross-rig stream and datagram timed out on.
        router.addTunnelParticipant(participant)
        deliveryTransport = I2NPLoopbackDeliveryTransport(hub: deliveryHub, localRouterHash: routerHash)
        router.deliveryTransport = deliveryTransport
        deliveryHub.attach(router)
        let label = routerHash.hex.prefix(4)
        router.onMessageRouted = { message, _ in
            SAMTestLog.note("\(label)<-\(message.type)(\(message.payload.count))")
        }
    }

    var peer: I2PTunnelPeer {
        I2PTunnelPeer(routerHash: routerHash, encryptionPublicKey: encryptionKey.publicKey.rawRepresentation)
    }
}

private final class SAMTestPeerProvider: I2PTunnelPeerProvider {
    private let nodes: [SAMTestNode]
    private let lock = NSLock()
    init(nodes: [SAMTestNode]) { self.nodes = nodes }
    func peers(count: Int, excluding: Set<Data>) -> [I2PTunnelPeer] {
        lock.lock(); defer { lock.unlock() }
        let candidates = nodes.filter { !excluding.contains($0.routerHash) }
        guard candidates.count >= count else { return [] }
        return Array(candidates.shuffled().prefix(count)).map(\.peer)
    }
}

private final class SAMTestRig {
    let buildHub: I2PTunnelBuildHub
    let deliveryHub: I2NPLoopbackDeliveryHub
    let owner: SAMTestNode
    let hopNodes: [SAMTestNode]
    let netDB: I2PNetworkDatabase
    let server: I2PSAMServer

    /// One delivery bus for every rig. Each rig models a separate router, but
    /// they all sit on the same network: a garlic envelope a sender's outbound
    /// tunnel hands to a lease gateway in the peer's rig must still be
    /// routable. A per-rig bus dropped it, which timed out every cross-rig
    /// stream and datagram case.
    private static let sharedDeliveryHub = I2NPLoopbackDeliveryHub()

    init(label: String) throws {
        // Build everything with local constants first so the core's
        // controlledRouter closure captures nodes, not self.
        let buildHub = I2PTunnelBuildHub()
        let deliveryHub = SAMTestRig.sharedDeliveryHub
        let ownerNode = SAMTestNode(buildHub: buildHub, deliveryHub: deliveryHub)
        let hopNodeList = (0..<3).map { _ in
            SAMTestNode(buildHub: buildHub, deliveryHub: deliveryHub)
        }
        let storage = try I2PNetDBStorage(directory: FileManager.default.temporaryDirectory
            .appendingPathComponent("sam-\(label)-\(UUID().uuidString)"))
        final class DropDelivery: I2PDeliveryTransport {
            func deliver(_ i2npBytes: Data, to routerHash: Data) async throws {}
        }
        let netDBInstance = I2PNetworkDatabase(localRouterHash: ownerNode.routerHash,
                                               transport: I2PNetDBI2NPAdapter(delivery: DropDelivery()),
                                               storage: storage)
        var poolConfig = I2PTunnelPool.Config()
        poolConfig.hopCount = 1
        poolConfig.outboundTarget = 1
        poolConfig.inboundTarget = 1
        poolConfig.staggerInterval = 0.02
        poolConfig.buildTimeout = 10
        poolConfig.maintenanceInterval = 30
        poolConfig.lifetime = 1200
        let core = I2PSAMRouterCore(
            routerHash: ownerNode.routerHash,
            netDB: netDBInstance,
            participant: ownerNode.participant,
            buildTransport: I2PTunnelLoopbackTransport(hub: buildHub, localRouterHash: ownerNode.routerHash),
            peerProvider: SAMTestPeerProvider(nodes: hopNodeList),
            delivery: I2NPLoopbackDeliveryTransport(hub: deliveryHub, localRouterHash: ownerNode.routerHash),
            i2npRouter: ownerNode.router,
            controlledRouter: { hash in
                if hash == ownerNode.routerHash { return ownerNode.router }
                return hopNodeList.first { $0.routerHash == hash }?.router
            }
        )
        let keyStore = I2PSAMKeyStore(
            service: "\(Bundle.main.bundleIdentifier ?? "ai.opd.garlicrouter").sam-test.\(UUID().uuidString)")
        let serverInstance = I2PSAMServer(core: core, port: 0, poolConfig: poolConfig,
                                          keyStore: keyStore)

        self.buildHub = buildHub
        self.deliveryHub = deliveryHub
        self.owner = ownerNode
        self.hopNodes = hopNodeList
        self.netDB = netDBInstance
        self.server = serverInstance
        SAMTestLog.register(serverInstance)
    }

    var boundPort: UInt16? {
        if case .listening(let port) = server.state { return port }
        return nil
    }

    func start() { server.start() }
    func stop() { server.stop() }
}

// MARK: - Test TCP client

private final class SAMTestPendingRead<Value> {
    private var continuation: CheckedContinuation<Value, Error>?
    private var completed = false
    init(continuation: CheckedContinuation<Value, Error>) {
        self.continuation = continuation
    }
    func fulfill(_ value: Value) {
        guard !completed else { return }
        completed = true
        continuation?.resume(returning: value)
        continuation = nil
    }
    func fail(_ error: Error) {
        guard !completed else { return }
        completed = true
        continuation?.resume(throwing: error)
        continuation = nil
    }
}

private enum SAMTestClientError: Error { case eof }

/// A real TCP client speaking SAM v3.3 lines over 127.0.0.1.
private final class SAMTestClient: @unchecked Sendable {
    private let queue = DispatchQueue(label: "i2p.sam.test.client")
    private var connection: NWConnection?
    private let lock = NSLock()
    private var buffer = Data()
    private var pendingLines: [SAMTestPendingRead<String>] = []
    private var pendingBytes: [(count: Int, pending: SAMTestPendingRead<Data>)] = []
    private var receivedEOF = false
    private var connectPending: SAMTestPendingRead<Void>?

    func connect(port: UInt16) async throws {
        let connection = NWConnection(host: NWEndpoint.Host("127.0.0.1"),
                                      port: NWEndpoint.Port(rawValue: port)!,
                                      using: .tcp)
        self.connection = connection
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.takeConnectPending()?.fulfill(())
                self.receiveNext()
            case .failed(let error):
                self.takeConnectPending()?.fail(error)
            case .cancelled:
                self.takeConnectPending()?.fail(I2PSAMError.timeout)
                self.handleEOF()
            default: break
            }
        }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            lock.lock()
            connectPending = SAMTestPendingRead(continuation: continuation)
            lock.unlock()
            connection.start(queue: queue)
        }
    }

    private func takeConnectPending() -> SAMTestPendingRead<Void>? {
        lock.lock()
        defer { lock.unlock() }
        let pending = connectPending
        connectPending = nil
        return pending
    }

    private func receiveNext() {
        connection?.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty { self.handleData(data) }
            if isComplete || error != nil { self.handleEOF(); return }
            self.receiveNext()
        }
    }

    private func handleData(_ data: Data) {
        lock.lock()
        buffer += data
        while !pendingLines.isEmpty {
            guard let newline = buffer.firstIndex(of: 0x0A) else { break }
            let lineData = Data(Array(buffer[buffer.startIndex..<newline]))
            buffer = Data(Array(buffer[buffer.index(after: newline)...]))
            pendingLines.removeFirst().fulfill(String(decoding: lineData, as: UTF8.self))
        }
        while !pendingBytes.isEmpty {
            guard buffer.count >= pendingBytes[0].count else { break }
            let payload = Data(Array(buffer.prefix(pendingBytes[0].count)))
            buffer = Data(Array(buffer.dropFirst(pendingBytes[0].count)))
            pendingBytes.removeFirst().pending.fulfill(payload)
        }
        lock.unlock()
    }

    private func handleEOF() {
        lock.lock()
        receivedEOF = true
        let lines = pendingLines
        pendingLines = []
        let bytes = pendingBytes
        pendingBytes = []
        lock.unlock()
        lines.forEach { $0.fail(SAMTestClientError.eof) }
        bytes.forEach { $0.pending.fail(SAMTestClientError.eof) }
    }

    func send(_ line: String) {
        connection?.send(content: Data((line + "\n").utf8), completion: .contentProcessed { _ in })
    }

    func sendRaw(_ data: Data) {
        connection?.send(content: data, completion: .contentProcessed { _ in })
    }

    func readLine() async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
            lock.lock()
            // Buffered data wins over EOF: the server may write its final reply
            // and close in one segment, so the line is already in the buffer by
            // the time the close is observed.
            if let newline = buffer.firstIndex(of: 0x0A) {
                let lineData = Data(Array(buffer[buffer.startIndex..<newline]))
                buffer = Data(Array(buffer[buffer.index(after: newline)...]))
                lock.unlock()
                continuation.resume(returning: String(decoding: lineData, as: UTF8.self))
                return
            }
            if receivedEOF {
                lock.unlock()
                continuation.resume(throwing: SAMTestClientError.eof)
                return
            }
            let pending = SAMTestPendingRead<String>(continuation: continuation)
            pendingLines.append(pending)
            lock.unlock()
            scheduleTimeout(pending)
        }
    }

    func readBytes(_ count: Int) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            lock.lock()
            if buffer.count >= count {
                let payload = Data(Array(buffer.prefix(count)))
                buffer = Data(Array(buffer.dropFirst(count)))
                lock.unlock()
                continuation.resume(returning: payload)
                return
            }
            if receivedEOF {
                lock.unlock()
                continuation.resume(throwing: SAMTestClientError.eof)
                return
            }
            let pending = SAMTestPendingRead<Data>(continuation: continuation)
            pendingBytes.append((count, pending))
            lock.unlock()
            scheduleTimeout(pending)
        }
    }

    private func scheduleTimeout<T>(_ pending: SAMTestPendingRead<T>) {
        Task { [weak pending] in
            try? await Task.sleep(for: .seconds(20))
            pending?.fail(I2PSAMError.timeout)
        }
    }

    /// Waits for the server to close the socket (stream teardown).
    func expectClosed(timeout: TimeInterval = 15) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            lock.lock()
            let eof = receivedEOF
            lock.unlock()
            if eof { return }
            try? await Task.sleep(for: .milliseconds(50))
        }
        throw I2PSAMError.timeout
    }

    func close() {
        connection?.cancel()
    }
}

// MARK: - Helpers

private func replyValue(after key: String, in line: String) -> String? {
    for token in line.split(separator: " ") {
        let parts = token.split(separator: "=", maxSplits: 1)
        if parts.count == 2, parts[0] == Substring(key) {
            return String(parts[1])
        }
    }
    return nil
}

private func destinationFromB64(_ text: String) throws -> I2PDestination {
    guard let data = I2PSAMEncoding.normalizedBase64(text) else {
        throw I2PSAMError.invalidDestination
    }
    var reader = I2PReader(data)
    guard let destination = try? I2PKeysAndCert.parse(&reader) else {
        throw I2PSAMError.invalidDestination
    }
    return destination
}

/// Cross-publishes one rig's owner session LeaseSet into the other rig's netdb.
///
/// A session answers `SESSION STATUS RESULT=OK` as soon as it exists, while its
/// LeaseSet publication (tunnel-pool build, then the store) lands shortly after.
/// Looking once and failing made the end-to-end suites flaky — about one run in
/// twenty reported `destinationNotFound` — so this waits for the lease the way
/// a client waits for a destination to become resolvable.
private func crossPublish(from source: SAMTestRig, destinationHash: Data, into target: SAMTestRig) async throws {
    let deadline = Date().addingTimeInterval(5)
    var leaseSet: I2PLeaseSet?
    while Date() < deadline {
        if let entry = await source.netDB.lookup(destinationHash), let found = entry.leaseSet {
            leaseSet = found
            break
        }
        try? await Task.sleep(for: .milliseconds(50))
    }
    guard let leaseSet else { throw I2PSAMError.destinationNotFound }
    try await target.netDB.ingestLeaseSet(leaseSet.serialize())
}

private func sampleSessionHandshake(_ client: SAMTestClient, id: String,
                                    style: I2PSAMStyle = .stream) async throws -> String {
    client.send("HELLO VERSION MIN=3.0 MAX=3.3")
    let hello = try await client.readLine()
    guard hello == "HELLO REPLY RESULT=OK VERSION=3.3" else {
        throw I2PSAMError.invalidCommand("unexpected HELLO reply: \(hello)")
    }
    client.send("SESSION CREATE STYLE=\(style.rawValue) ID=\(id) DESTINATION=TRANSIENT")
    let status = try await client.readLine()
    guard status.hasPrefix("SESSION STATUS RESULT=OK"),
          let destination = replyValue(after: "DESTINATION", in: status) else {
        throw I2PSAMError.invalidCommand("unexpected SESSION STATUS: \(status)")
    }
    return destination
}

// MARK: - Suite

enum I2PSAMConformanceTest {
    /// Stage tracing for the load case (SAM_TRACE=1), so a stalled concurrent
    /// stream names the step it reached instead of only reporting a timeout.
    private static let loadTrace = ProcessInfo.processInfo.environment["SAM_TRACE"] != nil

    static func runAll() async -> [I2PSelfTestResult] {
        var results: [I2PSelfTestResult] = []
        func run(_ name: String, _ body: () async throws -> String) async {
            SAMTestLog.reset()
            // Optional single-case filter for diagnosing one failing scenario
            // (SAM_ONLY=DATAGRAM), so a full 20 s timeout sweep isn't required.
            if let only = ProcessInfo.processInfo.environment["SAM_ONLY"],
               !name.uppercased().contains(only.uppercased()) {
                return
            }
            do {
                results.append(I2PSelfTestResult(name: name, passed: true, detail: try await body()))
            } catch {
                // A SAM failure is almost always a line that never arrived; the
                // bridge's own command log says which stage stalled.
                results.append(I2PSelfTestResult(name: name, passed: false,
                                                 detail: "\(error) · \(SAMTestLog.recent())"))
            }
        }
        await run("SAM handshake + command grammar edge cases over loopback TCP", handshakeTest)
        await run("SAM STREAM session create, LeaseSet publication + session registry", sessionTest)
        await run("SAM NAMING lookup (ME/b32/addressbook) + DEST GENERATE round trip", namingTest)
        await run("SAM NAMING b33 lookup (credentialled resolve + stranger opaque failure)", b33NamingTest)
        await run("SAM b33 publication (encrypted LS2 under the blinded key + self-resolution)", encryptedPublicationTest)
        await run("SAM STREAM CONNECT/ACCEPT end-to-end through tunnels", streamE2ETest)
        await run("SAM DATAGRAM SEND fragmentation + reassembly", datagramTest)
        await run("SAM RAW anonymous datagram delivery", rawTest)
        await run("SAM persistent key store migrates legacy files into Keychain", keyStoreTest)
        await run("SAM session persistence (save/restore private keys)", persistenceTest)
        await run("SAM load: 3 concurrent streams · latency + throughput", loadTest)
        await run("SAM session parameters (SIGNATURE_TYPE / ENCRYPTION_TYPE)", parametersTest)
        return results
    }

    private static func handshakeTest() async throws -> String {
        let rig = try SAMTestRig(label: "handshake")
        rig.start()
        defer { rig.stop() }
        guard let port = await waitForPort(rig) else { throw I2PSAMError.timeout }
        let client = SAMTestClient()
        try await client.connect(port: port)

        // SESSION CREATE before HELLO is rejected.
        client.send("SESSION CREATE STYLE=STREAM ID=x DESTINATION=TRANSIENT")
        let early = try await client.readLine()
        guard early.hasPrefix("SESSION STATUS RESULT=I2P_ERROR") else {
            throw I2PSAMError.invalidCommand("early session accepted: \(early)")
        }

        client.send("HELLO VERSION MIN=3.0 MAX=3.3")
        let hello = try await client.readLine()
        guard hello == "HELLO REPLY RESULT=OK VERSION=3.3" else {
            throw I2PSAMError.invalidCommand("unexpected HELLO: \(hello)")
        }

        // Unknown commands reply I2P_ERROR and keep the connection alive.
        client.send("BOGUS COMMAND ID=1")
        let bogus = try await client.readLine()
        guard bogus.hasPrefix("SESSION STATUS RESULT=I2P_ERROR") else {
            throw I2PSAMError.invalidCommand("bogus accepted: \(bogus)")
        }

        // Incompatible version negotiation.
        client.send("HELLO VERSION MIN=3.4 MAX=3.5")
        let stale = try await client.readLine()
        guard stale == "HELLO REPLY RESULT=NO_VERSION" else {
            throw I2PSAMError.invalidCommand("stale version accepted: \(stale)")
        }
        client.close()
        return "HELLO negotiated at 3.3; pre-HELLO session, bogus verbs and stale versions rejected"
    }

    private static func sessionTest() async throws -> String {
        let rig = try SAMTestRig(label: "session")
        rig.start()
        defer { rig.stop() }
        guard let port = await waitForPort(rig) else { throw I2PSAMError.timeout }
        let client = SAMTestClient()
        try await client.connect(port: port)
        let destination = try await sampleSessionHandshake(client, id: "sess-1")

        // The LeaseSet was published under the session identity.
        let destinationKeys = try destinationFromB64(destination)
        guard let entry = await rig.netDB.lookup(destinationKeys.hash), entry.leaseSet != nil else {
            throw I2PSAMError.destinationNotFound
        }

        // Duplicate session ID rejected.
        client.send("SESSION CREATE STYLE=STREAM ID=sess-1 DESTINATION=TRANSIENT")
        let duplicate = try await client.readLine()
        guard duplicate.hasPrefix("SESSION STATUS RESULT=DUPLICATED_ID") else {
            throw I2PSAMError.invalidCommand("duplicate accepted: \(duplicate)")
        }

        // Imported private destination keys reuse the same identity.
        let imported = I2PSAMDestinationKeys.generate()
        client.send("SESSION CREATE STYLE=STREAM ID=sess-2 DESTINATION=\(imported.privateKeyData.base64EncodedString())")
        let importedStatus = try await client.readLine()
        guard importedStatus.hasPrefix("SESSION STATUS RESULT=DUPLICATED_ID") == false else {
            throw I2PSAMError.invalidCommand("second session blocked: \(importedStatus)")
        }
        guard let importedDest = replyValue(after: "DESTINATION", in: importedStatus),
              importedDest == imported.destination.raw.base64EncodedString() else {
            throw I2PSAMError.invalidCommand("imported destination mismatch: \(importedStatus)")
        }

        // Garbage destination spec rejected.
        client.send("SESSION CREATE STYLE=STREAM ID=sess-3 DESTINATION=not-a-destination")
        let garbage = try await client.readLine()
        guard garbage.hasPrefix("SESSION STATUS RESULT=I2P_ERROR") else {
            throw I2PSAMError.invalidCommand("garbage destination accepted: \(garbage)")
        }
        client.close()
        return "transient + imported destinations verified; LeaseSet published; duplicates and garbage rejected"
    }

    private static func namingTest() async throws -> String {
        let rig = try SAMTestRig(label: "naming")
        rig.start()
        defer { rig.stop() }
        guard let port = await waitForPort(rig) else { throw I2PSAMError.timeout }
        let client = SAMTestClient()
        try await client.connect(port: port)
        let destination = try await sampleSessionHandshake(client, id: "n1")

        // ME resolves to the session destination.
        client.send("NAMING LOOKUP NAME=ME")
        let me = try await client.readLine()
        guard me.hasPrefix("NAMING REPLY RESULT=OK NAME=ME"),
              replyValue(after: "VALUE", in: me) == destination else {
            throw I2PSAMError.invalidCommand("ME lookup failed: \(me)")
        }

        // .b32.i2p hosts resolve via the netdb.
        let published = I2PSAMDestinationKeys.generate()
        let leaseSet = I2PLeaseSet(destination: published.destination, published: Date(), leases: [
            I2PLease(gatewayHash: rig.hopNodes[0].routerHash, tunnelId: 0x1234_5678,
                     expiration: Date().addingTimeInterval(600))
        ])
        var signed = leaseSet
        try signed.sign(withSeed: published.signingSeed)
        try await rig.netDB.ingestLeaseSet(signed.serialize())
        let host = "\(I2PSAMEncoding.base32Encode(published.destination.hash)).b32.i2p"
        client.send("NAMING LOOKUP NAME=\(host)")
        let b32Reply = try await client.readLine()
        guard b32Reply.hasPrefix("NAMING REPLY RESULT=OK"),
              replyValue(after: "VALUE", in: b32Reply) == published.destination.raw.base64EncodedString() else {
            throw I2PSAMError.invalidCommand("b32 lookup failed: \(b32Reply)")
        }

        // Unknown hosts return KEY_NOT_FOUND.
        client.send("NAMING LOOKUP NAME=nonexistent.i2p")
        let missing = try await client.readLine()
        guard missing.hasPrefix("NAMING REPLY RESULT=KEY_NOT_FOUND") else {
            throw I2PSAMError.invalidCommand("unknown host resolved: \(missing)")
        }

        // Addressbook import + lookup (destination import utility).
        client.send("NAMING ADD NAME=Example.eepsite DESTINATION=\(published.destination.raw.base64EncodedString())")
        let add = try await client.readLine()
        guard add.hasPrefix("NAMING REPLY RESULT=OK") else {
            throw I2PSAMError.invalidCommand("naming add failed: \(add)")
        }
        client.send("NAMING LOOKUP NAME=Example.eepsite")
        let book = try await client.readLine()
        guard book.hasPrefix("NAMING REPLY RESULT=OK") else {
            throw I2PSAMError.invalidCommand("addressbook lookup failed: \(book)")
        }

        // DEST GENERATE round trip: PUB from PRIV.
        client.send("DEST GENERATE")
        let dest = try await client.readLine()
        guard dest.hasPrefix("DEST REPLY PUB="), let pub = replyValue(after: "PUB", in: dest),
              let priv = replyValue(after: "PRIV", in: dest) else {
            throw I2PSAMError.invalidCommand("dest generate failed: \(dest)")
        }
        let parsed = try I2PSAMDestinationKeys.parse(I2PSAMEncoding.normalizedBase64(priv)!)
        guard parsed.destination.raw.base64EncodedString() == pub else {
            throw I2PSAMError.invalidCommand("key conversion mismatch")
        }
        client.close()
        return "ME/b32/addressbook lookups + import verified; DEST GENERATE pub/priv round-trips"
    }

    /// NAMING LOOKUP with b33 blinded addresses: a session holding the
    /// destination's credentials (Ed25519 seed + ECIES X25519 private key)
    /// resolves the encrypted LeaseSet2 through the blinding path; a stranger
    /// host's b33 — and a corrupted one — fail closed with the spec result.
    private static func b33NamingTest() async throws -> String {
        let rig = try SAMTestRig(label: "b33-naming")
        rig.start()
        defer { rig.stop() }
        guard let port = await waitForPort(rig) else { throw I2PSAMError.timeout }

        // A session with known credentials (imported keys, not TRANSIENT) so
        // the test can derive the destination's b33 and publish its encrypted
        // LeaseSet2 under the blinded key.
        let keys = I2PSAMDestinationKeys.generate()
        let client = SAMTestClient()
        try await client.connect(port: port)
        client.send("HELLO VERSION MIN=3.0 MAX=3.3")
        _ = try await client.readLine()
        client.send("SESSION CREATE STYLE=STREAM ID=b33 DESTINATION=\(keys.privateKeyData.base64EncodedString())")
        let status = try await client.readLine()
        guard status.hasPrefix("SESSION STATUS RESULT=OK") else {
            throw I2PSAMError.invalidCommand("b33 session failed: \(status)")
        }

        let credentials = I2PB33Credentials(
            ed25519Seed: keys.signingSeed,
            x25519PrivateKey: keys.encryptionKey.rawRepresentation)
        let blinded = try I2PB33Blinding.blind(
            destinationSeed: keys.signingSeed,
            encryptionPublicKey: keys.encryptionKey.publicKey.rawRepresentation)

        // Publish an encrypted LS2 envelope for the destination under its
        // blinded netdb key; the inner plain LS2 carries one live lease.
        let inner = try I2PLeaseSet2.build(
            storeType: .plain,
            destination: keys.destination,
            published: Date(),
            expiresOffsetSeconds: 600,
            leases: [
                I2PLease2(gatewayHash: rig.hopNodes[0].routerHash,
                          tunnelId: 0x0BAD_F00D,
                          expiration: Date().addingTimeInterval(600)),
            ],
            signingSeed: keys.signingSeed)
        let envelope = try I2PB33Blinding.buildEncryptedLeaseSet2(
            inner: inner, credentials: credentials)
        try await rig.netDB.ingestLeaseSet2(envelope.serialize(),
                                            entryType: .encryptedLeaseSet2)

        // The session's own b33 resolves to the real destination.
        client.send("NAMING LOOKUP NAME=\(blinded.b33Address)")
        let resolved = try await client.readLine()
        guard resolved.hasPrefix("NAMING REPLY RESULT=OK NAME="),
              replyValue(after: "VALUE", in: resolved) == keys.destination.raw.base64EncodedString() else {
            throw I2PSAMError.invalidCommand("b33 resolution failed: \(resolved)")
        }

        // A stranger's b33 (credentials we do not hold) fails closed: the
        // encrypted inner body stays opaque, the lookup answers the spec
        // resolution failure and no destination material surfaces.
        let strangerKeys = I2PSAMDestinationKeys.generate()
        let strangerBlinded = try I2PB33Blinding.blind(
            destinationSeed: strangerKeys.signingSeed,
            encryptionPublicKey: strangerKeys.encryptionKey.publicKey.rawRepresentation)
        client.send("NAMING LOOKUP NAME=\(strangerBlinded.b33Address)")
        let stranger = try await client.readLine()
        guard stranger.hasPrefix("NAMING REPLY RESULT=KEY_NOT_FOUND"),
              replyValue(after: "VALUE", in: stranger) == nil else {
            throw I2PSAMError.invalidCommand("stranger b33 leaked or resolved: \(stranger)")
        }

        // A corrupted b33 checksum is rejected by the codec — still no leak.
        var tampered = Array(strangerBlinded.b33Address)
        let original = tampered[2]
        let replacement = I2PB33Blinding.b33ChecksumSecond.first { $0 != original } ?? "a"
        guard replacement != original else { throw I2PSAMError.invalidCommand("checksum probe degenerate") }
        tampered[2] = replacement
        client.send("NAMING LOOKUP NAME=\(String(tampered))")
        let corrupt = try await client.readLine()
        guard corrupt.hasPrefix("NAMING REPLY RESULT=KEY_NOT_FOUND")
                || corrupt.hasPrefix("NAMING REPLY RESULT=I2P_ERROR") else {
            throw I2PSAMError.invalidCommand("corrupt b33 resolved: \(corrupt)")
        }

        client.close()
        return "credentialled b33 resolved to the real destination; stranger and corrupt b33 failed closed"
    }

    /// Encrypted (b33) LeaseSet2 publication: a session created with
    /// ENCRYPTED_LEASESET=true publishes its leases encrypted under its
    /// destination's blinded key (stored under the blinded netdb key, no plain
    /// entry left behind), hands out its own b33 address, and the published
    /// entry resolves back to the session's own live leases.
    private static func encryptedPublicationTest() async throws -> String {
        let rig = try SAMTestRig(label: "b33-publish")
        rig.start()
        defer { rig.stop() }
        guard let port = await waitForPort(rig) else { throw I2PSAMError.timeout }

        // Imported keys (not TRANSIENT) so the test derives the same b33.
        let keys = I2PSAMDestinationKeys.generate()
        let client = SAMTestClient()
        try await client.connect(port: port)
        defer { client.close() }
        client.send("HELLO VERSION MIN=3.0 MAX=3.3")
        _ = try await client.readLine()
        client.send("SESSION CREATE STYLE=STREAM ID=b33pub DESTINATION=\(keys.privateKeyData.base64EncodedString()) ENCRYPTED_LEASESET=true")
        let status = try await client.readLine()
        guard status.hasPrefix("SESSION STATUS RESULT=OK") else {
            throw I2PSAMError.invalidCommand("encrypted session failed: \(status)")
        }

        let blinded = try I2PB33Blinding.blind(
            destinationSeed: keys.signingSeed,
            encryptionPublicKey: keys.encryptionKey.publicKey.rawRepresentation)

        // The session hands out its own b33 address.
        guard replyValue(after: "B33", in: status) == blinded.b33Address,
              I2PB33Blinding.b33Decode(blinded.b33Address) == blinded.blindedPublicKey else {
            throw I2PSAMError.invalidCommand("b33 address not handed out: \(status)")
        }
        guard let session = rig.server.session(named: "b33pub"),
              session.b33Address == blinded.b33Address,
              session.blindedNetDBKey == blinded.netDBKey else {
            throw I2PSAMError.invalidCommand("session b33 key set mismatch")
        }

        let liveLeases = session.pool.inboundTunnels.filter { !$0.isExpired() }
        guard !liveLeases.isEmpty else { throw I2PSAMError.noTunnels }

        // Publication: the encrypted entry is stored under the blinded netdb
        // key, signature-verified, and its envelope destination carries the
        // blinded signing key.
        guard let entry = await rig.netDB.lookup(blinded.netDBKey),
              let envelope = entry.leaseSet2,
              entry.entryType == .encryptedLeaseSet2,
              envelope.storeType == .encrypted,
              envelope.destination.hash == blinded.netDBKey,
              envelope.destination.signingPublicKey == blinded.blindedPublicKey,
              envelope.verifySignature() else {
            throw I2PSAMError.invalidCommand("encrypted entry missing under the blinded key")
        }
        // Nothing plain was left behind under the destination hash.
        guard await rig.netDB.lookup(keys.destination.hash) == nil,
              session.leaseSet == nil else {
            throw I2PSAMError.invalidCommand("plain LeaseSet published alongside the b33 entry")
        }

        // Self-resolution: the published entry decrypts back to the session's
        // own live leases and destination.
        let credentials = I2PB33Credentials(
            ed25519Seed: keys.signingSeed,
            x25519PrivateKey: keys.encryptionKey.rawRepresentation)
        guard let resolved = await rig.netDB.lookupEncryptedLeaseSet2(credentials: credentials),
              resolved.storeType == .plain,
              resolved.destination.hash == keys.destination.hash,
              Set(resolved.leases.map(\.tunnelId)) == Set(liveLeases.map(\.gatewayTunnelID)),
              Set(resolved.leases.map(\.gatewayHash)) == Set(liveLeases.map { $0.hops[0].routerHash }) else {
            throw I2PSAMError.destinationNotFound
        }
        // ... and surfaces through the delivery path plain LS2s use.
        guard let delivery = await rig.netDB.resolveEncryptedDestination(credentials: credentials),
              delivery.destination.hash == keys.destination.hash,
              delivery.leases.count == liveLeases.count else {
            throw I2PSAMError.destinationNotFound
        }

        // A renewal cycle rebuilds from the live leases and the entry keeps
        // resolving; a stranger's credentials still resolve nothing.
        _ = await session.publishLeaseSet()
        _ = await session.refreshEncryptedPublication()
        guard let again = await rig.netDB.lookupEncryptedLeaseSet2(credentials: credentials),
              again.destination.hash == keys.destination.hash,
              Set(again.leases.map(\.tunnelId)) == Set(liveLeases.map(\.gatewayTunnelID)) else {
            throw I2PSAMError.invalidCommand("renewal lost the published b33 entry")
        }
        let stranger = I2PB33Credentials(
            ed25519Seed: I2PCrypto.generateEd25519Seed(),
            x25519PrivateKey: I2PCrypto.generateX25519KeyPair().privateKey)
        guard await rig.netDB.lookupEncryptedLeaseSet2(credentials: stranger) == nil else {
            throw I2PSAMError.invalidCommand("stranger credentials resolved the b33 entry")
        }

        // A session without the option publishes its plain LeaseSet and hands
        // out no b33 address.
        let plainClient = SAMTestClient()
        try await plainClient.connect(port: port)
        defer { plainClient.close() }
        plainClient.send("HELLO VERSION MIN=3.0 MAX=3.3")
        _ = try await plainClient.readLine()
        plainClient.send("SESSION CREATE STYLE=STREAM ID=plain1 DESTINATION=TRANSIENT")
        let plainStatus = try await plainClient.readLine()
        guard plainStatus.hasPrefix("SESSION STATUS RESULT=OK"),
              replyValue(after: "B33", in: plainStatus) == nil else {
            throw I2PSAMError.invalidCommand("plain session handed out a b33: \(plainStatus)")
        }

        return "b33 publication under the blinded key \(blinded.netDBKey.hex.prefix(12))… · \(liveLeases.count) leases self-resolved; plain session stayed unblinded"
    }

    private static func streamE2ETest() async throws -> String {
        let aliceRig = try SAMTestRig(label: "stream-a")
        let bobRig = try SAMTestRig(label: "stream-b")
        aliceRig.start()
        bobRig.start()
        defer { aliceRig.stop(); bobRig.stop() }
        guard let alicePort = await waitForPort(aliceRig), let bobPort = await waitForPort(bobRig) else {
            throw I2PSAMError.timeout
        }

        let aliceClient = SAMTestClient()
        try await aliceClient.connect(port: alicePort)
        let aliceDestination = try await sampleSessionHandshake(aliceClient, id: "a1")
        let aliceDestKeys = try destinationFromB64(aliceDestination)

        let bobClient = SAMTestClient()
        try await bobClient.connect(port: bobPort)
        let bobDestination = try await sampleSessionHandshake(bobClient, id: "b1")
        // Both sides must see each other's LeaseSet: Bob resolves Alice's to
        // send the SYN; Alice resolves Bob's to send the SYN-ACK and data back.
        try await crossPublish(from: aliceRig, destinationHash: aliceDestKeys.hash, into: bobRig)
        let bobDestKeys = try destinationFromB64(bobDestination)
        try await crossPublish(from: bobRig, destinationHash: bobDestKeys.hash, into: aliceRig)

        // The connect resolves the destination through the rig's netdb; wait
        // until that lookup can answer, so a rare slow ingest is not reported as
        // a connect failure.
        let resolveDeadline = Date().addingTimeInterval(5)
        var resolvable = false
        while Date() < resolveDeadline {
            if let entry = await bobRig.netDB.lookup(aliceDestKeys.hash), entry.leaseSet != nil {
                resolvable = true
                break
            }
            try? await Task.sleep(for: .milliseconds(100))
        }
        guard resolvable else { throw I2PSAMError.destinationNotFound }

        // Alice listens, Bob connects: the SYN traverses Bob's outbound tunnel,
        // Bob's lease registry, Alice's inbound tunnel and her garlic pipeline.
        aliceClient.send("STREAM ACCEPT ID=a1")
        bobClient.send("STREAM CONNECT ID=b1 DESTINATION=\(aliceDestination)")
        let bobStatus = try await bobClient.readLine()
        guard bobStatus.hasPrefix("STREAM STATUS RESULT=OK ID=b1") else {
            throw I2PSAMError.invalidCommand("connect failed: \(bobStatus)")
        }
        let aliceStatus = try await aliceClient.readLine()
        guard aliceStatus.hasPrefix("STREAM STATUS RESULT=OK ID=a1") else {
            throw I2PSAMError.invalidCommand("accept failed: \(aliceStatus)")
        }

        // Bidirectional data over the garlic'd stream.
        bobClient.sendRaw(Data("hello alice".utf8))
        let received = try await aliceClient.readBytes(11)
        guard received == Data("hello alice".utf8) else {
            throw I2PSAMError.invalidCommand("inbound stream data mismatch")
        }
        aliceClient.sendRaw(Data("hi bob".utf8))
        let reply = try await bobClient.readBytes(6)
        guard reply == Data("hi bob".utf8) else {
            throw I2PSAMError.invalidCommand("outbound stream data mismatch")
        }

        // Closing Bob's TCP propagates FIN through garlic and closes Alice's side.
        bobClient.close()
        try await aliceClient.expectClosed()
        return "CONNECT/ACCEPT established via tunnels; bidirectional data verified; FIN propagated"
    }

    private static func datagramTest() async throws -> String {
        let aliceRig = try SAMTestRig(label: "datagram-a")
        let bobRig = try SAMTestRig(label: "datagram-b")
        aliceRig.start()
        bobRig.start()
        defer { aliceRig.stop(); bobRig.stop() }
        guard let alicePort = await waitForPort(aliceRig), let bobPort = await waitForPort(bobRig) else {
            throw I2PSAMError.timeout
        }

        let aliceClient = SAMTestClient()
        try await aliceClient.connect(port: alicePort)
        let aliceDestination = try await sampleSessionHandshake(aliceClient, id: "a2", style: .datagram)
        let aliceDestKeys = try destinationFromB64(aliceDestination)

        let bobClient = SAMTestClient()
        try await bobClient.connect(port: bobPort)
        try await sampleSessionHandshake(bobClient, id: "b2", style: .datagram)
        try await crossPublish(from: aliceRig, destinationHash: aliceDestKeys.hash, into: bobRig)

        // A 2500-byte datagram splits into 5 garlic chunks and reassembles.
        let payload = I2PCrypto.randomBytes(2500)
        bobClient.send("DATAGRAM SEND ID=b2 DESTINATION=\(aliceDestination) SIZE=2500")
        bobClient.sendRaw(payload)
        let header = try await aliceClient.readLine()
        guard header.hasPrefix("DATAGRAM RECEIVED DESTINATION="),
              header.contains("SIZE=2500") else {
            throw I2PSAMError.invalidCommand("unexpected datagram header: \(header)")
        }
        let received = try await aliceClient.readBytes(2500)
        guard received == payload else {
            throw I2PSAMError.invalidCommand("datagram payload mismatch after reassembly")
        }
        aliceClient.close()
        bobClient.close()
        return "2500-byte datagram fragmented into garlic chunks and reassembled intact"
    }

    private static func rawTest() async throws -> String {
        let aliceRig = try SAMTestRig(label: "raw-a")
        let bobRig = try SAMTestRig(label: "raw-b")
        aliceRig.start()
        bobRig.start()
        defer { aliceRig.stop(); bobRig.stop() }
        guard let alicePort = await waitForPort(aliceRig), let bobPort = await waitForPort(bobRig) else {
            throw I2PSAMError.timeout
        }

        let aliceClient = SAMTestClient()
        try await aliceClient.connect(port: alicePort)
        let aliceDestination = try await sampleSessionHandshake(aliceClient, id: "a3", style: .datagram)
        let aliceDestKeys = try destinationFromB64(aliceDestination)

        let bobClient = SAMTestClient()
        try await bobClient.connect(port: bobPort)
        try await sampleSessionHandshake(bobClient, id: "b3", style: .raw)
        try await crossPublish(from: aliceRig, destinationHash: aliceDestKeys.hash, into: bobRig)

        // Anonymous send: the payload arrives with no return destination.
        let payload = I2PCrypto.randomBytes(400)
        bobClient.send("DATAGRAM SEND ID=b3 DESTINATION=\(aliceDestination) SIZE=400")
        bobClient.sendRaw(payload)
        let header = try await aliceClient.readLine()
        guard header.hasPrefix("DATAGRAM RECEIVED SIZE=400"), !header.contains("DESTINATION") else {
            throw I2PSAMError.invalidCommand("anonymous datagram carried a return address: \(header)")
        }
        let received = try await aliceClient.readBytes(400)
        guard received == payload else {
            throw I2PSAMError.invalidCommand("raw datagram payload mismatch")
        }
        aliceClient.close()
        bobClient.close()
        return "RAW datagram delivered anonymously without a return destination"
    }

    /// Legacy key files migrate only after a successful Keychain write, and
    /// normal saves never leave private destination material on disk.
    private static func keyStoreTest() async throws -> String {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("sam-key-store-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let nickname = "legacy-\(UUID().uuidString)"
        let service = "\(Bundle.main.bundleIdentifier ?? "ai.opd.garlicrouter").sam-test.\(UUID().uuidString)"
        let store = I2PSAMKeyStore(directory: directory, service: service)
        let legacyFile = directory.appendingPathComponent(
            I2PCrypto.sha256(Data(nickname.utf8)).hex + ".key")
        let legacyKey = I2PCrypto.randomBytes(64)
        try Data(legacyKey.base64EncodedString().utf8).write(to: legacyFile)
        defer {
            try? store.remove(nickname: nickname)
            try? FileManager.default.removeItem(at: directory)
        }

        let migrated = try store.load(nickname: nickname)
        guard migrated == legacyKey,
              !FileManager.default.fileExists(atPath: legacyFile.path) else {
            throw I2PSAMError.invalidCommand("legacy_key_migration_failed")
        }

        let replacement = I2PCrypto.randomBytes(64)
        try store.save(nickname: nickname, privateKey: replacement)
        guard try store.load(nickname: nickname) == replacement,
              (try FileManager.default.contentsOfDirectory(atPath: directory.path)).isEmpty else {
            throw I2PSAMError.invalidCommand("keychain_key_persistence_failed")
        }
        try store.remove(nickname: nickname)
        guard try store.load(nickname: nickname) == nil else {
            throw I2PSAMError.invalidCommand("keychain_key_removal_failed")
        }
        return "legacy key migrated and removed; new key persisted in Keychain without a plaintext file"
    }

    /// Session persistence: PERSISTENT=true saves the destination's private
    /// key in the Keychain; a later session with the same nickname restores the
    /// same destination. Plain TRANSIENT stays fresh.
    private static func persistenceTest() async throws -> String {
        let rig = try SAMTestRig(label: "persist")
        rig.start()
        defer {
            rig.stop()
            try? rig.server.keyStore.remove(nickname: "p1")
        }
        guard let port = await waitForPort(rig) else { throw I2PSAMError.timeout }

        let first = SAMTestClient()
        try await first.connect(port: port)
        first.send("HELLO VERSION MIN=3.0 MAX=3.3")
        _ = try await first.readLine()
        first.send("SESSION CREATE STYLE=STREAM ID=p1 DESTINATION=TRANSIENT PERSISTENT=true")
        let status1 = try await first.readLine()
        guard status1.hasPrefix("SESSION STATUS RESULT=OK"),
              let destination1 = replyValue(after: "DESTINATION", in: status1) else {
            throw I2PSAMError.invalidCommand("persistent session failed: \(status1)")
        }
        first.close()
        // Allow the bridge to tear the session down before re-creating it.
        try await Task.sleep(for: .milliseconds(200))

        let second = SAMTestClient()
        try await second.connect(port: port)
        second.send("HELLO VERSION MIN=3.0 MAX=3.3")
        _ = try await second.readLine()
        second.send("SESSION CREATE STYLE=STREAM ID=p1 DESTINATION=TRANSIENT PERSISTENT=true")
        let status2 = try await second.readLine()
        guard status2.hasPrefix("SESSION STATUS RESULT=OK"),
              let restored = replyValue(after: "DESTINATION", in: status2),
              restored == destination1 else {
            throw I2PSAMError.invalidCommand("session persistence failed: \(status2)")
        }

        // Without PERSISTENT, a TRANSIENT session gets a fresh destination.
        second.send("SESSION CREATE STYLE=STREAM ID=p2 DESTINATION=TRANSIENT")
        let status3 = try await second.readLine()
        guard status3.hasPrefix("SESSION STATUS RESULT=OK"),
              let fresh = replyValue(after: "DESTINATION", in: status3),
              fresh != destination1 else {
            throw I2PSAMError.invalidCommand("transient semantics failed: \(status3)")
        }
        second.close()
        return "persistent session restored the same destination; plain TRANSIENT stayed fresh"
    }

    /// Load validation: three concurrent stream pairs (each on its own
    /// connection, per SAM v3 one-stream-per-connection), latency probes and
    /// a bidirectional bulk round-trip per stream.
    private static func loadTest() async throws -> String {
        let aliceRig = try SAMTestRig(label: "load-a")
        let bobRig = try SAMTestRig(label: "load-b")
        aliceRig.start()
        bobRig.start()
        defer { aliceRig.stop(); bobRig.stop() }
        guard let alicePort = await waitForPort(aliceRig), let bobPort = await waitForPort(bobRig) else {
            throw I2PSAMError.timeout
        }

        let pairs = 3
        var aliceClients: [SAMTestClient] = []
        var bobClients: [SAMTestClient] = []
        defer {
            aliceClients.forEach { $0.close() }
            bobClients.forEach { $0.close() }
        }
        for index in 0..<pairs {
            let aliceClient = SAMTestClient()
            try await aliceClient.connect(port: alicePort)
            let aliceDestination = try await sampleSessionHandshake(aliceClient, id: "la\(index)")
            let bobClient = SAMTestClient()
            try await bobClient.connect(port: bobPort)
            let bobDestination = try await sampleSessionHandshake(bobClient, id: "lb\(index)")
            try await crossPublish(from: aliceRig, destinationHash: try destinationFromB64(aliceDestination).hash, into: bobRig)
            try await crossPublish(from: bobRig, destinationHash: try destinationFromB64(bobDestination).hash, into: aliceRig)

            aliceClient.send("STREAM ACCEPT ID=la\(index)")
            bobClient.send("STREAM CONNECT ID=lb\(index) DESTINATION=\(aliceDestination)")
            let connectStatus = try await bobClient.readLine()
            guard connectStatus.hasPrefix("STREAM STATUS RESULT=OK") else {
                throw I2PSAMError.invalidCommand("pair \(index) connect failed: \(connectStatus)")
            }
            let acceptStatus = try await aliceClient.readLine()
            guard acceptStatus.hasPrefix("STREAM STATUS RESULT=OK") else {
                throw I2PSAMError.invalidCommand("pair \(index) accept failed: \(acceptStatus)")
            }
            aliceClients.append(aliceClient)
            bobClients.append(bobClient)
            if loadTrace { print("TRACE load: pair \(index) established") }
        }

        // Concurrent workout: latency probes then a bidirectional bulk
        // transfer on every stream, all three pairs running at once.
        let probe = I2PCrypto.randomBytes(32)
        let bulk = I2PCrypto.randomBytes(8192)
        var totalRTTms = 0.0
        var aggregateKBps = 0.0
        let started = Date()
        try await withThrowingTaskGroup(of: (rttMs: Double, kbps: Double).self) { group in
            for index in 0..<pairs {
                group.addTask {
                    let trace = loadTrace
                    var rttTotal = 0.0
                    for round in 0..<6 {
                        let sent = Date()
                        bobClients[index].sendRaw(probe)
                        let echoed = try await aliceClients[index].readBytes(probe.count)
                        guard echoed == probe else {
                            throw I2PSAMError.invalidCommand("latency probe mismatch")
                        }
                        aliceClients[index].sendRaw(echoed)
                        _ = try await bobClients[index].readBytes(probe.count)
                        rttTotal += Date().timeIntervalSince(sent)
                        if trace { print("TRACE load: stream \(index) probe \(round) ok") }
                    }
                    let roundTripStart = Date()
                    bobClients[index].sendRaw(bulk)
                    if trace { print("TRACE load: stream \(index) bulk sent") }
                    let inbound = try await aliceClients[index].readBytes(bulk.count)
                    guard inbound == bulk else {
                        throw I2PSAMError.invalidCommand("bulk inbound mismatch")
                    }
                    if trace { print("TRACE load: stream \(index) bulk inbound ok") }
                    aliceClients[index].sendRaw(inbound)
                    let outbound = try await bobClients[index].readBytes(bulk.count)
                    guard outbound == bulk else {
                        throw I2PSAMError.invalidCommand("bulk echo mismatch")
                    }
                    if trace { print("TRACE load: stream \(index) bulk echo ok") }
                    let elapsed = Date().timeIntervalSince(roundTripStart)
                    let kbps = elapsed > 0 ? Double(bulk.count * 2) / elapsed / 1024 : 0
                    return (rttMs: (rttTotal / 6) * 1000, kbps: kbps)
                }
            }
            for try await result in group {
                totalRTTms += result.rttMs
                aggregateKBps += result.kbps
            }
        }
        let elapsed = Date().timeIntervalSince(started)
        return String(format: "3 concurrent streams verified · avg RTT %.1f ms · %.0f KB/s aggregate · %.1f s workout",
                      totalRTTms / Double(pairs), aggregateKBps, elapsed)
    }

    private static func parametersTest() async throws -> String {
        let rig = try SAMTestRig(label: "params")
        rig.start()
        defer { rig.stop() }
        guard let port = await waitForPort(rig) else { throw I2PSAMError.timeout }

        let client = SAMTestClient()
        try await client.connect(port: port)
        defer { client.close() }

        client.send("HELLO VERSION MIN=3.0 MAX=3.3")
        _ = try await client.readLine()

        // The router's native modern types are accepted, numeric and named.
        client.send("SESSION CREATE STYLE=STREAM ID=t1 DESTINATION=TRANSIENT SIGNATURE_TYPE=7 ENCRYPTION_TYPE=4")
        let ok = try await client.readLine()
        guard ok.hasPrefix("SESSION STATUS RESULT=OK") else {
            throw I2PSAMError.invalidCommand("modern types rejected: \(ok)")
        }
        client.send("SESSION CREATE STYLE=STREAM ID=t2 DESTINATION=TRANSIENT SIGNATURE_TYPE=EdDSA_SHA512_Ed25519 ENCRYPTION_TYPE=ECIES_X25519")
        let ok2 = try await client.readLine()
        guard ok2.hasPrefix("SESSION STATUS RESULT=OK") else {
            throw I2PSAMError.invalidCommand("named types rejected: \(ok2)")
        }

        // Legacy crypto is rejected: the router is modern-crypto only.
        client.send("SESSION CREATE STYLE=STREAM ID=t3 DESTINATION=TRANSIENT SIGNATURE_TYPE=DSA_SHA1")
        let legacySig = try await client.readLine()
        guard legacySig.hasPrefix("SESSION STATUS RESULT=I2P_ERROR"),
              legacySig.contains("unsupported_signature_type") else {
            throw I2PSAMError.invalidCommand("legacy signature type accepted: \(legacySig)")
        }
        client.send("SESSION CREATE STYLE=STREAM ID=t4 DESTINATION=TRANSIENT ENCRYPTION_TYPE=ELGAMAL_2048")
        let legacyEnc = try await client.readLine()
        guard legacyEnc.hasPrefix("SESSION STATUS RESULT=I2P_ERROR"),
              legacyEnc.contains("unsupported_encryption_type") else {
            throw I2PSAMError.invalidCommand("legacy encryption type accepted: \(legacyEnc)")
        }

        return "modern signature/encryption types accepted (numeric + named); legacy DSA/ElGamal rejected"
    }

    private static func waitForPort(_ rig: SAMTestRig, timeout: TimeInterval = 10) async -> UInt16? {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if let port = rig.boundPort { return port }
            try? await Task.sleep(for: .milliseconds(50))
        }
        return nil
    }
}