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

private final class SAMTestNode {
    let routerHash = I2PCrypto.randomBytes(32)
    let encryptionKey = Curve25519.KeyAgreement.PrivateKey()
    let participant: I2PTunnelParticipant
    let router: I2NPMessageRouter

    init(buildHub: I2PTunnelBuildHub, deliveryHub: I2NPLoopbackDeliveryHub) {
        participant = I2PTunnelParticipant(
            localRouterHash: routerHash,
            localEncryptionKey: encryptionKey,
            transport: I2PTunnelLoopbackTransport(hub: buildHub, localRouterHash: routerHash)
        )
        buildHub.register(participant)
        router = I2NPMessageRouter(localRouterHash: routerHash)
        let delivery = I2NPLoopbackDeliveryTransport(hub: deliveryHub, localRouterHash: routerHash)
        router.deliveryTransport = delivery
        deliveryHub.attach(router)
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

    init(label: String) throws {
        // Build everything with local constants first so the core's
        // controlledRouter closure captures nodes, not self.
        let buildHub = I2PTunnelBuildHub()
        let deliveryHub = I2NPLoopbackDeliveryHub()
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
        let serverInstance = I2PSAMServer(core: core, port: 0, poolConfig: poolConfig)

        self.buildHub = buildHub
        self.deliveryHub = deliveryHub
        self.owner = ownerNode
        self.hopNodes = hopNodeList
        self.netDB = netDBInstance
        self.server = serverInstance
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
            if receivedEOF {
                lock.unlock()
                continuation.resume(throwing: SAMTestClientError.eof)
                return
            }
            if let newline = buffer.firstIndex(of: 0x0A) {
                let lineData = Data(Array(buffer[buffer.startIndex..<newline]))
                buffer = Data(Array(buffer[buffer.index(after: newline)...]))
                lock.unlock()
                continuation.resume(returning: String(decoding: lineData, as: UTF8.self))
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
            if receivedEOF {
                lock.unlock()
                continuation.resume(throwing: SAMTestClientError.eof)
                return
            }
            if buffer.count >= count {
                let payload = Data(Array(buffer.prefix(count)))
                buffer = Data(Array(buffer.dropFirst(count)))
                lock.unlock()
                continuation.resume(returning: payload)
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
private func crossPublish(from source: SAMTestRig, destinationHash: Data, into target: SAMTestRig) async throws {
    guard let entry = await source.netDB.lookup(destinationHash), let leaseSet = entry.leaseSet else {
        throw I2PSAMError.destinationNotFound
    }
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
    static func runAll() async -> [I2PSelfTestResult] {
        var results: [I2PSelfTestResult] = []
        func run(_ name: String, _ body: () async throws -> String) async {
            do {
                results.append(I2PSelfTestResult(name: name, passed: true, detail: try await body()))
            } catch {
                results.append(I2PSelfTestResult(name: name, passed: false, detail: String(describing: error)))
            }
        }
        await run("SAM handshake + command grammar edge cases over loopback TCP", handshakeTest)
        await run("SAM STREAM session create, LeaseSet publication + session registry", sessionTest)
        await run("SAM NAMING lookup (ME/b32/addressbook) + DEST GENERATE round trip", namingTest)
        await run("SAM STREAM CONNECT/ACCEPT end-to-end through tunnels", streamE2ETest)
        await run("SAM DATAGRAM SEND fragmentation + reassembly", datagramTest)
        await run("SAM RAW anonymous datagram delivery", rawTest)
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

    private static func waitForPort(_ rig: SAMTestRig, timeout: TimeInterval = 10) async -> UInt16? {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if let port = rig.boundPort { return port }
            try? await Task.sleep(for: .milliseconds(50))
        }
        return nil
    }
}