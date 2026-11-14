//
//  I2PNetDBTests.swift
//  Self-tests for the Network Database: XOR metric, message round trips,
//  signature-gated acceptance, store→lookup across floodfills, replication gossip,
//  expiration, persistence and bootstrapping discovery — exercised over a loopback
//  message bus connecting multiple NetDB instances.
//

import Foundation

enum I2PNetDBSelfTest {
    /// Named failure so a self-test row reports which assertion broke instead
    /// of a bare `invalidFormat`.
    private struct Failure: Error, CustomStringConvertible {
        let description: String
        init(_ description: String) { self.description = description }
    }

    static func runAll() async -> [I2PSelfTestResult] {
        var results: [I2PSelfTestResult] = []
        func run(_ name: String, _ body: () async throws -> String) async {
            do {
                let detail = try await body()
                results.append(I2PSelfTestResult(name: name, passed: true, detail: detail))
            } catch {
                results.append(I2PSelfTestResult(name: name, passed: false, detail: String(describing: error)))
            }
        }

        await run("NetDB store→lookup across floodfills") { try await testStoreLookup() }
        await run("NetDB lookup not blocked by an unreachable floodfill") { try await testUnreachableFloodfillLookup() }
        await run("NetDB lookup reaches a live floodfill beyond the closest set") { try await testReachableBeyondClosest() }
        await run("NetDB floodfill replication gossip") { try await testReplicationGossip() }
        await run("NetDB accepts verified entries only") { try await testRejectsUnverified() }
        await run("NetDB expiration & pruning") { try await testExpiration() }
        await run("NetDB persistent storage restore") { try await testPersistence() }
        await run("NetDB bootstrapping discovery") { try await testBootstrap() }
        return results
    }

    // MARK: Test harness

    /// A loopback transport that only delivers to an allowed set of peers; sends
    /// to every other hash are dropped, modeling floodfills we cannot reach.
    private final class SelectiveTransport: I2PNetDBTransport {
        private unowned let hub: I2PNetDBLoopbackHub
        private let allowed: Set<Data>
        init(hub: I2PNetDBLoopbackHub, allowed: Set<Data>) {
            self.hub = hub
            self.allowed = allowed
        }
        func send(to routerHash: Data, message: I2PNetDBMessage) async throws {
            guard allowed.contains(routerHash) else { return }
            hub.deliver(to: routerHash, message: message)
        }
    }

    /// A loopback transport where sends to one peer hang, modeling a floodfill
    /// with no session whose demand-dial never completes. Sends to any other
    /// peer are delivered normally.
    private final class HangingTransport: I2PNetDBTransport {
        private unowned let hub: I2PNetDBLoopbackHub
        private let hangOn: Data
        init(hub: I2PNetDBLoopbackHub, hangOn: Data) {
            self.hub = hub
            self.hangOn = hangOn
        }
        func send(to routerHash: Data, message: I2PNetDBMessage) async throws {
            if routerHash == hangOn {
                try? await Task.sleep(for: .seconds(30))
                return
            }
            hub.deliver(to: routerHash, message: message)
        }
    }

    private struct Mesh {
        let hub: I2PNetDBLoopbackHub
        let nodes: [I2PNetworkDatabase]
        let hashes: [Data]
    }

    private static func makeTempDirectory() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("i2p-netdb-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private static func makeRouterInfo(caps: String? = nil) throws -> (info: I2PRouterInfo, seed: Data) {
        let seed = I2PCrypto.generateEd25519Seed()
        let x25519 = I2PCrypto.generateX25519KeyPair()
        var options: [String: String] = ["router.version": "0.9.62"]
        if let caps { options["caps"] = caps }
        let identity = I2PKeysAndCert(
            encryptionPublicKey: x25519.publicKey,
            signingPublicKey: I2PCrypto.ed25519PublicKey(fromSeed: seed)
        )
        var info = I2PRouterInfo(
            identity: identity,
            published: Date(),
            addresses: [
                I2PRouterAddress(
                    cost: 5,
                    transportStyle: "NTCP2",
                    expiration: nil,
                    options: ["host": "192.0.2.1", "port": "8887"]
                )
            ],
            options: options
        )
        try info.sign(withSeed: seed)
        return (info, seed)
    }

    private static func makeLeaseSet(leaseLifetime: TimeInterval = 900) throws -> I2PLeaseSet {
        let seed = I2PCrypto.generateEd25519Seed()
        let x25519 = I2PCrypto.generateX25519KeyPair()
        let destination = I2PKeysAndCert(
            encryptionPublicKey: x25519.publicKey,
            signingPublicKey: I2PCrypto.ed25519PublicKey(fromSeed: seed)
        )
        // Both leases share the lifetime the caller asks for: the entry's
        // validity is the latest lease + grace, so a longer second lease would
        // silently stretch the expected window.
        var leaseSet = I2PLeaseSet(
            destination: destination,
            published: Date(),
            leases: [
                I2PLease(
                    gatewayHash: I2PCrypto.sha256(I2PCrypto.randomBytes(8)),
                    tunnelId: UInt32.random(in: 1...UInt32.max),
                    expiration: Date().addingTimeInterval(leaseLifetime)
                ),
                I2PLease(
                    gatewayHash: I2PCrypto.sha256(I2PCrypto.randomBytes(8)),
                    tunnelId: UInt32.random(in: 1...UInt32.max),
                    expiration: Date().addingTimeInterval(leaseLifetime)
                )
            ]
        )
        try leaseSet.sign(withSeed: seed)
        return leaseSet
    }

    /// Builds `nodeCount` NetDB instances on a loopback bus. The first `floodfillCount`
    /// routers are floodfills: they mark themselves locally and hold every router's
    /// RouterInfo (simulating prior replication). Each node's local hash is its own
    /// RouterInfo identity hash, so netdb targets learned from the entries are
    /// routable on the loopback bus (a router is addressed by its identity).
    private static func makeMesh(nodeCount: Int, floodfillCount: Int) async throws -> Mesh {
        precondition(floodfillCount <= nodeCount)
        let hub = I2PNetDBLoopbackHub()
        var infos: [I2PRouterInfo] = []
        for index in 0..<nodeCount {
            infos.append(try makeRouterInfo(caps: index < floodfillCount ? "ff" : nil).info)
        }
        var nodes: [I2PNetworkDatabase] = []
        var hashes: [Data] = []
        for index in 0..<nodeCount {
            let hash = infos[index].identity.hash
            let storage = try I2PNetDBStorage(directory: makeTempDirectory())
            let db = I2PNetworkDatabase(
                localRouterHash: hash,
                transport: I2PNetDBLoopbackTransport(hub: hub),
                storage: storage
            )
            nodes.append(db)
            hashes.append(hash)
        }
        for index in 0..<floodfillCount {
            await nodes[index].configureLocalFloodfill(true)
            _ = await nodes[index].publish(routerInfo: infos[index]) // local store; no floodfill targets yet
        }
        for floodfill in 0..<floodfillCount {
            for info in infos {
                try await nodes[floodfill].ingestRouterInfo(info.serialize())
            }
        }
        for (index, db) in nodes.enumerated() {
            hub.add(db, at: hashes[index])
        }
        return Mesh(hub: hub, nodes: nodes, hashes: hashes)
    }

    // MARK: Tests

    /// The mainnet shape: the floodfills closest to a key are peers this router
    /// cannot reach, and the one floodfill it *does* hold a session with is far
    /// down the XOR order. The lookup must query the reachable peer anyway — the
    /// reachable set is drawn from every known floodfill, not only the nearest
    /// handful — or it can never be answered.
    private static func testReachableBeyondClosest() async throws -> String {
        let hub = I2PNetDBLoopbackHub()
        let (targetInfo, _) = try makeRouterInfo()
        let key = targetInfo.identity.hash
        let localHash = I2PCrypto.randomBytes(32)
        var decoys: [Data] = []
        while decoys.count < 30 {
            let candidate = I2PCrypto.randomBytes(32)
            if !decoys.contains(candidate) { decoys.append(candidate) }
        }
        // Make sure the reachable holder is outside the closest 12 peers, which
        // is the window a distance-limited reachable search would have looked in.
        var holderInfo = try makeRouterInfo(caps: "ff").info
        var rank = 0
        for _ in 0..<20 {
            let ordered = (decoys + [holderInfo.identity.hash])
                .sorted { I2PNetworkDatabase.isCloser($0, than: $1, to: key) }
            if let index = ordered.firstIndex(of: holderInfo.identity.hash) {
                rank = index
                if index >= 12 { break }
            }
            holderInfo = try makeRouterInfo(caps: "ff").info
        }
        guard rank >= 12 else {
            throw Failure("could not place the reachable floodfill outside the closest 12 (rank \(rank))")
        }
        let holderHash = holderInfo.identity.hash

        let local = I2PNetworkDatabase(
            localRouterHash: localHash,
            transport: SelectiveTransport(hub: hub, allowed: [holderHash]),
            storage: try I2PNetDBStorage(directory: makeTempDirectory()))
        let holder = I2PNetworkDatabase(
            localRouterHash: holderHash,
            transport: I2PNetDBLoopbackTransport(hub: hub),
            storage: try I2PNetDBStorage(directory: makeTempDirectory()))
        hub.add(local, at: localHash)
        hub.add(holder, at: holderHash)
        await holder.configureLocalFloodfill(true)
        try await holder.ingestRouterInfo(targetInfo.serialize())
        for peer in decoys { await local.registerFloodfill(peer) }
        await local.registerFloodfill(holderHash)
        await local.installReachabilityProbe { $0 == holderHash }

        let started = Date()
        let found = await local.lookup(key, timeoutPerRound: 1, maxRounds: 2)
        let elapsed = Date().timeIntervalSince(started)
        guard let found, found.raw == targetInfo.serialize() else {
            throw Failure("lookup ignored the only reachable floodfill (XOR rank \(rank) of \(decoys.count + 1)) and returned nothing")
        }
        guard elapsed < 3 else {
            throw Failure("lookup took \(String(format: "%.1f", elapsed))s instead of asking the reachable peer at once")
        }
        return String(format: "entry fetched in %.2fs from the reachable floodfill at XOR rank %d", elapsed, rank)
    }
    /// The DHT row's other real-world failure: a lookup's closest floodfill has
    /// no session and its demand-dial hangs. The query must still go out to the
    /// other candidates — sends are dispatched concurrently, so one dead peer
    /// cannot hold the round hostage until its timeout.
    private static func testUnreachableFloodfillLookup() async throws -> String {
        let hub = I2PNetDBLoopbackHub()
        let (targetInfo, _) = try makeRouterInfo()
        let key = targetInfo.identity.hash
        // A known floodfill one bit away from the key: XOR distance 1, so it is
        // always the first candidate the lookup picks, and no node is behind it.
        var dead = key
        dead[key.count - 1] ^= 0x01

        let localHash = I2PCrypto.randomBytes(32)
        let holderInfo = try makeRouterInfo(caps: "ff").info
        let otherInfo = try makeRouterInfo(caps: "ff").info
        let local = I2PNetworkDatabase(
            localRouterHash: localHash,
            transport: HangingTransport(hub: hub, hangOn: dead),
            storage: try I2PNetDBStorage(directory: makeTempDirectory()))
        let holder = I2PNetworkDatabase(
            localRouterHash: holderInfo.identity.hash,
            transport: I2PNetDBLoopbackTransport(hub: hub),
            storage: try I2PNetDBStorage(directory: makeTempDirectory()))
        let other = I2PNetworkDatabase(
            localRouterHash: otherInfo.identity.hash,
            transport: I2PNetDBLoopbackTransport(hub: hub),
            storage: try I2PNetDBStorage(directory: makeTempDirectory()))
        hub.add(local, at: localHash)
        hub.add(holder, at: holderInfo.identity.hash)
        hub.add(other, at: otherInfo.identity.hash)
        await holder.configureLocalFloodfill(true)
        await other.configureLocalFloodfill(true)
        try await holder.ingestRouterInfo(targetInfo.serialize())
        for floodfill in [dead, holderInfo.identity.hash, otherInfo.identity.hash] {
            await local.registerFloodfill(floodfill)
        }

        let started = Date()
        let found = await local.lookup(key, timeoutPerRound: 2, maxRounds: 2)
        let elapsed = Date().timeIntervalSince(started)
        guard let found, found.raw == targetInfo.serialize() else {
            throw Failure("lookup did not return the entry while the closest floodfill's send hung (\(String(format: "%.1f", elapsed))s)")
        }
        guard elapsed < 5 else {
            throw Failure("lookup took \(String(format: "%.1f", elapsed))s — the dead floodfill serialized the round")
        }
        return String(format: "entry fetched in %.2fs with the closest floodfill unreachable", elapsed)
    }

    private static func testStoreLookup() async throws -> String {
        let mesh = try await makeMesh(nodeCount: 6, floodfillCount: 3)
        let seeds = Array(mesh.hashes.prefix(3))
        _ = await mesh.nodes[3].bootstrap(seedFloodfills: seeds, targetPeers: 3, maxRounds: 1)
        _ = await mesh.nodes[4].bootstrap(seedFloodfills: seeds, targetPeers: 3, maxRounds: 1)

        let (info, _) = try makeRouterInfo()
        let acks = await mesh.nodes[3].publish(routerInfo: info)
        guard acks >= 1 else { throw I2PWireError.invalidSignature }
        guard acks == 3 else { throw I2PWireError.invalidFormat }

        let key = info.identity.hash
        let fetched = await mesh.nodes[4].lookup(key)
        guard let fetched else { throw I2PWireError.invalidSignature }
        guard fetched.raw == info.serialize() else { throw I2PWireError.invalidFormat }
        guard await mesh.nodes[4].hasEntry(key) else { throw I2PWireError.invalidFormat }
        return "\(acks)/3 floodfill acks · retrieved \(fetched.raw.count)-byte RouterInfo"
    }

    private static func testReplicationGossip() async throws -> String {
        let mesh = try await makeMesh(nodeCount: 9, floodfillCount: 7)
        let (info, _) = try makeRouterInfo()
        let publisher = mesh.nodes[7]
        _ = await publisher.bootstrap(
            seedFloodfills: Array(mesh.hashes.prefix(7)),
            targetPeers: 7,
            maxRounds: 1
        )
        let acks = await publisher.publish(routerInfo: info)
        guard acks >= 1 else { throw I2PWireError.invalidSignature }
        try await Task.sleep(for: .milliseconds(800))
        let key = info.identity.hash
        for (index, floodfill) in mesh.nodes.prefix(7).enumerated() {
            guard await floodfill.hasEntry(key) else {
                let ordered = mesh.hashes.prefix(7).sorted { I2PNetworkDatabase.isCloser($0, than: $1, to: key) }
                let orderIndexes = ordered.compactMap { h in mesh.hashes.prefix(7).firstIndex(of: h) }
                var states: [String] = []
                for (i, node) in mesh.nodes.prefix(7).enumerated() {
                    states.append("\(i):\(await node.hasEntry(key) ? "yes" : "no")")
                }
                throw Failure("floodfill \(index) of 7 missing the entry after gossip (\(acks) direct acks; distance order \(orderIndexes); holds \(states.joined(separator: " ")); ids \(mesh.hashes.prefix(7).map { String($0.hex.prefix(6)) }))")
            }
        }
        return "\(acks) direct acks · all 7 floodfills hold the entry after gossip"
    }

    private static func testRejectsUnverified() async throws -> String {
        let mesh = try await makeMesh(nodeCount: 2, floodfillCount: 1)
        let (info, _) = try makeRouterInfo()
        let raw = info.serialize()
        var tampered = raw
        tampered[tampered.count - 65] ^= 0xff // corrupt the Ed25519 signature
        let key = info.identity.hash

        await mesh.nodes[0].handleIncoming(.store(I2PDatabaseStore(
            key: key, entryType: .routerInfo, replyToken: 0, payload: tampered
        )))
        try await Task.sleep(for: .milliseconds(150))
        guard !(await mesh.nodes[0].hasEntry(key)) else { throw I2PWireError.invalidSignature }

        try await mesh.nodes[0].ingestRouterInfo(raw)
        guard await mesh.nodes[0].hasEntry(key) else { throw I2PWireError.invalidFormat }
        return "tampered RouterInfo rejected · verified entry accepted"
    }

    private static func testExpiration() async throws -> String {
        let mesh = try await makeMesh(nodeCount: 2, floodfillCount: 1)
        _ = await mesh.nodes[1].bootstrap(seedFloodfills: [mesh.hashes[0]], targetPeers: 1, maxRounds: 1)

        let leaseSet = try makeLeaseSet(leaseLifetime: 900) // 15-minute leases
        let leaseSetKey = leaseSet.destination.hash
        let acks = await mesh.nodes[1].publish(leaseSet: leaseSet)
        guard acks >= 1 else { throw I2PWireError.invalidSignature }

        let now = Date()
        let leaseExpiry = await mesh.nodes[1].entryExpiration(leaseSetKey)
        guard let leaseExpiry else { throw Failure("lease set published but holds no expiry") }
        guard leaseExpiry <= now.addingTimeInterval(900 + 600 + 5) &&
              leaseExpiry >= now.addingTimeInterval(895) else {
            throw Failure(String(format: "lease expiry %.0fs is outside the 15m-lease + 10m-grace window", leaseExpiry.timeIntervalSince(now)))
        }

        let (info, _) = try makeRouterInfo()
        let routerKey = info.identity.hash
        _ = await mesh.nodes[1].publish(routerInfo: info)
        let routerExpiry = await mesh.nodes[1].entryExpiration(routerKey)
        guard let routerExpiry, abs(routerExpiry.timeIntervalSince(now) - 3600) < 5 else {
            throw Failure("RouterInfo expiry is not ~1h")
        }

        let pruned = await mesh.nodes[1].pruneExpired(now: now.addingTimeInterval(3600 + 10))
        guard pruned >= 2 else { throw Failure("pruned only \(pruned) of the 2 expired entries") }
        guard !(await mesh.nodes[1].hasEntry(leaseSetKey)) else {
            throw Failure("pruned lease set still resident")
        }
        return "LeaseSet ~25 min (15m lease + 10m grace) · RouterInfo ~1h · pruned \(pruned)"
    }

    private static func testPersistence() async throws -> String {
        let directory = try makeTempDirectory()
        let storage1 = try I2PNetDBStorage(directory: directory)
        let node1 = I2PNetworkDatabase(
            localRouterHash: I2PCrypto.randomBytes(32),
            transport: I2PNetDBLoopbackTransport(hub: I2PNetDBLoopbackHub()),
            storage: storage1
        )
        let (info, _) = try makeRouterInfo()
        try await node1.ingestRouterInfo(info.serialize())
        let leaseSet = try makeLeaseSet()
        try await node1.ingestLeaseSet(leaseSet.serialize())
        let liveCount = await node1.entryCount()
        guard liveCount == 2 else { throw Failure("node1 holds \(liveCount) entries after two verified ingests") }

        // A fresh router instance on the same directory restores the verified entries.
        let storage2 = try I2PNetDBStorage(directory: directory)
        let node2 = I2PNetworkDatabase(
            localRouterHash: I2PCrypto.randomBytes(32),
            transport: I2PNetDBLoopbackTransport(hub: I2PNetDBLoopbackHub()),
            storage: storage2
        )
        // The restore runs asynchronously on the actor after init.
        var restoredCount = await node2.entryCount()
        let deadline = Date().addingTimeInterval(5)
        while restoredCount < 2, Date() < deadline {
            try? await Task.sleep(for: .milliseconds(50))
            restoredCount = await node2.entryCount()
        }
        guard restoredCount == 2 else {
            throw Failure("fresh instance restored \(restoredCount) of 2 persisted entries (files: \(storage2.loadAll().count))")
        }
        guard await node2.hasEntry(info.identity.hash) else { throw Failure("restored set is missing the RouterInfo") }
        guard await node2.hasEntry(leaseSet.destination.hash) else { throw Failure("restored set is missing the LeaseSet") }
        return "2 signature-verified entries restored from disk"
    }

    private static func testBootstrap() async throws -> String {
        let mesh = try await makeMesh(nodeCount: 10, floodfillCount: 3)
        let seeds = Array(mesh.hashes.prefix(3))
        let discovered = await mesh.nodes[9].bootstrap(seedFloodfills: seeds, targetPeers: 9, maxRounds: 6)
        guard discovered >= 9 else { throw I2PWireError.invalidFormat }
        let floodfills = await mesh.nodes[9].floodfillCount()
        guard floodfills >= 3 else { throw I2PWireError.invalidFormat }
        return "\(discovered) peers discovered via iterative lookups (\(floodfills) floodfills)"
    }
}