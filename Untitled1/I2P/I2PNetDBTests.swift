//
//  I2PNetDBTests.swift
//  Self-tests for the Network Database: XOR metric, message round trips,
//  signature-gated acceptance, store→lookup across floodfills, replication gossip,
//  expiration, persistence and bootstrapping discovery — exercised over a loopback
//  message bus connecting multiple NetDB instances.
//

import Foundation

enum I2PNetDBSelfTest {
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
        await run("NetDB floodfill replication gossip") { try await testReplicationGossip() }
        await run("NetDB accepts verified entries only") { try await testRejectsUnverified() }
        await run("NetDB expiration & pruning") { try await testExpiration() }
        await run("NetDB persistent storage restore") { try await testPersistence() }
        await run("NetDB bootstrapping discovery") { try await testBootstrap() }
        return results
    }

    // MARK: Test harness

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
                    expiration: Date().addingTimeInterval(leaseLifetime + 60)
                )
            ]
        )
        try leaseSet.sign(withSeed: seed)
        return leaseSet
    }

    /// Builds `nodeCount` NetDB instances on a loopback bus. The first `floodfillCount`
    /// routers are floodfills: they mark themselves locally and hold every router's
    /// RouterInfo (simulating prior replication).
    private static func makeMesh(nodeCount: Int, floodfillCount: Int) async throws -> Mesh {
        precondition(floodfillCount <= nodeCount)
        let hub = I2PNetDBLoopbackHub()
        var nodes: [I2PNetworkDatabase] = []
        var hashes: [Data] = []
        var infos: [I2PRouterInfo] = []
        for _ in 0..<nodeCount {
            let hash = I2PCrypto.randomBytes(32)
            let storage = try I2PNetDBStorage(directory: makeTempDirectory())
            let db = I2PNetworkDatabase(
                localRouterHash: hash,
                transport: I2PNetDBLoopbackTransport(hub: hub),
                storage: storage
            )
            nodes.append(db)
            hashes.append(hash)
        }
        for index in 0..<nodeCount {
            let (info, _) = try makeRouterInfo(caps: index < floodfillCount ? "ff" : nil)
            infos.append(info)
            if index < floodfillCount {
                await nodes[index].configureLocalFloodfill(true)
                _ = await nodes[index].publish(routerInfo: info) // local store; no floodfill targets yet
            }
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
        for floodfill in mesh.nodes.prefix(7) {
            guard await floodfill.hasEntry(key) else { throw I2PWireError.invalidFormat }
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
        guard let leaseExpiry else { throw I2PWireError.invalidFormat }
        guard leaseExpiry <= now.addingTimeInterval(900 + 600 + 5) &&
              leaseExpiry >= now.addingTimeInterval(895) else {
            throw I2PWireError.invalidFormat // ~25 min: 15-min lease + 10-min grace
        }

        let (info, _) = try makeRouterInfo()
        let routerKey = info.identity.hash
        _ = await mesh.nodes[1].publish(routerInfo: info)
        let routerExpiry = await mesh.nodes[1].entryExpiration(routerKey)
        guard let routerExpiry, abs(routerExpiry.timeIntervalSince(now) - 3600) < 5 else {
            throw I2PWireError.invalidFormat // RouterInfo ~1h
        }

        let pruned = await mesh.nodes[1].pruneExpired(now: now.addingTimeInterval(3600 + 10))
        guard pruned >= 2 else { throw I2PWireError.invalidFormat }
        guard !(await mesh.nodes[1].hasEntry(leaseSetKey)) else { throw I2PWireError.invalidFormat }
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
        guard await node1.entryCount() == 2 else { throw I2PWireError.invalidFormat }

        // A fresh router instance on the same directory restores the verified entries.
        let storage2 = try I2PNetDBStorage(directory: directory)
        let node2 = I2PNetworkDatabase(
            localRouterHash: I2PCrypto.randomBytes(32),
            transport: I2PNetDBLoopbackTransport(hub: I2PNetDBLoopbackHub()),
            storage: storage2
        )
        guard await node2.entryCount() == 2 else { throw I2PWireError.invalidFormat }
        guard await node2.hasEntry(info.identity.hash) else { throw I2PWireError.invalidFormat }
        guard await node2.hasEntry(leaseSet.destination.hash) else { throw I2PWireError.invalidFormat }
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