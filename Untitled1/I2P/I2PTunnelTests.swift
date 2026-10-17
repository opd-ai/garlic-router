//
//  I2PTunnelTests.swift
//  Self-tests for tunnel establishment and the tunnel pool.
//

import Foundation
import CryptoKit

private enum I2PTunnelTestTimeout: Error {
    case timedOut
}

private func tunnelTestWaitUntil(timeout: TimeInterval = 15, _ condition: @escaping () -> Bool) async throws {
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        if condition() { return }
        try await Task.sleep(for: .milliseconds(50))
    }
    if condition() { return }
    throw I2PTunnelTestTimeout.timedOut
}

/// A loopback node with tunnel-participation capability.
private final class I2PTunnelTestNode {
    let routerHash: Data
    let encryptionKey: Curve25519.KeyAgreement.PrivateKey
    let participant: I2PTunnelParticipant
    let transport: I2PTunnelBuildTransport

    init(hub: I2PTunnelBuildHub) {
        routerHash = I2PCrypto.randomBytes(32)
        encryptionKey = Curve25519.KeyAgreement.PrivateKey()
        transport = I2PTunnelLoopbackTransport(hub: hub, localRouterHash: routerHash)
        participant = I2PTunnelParticipant(
            localRouterHash: routerHash,
            localEncryptionKey: encryptionKey,
            transport: transport
        )
        hub.register(participant)
    }

    var peer: I2PTunnelPeer {
        I2PTunnelPeer(
            routerHash: routerHash,
            encryptionPublicKey: encryptionKey.publicKey.rawRepresentation
        )
    }
}

private final class I2PTunnelTestPeerProvider: I2PTunnelPeerProvider {
    let peers: [I2PTunnelPeer]

    init(peers: [I2PTunnelPeer]) {
        self.peers = peers
    }

    func peers(count: Int, excluding: Set<Data>) -> [I2PTunnelPeer] {
        Array(peers.filter { !excluding.contains($0.routerHash) }.shuffled().prefix(count))
    }
}

enum I2PTunnelSelfTest {
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

        await run("Tunnel build record encryption (528-byte ECIES)") {
            try await recordEncryptionTest()
        }
        await run("Outbound tunnel build through 2 hops") {
            try await outboundBuildTest()
        }
        await run("Inbound tunnel build (gateway-oriented)") {
            try await inboundBuildTest()
        }
        await run("Build reply carries per-hop reject codes") {
            try await rejectTest()
        }
        await run("Tunnel pool: staggered builds, expiry, prebuilding, selection") {
            try await poolLifecycleTest()
        }
        return results
    }

    private static func recordEncryptionTest() async throws -> String {
        let key = Curve25519.KeyAgreement.PrivateKey()
        let record = I2PTunnelBuildRequestRecord(
            hopNumber: 1,
            receiveTunnelID: 0x11223344,
            nextHopHash: I2PCrypto.randomBytes(32),
            nextTunnelID: 0x55667788,
            layerKey: I2PCrypto.randomBytes(32),
            ivKey: I2PCrypto.randomBytes(32),
            replyKey: I2PCrypto.randomBytes(32),
            replyIV: I2PCrypto.randomBytes(16),
            isMessagePathEnd: true,
            nextHopIsOriginator: true,
            hasMoreRecords: false,
            padding: I2PCrypto.randomBytes(372)
        )
        let wire = try I2PTunnelBuildCrypto.encryptRecord(
            record.serialize(),
            to: key.publicKey.rawRepresentation,
            recordIndex: 3
        )
        guard wire.count == I2PTunnelBuildRequestRecord.wireLength else {
            throw I2PWireError.invalidFormat
        }
        let plaintext = try I2PTunnelBuildCrypto.decryptRecord(
            wire,
            localEncryptionKey: key,
            recordIndex: 3
        )
        let parsed = try I2PTunnelBuildRequestRecord.parse(plaintext)
        guard parsed.receiveTunnelID == record.receiveTunnelID,
              parsed.nextHopHash == record.nextHopHash,
              parsed.layerKey == record.layerKey,
              parsed.ivKey == record.ivKey,
              parsed.replyKey == record.replyKey,
              parsed.replyIV == record.replyIV,
              parsed.flags == record.flags,
              parsed.hasMoreRecords == record.hasMoreRecords else {
            throw I2PWireError.invalidFormat
        }
        // A record index mismatch must fail the AEAD.
        var wrongIndexWorked = false
        if (try? I2PTunnelBuildCrypto.decryptRecord(wire, localEncryptionKey: key, recordIndex: 4)) != nil {
            wrongIndexWorked = true
        }
        guard !wrongIndexWorked else { throw I2PWireError.invalidFormat }
        return "528-byte record: X25519 + HKDF AEAD, all fields intact"
    }
private static func outboundBuildTest() async throws -> String {
        let hub = I2PTunnelBuildHub()
        let originator = I2PTunnelTestNode(hub: hub)
        let hop1 = I2PTunnelTestNode(hub: hub)
        let hop2 = I2PTunnelTestNode(hub: hub)
        let builder = I2PTunnelBuilder(
            localRouterHash: originator.routerHash,
            participant: originator.participant,
            transport: originator.transport
        )
        let tunnel = try await builder.buildTunnel(
            direction: .outbound,
            hops: [hop1.peer, hop2.peer],
            lifetime: 900,
            timeout: 10
        )
        guard tunnel.direction == .outbound, tunnel.hopCount == 2 else {
            throw I2PWireError.invalidFormat
        }
        guard tunnel.hops[0].routerHash == hop1.routerHash,
              tunnel.hops[1].routerHash == hop2.routerHash else {
            throw I2PWireError.invalidFormat
        }
        guard tunnel.hops[0].nextTunnelID == tunnel.hops[1].receiveTunnelID else {
            throw I2PWireError.invalidFormat
        }
        guard tunnel.hops[1].isTunnelEndpoint, !tunnel.hops[0].isTunnelEndpoint else {
            throw I2PWireError.invalidFormat
        }
        guard tunnel.gatewayTunnelID == tunnel.hops[0].receiveTunnelID,
              tunnel.endpointTunnelID == tunnel.hops[1].receiveTunnelID else {
            throw I2PWireError.invalidFormat
        }
        guard let latency = tunnel.buildLatency, latency >= 0,
              tunnel.expiresAt.timeIntervalSince(tunnel.createdAt) > 890 else {
            throw I2PWireError.invalidFormat
        }
        // Hop participants must have registered their tunnel state, carrying
        // the exact layer/IV keys and next-hop info from the build records.
        guard hop1.participant.hasHopState(receiveTunnelID: tunnel.hops[0].receiveTunnelID),
              hop2.participant.hasHopState(receiveTunnelID: tunnel.hops[1].receiveTunnelID) else {
            throw I2PWireError.invalidFormat
        }
        guard hop1.participant.hopState(receiveTunnelID: tunnel.hops[0].receiveTunnelID)?.layerKey == tunnel.layerKeys[0],
              hop2.participant.hopState(receiveTunnelID: tunnel.hops[1].receiveTunnelID)?.ivKey == tunnel.ivKeys[1],
              hop1.participant.hopState(receiveTunnelID: tunnel.hops[0].receiveTunnelID)?.nextHopHash == hop2.routerHash else {
            throw I2PWireError.invalidFormat
        }
        return "2-hop outbound tunnel built in \(String(format: "%.0f", latency * 1000)) ms; hop state registered"
    }

    private static func inboundBuildTest() async throws -> String {
        let hub = I2PTunnelBuildHub()
        let originator = I2PTunnelTestNode(hub: hub)
        let nearest = I2PTunnelTestNode(hub: hub)   // build message-path first hop
        let gateway = I2PTunnelTestNode(hub: hub)   // inbound gateway, message-path last hop
        let builder = I2PTunnelBuilder(
            localRouterHash: originator.routerHash,
            participant: originator.participant,
            transport: originator.transport
        )
        let tunnel = try await builder.buildTunnel(
            direction: .inbound,
            hops: [nearest.peer, gateway.peer],
            lifetime: 900,
            timeout: 10
        )
        // Tunnel data path is the reversed build message path: gateway first.
        guard tunnel.direction == .inbound,
              tunnel.hops.map(\.routerHash) == [gateway.routerHash, nearest.routerHash] else {
            throw I2PWireError.invalidFormat
        }
        guard tunnel.gatewayTunnelID == tunnel.hops[0].receiveTunnelID else {
            throw I2PWireError.invalidFormat
        }
        guard tunnel.hops[0].nextTunnelID == tunnel.hops[1].receiveTunnelID else {
            throw I2PWireError.invalidFormat
        }
        guard tunnel.hops[1].isTunnelEndpoint,
              tunnel.hops[1].nextTunnelID == tunnel.endpointTunnelID else {
            throw I2PWireError.invalidFormat
        }
        guard gateway.participant.hopState(receiveTunnelID: tunnel.hops[0].receiveTunnelID)?.nextHopHash == originator.routerHash,
              gateway.participant.hopState(receiveTunnelID: tunnel.hops[0].receiveTunnelID)?.nextTunnelID == tunnel.endpointTunnelID else {
            throw I2PWireError.invalidFormat
        }
        guard gateway.participant.hopState(receiveTunnelID: tunnel.hops[0].receiveTunnelID)?.layerKey == tunnel.layerKeys[0] else {
            throw I2PWireError.invalidFormat
        }
        return "inbound tunnel: gateway → \(tunnel.hopCount) hops → originator endpoint"
    }
private static func rejectTest() async throws -> String {
        let hub = I2PTunnelBuildHub()
        let originator = I2PTunnelTestNode(hub: hub)
        let hop1 = I2PTunnelTestNode(hub: hub)
        let hop2 = I2PTunnelTestNode(hub: hub)
        hop1.participant.forcedRejectCode = I2PTunnelBuildReturnCode.bandwidthExceeded.rawValue
        let builder = I2PTunnelBuilder(
            localRouterHash: originator.routerHash,
            participant: originator.participant,
            transport: originator.transport
        )
        var caughtCode: UInt8?
        do {
            _ = try await builder.buildTunnel(
                direction: .outbound,
                hops: [hop1.peer, hop2.peer],
                lifetime: 900,
                timeout: 10
            )
        } catch let error as I2PTunnelBuildError {
            if case .rejected(let code) = error { caughtCode = code }
        }
        guard caughtCode == I2PTunnelBuildReturnCode.bandwidthExceeded.rawValue else {
            throw I2PWireError.invalidFormat
        }
        // The rejecting hop did not forward the request, so the endpoint never
        // registered any tunnel state.
        guard hop2.participant.hopStateCount == 0 else {
            throw I2PWireError.invalidFormat
        }
        return "hop rejected with bandwidth-exceeded; tunnel not built"
    }

    private static func poolLifecycleTest() async throws -> String {
        let hub = I2PTunnelBuildHub()
        let originator = I2PTunnelTestNode(hub: hub)
        var peerNodes: [I2PTunnelTestNode] = []
        for _ in 0..<5 {
            peerNodes.append(I2PTunnelTestNode(hub: hub))
        }
        let provider = I2PTunnelTestPeerProvider(peers: peerNodes.map(\.peer))

        var config = I2PTunnelPool.Config()
        config.outboundTarget = 2
        config.inboundTarget = 2
        config.hopCount = 2
        config.lifetime = 3
        config.enforceSpecLimits = false
        config.staggerInterval = 0.5
        config.prebuildThreshold = 1
        config.maintenanceInterval = 0.4
        config.buildTimeout = 10
        let pool = I2PTunnelPool(
            localRouterHash: originator.routerHash,
            participant: originator.participant,
            transport: originator.transport,
            peerProvider: provider,
            config: config
        )

        let fillStarted = Date()
        await pool.fillPools()
        guard pool.outboundCount == 2, pool.inboundCount == 2 else {
            throw I2PWireError.invalidFormat
        }
        // Builds must be staggered: consecutive build starts are spread out.
        let starts = pool.buildStartTimes.map { $0.timeIntervalSince(fillStarted) }
        guard starts.count == 4 else { throw I2PWireError.invalidFormat }
        for index in 1..<starts.count {
            guard starts[index] - starts[index - 1] >= config.staggerInterval * 0.3 else {
                throw I2PWireError.invalidFormat
            }
        }
        guard let average = pool.averageBuildLatency, average >= 0 else {
            throw I2PWireError.invalidFormat
        }

        // Lifetime clamping into the spec's 10-30 minute range.
        var clampConfig = I2PTunnelPool.Config()
        clampConfig.enforceSpecLimits = true
        clampConfig.lifetime = 60
        guard clampConfig.clampedLifetime == 600 else { throw I2PWireError.invalidFormat }
        clampConfig.lifetime = 4000
        guard clampConfig.clampedLifetime == 1800 else { throw I2PWireError.invalidFormat }

        // Selection + pruning on a quiet pool (targets 0 = no auto builds).
        var quietConfig = I2PTunnelPool.Config()
        quietConfig.outboundTarget = 0
        quietConfig.inboundTarget = 0
        quietConfig.enforceSpecLimits = false
        let quiet = I2PTunnelPool(
            localRouterHash: originator.routerHash,
            participant: originator.participant,
            transport: originator.transport,
            peerProvider: provider,
            config: quietConfig
        )
        let expired = I2PTunnel(
            direction: .outbound,
            hops: [],
            gatewayTunnelID: 1,
            endpointTunnelID: 2,
            layerKeys: [],
            ivKeys: [],
            createdAt: Date().addingTimeInterval(-700),
            expiresAt: Date().addingTimeInterval(-100),
            buildLatency: 0.1
        )
        quiet.adopt(expired)
        guard quiet.pruneExpired() == 1 else { throw I2PWireError.invalidFormat }
        let fast = I2PTunnel(
            direction: .outbound,
            hops: [],
            gatewayTunnelID: 3,
            endpointTunnelID: 4,
            layerKeys: [],
            ivKeys: [],
            createdAt: Date(),
            expiresAt: Date().addingTimeInterval(600),
            buildLatency: 0.05
        )
        let slow = I2PTunnel(
            direction: .outbound,
            hops: [],
            gatewayTunnelID: 5,
            endpointTunnelID: 6,
            layerKeys: [],
            ivKeys: [],
            createdAt: Date(),
            expiresAt: Date().addingTimeInterval(600),
            buildLatency: 1.5
        )
        quiet.adopt(fast)
        quiet.adopt(slow)
        guard quiet.selectOutboundTunnel()?.buildLatency == 0.05 else {
            throw I2PWireError.invalidFormat
        }
        guard quiet.selectInboundTunnel() == nil else { throw I2PWireError.invalidFormat }

        // Maintenance: expired tunnels are pruned and replacements are
        // pre-built before the pool drains.
        pool.start()
        try await tunnelTestWaitUntil(timeout: 15) {
            pool.outboundCount == 2
                && pool.inboundCount == 2
                && pool.outboundTunnels.allSatisfy { $0.remainingLifetime() > 1.2 }
                && pool.inboundTunnels.allSatisfy { $0.remainingLifetime() > 1.2 }
        }
        pool.stop()
        return String(
            format: "pools filled staggered (%d builds, avg %.1f ms); expired tunnels replaced by prebuilt ones; latency-based selection",
            pool.buildStartTimes.count,
            (average * 1000)
        )
    }
}