//
//  I2PTunnelTests.swift
//  Self-tests for tunnel establishment and the tunnel pool.
//

import Foundation
import CryptoKit

private enum I2PTunnelTestTimeout: Error {
    case timedOut
}

/// A named pool-invariant violation, so a failing run names the property it
/// broke instead of reporting a bare `invalidFormat`.
private struct I2PTunnelTestFailure: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

private extension Data {
    /// Parses a lowercase/uppercase hex string into bytes (test vectors).
    init(hex: String) {
        var bytes = [UInt8]()
        var index = hex.startIndex
        while index < hex.endIndex {
            guard let next = hex.index(index, offsetBy: 2, limitedBy: hex.endIndex),
                  let byte = UInt8(hex[index..<next], radix: 16) else {
                self = Data()
                return
            }
            bytes.append(byte)
            index = next
        }
        self.init(bytes)
    }
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

        await run("Tunnel build record encryption (218-byte short ECIES)") {
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
            isMessagePathEnd: true,
            nextHopIsOriginator: true,
            hasMoreRecords: false
        )
        let encrypted = try I2PTunnelBuildCrypto.encryptRecordWithMaterial(
            record.serialize(),
            to: key.publicKey.rawRepresentation,
            hopHash: nil,
            recordIndex: 3
        )
        let wire = encrypted.wire
        guard wire.count == I2PTunnelBuildRequestRecord.wireLength else {
            throw I2PWireError.invalidFormat
        }
        let (plaintext, material) = try I2PTunnelBuildCrypto.decryptRecordWithMaterial(
            wire,
            localEncryptionKey: key,
            recordIndex: 3
        )
        guard plaintext.count == I2PTunnelBuildRequestRecord.plaintextLength else {
            throw I2PWireError.invalidFormat
        }
        let parsed = try I2PTunnelBuildRequestRecord.parse(plaintext)
        guard parsed.receiveTunnelID == record.receiveTunnelID,
              parsed.nextHopHash == record.nextHopHash,
              parsed.nextTunnelID == record.nextTunnelID,
              parsed.flags == record.flags,
              parsed.isMessagePathEnd,
              parsed.layerEncryptionType == 0 else {
            throw I2PWireError.invalidFormat
        }
        guard material.layerKey == encrypted.material.layerKey,
              material.replyKey == encrypted.material.replyKey else {
            throw I2PWireError.invalidFormat
        }
        // A record addressed to another hop must fail its AEAD.
        let otherHop = Curve25519.KeyAgreement.PrivateKey()
        var wrongKeyWorked = false
        if (try? I2PTunnelBuildCrypto.decryptRecord(wire, localEncryptionKey: otherHop, recordIndex: 3)) != nil {
            wrongKeyWorked = true
        }
        guard !wrongKeyWorked else { throw I2PWireError.invalidFormat }
        // The reply path rides plain ChaCha20: pin the all-zero block against
        // the well-known RFC 8439 keystream before trusting the re-encryption.
        guard let stream = I2PChaCha20.apply(key: Data(repeating: 0, count: 32),
                                             nonce: Data(repeating: 0, count: 12),
                                             data: Data(repeating: 0, count: 64)) else {
            throw I2PWireError.invalidFormat
        }
        guard stream == Data(hex: "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586") else {
            throw I2PWireError.invalidFormat
        }
        return "218-byte short record: Noise N + X25519 + HKDF AEAD; reply ChaCha20 matches RFC 8439"
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
        let gateway = I2PTunnelTestNode(hub: hub)   // inbound gateway (data-path first hop)
        let nearest = I2PTunnelTestNode(hub: hub)   // hop nearest the originator (data-path last hop)
        let builder = I2PTunnelBuilder(
            localRouterHash: originator.routerHash,
            participant: originator.participant,
            transport: originator.transport
        )
        let tunnel = try await builder.buildTunnel(
            direction: .inbound,
            hops: [gateway.peer, nearest.peer],
            lifetime: 900,
            timeout: 10
        )
        // Hops are listed and built in tunnel data-path order: gateway first.
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
        // Hop states mirror the data path: the gateway forwards to the next
        // hop; the last hop delivers the inner payload to the originator.
        guard gateway.participant.hopState(receiveTunnelID: tunnel.hops[0].receiveTunnelID)?.nextHopHash == nearest.routerHash,
              gateway.participant.hopState(receiveTunnelID: tunnel.hops[0].receiveTunnelID)?.nextTunnelID == tunnel.hops[1].receiveTunnelID else {
            throw I2PWireError.invalidFormat
        }
        guard nearest.participant.hopState(receiveTunnelID: tunnel.hops[1].receiveTunnelID)?.nextHopHash == originator.routerHash,
              nearest.participant.hopState(receiveTunnelID: tunnel.hops[1].receiveTunnelID)?.nextTunnelID == tunnel.endpointTunnelID else {
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
            throw I2PTunnelTestFailure(
                "fillPools reached \(pool.outboundCount) outbound / \(pool.inboundCount) inbound, expected 2 / 2")
        }
        // Tunnel-health telemetry: every attempt is recorded with its outcome so
        // the screen can compute a success rate, latencies and failure codes.
        let history = pool.buildHistory()
        guard !history.isEmpty, history.count == pool.buildStartTimes.count else {
            throw I2PTunnelTestFailure(
                "build history recorded \(history.count) attempts for \(pool.buildStartTimes.count) starts")
        }
        guard history.allSatisfy({
            $0.succeeded
                && $0.returnCode == I2PTunnelBuildReturnCode.accepted.rawValue
                && ($0.latency ?? -1) >= 0
        }) else {
            throw I2PTunnelTestFailure("a loopback build was not recorded as accepted with a latency")
        }
        guard pool.buildingCount(.outbound) == 0, pool.buildingCount(.inbound) == 0 else {
            throw I2PTunnelTestFailure("the pool still reports builds in flight after fillPools returned")
        }
        guard history.contains(where: { $0.direction == .inbound }),
              history.contains(where: { $0.direction == .outbound }) else {
            throw I2PTunnelTestFailure("build history does not cover both directions")
        }
        // Builds must be staggered: consecutive build starts are spread out.
        let starts = pool.buildStartTimes.map { $0.timeIntervalSince(fillStarted) }
        guard starts.count == 4 else {
            throw I2PTunnelTestFailure("fillPools initiated \(starts.count) builds, expected 4")
        }
        for index in 1..<starts.count {
            let gap = starts[index] - starts[index - 1]
            guard gap >= config.staggerInterval * 0.3 else {
                throw I2PTunnelTestFailure(String(
                    format: "builds %d and %d started %.3f s apart; stagger requires >= %.3f s",
                    index - 1, index, gap, config.staggerInterval * 0.3))
            }
        }
        guard let average = pool.averageBuildLatency, average >= 0 else {
            throw I2PTunnelTestFailure("average build latency missing on a filled pool")
        }

        // Lifetime clamping into the spec's 10-30 minute range.
        var clampConfig = I2PTunnelPool.Config()
        clampConfig.enforceSpecLimits = true
        clampConfig.lifetime = 60
        guard clampConfig.clampedLifetime == 600 else {
            throw I2PTunnelTestFailure(
                "lifetime 60 clamped to \(clampConfig.clampedLifetime), expected 600")
        }
        clampConfig.lifetime = 4000
        guard clampConfig.clampedLifetime == 1800 else {
            throw I2PTunnelTestFailure(
                "lifetime 4000 clamped to \(clampConfig.clampedLifetime), expected 1800")
        }

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
        let pruned = quiet.pruneExpired()
        guard pruned == 1 else {
            throw I2PTunnelTestFailure("pruneExpired removed \(pruned) tunnels, expected exactly 1")
        }

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
            throw I2PTunnelTestFailure(
                "selection picked a tunnel with latency \(String(describing: quiet.selectOutboundTunnel()?.buildLatency)), expected 0.05")
        }
        guard quiet.selectInboundTunnel() == nil else {
            throw I2PTunnelTestFailure("an empty inbound pool returned a tunnel")
        }

        // Maintenance: expired tunnels are pruned and replacements are
        // pre-built before the pool drains. A pre-build briefly overlaps the
        // expiring tunnel it replaces (that is the point of pre-building), so
        // the pool holds at least the target, never fewer, with at least the
        // target's worth of young tunnels.
        pool.start()
        let youngThreshold: TimeInterval = 1.2
        do {
            try await tunnelTestWaitUntil(timeout: 15) {
                pool.outboundCount >= 2
                    && pool.outboundTunnels.filter { $0.remainingLifetime() > youngThreshold }.count >= 2
                    && pool.inboundCount >= 2
                    && pool.inboundTunnels.filter { $0.remainingLifetime() > youngThreshold }.count >= 2
            }
        } catch {
            throw I2PTunnelTestFailure(String(
                format: "maintenance left %d outbound (%d young) / %d inbound (%d young)",
                pool.outboundCount,
                pool.outboundTunnels.filter { $0.remainingLifetime() > youngThreshold }.count,
                pool.inboundCount,
                pool.inboundTunnels.filter { $0.remainingLifetime() > youngThreshold }.count))
        }
        pool.stop()
        return String(
            format: "pools filled staggered (%d builds, avg %.1f ms); expired tunnels replaced by prebuilt ones; latency-based selection",
            pool.buildStartTimes.count,
            (average * 1000)
        )
    }
}