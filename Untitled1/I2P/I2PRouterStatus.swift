//
//  I2PRouterStatus.swift
//  Live router status: a status engine attaches to the running router's
//  components (netdb, NTCP2 transport, tunnel pool, I2NP router), counts
//  routed traffic and emits a status snapshot every second on an event
//  stream that the router dashboard consumes.
//

import Foundation
import CryptoKit

// MARK: - Snapshot

/// One live status reading of the running router.
struct I2PRouterStatusSnapshot {
    struct TunnelSummary: Identifiable {
        let id: String
        let direction: String
        let hopCount: Int
        let expiresAt: Date
        let buildLatency: TimeInterval?
    }

    struct PoolSummary {
        let direction: String
        let tunnels: [TunnelSummary]
    }

    let capturedAt: Date
    // Identity and participation
    let identityHashHex: String
    let isLocalFloodfill: Bool
    let floodfillCount: Int
    let peerCount: Int
    // Transport
    let ntcp2SessionCount: Int
    // Network database
    let routerInfoCount: Int
    let leaseSetCount: Int
    // Uptime
    let uptime: TimeInterval
    // Tunnels
    let pools: [PoolSummary]
    // Message throughput
    let messagesIn: Int
    let messagesOut: Int
    let bytesIn: Int
    let bytesOut: Int
    let inRate: Double
    let outRate: Double
    let inRateHistory: [Double]
    let outRateHistory: [Double]
    // Per-peer session readings (peer inspector)
    let peers: [I2PPeerSummary]
}

/// One live per-peer session reading for the peer inspector.
struct I2PPeerSummary: Identifiable {
    let id: String                      // peer identity hash, hex
    let transport: String               // "NTCP2" or "SSU2"
    let establishedAt: Date
    let bytesIn: Int
    let bytesOut: Int
    /// XOR distance between our router hash and the peer's, hex.
    let xorDistanceHex: String
    /// Kademlia bucket = leading zero bits of the XOR distance.
    let kademliaBucket: Int
    let isFloodfill: Bool
    /// nil when the peer takes no part in one of our tunnels.
    let tunnelRole: String?
}

/// Aggregated netdb reading served by the network database actor.
struct I2PNetDBStatus {
    let routerInfoCount: Int
    let leaseSetCount: Int
    let floodfillCount: Int
    let peerCount: Int
    let isLocalFloodfill: Bool
}

// MARK: - Netdb <-> I2NP bridging

/// Maps netdb messages to I2NP envelopes and back, so the network database
/// rides the I2NP router and its delivery transport.
enum I2PNetDBI2NPBridge {
    static func outbound(_ message: I2PNetDBMessage) -> I2NPMessage {
        switch message {
        case .store(let s):
            return I2NPMessage(type: .databaseStore, payload: s.serialize())
        case .lookup(let l):
            return I2NPMessage(type: .databaseLookup, payload: l.serialize())
        case .searchReply(let r):
            return I2NPMessage(type: .databaseSearchReply, payload: r.serialize())
        }
    }

    static func inbound(_ message: I2NPMessage) -> I2PNetDBMessage? {
        guard let body = try? message.parseBody() else { return nil }
        switch body {
        case .databaseStore(let s): return .store(s)
        case .databaseLookup(let l): return .lookup(l)
        case .databaseSearchReply(let r): return .searchReply(r)
        default: return nil
        }
    }
}

/// Sends netdb messages as I2NP envelopes over the delivery transport.
final class I2PNetDBI2NPAdapter: I2PNetDBTransport {
    private let delivery: I2PDeliveryTransport

    init(delivery: I2PDeliveryTransport) {
        self.delivery = delivery
    }

    func send(to routerHash: Data, message: I2PNetDBMessage) async throws {
        try await delivery.deliver(I2PNetDBI2NPBridge.outbound(message).serialize(), to: routerHash)
    }
}

/// NTCP2 <-> I2NP delivery adapter with a throughput hook.
final class I2PNTCP2DeliveryTransport: I2PDeliveryTransport {
    weak var ntcp2: NTCP2Transport?
    var onSent: ((Int) -> Void)?

    init(ntcp2: NTCP2Transport) {
        self.ntcp2 = ntcp2
    }

    func deliver(_ i2npBytes: Data, to routerHash: Data) async throws {
        guard let ntcp2 else { throw NTCP2Error.notEstablished }
        try ntcp2.send(to: routerHash, data: i2npBytes)
        onSent?(i2npBytes.count)
    }
}

// MARK: - Status engine

/// Attaches to the running router's components, counts routed traffic and
/// emits a status snapshot each tick on `snapshots` (the router's event
/// stream, buffered to keep only the newest reading for late subscribers).
final class I2PRouterStatusEngine {
    private weak var netDB: I2PNetworkDatabase?
    private weak var ntcp2: NTCP2Transport?
    private weak var tunnelPool: I2PTunnelPool?
    let localRouterHash: Data
    /// Optional SSU2 session source: once the SSU2 transport is wired into the
    /// running router, it supplies established-session readings in the same
    /// shape the NTCP2 transport reports, so the peer inspector lists both.
    var ssu2PeerSummaries: (() -> [(hash: Data, establishedAt: Date, bytesIn: Int, bytesOut: Int)])?

    private let startedAt = Date()
    private let lock = NSLock()
    private var messagesIn = 0
    private var messagesOut = 0
    private var bytesIn = 0
    private var bytesOut = 0
    private var lastSampleAt = Date()
    private var lastSampleIn = 0
    private var lastSampleOut = 0
    private var inRateHistory: [Double] = []
    private var outRateHistory: [Double] = []
    private var emitTask: Task<Void, Never>?
    private var continuation: AsyncStream<I2PRouterStatusSnapshot>.Continuation?

    private(set) lazy var snapshots: AsyncStream<I2PRouterStatusSnapshot> = {
        AsyncStream(bufferingPolicy: .bufferingNewest(1)) { [weak self] continuation in
            self?.continuation = continuation
        }
    }()

    init(localRouterHash: Data) {
        self.localRouterHash = localRouterHash
    }

    func attach(netDB: I2PNetworkDatabase) { self.netDB = netDB }
    func attach(ntcp2: NTCP2Transport) { self.ntcp2 = ntcp2 }
    func attach(tunnelPool: I2PTunnelPool) { self.tunnelPool = tunnelPool }

    /// Counts routed inbound messages via the I2NP router's observation hook.
    func attach(to i2npRouter: I2NPMessageRouter) {
        i2npRouter.onMessageRouted = { [weak self] message, _ in
            self?.recordIncoming(bytes: I2NPMessage.headerLength + message.payload.count)
        }
    }

    func recordIncoming(bytes: Int) {
        lock.lock()
        messagesIn += 1
        bytesIn += bytes
        lock.unlock()
    }

    func recordOutgoing(bytes: Int) {
        lock.lock()
        messagesOut += 1
        bytesOut += bytes
        lock.unlock()
    }

    /// Starts the snapshot emit loop (idempotent).
    func start(interval: TimeInterval = 1.0) {
        lock.lock()
        guard emitTask == nil else { lock.unlock(); return }
        lock.unlock()
        _ = snapshots // materialize the continuation before emitting
        emitTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { break }
                let snapshot = await self.snapshot()
                self.continuation?.yield(snapshot)
                try? await Task.sleep(for: .seconds(interval))
            }
        }
    }

    func stop() {
        emitTask?.cancel()
        emitTask = nil
    }

    /// Gathers a live reading from every attached router component.
    func snapshot() async -> I2PRouterStatusSnapshot {
        var netDBStatus: I2PNetDBStatus?
        if let netDB { netDBStatus = await netDB.status() }

        var pools: [I2PRouterStatusSnapshot.PoolSummary] = []
        if let tunnelPool {
            for (direction, tunnels) in [
                ("outbound", tunnelPool.outboundTunnels),
                ("inbound", tunnelPool.inboundTunnels)
            ] {
                let summaries = tunnels.enumerated().map { index, tunnel in
                    I2PRouterStatusSnapshot.TunnelSummary(
                        id: "\(direction)-\(index)",
                        direction: direction,
                        hopCount: tunnel.hops.count,
                        expiresAt: tunnel.expiresAt,
                        buildLatency: tunnel.buildLatency
                    )
                }
                pools.append(.init(direction: direction, tunnels: summaries))
            }
        }

        let peers = await peerSummaries(tunnelPool: tunnelPool)

        return sample(netDBStatus: netDBStatus,
                      ntcp2SessionCount: ntcp2?.sessionCount() ?? 0,
                      pools: pools,
                      peers: peers)
    }

    /// Builds per-peer session readings: transport sessions enriched with the
    /// Kademlia XOR distance, floodfill status and tunnel participation.
    private func peerSummaries(tunnelPool: I2PTunnelPool?) async -> [I2PPeerSummary] {
        var roles: [Data: String] = [:]
        if let tunnelPool {
            for tunnel in tunnelPool.outboundTunnels {
                for hop in tunnel.hops { roles[hop.routerHash] = "Outbound tunnel hop" }
            }
            for tunnel in tunnelPool.inboundTunnels {
                for hop in tunnel.hops { roles[hop.routerHash] = "Inbound tunnel hop" }
            }
        }

        var sessions: [(hash: Data, transport: String, establishedAt: Date, bytesIn: Int, bytesOut: Int)] = []
        if let ntcp2 {
            for summary in ntcp2.sessionSummaries() {
                sessions.append((summary.hash, "NTCP2", summary.establishedAt, summary.bytesIn, summary.bytesOut))
            }
        }
        if let ssu2PeerSummaries {
            for summary in ssu2PeerSummaries() {
                sessions.append((summary.hash, "SSU2", summary.establishedAt, summary.bytesIn, summary.bytesOut))
            }
        }

        var result: [I2PPeerSummary] = []
        var seen: Set<Data> = []
        for session in sessions.sorted(by: { $0.bytesIn + $0.bytesOut > $1.bytesIn + $1.bytesOut }) {
            guard !seen.contains(session.hash) else { continue }
            seen.insert(session.hash)
            let distance = I2PNetworkDatabase.xorDistance(localRouterHash, session.hash)
            let floodfill = await netDB?.isFloodfill(session.hash) ?? false
            result.append(I2PPeerSummary(
                id: Self.hex(session.hash),
                transport: session.transport,
                establishedAt: session.establishedAt,
                bytesIn: session.bytesIn,
                bytesOut: session.bytesOut,
                xorDistanceHex: Self.hex(distance),
                kademliaBucket: Self.leadingZeroBits(distance),
                isFloodfill: floodfill,
                tunnelRole: roles[session.hash]
            ))
        }
        return result
    }

    private static func leadingZeroBits(_ data: Data) -> Int {
        var bits = 0
        for byte in data {
            if byte == 0 { bits += 8; continue }
            var value = byte
            while value & 0x80 == 0 { bits += 1; value <<= 1 }
            break
        }
        return bits
    }

    /// Synchronous sampling of the counters (kept sync for lock safety).
    private func sample(netDBStatus: I2PNetDBStatus?,
                        ntcp2SessionCount: Int,
                        pools: [I2PRouterStatusSnapshot.PoolSummary],
                        peers: [I2PPeerSummary]) -> I2PRouterStatusSnapshot {
        lock.lock()
        defer { lock.unlock() }
        let now = Date()
        let elapsed = max(now.timeIntervalSince(lastSampleAt), 0.001)
        let inRate = Double(messagesIn - lastSampleIn) / elapsed
        let outRate = Double(messagesOut - lastSampleOut) / elapsed
        inRateHistory.append(inRate)
        outRateHistory.append(outRate)
        if inRateHistory.count > 12 { inRateHistory.removeFirst(inRateHistory.count - 12) }
        if outRateHistory.count > 12 { outRateHistory.removeFirst(outRateHistory.count - 12) }
        let snapshot = I2PRouterStatusSnapshot(
            capturedAt: now,
            identityHashHex: Self.hex(localRouterHash),
            isLocalFloodfill: netDBStatus?.isLocalFloodfill ?? false,
            floodfillCount: netDBStatus?.floodfillCount ?? 0,
            peerCount: netDBStatus?.peerCount ?? 0,
            ntcp2SessionCount: ntcp2SessionCount,
            routerInfoCount: netDBStatus?.routerInfoCount ?? 0,
            leaseSetCount: netDBStatus?.leaseSetCount ?? 0,
            uptime: now.timeIntervalSince(startedAt),
            pools: pools,
            messagesIn: messagesIn,
            messagesOut: messagesOut,
            bytesIn: bytesIn,
            bytesOut: bytesOut,
            inRate: inRate,
            outRate: outRate,
            inRateHistory: inRateHistory,
            outRateHistory: outRateHistory,
            peers: peers
        )
        lastSampleAt = now
        lastSampleIn = messagesIn
        lastSampleOut = messagesOut
        return snapshot
    }

    private static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - Self-test

enum I2PRouterStatusSelfTest {
    static func runAll() async -> [I2PSelfTestResult] {
        var results: [I2PSelfTestResult] = []
        func run(_ name: String, _ body: () async throws -> String) async {
            do {
                results.append(I2PSelfTestResult(name: name, passed: true, detail: try await body()))
            } catch {
                results.append(I2PSelfTestResult(name: name, passed: false, detail: "\(error)"))
            }
        }
        await run("Router status engine emits live snapshots", dashboardSnapshotTest)
        return results
    }

    private final class StatusTestNode {
        let routerHash = I2PCrypto.randomBytes(32)
        let encryptionKey = Curve25519.KeyAgreement.PrivateKey()
        let hub: I2PTunnelBuildHub
        let transport: I2PTunnelLoopbackTransport
        let participant: I2PTunnelParticipant

        init(hub: I2PTunnelBuildHub) {
            self.hub = hub
            transport = I2PTunnelLoopbackTransport(hub: hub, localRouterHash: routerHash)
            participant = I2PTunnelParticipant(
                localRouterHash: routerHash,
                localEncryptionKey: encryptionKey,
                transport: transport
            )
            hub.register(participant)
        }

        var peer: I2PTunnelPeer {
            I2PTunnelPeer(routerHash: routerHash,
                          encryptionPublicKey: encryptionKey.publicKey.rawRepresentation)
        }
    }

    private static func dashboardSnapshotTest() async throws -> String {
        let localHash = I2PCrypto.randomBytes(32)
        let remoteHash = I2PCrypto.randomBytes(32)
        let hub = I2NPLoopbackDeliveryHub()
        let engine = I2PRouterStatusEngine(localRouterHash: localHash)

        // Real netdb instances with throwaway storage directories.
        func tempStorage() throws -> I2PNetDBStorage {
            try I2PNetDBStorage(directory: FileManager.default.temporaryDirectory
                .appendingPathComponent("i2p-status-\(UUID().uuidString)"))
        }
        final class DropTransport: I2PDeliveryTransport {
            func deliver(_ i2npBytes: Data, to routerHash: Data) async throws {}
        }
        let localStorage = try tempStorage()
        let remoteStorage = try tempStorage()
        let netDB = I2PNetworkDatabase(localRouterHash: localHash,
                                       transport: I2PNetDBI2NPAdapter(delivery: DropTransport()),
                                       storage: localStorage)
        let remoteNetDB = I2PNetworkDatabase(localRouterHash: remoteHash,
                                             transport: I2PNetDBI2NPAdapter(delivery: DropTransport()),
                                             storage: remoteStorage)
        await remoteNetDB.configureLocalFloodfill(true)

        let i2npRouter = I2NPMessageRouter(localRouterHash: localHash)
        engine.attach(netDB: netDB)
        engine.attach(to: i2npRouter)
        i2npRouter.addBodyHandler { [weak netDB] message, _ in
            guard let netDB, let netdbMessage = I2PNetDBI2NPBridge.inbound(message) else { return }
            Task { await netDB.handleIncoming(netdbMessage) }
        }
        hub.attach(i2npRouter)

        // Publish a real signed RouterInfo with floodfill caps from the remote node.
        let signingKey = Curve25519.Signing.PrivateKey()
        let identity = I2PRouterIdentity(
            encryptionPublicKey: Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation,
            signingPublicKey: signingKey.publicKey.rawRepresentation
        )
        var routerInfo = I2PRouterInfo(
            identity: identity, published: Date(), addresses: [], options: ["caps": "f"]
        )
        try routerInfo.sign(withSeed: signingKey.rawRepresentation)
        _ = await remoteNetDB.publish(routerInfo: routerInfo)
        let store = I2PDatabaseStore(
            key: routerInfo.identity.hash,
            entryType: .routerInfo,
            replyToken: 0,
            replyTunnelId: 0,
            replyGateway: Data(),
            payload: routerInfo.serialize()
        )
        let envelope = I2NPMessage(type: .databaseStore, payload: store.serialize())
        await hub.deliver(from: remoteHash, envelope.serialize(), to: localHash)

        // A real two-hop outbound tunnel adopted into the pool.
        let buildHub = I2PTunnelBuildHub()
        let localNode = StatusTestNode(hub: buildHub)
        let hop1 = StatusTestNode(hub: buildHub)
        let hop2 = StatusTestNode(hub: buildHub)
        let pool = I2PTunnelPool(
            localRouterHash: localHash,
            participant: localNode.participant,
            transport: localNode.transport,
            peerProvider: EmptyTunnelPeerProvider()
        )
        engine.attach(tunnelPool: pool)
        let builder = I2PTunnelBuilder(
            localRouterHash: localHash,
            participant: localNode.participant,
            transport: localNode.transport
        )
        let tunnel = try await builder.buildTunnel(
            direction: .outbound, hops: [hop1.peer, hop2.peer], lifetime: 900, timeout: 10
        )
        pool.adopt(tunnel)

        let snapshot = await engine.snapshot()
        guard snapshot.routerInfoCount == 1 else { throw I2PWireError.invalidFormat }
        guard snapshot.floodfillCount == 1 else { throw I2PWireError.invalidFormat }
        guard snapshot.messagesIn >= 1 else { throw I2PWireError.invalidFormat }
        guard snapshot.pools.count == 2 else { throw I2PWireError.invalidFormat }

        // The event stream yields snapshots.
        engine.start(interval: 0.1)
        defer { engine.stop() }
        var received = 0
        for await _ in engine.snapshots {
            received += 1
            if received >= 2 { break }
        }
        guard received >= 2 else { throw I2PWireError.invalidFormat }

        let outbound = snapshot.pools.first { $0.direction == "outbound" }
        guard let outbound, outbound.tunnels.count == 1, outbound.tunnels[0].hopCount == 2 else {
            throw I2PWireError.invalidFormat
        }
        return "1 RI, 1 floodfill, \(snapshot.messagesIn) routed msgs, outbound pool 2 hops; stream emitted \(received)"
    }
}

/// Placeholder peer provider: no peers are known until the netdb fills.
final class EmptyTunnelPeerProvider: I2PTunnelPeerProvider {
    func peers(count: Int, excluding: Set<Data>) -> [I2PTunnelPeer] { [] }
}
