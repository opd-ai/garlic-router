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
    // Network participation (participation controls)
    let participatingTunnelCount: Int
    let transitMessages: Int
    let transitBytes: Int
    let transitRatePerMinute: Double
    let measuredTransitShare: Double
    let floodfillAdvertised: Bool
    let routerInfoPublishedAt: Date?
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
        case .deliveryStatus(let id, let timestamp):
            var writer = I2PWriter()
            writer.integer(id)
            writer.long(UInt64((timestamp.timeIntervalSince1970 * 1000).rounded()))
            return I2NPMessage(type: .deliveryStatus, payload: writer.data)
        }
    }

    static func inbound(_ message: I2NPMessage) -> I2PNetDBMessage? {
        guard let body = try? message.parseBody() else { return nil }
        switch body {
        case .databaseStore(let s): return .store(s)
        case .databaseLookup(let l): return .lookup(l)
        case .databaseSearchReply(let r): return .searchReply(r)
        case .deliveryStatus(let id, let stamp): return .deliveryStatus(messageID: id, timestamp: stamp)
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

/// Serializes demand-dial bookkeeping across concurrent callers (netdb
/// deliveries, tunnel builds, the bootstrap dialer): at most one in-flight
/// endpoint resolution + dial attempt per peer hash.
actor DemandDialTracker {
    private var inFlight: Set<Data> = []

    /// Claims the dial slot for a hash; false when another caller is already
    /// dialing it (the caller then simply waits for the session to appear).
    func claim(_ hash: Data) -> Bool {
        if inFlight.contains(hash) { return false }
        inFlight.insert(hash)
        return true
    }

    func release(_ hash: Data) {
        inFlight.remove(hash)
    }
}

/// NTCP2 <-> I2NP delivery adapter with a throughput hook and demand-dialing:
/// a delivery to a peer we hold no session for resolves the peer's RouterInfo
/// (netdb cache-first), dials it, waits for the Noise handshake, and rides the
/// resulting session — so netdb lookups, stores and exploratory round-trips
/// work against any signature-verified peer the netdb knows, not just the few
/// dialed at bootstrap.
final class I2PNTCP2DeliveryTransport: I2PDeliveryTransport {
    weak var ntcp2: NTCP2Transport?
    var onSent: ((Int) -> Void)?
    /// Demand-dial hook: resolves the endpoint for a router hash and initiates
    /// the NTCP2 connect. Wired by the running router context.
    var dialPeer: ((Data) async -> Bool)?
    /// How long a demand-dialed handshake gets to complete before the send
    /// re-attempts (and the caller's own round timeout governs retries).
    var dialTimeout: TimeInterval = 6

    init(ntcp2: NTCP2Transport) {
        self.ntcp2 = ntcp2
    }

    func deliver(_ i2npBytes: Data, to routerHash: Data) async throws {
        guard let ntcp2 else { throw NTCP2Error.notEstablished }
        if !ntcp2.hasSession(for: routerHash), dialPeer != nil {
            _ = await dialPeer?(routerHash)
            await waitForSession(to: routerHash)
        }
        // Outbound bandwidth cap: the send waits for its tokens, so the cap
        // takes effect on the running router as soon as it is configured.
        await I2PBandwidthGovernor.shared.admitOutbound(bytes: i2npBytes.count)
        try ntcp2.send(to: routerHash, data: i2npBytes)
        onSent?(i2npBytes.count)
    }

    private func waitForSession(to routerHash: Data) async {
        guard let ntcp2 else { return }
        let deadline = Date().addingTimeInterval(dialTimeout)
        while !ntcp2.hasSession(for: routerHash), Date() < deadline {
            try? await Task.sleep(for: .milliseconds(250))
        }
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
    /// Optional participation surface: the live count of tunnels this router
    /// currently carries for other participants (the share's measured side).
    var participatingTunnels: (() -> Int)?

    private let startedAt = Date()
    private let lock = NSLock()
    private var messagesIn = 0
    private var messagesOut = 0
    private var bytesIn = 0
    private var bytesOut = 0
    private var transitMessages = 0
    private var transitBytes = 0
    private var localTunnelMessages = 0
    private var transitHistory: [(date: Date, transit: Int, local: Int)] = []
    private var floodfillAdvertised = false
    private var routerInfoPublishedAt: Date?
    private var lastSampleAt = Date()
    private var lastSampleIn = 0
    private var lastSampleOut = 0
    private var inRateHistory: [Double] = []
    private var outRateHistory: [Double] = []
    private var emitTask: Task<Void, Never>?
    private var continuation: AsyncStream<I2PRouterStatusSnapshot>.Continuation?

    /// The window the participation share and transit rate are measured over.
    private static let participationWindow: TimeInterval = 60

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

    /// Attaches the tunnel participant so the participation screen can read how
    /// many tunnels the router currently carries for other participants.
    func attach(participant: I2PTunnelParticipant) {
        participatingTunnels = { [weak participant] in
            participant?.activeHopStateCount ?? 0
        }
    }

    /// Counts routed inbound messages via the I2NP router's observation hook.
    func attach(to i2npRouter: I2NPMessageRouter) {
        i2npRouter.onMessageRouted = { [weak self] message, _ in
            self?.recordIncoming(bytes: I2NPMessage.headerLength + message.payload.count)
        }
        i2npRouter.onTransitForward = { [weak self] bytes in
            self?.recordTransit(bytes: bytes)
        }
        i2npRouter.onLocalTunnelDelivery = { [weak self] in
            self?.recordLocalTunnelDelivery()
        }
    }

    /// Records traffic forwarded for another participant's tunnel.
    func recordTransit(bytes: Int) {
        lock.lock()
        transitMessages += 1
        transitBytes += bytes
        lock.unlock()
    }

    /// Records a tunnel message this router consumed at its message-path end.
    func recordLocalTunnelDelivery() {
        lock.lock()
        localTunnelMessages += 1
        lock.unlock()
    }

    /// Records the floodfill capability our published RouterInfo carries, so
    /// the participation screen can name the advertisement's state and age.
    func recordFloodfillAdvertisement(advertised: Bool, publishedAt: Date?) {
        lock.lock()
        floodfillAdvertised = advertised
        routerInfoPublishedAt = publishedAt
        lock.unlock()
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
        // The tunnel participant owns its own lock; read it before taking ours
        // so the lock order stays one-way.
        let participating = participatingTunnels?() ?? 0
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
        let participation = participationReadingLocked(now: now)
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
            participatingTunnelCount: participating,
            transitMessages: transitMessages,
            transitBytes: transitBytes,
            transitRatePerMinute: participation.rate,
            measuredTransitShare: participation.share,
            floodfillAdvertised: floodfillAdvertised,
            routerInfoPublishedAt: routerInfoPublishedAt,
            peers: peers
        )
        lastSampleAt = now
        lastSampleIn = messagesIn
        lastSampleOut = messagesOut
        return snapshot
    }

    /// Transit rate (messages per minute) and the measured share ratio: the
    /// transit messages we forwarded versus the tunnel traffic we consumed at
    /// our own message-path end, over the last minute.
    private func participationReadingLocked(now: Date) -> (rate: Double, share: Double) {
        transitHistory.append((now, transitMessages, localTunnelMessages))
        let cutoff = now.addingTimeInterval(-Self.participationWindow)
        transitHistory.removeAll { $0.date < cutoff }
        guard let oldest = transitHistory.first else { return (0, 0) }
        let seconds = max(now.timeIntervalSince(oldest.date), 1)
        let transitDelta = transitMessages - oldest.transit
        let localDelta = max(0, localTunnelMessages - oldest.local)
        let rate = Double(transitDelta) / seconds * 60
        let share = transitDelta + localDelta > 0
            ? Double(transitDelta) / Double(transitDelta + localDelta)
            : 0
        return (rate, share)
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
