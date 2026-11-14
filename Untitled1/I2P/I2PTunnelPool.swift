//
//  I2PTunnelPool.swift
//  Per-destination pool of 3-5 outbound and 3-5 inbound tunnels with
//  staggered creation, expiration (10-30 min lifetime), pre-built
//  replacements, latency monitoring, and latency-based selection.
//

import Foundation

final class I2PTunnelPool {
    struct Config {
        /// Pool targets (I2P spec: 3-5 tunnels per direction).
        var outboundTarget = 3
        var inboundTarget = 3
        /// Tunnels are 2-3 hops in practice.
        var hopCount = 2
        /// Tunnel lifetime; spec range is 10-30 minutes (clamped below).
        var lifetime: TimeInterval = 900
        /// Delay between consecutive tunnel builds when filling the pool.
        var staggerInterval: TimeInterval = 1.0
        /// Pre-build a replacement when this much lifetime remains.
        var prebuildThreshold: TimeInterval = 180
        var maintenanceInterval: TimeInterval = 2
        var buildTimeout: TimeInterval = 20
        /// Clamp the lifetime into the spec's 10-30 minute range.
        var enforceSpecLimits = true

        var clampedLifetime: TimeInterval {
            guard enforceSpecLimits else { return lifetime }
            return min(max(lifetime, 600), 1800)
        }

        init() {}
    }

    private let config: Config
    private let localRouterHash: Data
    private let participant: I2PTunnelParticipant
    private let transport: I2PTunnelBuildTransport
    private let peerProvider: I2PTunnelPeerProvider
    private let builder: I2PTunnelBuilder
    private let lock = NSLock()

    private var outbound: [I2PTunnel] = []
    private var inbound: [I2PTunnel] = []
    /// Wall-clock marks of every initiated build (stagger verification).
    private(set) var buildStartTimes: [Date] = []
    private var maintenanceTask: Task<Void, Never>?
    private var filling = false

    /// Where an outbound build's endpoint sends its build reply ("Reply through
    /// existing inbound D-E-F"). A live inbound tunnel of ours when one exists;
    /// otherwise the pool registers a local endpoint and addresses the reply to
    /// its own router. Without this the pool's own outbound builds can never be
    /// acknowledged on mainnet — the reply has no route and the build times out
    /// even though every hop accepted its record.
    var replyRouteProvider: (() -> (gateway: Data, tunnelID: UInt32)?)?

    /// Registers an I2NP gateway handler for an endpoint ID of this router, so a
    /// message delivered to the end of our own tunnel — a build reply that rode
    /// an inbound tunnel, or any payload addressed to us — reaches the local
    /// router instead of being dropped as an unknown tunnel.
    var installLocalEndpoint: ((UInt32) -> Void)?

    init(localRouterHash: Data,
         participant: I2PTunnelParticipant,
         transport: I2PTunnelBuildTransport,
         peerProvider: I2PTunnelPeerProvider,
         config: Config = Config()) {
        self.localRouterHash = localRouterHash
        self.participant = participant
        self.transport = transport
        self.peerProvider = peerProvider
        self.config = config
        self.builder = I2PTunnelBuilder(
            localRouterHash: localRouterHash,
            participant: participant,
            transport: transport
        )
    }

    private func targetCount(_ direction: I2PTunnel.Direction) -> Int {
        direction == .outbound ? config.outboundTarget : config.inboundTarget
    }

    private func tunnels(_ direction: I2PTunnel.Direction) -> [I2PTunnel] {
        lock.lock()
        defer { lock.unlock() }
        return direction == .outbound ? outbound : inbound
    }

    func activeCount(_ direction: I2PTunnel.Direction) -> Int {
        tunnels(direction).filter { !$0.isExpired() }.count
    }

    private func expiringCount(_ direction: I2PTunnel.Direction) -> Int {
        tunnels(direction).filter {
            !$0.isExpired() && $0.remainingLifetime() < config.prebuildThreshold
        }.count
    }

    var outboundTunnels: [I2PTunnel] {
        tunnels(.outbound).filter { !$0.isExpired() }
    }

    var inboundTunnels: [I2PTunnel] {
        tunnels(.inbound).filter { !$0.isExpired() }
    }

    var outboundCount: Int { activeCount(.outbound) }
    var inboundCount: Int { activeCount(.inbound) }

    /// Mean build latency across live tunnels (latency monitoring).
    var averageBuildLatency: TimeInterval? {
        let latencies = (outboundTunnels + inboundTunnels).compactMap(\.buildLatency)
        guard !latencies.isEmpty else { return nil }
        return latencies.reduce(0, +) / Double(latencies.count)
    }

    /// Registers a tunnel (used by the builder and by tests).
    func adopt(_ tunnel: I2PTunnel) {
        lock.lock()
        switch tunnel.direction {
        case .outbound: outbound.append(tunnel)
        case .inbound: inbound.append(tunnel)
        }
        lock.unlock()
    }

    @discardableResult
    func pruneExpired(now: Date = Date()) -> Int {
        lock.lock()
        defer { lock.unlock() }
        let before = outbound.count + inbound.count
        outbound.removeAll { $0.isExpired(now: now) }
        inbound.removeAll { $0.isExpired(now: now) }
        return before - (outbound.count + inbound.count)
    }

    /// Picks the outbound tunnel with the lowest measured build latency.
    func selectOutboundTunnel() -> I2PTunnel? {
        lock.lock()
        let candidates = outbound.filter { !$0.isExpired() }
        lock.unlock()
        return candidates.min {
            ($0.buildLatency ?? TimeInterval.greatestFiniteMagnitude) < ($1.buildLatency ?? TimeInterval.greatestFiniteMagnitude)
        }
    }

    /// Picks the inbound tunnel with the lowest measured build latency.
    func selectInboundTunnel() -> I2PTunnel? {
        lock.lock()
        let candidates = inbound.filter { !$0.isExpired() }
        lock.unlock()
        return candidates.min {
            ($0.buildLatency ?? TimeInterval.greatestFiniteMagnitude) < ($1.buildLatency ?? TimeInterval.greatestFiniteMagnitude)
        }
    }
    /// Builds one tunnel for `direction`.
    ///
    /// Hops are whatever the provider can supply up to the configured count: the
    /// spec allows a 1-hop tunnel, and a pool that insists on a full path while
    /// only one hop is usable builds nothing at all — the live pool sat at
    /// 0 outbound + 0 inbound for exactly that reason. An outbound build is given
    /// the reply route its endpoint needs, and an inbound tunnel's endpoint is
    /// registered locally so a message delivered to it reaches this router.
    private func buildOne(_ direction: I2PTunnel.Direction) async {
        var peers = hopCandidates()
        if peers.isEmpty {
            // A pool that runs out of hops must ask the provider to refresh
            // (the netdb fills asynchronously) instead of skipping the build.
            _ = await peerProvider.refreshPeers()
            peers = hopCandidates()
        }
        guard !peers.isEmpty else { return }
        recordBuildStart()
        let started = Date()
        let replyRoute = direction == .outbound ? outboundReplyRoute() : nil
        do {
            let tunnel = try await builder.buildTunnel(
                direction: direction,
                hops: peers,
                lifetime: config.clampedLifetime,
                timeout: config.buildTimeout,
                replyRoute: replyRoute
            )
            peerProvider.recordBuildOutcome(I2PTunnelPeerBuildOutcome(
                peers: peers.map(\.routerHash),
                succeeded: true,
                latency: Date().timeIntervalSince(started)))
            adopt(tunnel)
            if tunnel.direction == .inbound {
                // The end of our own inbound tunnel is this router: every payload
                // it delivers (including a build reply that rode it) must land on
                // a gateway handler or the router drops it as an unknown tunnel.
                installLocalEndpoint?(tunnel.endpointTunnelID)
            }
        } catch {
            // Failed builds feed the hop profiles, so the next selection avoids
            // the hops that just failed instead of retrying them forever.
            peerProvider.recordBuildOutcome(I2PTunnelPeerBuildOutcome(
                peers: peers.map(\.routerHash),
                succeeded: false,
                latency: nil))
        }
    }

    /// The reply route an outbound endpoint uses: an existing inbound tunnel of
    /// ours (the spec's "reply through existing inbound D-E-F"), otherwise our
    /// own router with a freshly registered local endpoint ID.
    private func outboundReplyRoute() -> (gateway: Data, tunnelID: UInt32) {
        if let live = replyRouteProvider?() { return live }
        let endpointID = UInt32.random(in: 1...UInt32.max)
        installLocalEndpoint?(endpointID)
        return (gateway: localRouterHash, tunnelID: endpointID)
    }

    /// Up to `config.hopCount` distinct hops (the spec permits 1..4).
    private func hopCandidates() -> [I2PTunnelPeer] {
        Array(peerProvider.peers(count: config.hopCount,
                                 excluding: Set([localRouterHash])).prefix(config.hopCount))
    }

    /// Synchronous lock helpers for `fillPools`: `NSLock` may not be taken
    /// directly from an async context (an error in the Swift 6 language mode).
    private func beginFilling() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !filling else { return false }
        filling = true
        return true
    }

    private func endFilling() {
        lock.lock()
        filling = false
        lock.unlock()
    }

    private func recordBuildStart() {
        lock.lock()
        buildStartTimes.append(Date())
        lock.unlock()
    }

    /// Builds tunnels until both pools meet their targets, staggering
    /// consecutive builds so pool creation is spread out — including the
    /// hand-off from the outbound to the inbound pool, which otherwise fires
    /// its first build the moment the last outbound one returns.
    func fillPools() async {
        guard beginFilling() else { return }
        defer { endFilling() }
        var builtAny = false
        for direction in [I2PTunnel.Direction.outbound, .inbound] {
            // A failed build benched its hops, so the next attempt draws a fresh
            // path: retry a few times instead of giving up on the direction at
            // the first unreachable hop (which left the live pool at zero).
            var failedAttempts = 0
            while activeCount(direction) < targetCount(direction), failedAttempts < 3 {
                if builtAny {
                    try? await Task.sleep(for: .seconds(config.staggerInterval))
                }
                let before = activeCount(direction)
                await buildOne(direction)
                if activeCount(direction) > before {
                    builtAny = true
                    failedAttempts = 0
                } else {
                    failedAttempts += 1
                }
            }
        }
    }

    /// Maintenance: prune expired tunnels, then pre-build replacements for
    /// tunnels nearing expiration so the pool never drains.
    func maintain() async {
        pruneExpired()
        for direction in [I2PTunnel.Direction.outbound, .inbound] {
            let active = activeCount(direction)
            let expiring = expiringCount(direction)
            let needed = min(2, max(0, targetCount(direction) + expiring - active))
            // One failed build per tick is retried with a fresh hop set instead
            // of deferring the whole direction to the next maintenance pass.
            for _ in 0..<max(1, needed) {
                let before = activeCount(direction)
                await buildOne(direction)
                guard activeCount(direction) > before else { break }
                if activeCount(direction) >= targetCount(direction) { break }
            }
        }
    }

    /// Starts the pool: fills it (staggered) and runs the maintenance loop.
    func start() {
        lock.lock()
        guard maintenanceTask == nil else {
            lock.unlock()
            return
        }
        let interval = config.maintenanceInterval
        lock.unlock()
        maintenanceTask = Task { [weak self] in
            await self?.fillPools()
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(interval))
                guard let self, !Task.isCancelled else { break }
                await self.maintain()
            }
        }
    }

    func stop() {
        lock.lock()
        maintenanceTask?.cancel()
        maintenanceTask = nil
        lock.unlock()
    }
}