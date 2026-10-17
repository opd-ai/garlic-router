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
private func buildOne(_ direction: I2PTunnel.Direction) async {
        let peers = peerProvider.peers(
            count: config.hopCount,
            excluding: Set([localRouterHash])
        )
        guard peers.count == config.hopCount else { return }
        lock.lock()
        buildStartTimes.append(Date())
        lock.unlock()
        guard let tunnel = try? await builder.buildTunnel(
            direction: direction,
            hops: peers,
            lifetime: config.clampedLifetime,
            timeout: config.buildTimeout
        ) else { return }
        adopt(tunnel)
    }

    /// Builds tunnels until both pools meet their targets, staggering
    /// consecutive builds so pool creation is spread out.
    func fillPools() async {
        lock.lock()
        if filling {
            lock.unlock()
            return
        }
        filling = true
        lock.unlock()
        defer {
            lock.lock()
            filling = false
            lock.unlock()
        }
        for direction in [I2PTunnel.Direction.outbound, .inbound] {
            while activeCount(direction) < targetCount(direction) {
                let before = activeCount(direction)
                await buildOne(direction)
                guard activeCount(direction) > before else { break } // build failed; don't spin
                if activeCount(direction) < targetCount(direction) {
                    try? await Task.sleep(for: .seconds(config.staggerInterval))
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
            if needed > 0 {
                await buildOne(direction)
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