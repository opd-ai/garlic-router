//
//  I2PTunnelPeerSelection.swift
//  Live mainnet hop selection with per-peer profiles — the Swift analogue of
//  Java I2P's TunnelPool/TunnelManager selection driven by RouterProfileManager.
//
//  Hops come from the signature-verified RouterInfos in the live netdb, not
//  from the floodfill set alone. A candidate must be fresh (the spec lifetime
//  of a RouterInfo is about an hour), carry a modern non-degenerate X25519
//  identity and at least one live NTCP2/SSU2 address with a usable host and
//  port. Each peer keeps a build profile: attempts, successes and consecutive
//  failures bench a failing hop with exponential backoff, ordinary routers are
//  preferred over floodfills (which back the netdb), and recently used hops are
//  diluted so consecutive tunnels from one pool do not share a path.
//

import Foundation

/// The outcome of one tunnel build attempt, reported back to the peer provider
/// so hop profiles keep a live success/failure history.
struct I2PTunnelPeerBuildOutcome {
    let peers: [Data]
    let succeeded: Bool
    let latency: TimeInterval?
}

/// Live build profile of one hop (the RouterProfileManager analogue).
struct I2PTunnelPeerProfile {
    var attempts = 0
    var successes = 0
    var consecutiveFailures = 0
    var lastFailureAt: Date?
    var lastSelectedAt: Date?
    var lastLatency: TimeInterval?

    /// Laplace-smoothed success rate, so an untried hop is not automatically
    /// better or worse than a proven one.
    var successRate: Double {
        Double(successes + 1) / Double(attempts + 2)
    }

    /// Exponential backoff once the failure threshold is crossed.
    func backoff(for failures: Int, config: I2PTunnelPeerSelector.Config) -> TimeInterval {
        guard failures >= config.failureThreshold else { return 0 }
        let exponent = min(Double(failures - config.failureThreshold), 8)
        return min(config.maxBackoff, config.baseBackoff * pow(2, exponent))
    }

    func isBackedOff(now: Date, config: I2PTunnelPeerSelector.Config) -> Bool {
        guard let lastFailureAt, consecutiveFailures >= config.failureThreshold else { return false }
        return now.timeIntervalSince(lastFailureAt) < backoff(for: consecutiveFailures, config: config)
    }
}

/// Selects tunnel hops from the live netdb candidate set, and keeps a bounded
/// profile per peer. Thread-safe: the tunnel pool's maintenance loop, the SAM
/// core and the eepsite browser all select hops, and builds report back
/// concurrently.
final class I2PTunnelPeerSelector {
    struct Config {
        /// RouterInfos older than this are stale hops (spec lifetime ≈ 1h).
        var freshnessWindow: TimeInterval = 2 * 3600
        /// A RouterInfo published further in the future than this is rejected.
        var clockSkewTolerance: TimeInterval = 300
        /// Consecutive failed builds that bench a hop.
        var failureThreshold = 2
        /// First backoff after the threshold; doubles with each further failure.
        var baseBackoff: TimeInterval = 120
        var maxBackoff: TimeInterval = 1800
        /// Floodfills are the netdb backbone: they are used as hops only when
        /// the ordinary peer pool cannot fill the tunnel.
        var floodfillPenalty = 0.25
        /// Recently used hops are diluted so consecutive tunnels differ.
        var recencyPenalty = 0.5
        var diversityWindow: TimeInterval = 60
        /// Score jitter, so builds do not lock onto the same few hops.
        var selectionJitter = 0.35
        /// Bounded profile storage (bounded like the netdb cache itself).
        var maxProfiles = 5000
        /// Multiplier for a candidate this router already holds a live session
        /// to. A build's first record has to reach its hop now: over an existing
        /// session it leaves immediately, while a cold hop depends on a
        /// handshake that can stall or be refused. Demand-dialing every hop is
        /// how a pool ends up logging build attempts and adopting nothing.
        var connectedBonus = 4.0

        init() {}
    }

    private let config: Config
    private let lock = NSLock()
    private var profiles: [Data: I2PTunnelPeerProfile] = [:]

    /// Whether this router currently holds a live session to a peer. Set by the
    /// running router; nil (no preference) elsewhere, such as test harnesses.
    var isConnected: ((Data) -> Bool)?

    init(config: Config = Config()) {
        self.config = config
    }

    // MARK: Eligibility

    /// Count of live NTCP2/SSU2 addresses carrying a usable host and port.
    static func usableAddressCount(_ info: I2PRouterInfo, now: Date = Date()) -> Int {
        info.addresses.filter { address in
            let style = address.transportStyle.uppercased()
            guard style == "NTCP2" || style == "SSU2" else { return false }
            if let expiration = address.expiration, expiration <= now { return false }
            let host = (address.options["host"] ?? "")
                .trimmingCharacters(in: .whitespacesAndNewlines)
            guard !host.isEmpty, host != "0.0.0.0", host != "::" else { return false }
            guard let portText = address.options["port"],
                  let port = Int(portText), port > 0, port <= 65_535 else { return false }
            return true
        }.count
    }

    /// A modern X25519 identity that is neither empty nor degenerate (fail
    /// closed on poisoned key material, per the hardening rules).
    static func isUsableEncryptionKey(_ key: Data) -> Bool {
        guard key.count == 32 else { return false }
        return key.contains { $0 != 0 } && key.contains { $0 != 0xff }
    }

    // MARK: Selection

    /// Picks up to `count` distinct hops from the given live candidates, in
    /// preference order (ordinary routers first, floodfills only as a fallback).
    func select(count: Int,
                excluding: Set<Data>,
                from candidates: [(hash: Data, info: I2PRouterInfo)],
                localRouterHash: Data,
                now: Date = Date()) -> [I2PTunnelPeer] {
        guard count > 0 else { return [] }
        lock.lock()
        var seen = Set<Data>()
        var ranked: [(peer: I2PTunnelPeer, isFloodfill: Bool, score: Double)] = []
        for candidate in candidates {
            let hash = candidate.hash
            guard seen.insert(hash).inserted,
                  hash.count == 32,
                  hash != localRouterHash,
                  !excluding.contains(hash) else { continue }
            let key = candidate.info.identity.encryptionPublicKey
            guard Self.isUsableEncryptionKey(key) else { continue }
            let published = candidate.info.published
            guard published > now.addingTimeInterval(-config.freshnessWindow),
                  published < now.addingTimeInterval(config.clockSkewTolerance) else { continue }
            guard Self.usableAddressCount(candidate.info, now: now) > 0 else { continue }
            let profile = profiles[hash] ?? I2PTunnelPeerProfile()
            guard !profile.isBackedOff(now: now, config: config) else { continue }
            var score = 0.5 + profile.successRate
            if let latency = profile.lastLatency, latency > 0 {
                score *= max(0.5, min(1.0, 1.0 / (1.0 + latency / 5.0)))
            }
            let isFloodfill = candidate.info.options["caps"]?.contains("f") ?? false
            if isFloodfill { score *= config.floodfillPenalty }
            if let selected = profile.lastSelectedAt,
               now.timeIntervalSince(selected) < config.diversityWindow {
                score *= config.recencyPenalty
            }
            if isConnected?(hash) ?? false { score *= config.connectedBonus }
            score += Self.jitter(config.selectionJitter)
            ranked.append((peer: I2PTunnelPeer(routerHash: hash, encryptionPublicKey: key),
                           isFloodfill: isFloodfill, score: score))
        }
        let ordinary = ranked.filter { !$0.isFloodfill }.sorted { $0.score > $1.score }
        let floodfills = ranked.filter { $0.isFloodfill }.sorted { $0.score > $1.score }
        let chosen = Array((ordinary + floodfills).prefix(count))
        for entry in chosen {
            var profile = profiles[entry.peer.routerHash] ?? I2PTunnelPeerProfile()
            profile.lastSelectedAt = now
            profiles[entry.peer.routerHash] = profile
        }
        pruneProfilesLocked()
        lock.unlock()
        return chosen.map { $0.peer }
    }

    // MARK: Outcome feedback

    /// Folds one build attempt into every participating hop's profile. A
    /// success clears the failure streak; a failure starts (or extends) the
    /// hop's backoff window.
    func recordBuildOutcome(_ outcome: I2PTunnelPeerBuildOutcome, now: Date = Date()) {
        lock.lock()
        defer { lock.unlock() }
        for hash in outcome.peers {
            var profile = profiles[hash] ?? I2PTunnelPeerProfile()
            profile.attempts += 1
            if outcome.succeeded {
                profile.successes += 1
                profile.consecutiveFailures = 0
                profile.lastFailureAt = nil
                if let latency = outcome.latency { profile.lastLatency = latency }
            } else {
                profile.consecutiveFailures += 1
                profile.lastFailureAt = now
            }
            profiles[hash] = profile
        }
        pruneProfilesLocked()
    }

    func profile(for routerHash: Data) -> I2PTunnelPeerProfile? {
        lock.lock()
        defer { lock.unlock() }
        return profiles[routerHash]
    }

    // MARK: Private

    /// Keeps profile storage bounded: once over the cap, the least recently
    /// selected peers are forgotten first.
    private func pruneProfilesLocked() {
        guard profiles.count > config.maxProfiles else { return }
        let excess = profiles.count - config.maxProfiles
        let victims = profiles.keys
            .sorted {
                (profiles[$0]?.lastSelectedAt ?? .distantPast)
                    < (profiles[$1]?.lastSelectedAt ?? .distantPast)
            }
            .prefix(excess)
        for key in victims { profiles.removeValue(forKey: key) }
    }

    private static func jitter(_ amplitude: Double) -> Double {
        let bytes = [UInt8](I2PCrypto.randomBytes(2))
        guard bytes.count == 2 else { return 0 }
        let value = Double(UInt16(bytes[0]) << 8 | UInt16(bytes[1])) / Double(UInt16.max)
        return value * amplitude
    }
}
