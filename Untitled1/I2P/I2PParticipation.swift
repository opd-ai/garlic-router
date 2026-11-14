//
//  I2PParticipation.swift
//  Network-participation controls: the router's bandwidth governor (token
//  buckets per direction with measured 1-minute rates), the persisted
//  participation settings (caps, tunnel-share ratio, floodfill role) and the
//  tunnel budget the share ratio derives.
//

import Foundation

// MARK: - Bandwidth governor

/// Enforces the router's inbound/outbound bandwidth caps and measures what
/// actually moves through each direction.
///
/// The caps are token buckets: a direction gets `cap` bytes per second, with a
/// burst allowance of two seconds (never less than one transport frame, so a
/// capped path still admits whole frames). A cap of zero disables enforcement
/// in that direction. Traffic is recorded when it is offered, so the reading
/// is what the router tried to carry, not only what the cap let through.
final class I2PBandwidthGovernor: @unchecked Sendable {
    struct Reading {
        let inboundBytesPerSecond: Double
        let outboundBytesPerSecond: Double
        let inboundCapped: Bool
        let outboundCapped: Bool
    }

    static let shared = I2PBandwidthGovernor()

    /// Measured rates cover the last 60 seconds (the "1-minute average").
    static let sampleWindow: TimeInterval = 60

    private static let burstSeconds: Double = 2
    /// Smaller buckets than a frame could never admit one; keep at least a
    /// full 65 KiB transport frame worth of tokens.
    private static let minimumBucket: Double = 65_536

    private let lock = NSLock()
    /// Bytes per second; 0 = uncapped.
    private var inboundCap = 0
    private var outboundCap = 0
    private var inboundTokens: Double = 0
    private var outboundTokens: Double = 0
    private var lastRefill = Date()
    private var inboundSamples: [(date: Date, bytes: Int)] = []
    private var outboundSamples: [(date: Date, bytes: Int)] = []

    /// Applies the caps to the running router. Takes effect immediately.
    func configure(inboundBytesPerSecond: Int, outboundBytesPerSecond: Int) {
        lock.lock()
        inboundCap = max(0, inboundBytesPerSecond)
        outboundCap = max(0, outboundBytesPerSecond)
        inboundTokens = bucketCapacity(for: inboundCap)
        outboundTokens = bucketCapacity(for: outboundCap)
        lastRefill = Date()
        lock.unlock()
    }

    var currentCaps: (inbound: Int, outbound: Int) {
        lock.lock()
        defer { lock.unlock() }
        return (inboundCap, outboundCap)
    }

    /// Blocks until `bytes` may be admitted on the inbound path.
    func admitInbound(bytes: Int) async {
        await admit(bytes: max(1, bytes), inbound: true)
    }

    /// Blocks until `bytes` may be admitted on the outbound path.
    func admitOutbound(bytes: Int) async {
        await admit(bytes: max(1, bytes), inbound: false)
    }

    /// The measured rates over the last minute, per direction.
    func reading() -> Reading {
        lock.lock()
        defer { lock.unlock() }
        let now = Date()
        pruneLocked(now: now)
        let inboundBytes = inboundSamples.reduce(0) { $0 + $1.bytes }
        let outboundBytes = outboundSamples.reduce(0) { $0 + $1.bytes }
        let window = Self.sampleWindow
        return Reading(
            inboundBytesPerSecond: Double(inboundBytes) / window,
            outboundBytesPerSecond: Double(outboundBytes) / window,
            inboundCapped: inboundCap > 0,
            outboundCapped: outboundCap > 0
        )
    }

    // MARK: Internals

    private func admit(bytes: Int, inbound: Bool) async {
        record(bytes: bytes, inbound: inbound)
        while !Task.isCancelled {
            lock.lock()
            refillLocked()
            let cap = inbound ? inboundCap : outboundCap
            guard cap > 0 else {
                lock.unlock()
                return // uncapped
            }
            var tokens = inbound ? inboundTokens : outboundTokens
            if tokens >= Double(bytes) {
                tokens -= Double(bytes)
                if inbound { inboundTokens = tokens } else { outboundTokens = tokens }
                lock.unlock()
                return
            }
            // Wait out the shortfall, bounded so a lowered cap or a cancelled
            // caller re-evaluates promptly instead of sleeping the full time.
            let wait = (Double(bytes) - tokens) / Double(cap)
            lock.unlock()
            try? await Task.sleep(for: .seconds(min(max(wait, 0.02), 0.5)))
        }
    }

    private func bucketCapacity(for cap: Int) -> Double {
        guard cap > 0 else { return 0 }
        return max(Double(cap) * Self.burstSeconds, Self.minimumBucket)
    }

    private func refillLocked() {
        let now = Date()
        let elapsed = now.timeIntervalSince(lastRefill)
        guard elapsed > 0 else { return }
        lastRefill = now
        if inboundCap > 0 {
            inboundTokens = min(bucketCapacity(for: inboundCap),
                                inboundTokens + Double(inboundCap) * elapsed)
        } else {
            inboundTokens = 0
        }
        if outboundCap > 0 {
            outboundTokens = min(bucketCapacity(for: outboundCap),
                                 outboundTokens + Double(outboundCap) * elapsed)
        } else {
            outboundTokens = 0
        }
    }

    private func record(bytes: Int, inbound: Bool) {
        let now = Date()
        lock.lock()
        if inbound {
            inboundSamples.append((now, bytes))
        } else {
            outboundSamples.append((now, bytes))
        }
        pruneLocked(now: now)
        lock.unlock()
    }

    private func pruneLocked(now: Date) {
        let cutoff = now.addingTimeInterval(-Self.sampleWindow)
        inboundSamples.removeAll { $0.date < cutoff }
        outboundSamples.removeAll { $0.date < cutoff }
    }
}

// MARK: - Persisted settings

/// The router's participation controls, persisted across launches in
/// user defaults and applied to the running router whenever they change.
final class I2PParticipationSettings: @unchecked Sendable {
    static let shared = I2PParticipationSettings()

    /// Bandwidth cap slider bounds, in KB/s.
    static let minCapKBps = 16
    static let maxCapKBps = 1024
    static let capStepKBps = 16
    static let defaultCapKBps = 256
    static let defaultTunnelSharePercent = 50

    private enum Keys {
        static let inboundCap = "i2p.participation.inboundCapKBps"
        static let outboundCap = "i2p.participation.outboundCapKBps"
        static let tunnelShare = "i2p.participation.tunnelSharePercent"
        static let floodfill = "i2p.participation.floodfillEnabled"
    }

    private let defaults: UserDefaults

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        defaults.register(defaults: [
            Keys.inboundCap: Self.defaultCapKBps,
            Keys.outboundCap: Self.defaultCapKBps,
            Keys.tunnelShare: Self.defaultTunnelSharePercent,
            Keys.floodfill: false
        ])
    }

    var inboundCapKBps: Int {
        get { Self.clampCap(defaults.integer(forKey: Keys.inboundCap)) }
        set { defaults.set(Self.clampCap(newValue), forKey: Keys.inboundCap) }
    }

    var outboundCapKBps: Int {
        get { Self.clampCap(defaults.integer(forKey: Keys.outboundCap)) }
        set { defaults.set(Self.clampCap(newValue), forKey: Keys.outboundCap) }
    }

    /// The participating-tunnel share ratio, 0...100 percent.
    var tunnelSharePercent: Int {
        get { min(100, max(0, defaults.integer(forKey: Keys.tunnelShare))) }
        set { defaults.set(min(100, max(0, newValue)), forKey: Keys.tunnelShare) }
    }

    var floodfillEnabled: Bool {
        get { defaults.bool(forKey: Keys.floodfill) }
        set { defaults.set(newValue, forKey: Keys.floodfill) }
    }

    /// Pushes the persisted bandwidth caps into the live governor.
    func applyBandwidthCaps(to governor: I2PBandwidthGovernor = .shared) {
        governor.configure(inboundBytesPerSecond: inboundCapKBps * 1024,
                           outboundBytesPerSecond: outboundCapKBps * 1024)
    }

    private static func clampCap(_ value: Int) -> Int {
        guard value > 0 else { return defaultCapKBps }
        let clamped = min(max(value, minCapKBps), maxCapKBps)
        // Snap to the slider's step so a persisted value always maps back.
        return max(minCapKBps, (clamped / capStepKBps) * capStepKBps)
    }
}
