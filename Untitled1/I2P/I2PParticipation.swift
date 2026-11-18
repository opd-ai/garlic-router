//
//  I2PParticipation.swift
//  Network-participation controls: the router's bandwidth governor (token
//  buckets per direction with measured 1-minute rates), the persisted
//  participation settings (caps, tunnel-share ratio, floodfill role) and the
//  tunnel budget the share ratio derives.
//

import Foundation

// MARK: - Bandwidth governor

/// One completed minute of measured traffic, in bytes per second per direction.
/// The governor keeps the latest 60 of these for the participation screen's
/// history chart; they live in memory only, so a relaunch starts a fresh window.
struct BandwidthMinuteSample: Identifiable {
    let id: Int
    /// Start of the minute this sample covers.
    let minute: Date
    let inboundBytesPerSecond: Double
    let outboundBytesPerSecond: Double
}

/// One completed minute of a single SAM session's measured send rate, in bytes
/// per second. Like the router-wide history these live in memory only, so a
/// relaunch starts a fresh window.
struct SessionRateMinuteSample: Identifiable {
    let id: Int
    /// Start of the minute this sample covers.
    let minute: Date
    let bytesPerSecond: Double
}

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
    /// The history keeps one sample per minute for the last hour.
    static let historyMinutes = 60
    /// Each session's sparkline on the SAM screen covers the last 15 minutes.
    static let sessionHistoryMinutes = 15
    private static let minuteLength: TimeInterval = 60

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

    /// The minute currently being accumulated and the completed minutes before
    /// it, oldest first (the history chart's 60 one-minute averages).
    private var minuteStart = Date()
    private var minuteInboundBytes = 0
    private var minuteOutboundBytes = 0
    private var minuteHistorySamples: [BandwidthMinuteSample] = []

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
        rollMinuteLocked(now: now)
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

    /// One sample per minute for the last `minutes` minutes, oldest first, in
    /// bytes per second per direction. The newest entry is the minute in
    /// progress, so the chart's right edge is live; it is scaled by the part of
    /// the minute that has actually elapsed.
    func minuteHistory(minutes: Int = I2PBandwidthGovernor.historyMinutes) -> [BandwidthMinuteSample] {
        lock.lock()
        defer { lock.unlock() }
        let now = Date()
        rollMinuteLocked(now: now)
        var samples = minuteHistorySamples
        let elapsed = max(now.timeIntervalSince(minuteStart), 1)
        samples.append(BandwidthMinuteSample(
            id: 0,
            minute: minuteStart,
            inboundBytesPerSecond: Double(minuteInboundBytes) / elapsed,
            outboundBytesPerSecond: Double(minuteOutboundBytes) / elapsed))
        if samples.count > minutes {
            samples.removeFirst(samples.count - minutes)
        }
        // Renumber so the identifiers stay stable and unique for the view.
        return samples.enumerated().map { index, sample in
            BandwidthMinuteSample(id: index,
                                  minute: sample.minute,
                                  inboundBytesPerSecond: sample.inboundBytesPerSecond,
                                  outboundBytesPerSecond: sample.outboundBytesPerSecond)
        }
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
        rollMinuteLocked(now: now)
        if inbound {
            inboundSamples.append((now, bytes))
            minuteInboundBytes += bytes
        } else {
            outboundSamples.append((now, bytes))
            minuteOutboundBytes += bytes
        }
        pruneLocked(now: now)
        lock.unlock()
    }

    /// Closes every minute that has fully elapsed since `minuteStart`, folding
    /// its accumulated traffic into the history. Idle minutes become zero
    /// samples rather than gaps, so the chart's timeline stays proportional.
    private func rollMinuteLocked(now: Date) {
        while now.timeIntervalSince(minuteStart) >= Self.minuteLength {
            minuteHistorySamples.append(BandwidthMinuteSample(
                id: 0,
                minute: minuteStart,
                inboundBytesPerSecond: Double(minuteInboundBytes) / Self.minuteLength,
                outboundBytesPerSecond: Double(minuteOutboundBytes) / Self.minuteLength))
            if minuteHistorySamples.count > Self.historyMinutes {
                minuteHistorySamples.removeFirst(minuteHistorySamples.count - Self.historyMinutes)
            }
            minuteStart = minuteStart.addingTimeInterval(Self.minuteLength)
            minuteInboundBytes = 0
            minuteOutboundBytes = 0
        }
    }

    private func pruneLocked(now: Date) {
        let cutoff = now.addingTimeInterval(-Self.sampleWindow)
        inboundSamples.removeAll { $0.date < cutoff }
        outboundSamples.removeAll { $0.date < cutoff }
    }

    // MARK: Per-session buckets (SAM sessions)

    /// What a SAM session's row shows: the rate its sends measured over the
    /// last minute and the ceiling it is held to.
    struct SessionReading {
        let bytesPerSecond: Double
        let capBytesPerSecond: Int
    }

    /// One session's own token bucket. A cap of zero leaves the session
    /// uncapped; its traffic is still measured so the list has a rate to show.
    private final class SessionBucket {
        var cap: Int
        var tokens: Double
        var lastRefill: Date
        /// Bytes offered over the last `sampleWindow` seconds.
        var samples: [(date: Date, bytes: Int)] = []
        /// The minute currently being accumulated for the session's sparkline
        /// and the completed minutes before it, oldest first.
        var minuteStart: Date
        var minuteBytes = 0
        var minuteHistory: [SessionRateMinuteSample] = []

        init(cap: Int, tokens: Double, lastRefill: Date, minuteStart: Date) {
            self.cap = cap
            self.tokens = tokens
            self.lastRefill = lastRefill
            self.minuteStart = minuteStart
        }
    }

    /// A session bucket smaller than a couple of SAM frames could never admit
    /// a whole chunk, so it always keeps at least that many tokens.
    private static let minimumSessionBucket = Double(I2PSAMChunker.maxFrameBytes * 2)

    private var sessionBuckets: [String: SessionBucket] = [:]

    /// Sets one session's ceiling in bytes per second (0 = uncapped) and
    /// applies it to the running session at once: the bucket is re-armed at
    /// the new rate, so a lowered cap bites on the very next send.
    func configureSession(_ key: String, bytesPerSecond: Int) {
        guard !key.isEmpty else { return }
        let cap = max(0, bytesPerSecond)
        let now = Date()
        lock.lock()
        let bucket = sessionBucketLocked(key, now: now)
        bucket.cap = cap
        bucket.tokens = sessionBucketCapacity(for: cap)
        bucket.lastRefill = now
        lock.unlock()
    }

    /// The ceiling a session is held to, in bytes per second.
    func sessionCap(_ key: String) -> Int {
        lock.lock()
        defer { lock.unlock() }
        return sessionBuckets[key]?.cap ?? 0
    }

    /// Blocks until `bytes` of a session's stream or datagram send may leave
    /// under its own ceiling. Like the router-wide directions, traffic is
    /// recorded when it is offered, so the reading is what the session tried
    /// to send rather than only what its cap let through.
    func admitSessionSend(_ key: String, bytes: Int) async {
        guard !key.isEmpty else { return }
        let size = max(1, bytes)
        recordSession(bytes: size, key: key)
        while !Task.isCancelled {
            let now = Date()
            lock.lock()
            let bucket = sessionBucketLocked(key, now: now)
            refillSessionLocked(bucket, now: now)
            let cap = bucket.cap
            guard cap > 0 else {
                lock.unlock()
                return // uncapped session
            }
            if bucket.tokens >= Double(size) {
                bucket.tokens -= Double(size)
                lock.unlock()
                return
            }
            let wait = (Double(size) - bucket.tokens) / Double(cap)
            lock.unlock()
            try? await Task.sleep(for: .seconds(min(max(wait, 0.02), 0.5)))
        }
    }

    /// A session's measured send rate over the last minute and its ceiling.
    func sessionReading(_ key: String) -> SessionReading {
        lock.lock()
        defer { lock.unlock() }
        let now = Date()
        guard let bucket = sessionBuckets[key] else {
            return SessionReading(bytesPerSecond: 0, capBytesPerSecond: 0)
        }
        rollSessionMinuteLocked(bucket, now: now)
        let cutoff = now.addingTimeInterval(-Self.sampleWindow)
        bucket.samples.removeAll { $0.date < cutoff }
        let bytes = bucket.samples.reduce(0) { $0 + $1.bytes }
        return SessionReading(bytesPerSecond: Double(bytes) / Self.sampleWindow,
                              capBytesPerSecond: bucket.cap)
    }

    /// One sample per minute for a session's send rate, oldest first, in bytes
    /// per second — the sparkline under its row on the SAM screen. The window is
    /// always `minutes` long: minutes before the session had any traffic are
    /// zero samples rather than a gap, so an idle session draws a flat line.
    /// The newest entry is the minute in progress, scaled by the part of it that
    /// has actually elapsed. Memory only, like the router-wide history.
    func sessionMinuteHistory(_ key: String,
                              minutes: Int = I2PBandwidthGovernor.sessionHistoryMinutes)
        -> [SessionRateMinuteSample] {
        let span = max(1, minutes)
        lock.lock()
        defer { lock.unlock() }
        let now = Date()
        guard let bucket = sessionBuckets[key] else {
            return (0..<span).map { index in
                SessionRateMinuteSample(
                    id: index,
                    minute: now.addingTimeInterval(Double(index - span + 1) * Self.minuteLength),
                    bytesPerSecond: 0)
            }
        }
        rollSessionMinuteLocked(bucket, now: now)
        var samples = bucket.minuteHistory
        let elapsed = max(now.timeIntervalSince(bucket.minuteStart), 1)
        samples.append(SessionRateMinuteSample(
            id: 0,
            minute: bucket.minuteStart,
            bytesPerSecond: Double(bucket.minuteBytes) / elapsed))
        if samples.count > span {
            samples.removeFirst(samples.count - span)
        }
        // Pad the front of the window with idle minutes so the line always
        // spans the whole range instead of starting part-way in.
        while samples.count < span {
            let firstMinute = samples.first?.minute ?? now
            samples.insert(SessionRateMinuteSample(
                id: 0,
                minute: firstMinute.addingTimeInterval(-Self.minuteLength),
                bytesPerSecond: 0), at: 0)
        }
        return samples.enumerated().map { index, sample in
            SessionRateMinuteSample(id: index,
                                    minute: sample.minute,
                                    bytesPerSecond: sample.bytesPerSecond)
        }
    }

    /// Drops a closed session's bucket; the saved ceiling stays saved.
    func forgetSession(_ key: String) {
        lock.lock()
        sessionBuckets[key] = nil
        lock.unlock()
    }

    private func sessionBucketLocked(_ key: String, now: Date) -> SessionBucket {
        if let bucket = sessionBuckets[key] { return bucket }
        let bucket = SessionBucket(cap: 0, tokens: 0, lastRefill: now, minuteStart: now)
        sessionBuckets[key] = bucket
        return bucket
    }

    private func sessionBucketCapacity(for cap: Int) -> Double {
        guard cap > 0 else { return 0 }
        return max(Double(cap) * Self.burstSeconds, Self.minimumSessionBucket)
    }

    private func refillSessionLocked(_ bucket: SessionBucket, now: Date) {
        let elapsed = now.timeIntervalSince(bucket.lastRefill)
        guard elapsed > 0 else { return }
        bucket.lastRefill = now
        guard bucket.cap > 0 else {
            bucket.tokens = 0
            return
        }
        bucket.tokens = min(sessionBucketCapacity(for: bucket.cap),
                            bucket.tokens + Double(bucket.cap) * elapsed)
    }

    private func recordSession(bytes: Int, key: String) {
        let now = Date()
        lock.lock()
        let bucket = sessionBucketLocked(key, now: now)
        rollSessionMinuteLocked(bucket, now: now)
        bucket.samples.append((now, bytes))
        bucket.minuteBytes += bytes
        let cutoff = now.addingTimeInterval(-Self.sampleWindow)
        bucket.samples.removeAll { $0.date < cutoff }
        lock.unlock()
    }

    /// Closes every minute that has fully elapsed for a session since its
    /// `minuteStart`, folding the traffic into its sparkline history. Idle
    /// minutes become zero samples, so the line never breaks.
    private func rollSessionMinuteLocked(_ bucket: SessionBucket, now: Date) {
        while now.timeIntervalSince(bucket.minuteStart) >= Self.minuteLength {
            bucket.minuteHistory.append(SessionRateMinuteSample(
                id: 0,
                minute: bucket.minuteStart,
                bytesPerSecond: Double(bucket.minuteBytes) / Self.minuteLength))
            if bucket.minuteHistory.count > Self.sessionHistoryMinutes {
                bucket.minuteHistory.removeFirst(
                    bucket.minuteHistory.count - Self.sessionHistoryMinutes)
            }
            bucket.minuteStart = bucket.minuteStart.addingTimeInterval(Self.minuteLength)
            bucket.minuteBytes = 0
        }
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
    /// Quiet hours default to a night window; the share ratio applies outside it.
    static let defaultQuietStartMinutes = 22 * 60
    static let defaultQuietEndMinutes = 7 * 60

    private enum Keys {
        static let inboundCap = "i2p.participation.inboundCapKBps"
        static let outboundCap = "i2p.participation.outboundCapKBps"
        static let tunnelShare = "i2p.participation.tunnelSharePercent"
        static let floodfill = "i2p.participation.floodfillEnabled"
        static let quietEnabled = "i2p.participation.quietHoursEnabled"
        static let quietStart = "i2p.participation.quietHoursStartMinutes"
        static let quietEnd = "i2p.participation.quietHoursEndMinutes"
    }

    private let defaults: UserDefaults

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        defaults.register(defaults: [
            Keys.inboundCap: Self.defaultCapKBps,
            Keys.outboundCap: Self.defaultCapKBps,
            Keys.tunnelShare: Self.defaultTunnelSharePercent,
            Keys.floodfill: false,
            Keys.quietEnabled: false,
            Keys.quietStart: Self.defaultQuietStartMinutes,
            Keys.quietEnd: Self.defaultQuietEndMinutes
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

    /// Whether the quiet-hours window is in effect.
    var quietHoursEnabled: Bool {
        get { defaults.bool(forKey: Keys.quietEnabled) }
        set { defaults.set(newValue, forKey: Keys.quietEnabled) }
    }

    /// Start of the quiet window, in minutes after midnight.
    var quietHoursStartMinutes: Int {
        get { Self.clampMinutes(defaults.integer(forKey: Keys.quietStart)) }
        set { defaults.set(Self.clampMinutes(newValue), forKey: Keys.quietStart) }
    }

    /// End of the quiet window, in minutes after midnight. A window whose start
    /// is after its end wraps midnight (22:00 to 07:00); equal times mean no
    /// quiet window at all.
    var quietHoursEndMinutes: Int {
        get { Self.clampMinutes(defaults.integer(forKey: Keys.quietEnd)) }
        set { defaults.set(Self.clampMinutes(newValue), forKey: Keys.quietEnd) }
    }

    /// The saved schedule as a "22:00–07:00" label.
    var quietHoursRangeLabel: String {
        "\(Self.timeLabel(minutes: quietHoursStartMinutes))–\(Self.timeLabel(minutes: quietHoursEndMinutes))"
    }

    /// Whether the saved schedule is active at `date`.
    func isQuietHours(at date: Date = Date(), calendar: Calendar = .current) -> Bool {
        Self.isQuietHours(enabled: quietHoursEnabled,
                          startMinutes: quietHoursStartMinutes,
                          endMinutes: quietHoursEndMinutes,
                          at: date,
                          calendar: calendar)
    }

    /// The moment the current quiet window closes; nil when it is not active.
    func quietHoursEndDate(after date: Date = Date(), calendar: Calendar = .current) -> Date? {
        Self.quietHoursEndDate(startMinutes: quietHoursStartMinutes,
                               endMinutes: quietHoursEndMinutes,
                               after: date,
                               calendar: calendar)
    }

    /// The share ratio the router actually applies right now: zero inside the
    /// quiet window (so new transit builds are refused), the saved ratio outside.
    func effectiveTunnelSharePercent(at date: Date = Date()) -> Int {
        isQuietHours(at: date) ? 0 : tunnelSharePercent
    }

    /// Whether a quiet window covers `date`. A start after the end wraps
    /// midnight; equal times are an empty window.
    static func isQuietHours(enabled: Bool,
                             startMinutes: Int,
                             endMinutes: Int,
                             at date: Date = Date(),
                             calendar: Calendar = .current) -> Bool {
        guard enabled else { return false }
        let start = clampMinutes(startMinutes)
        let end = clampMinutes(endMinutes)
        guard start != end else { return false }
        let components = calendar.dateComponents([.hour, .minute], from: date)
        let minutes = (components.hour ?? 0) * 60 + (components.minute ?? 0)
        if start < end {
            return minutes >= start && minutes < end
        }
        return minutes >= start || minutes < end
    }

    /// When a quiet window that is active at `date` lets go. Nil when the window
    /// is not active (or the schedule is empty).
    static func quietHoursEndDate(startMinutes: Int,
                                  endMinutes: Int,
                                  after date: Date = Date(),
                                  calendar: Calendar = .current) -> Date? {
        guard isQuietHours(enabled: true,
                           startMinutes: startMinutes,
                           endMinutes: endMinutes,
                           at: date,
                           calendar: calendar) else {
            return nil
        }
        let end = clampMinutes(endMinutes)
        let components = calendar.dateComponents([.hour, .minute], from: date)
        let minutes = (components.hour ?? 0) * 60 + (components.minute ?? 0)
        // A window that wraps midnight closes tomorrow, one that does not closes later today.
        let dayOffset = end <= minutes ? 1 : 0
        let startOfDay = calendar.startOfDay(for: date)
        let day = calendar.date(byAdding: .day, value: dayOffset, to: startOfDay) ?? startOfDay
        return calendar.date(bySettingHour: end / 60, minute: end % 60, second: 0, of: day)
    }

    /// "22:00" from 1320 minutes after midnight.
    static func timeLabel(minutes: Int) -> String {
        let clamped = clampMinutes(minutes)
        return String(format: "%02d:%02d", clamped / 60, clamped % 60)
    }

    private static func clampMinutes(_ value: Int) -> Int {
        min(max(value, 0), 24 * 60 - 1)
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

// MARK: - Self-test

enum I2PParticipationSelfTest {
    static func runAll() -> [I2PSelfTestResult] {
        var results: [I2PSelfTestResult] = []
        func run(_ name: String, _ body: () throws -> String) {
            do {
                results.append(I2PSelfTestResult(name: name, passed: true, detail: try body()))
            } catch {
                results.append(I2PSelfTestResult(name: name, passed: false, detail: "\(error)"))
            }
        }

        run("Quiet hours · window that wraps midnight") {
            // 22:00 to 07:00 covers the evening and the small hours.
            let active = { (hour: Int) in
                I2PParticipationSettings.isQuietHours(enabled: true,
                                                      startMinutes: 22 * 60,
                                                      endMinutes: 7 * 60,
                                                      at: date(hour: hour))
            }
            guard active(23), active(3), active(0), active(6) else { throw I2PWireError.invalidFormat }
            guard !active(12), !active(7), !active(8) else { throw I2PWireError.invalidFormat }
            return "22:00–07:00 covers 23:00, 00:00, 03:00 and 06:00 but not 07:00, 08:00 or 12:00"
        }

        run("Quiet hours · window inside one day") {
            let active = { (hour: Int, minute: Int) in
                I2PParticipationSettings.isQuietHours(enabled: true,
                                                      startMinutes: 13 * 60,
                                                      endMinutes: 14 * 60,
                                                      at: date(hour: hour, minute: minute))
            }
            guard active(13, 0), active(13, 59) else { throw I2PWireError.invalidFormat }
            guard !active(14, 0), !active(12, 59) else { throw I2PWireError.invalidFormat }
            return "13:00–14:00 covers 13:00 and 13:59 but not 14:00 or 12:59"
        }

        run("Quiet hours · off and empty windows never pause") {
            guard !I2PParticipationSettings.isQuietHours(enabled: false,
                                                          startMinutes: 22 * 60,
                                                          endMinutes: 7 * 60,
                                                          at: date(hour: 23)) else {
                throw I2PWireError.invalidFormat
            }
            guard !I2PParticipationSettings.isQuietHours(enabled: true,
                                                          startMinutes: 600,
                                                          endMinutes: 600,
                                                          at: date(hour: 10)) else {
                throw I2PWireError.invalidFormat
            }
            return "a disabled schedule and an empty one both leave the share ratio in force"
        }

        run("Quiet hours · closes at the scheduled end") {
            let wrapping = I2PParticipationSettings.quietHoursEndDate(startMinutes: 22 * 60,
                                                                      endMinutes: 7 * 60,
                                                                      after: date(hour: 23))
            let overnight = I2PParticipationSettings.quietHoursEndDate(startMinutes: 22 * 60,
                                                                       endMinutes: 7 * 60,
                                                                       after: date(hour: 3))
            let daytime = I2PParticipationSettings.quietHoursEndDate(startMinutes: 22 * 60,
                                                                     endMinutes: 7 * 60,
                                                                     after: date(hour: 12))
            let calendar = Calendar.current
            guard let wrapping, let overnight, daytime == nil else { throw I2PWireError.invalidFormat }
            let wrappingHour = calendar.component(.hour, from: wrapping)
            let overnightHour = calendar.component(.hour, from: overnight)
            guard wrappingHour == 7, overnightHour == 7 else { throw I2PWireError.invalidFormat }
            guard calendar.startOfDay(for: wrapping) > calendar.startOfDay(for: date(hour: 23)) else {
                throw I2PWireError.invalidFormat
            }
            return "an evening window closes at 07:00 the next morning and a small-hours one at 07:00 same day; outside it there is no end date"
        }

        run("Quiet hours · force the transit budget to zero") {
            let defaults = UserDefaults(suiteName: "i2p.participation.selftest.\(UUID().uuidString)")
            guard let defaults else { throw I2PWireError.invalidFormat }
            let settings = I2PParticipationSettings(defaults: defaults)
            settings.tunnelSharePercent = 60
            settings.quietHoursEnabled = true
            settings.quietHoursStartMinutes = 22 * 60
            settings.quietHoursEndMinutes = 7 * 60

            let paused = settings.effectiveTunnelSharePercent(at: date(hour: 23))
            let running = settings.effectiveTunnelSharePercent(at: date(hour: 12))
            guard paused == 0, running == 60 else { throw I2PWireError.invalidFormat }
            guard I2PTunnelParticipant.transitTunnelBudget(forSharePercent: paused) == 0 else {
                throw I2PWireError.invalidFormat
            }
            // The saved ratio applies again once quiet hours are off.
            settings.quietHoursEnabled = false
            guard settings.effectiveTunnelSharePercent(at: date(hour: 23)) == 60 else {
                throw I2PWireError.invalidFormat
            }
            return "effective share 60% → 0% inside 22:00–07:00 and back to 60% outside it; a zero share maps to a zero tunnel budget"
        }

        return results
    }

    private static func date(hour: Int, minute: Int = 0) -> Date {
        var components = DateComponents()
        components.year = 2026
        components.month = 1
        components.day = 15
        components.hour = hour
        components.minute = minute
        return Calendar.current.date(from: components) ?? Date()
    }
}
