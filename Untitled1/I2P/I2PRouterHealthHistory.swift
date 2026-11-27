//
//  I2PRouterHealthHistory.swift
//  One-minute local router-health samples. History is stored only in this
//  installation, trimmed to seven days, and interrupted sampling is kept as an
//  explicit gap rather than being drawn as continuous availability.
//

import Foundation

// MARK: - Samples

enum I2PRouterHealthWindow: CaseIterable, Identifiable {
    case sixHours
    case twentyFourHours
    case sevenDays

    var id: Int {
        switch self {
        case .sixHours: return 6
        case .twentyFourHours: return 24
        case .sevenDays: return 168
        }
    }

    var duration: TimeInterval { TimeInterval(id * 60 * 60) }

    var title: String {
        switch self {
        case .sixHours: return "6 hours"
        case .twentyFourHours: return "24 hours"
        case .sevenDays: return "7 days"
        }
    }
}

struct I2PRouterHealthInterruption: Codable, Equatable, Identifiable {
    enum Cause: String, Codable {
        case appSuspended
        case samplingPaused
        case routerStopped

        var title: String {
            switch self {
            case .appSuspended: return "App suspended"
            case .samplingPaused: return "Sampling paused"
            case .routerStopped: return "Router stopped"
            }
        }
    }

    let startedAt: Date
    let duration: TimeInterval
    let cause: Cause

    var id: Int64 { Int64(startedAt.timeIntervalSince1970) }
    var midpoint: Date { startedAt.addingTimeInterval(duration / 2) }
}

enum I2PRouterHealthEventKind: String, Codable, Equatable {
    case started
    case cleanStop

    var title: String {
        switch self {
        case .started: return "Router started"
        case .cleanStop: return "Router cleanly stopped"
        }
    }
}

struct I2PRouterHealthEvent: Codable, Equatable, Identifiable {
    let id: UUID
    let kind: I2PRouterHealthEventKind
    let occurredAt: Date

    init(kind: I2PRouterHealthEventKind, at date: Date) {
        id = UUID()
        self.kind = kind
        occurredAt = date
    }
}

struct I2PRouterHealthSample: Codable, Equatable, Identifiable {
    let sampledAt: Date
    let available: Bool
    let activePeers: Int
    let readyTunnels: Int
    let receivedBytes: Int
    let sentBytes: Int
    /// The part of the minute before this reading for which availability was
    /// observed. A suspension gap contributes no online time.
    let availableSeconds: TimeInterval
    let interruptionBefore: I2PRouterHealthInterruption?

    var id: Int64 { Int64(sampledAt.timeIntervalSince1970) }
}

struct I2PRouterHealthChartPoint: Identifiable {
    let sample: I2PRouterHealthSample
    let segment: Int

    var id: Int64 { sample.id }
    var value: Double { sample.available ? 100 : 0 }
}

/// How much of the window each cause accounts for, after overlapping time is
/// attributed once. A cause whose gap has not closed yet reports no duration:
/// an unfinished gap has no measurable total, and reporting the time so far
/// would read as a completed outage.
struct I2PRouterHealthDowntime: Identifiable, Equatable {
    let cause: I2PRouterHealthInterruption.Cause
    let count: Int
    /// Seconds attributed to this cause, or nil when a gap of it is still open.
    let seconds: TimeInterval?

    var id: String { cause.rawValue }
    var isMeasurable: Bool { seconds != nil }
}

struct I2PRouterHealthReading {
    let samples: [I2PRouterHealthSample]
    let chartPoints: [I2PRouterHealthChartPoint]
    let events: [I2PRouterHealthEvent]
    let uptimePercent: Double?
    let onlineSeconds: TimeInterval
    let receivedBytes: Int
    let sentBytes: Int
    let lastInterruption: I2PRouterHealthInterruption?
    /// The window's interruptions attributed to one cause each, in the order
    /// the screen lists them. Empty when the window holds no interruption.
    let downtime: [I2PRouterHealthDowntime]

    var hasSamples: Bool { !samples.isEmpty }
    var hasDowntime: Bool { !downtime.isEmpty }
}

/// One row of the lifecycle timeline: a router start or clean stop, or one of
/// the three interruption causes. Both kinds share the screen, because a reader
/// asking "what happened at 14:20" wants one list, not two.
struct I2PRouterTimelineEntry: Identifiable, Equatable {
    let id: String
    let kind: I2PRouterHealthEventKind?
    let cause: I2PRouterHealthInterruption.Cause?
    let startedAt: Date
    /// Nil for a start/stop event and for a gap that has not closed yet.
    let duration: TimeInterval?

    var title: String {
        kind?.title ?? cause?.title ?? "Unknown"
    }

    var isEvent: Bool { kind != nil }
}

// MARK: - Local recorder

final class I2PRouterHealthHistory: @unchecked Sendable {
    static let shared = I2PRouterHealthHistory()
    static let sampleInterval: TimeInterval = 60
    static let retention: TimeInterval = 7 * 24 * 60 * 60
    static let maximumSamples = 7 * 24 * 60

    private struct StoredState: Codable {
        var samples: [I2PRouterHealthSample]
        var isSuspended: Bool
        var suspensionStartedAt: Date?
        var resumedAt: Date?
        var lastCumulativeReceivedBytes: Int?
        var lastCumulativeSentBytes: Int?
        // Optional for decoding history written before lifecycle events existed.
        var events: [I2PRouterHealthEvent]?
    }

    private static let storageKey = "i2p.router.health.history.v1"
    private let lock = NSLock()
    private let defaults: UserDefaults
    private var samples: [I2PRouterHealthSample]
    private var events: [I2PRouterHealthEvent]
    private var routerIsRunning = false
    private var isSuspended: Bool
    private var suspensionStartedAt: Date?
    private var resumedAt: Date?
    private var lastCumulativeReceivedBytes: Int?
    private var lastCumulativeSentBytes: Int?
    private var forceNextSample = false

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        if let data = defaults.data(forKey: Self.storageKey),
           let state = try? JSONDecoder().decode(StoredState.self, from: data) {
            samples = state.samples
            events = state.events ?? []
            isSuspended = state.isSuspended
            suspensionStartedAt = state.suspensionStartedAt
            resumedAt = state.resumedAt
            lastCumulativeReceivedBytes = state.lastCumulativeReceivedBytes
            lastCumulativeSentBytes = state.lastCumulativeSentBytes
            forceNextSample = state.resumedAt != nil && !state.isSuspended
        } else {
            samples = []
            events = []
            isSuspended = false
            suspensionStartedAt = nil
            resumedAt = nil
            lastCumulativeReceivedBytes = nil
            lastCumulativeSentBytes = nil
        }
        pruneLocked(at: Date())
    }

    /// Records the metrics in a live router snapshot at most once per minute.
    /// The status engine calls this only while its running sample loop is active.
    func record(snapshot: I2PRouterStatusSnapshot) {
        record(available: true,
               activePeers: snapshot.peers.count,
               readyTunnels: snapshot.pools.reduce(0) { $0 + $1.tunnels.count },
               cumulativeReceivedBytes: snapshot.lifetime.bytesIn,
               cumulativeSentBytes: snapshot.lifetime.bytesOut,
               at: snapshot.capturedAt)
    }

    /// Kept internal so the sampling and retention rules can be exercised with
    /// deterministic timestamps without starting network transports.
    func record(available: Bool,
                activePeers: Int,
                readyTunnels: Int,
                cumulativeReceivedBytes: Int,
                cumulativeSentBytes: Int,
                at now: Date = Date()) {
        lock.lock()
        defer { lock.unlock() }
        guard !isSuspended else { return }

        let previous = samples.last
        if !forceNextSample,
           let previous,
           now.timeIntervalSince(previous.sampledAt) < Self.sampleInterval {
            return
        }
        guard previous.map({ now > $0.sampledAt }) ?? true else { return }

        var interruption: I2PRouterHealthInterruption?
        var availableSeconds: TimeInterval = 0
        if let previous {
            let elapsed = now.timeIntervalSince(previous.sampledAt)
            if let suspensionStartedAt, let resumedAt {
                let duration = max(0, resumedAt.timeIntervalSince(suspensionStartedAt))
                if duration > 0 {
                    interruption = I2PRouterHealthInterruption(
                        startedAt: suspensionStartedAt,
                        duration: duration,
                        cause: .appSuspended)
                }
            } else if let shutdown = completedShutdown(after: previous.sampledAt, through: now) {
                interruption = I2PRouterHealthInterruption(
                    startedAt: shutdown.stoppedAt,
                    duration: max(0, shutdown.startedAt.timeIntervalSince(shutdown.stoppedAt)),
                    cause: .routerStopped)
            } else if elapsed > Self.sampleInterval * 1.5 {
                let gapStart = previous.sampledAt.addingTimeInterval(Self.sampleInterval)
                interruption = I2PRouterHealthInterruption(
                    startedAt: gapStart,
                    duration: max(0, now.timeIntervalSince(gapStart)),
                    cause: .samplingPaused)
            } else {
                availableSeconds = min(Self.sampleInterval, max(0, elapsed))
            }
        }

        let receivedDelta = lastCumulativeReceivedBytes.map {
            max(0, cumulativeReceivedBytes - $0)
        } ?? 0
        let sentDelta = lastCumulativeSentBytes.map {
            max(0, cumulativeSentBytes - $0)
        } ?? 0
        samples.append(I2PRouterHealthSample(
            sampledAt: now,
            available: available,
            activePeers: max(0, activePeers),
            readyTunnels: max(0, readyTunnels),
            receivedBytes: receivedDelta,
            sentBytes: sentDelta,
            availableSeconds: available ? availableSeconds : 0,
            interruptionBefore: interruption
        ))
        lastCumulativeReceivedBytes = max(0, cumulativeReceivedBytes)
        lastCumulativeSentBytes = max(0, cumulativeSentBytes)
        suspensionStartedAt = nil
        resumedAt = nil
        forceNextSample = false
        pruneLocked(at: now)
        persistLocked()
    }

    /// Records an intentional router start independently of the minute samples.
    /// Duplicate lifecycle calls do not create duplicate markers.
    func recordRouterStart(at date: Date = Date()) {
        recordRouterLifecycleEvent(.started, at: date)
    }

    /// Records an intentional, clean router shutdown. App suspension uses the
    /// separate sampling-gap path and must never be reported as a clean stop.
    func recordRouterCleanStop(at date: Date = Date()) {
        recordRouterLifecycleEvent(.cleanStop, at: date)
    }

    private func recordRouterLifecycleEvent(_ kind: I2PRouterHealthEventKind, at date: Date) {
        lock.lock()
        defer { lock.unlock() }
        let shouldBeRunning = kind == .started
        guard routerIsRunning != shouldBeRunning else { return }
        routerIsRunning = shouldBeRunning
        events.append(I2PRouterHealthEvent(kind: kind, at: date))
        pruneLocked(at: date)
        persistLocked()
    }

    /// Finds a clean stop/start pair between two samples. The resulting gap is
    /// classified as intentional downtime, not as an app-suspension gap.
    private func completedShutdown(after date: Date, through end: Date) -> (stoppedAt: Date, startedAt: Date)? {
        var pendingStop: Date?
        var completed: (stoppedAt: Date, startedAt: Date)?
        for event in events where event.occurredAt > date && event.occurredAt <= end {
            switch event.kind {
            case .cleanStop:
                pendingStop = event.occurredAt
            case .started:
                if let stoppedAt = pendingStop {
                    completed = (stoppedAt, event.occurredAt)
                    pendingStop = nil
                }
            }
        }
        return completed
    }

    /// Called as the app enters the background. The recorder ignores any final
    /// status ticks after this point and saves the start of the sampling gap.
    func markAppSuspended(at date: Date = Date()) {
        lock.lock()
        defer { lock.unlock() }
        guard !isSuspended else { return }
        isSuspended = true
        suspensionStartedAt = date
        resumedAt = nil
        persistLocked()
    }

    /// Called when the app becomes active again. The next running-router sample
    /// is captured immediately and carries an explicit suspension marker.
    func resumeSampling(at date: Date = Date()) {
        lock.lock()
        defer { lock.unlock() }
        if isSuspended {
            isSuspended = false
            resumedAt = date
            forceNextSample = true
            persistLocked()
        }
    }

    func allSamples(at now: Date = Date()) -> [I2PRouterHealthSample] {
        lock.lock()
        defer { lock.unlock() }
        pruneLocked(at: now)
        return samples
    }

    func reading(window: I2PRouterHealthWindow, at now: Date = Date()) -> I2PRouterHealthReading {
        let cutoff = now.addingTimeInterval(-window.duration)
        let selected = allSamples(at: now).filter { $0.sampledAt >= cutoff }
        let selectedEvents = allEvents(at: now).filter { $0.occurredAt >= cutoff }
        let openSuspension = isSuspensionOpen(at: now)
        var segment = 0
        let points = selected.map { sample -> I2PRouterHealthChartPoint in
            if sample.interruptionBefore != nil { segment += 1 }
            return I2PRouterHealthChartPoint(sample: sample, segment: segment)
        }

        guard let first = selected.first, let last = selected.last else {
            return I2PRouterHealthReading(samples: [], chartPoints: [], events: selectedEvents,
                                          uptimePercent: nil, onlineSeconds: 0,
                                          receivedBytes: 0, sentBytes: 0, lastInterruption: nil,
                                          downtime: downtime(interruptions: [],
                                                             in: cutoff...now,
                                                             openSince: openSuspension))
        }

        let windowStart = max(cutoff, first.sampledAt.addingTimeInterval(-first.availableSeconds))
        let windowEnd = min(now, last.sampledAt)
        let span = max(0, windowEnd.timeIntervalSince(windowStart))
        var onlineSeconds: TimeInterval = 0
        for sample in selected where sample.available && sample.availableSeconds > 0 {
            let intervalStart = sample.sampledAt.addingTimeInterval(-sample.availableSeconds)
            let overlapStart = max(windowStart, intervalStart)
            let overlapEnd = min(windowEnd, sample.sampledAt)
            onlineSeconds += max(0, overlapEnd.timeIntervalSince(overlapStart))
        }

        return I2PRouterHealthReading(
            samples: selected,
            chartPoints: points,
            events: selectedEvents,
            uptimePercent: span > 0 ? min(100, onlineSeconds / span * 100) : nil,
            onlineSeconds: onlineSeconds,
            receivedBytes: selected.reduce(0) { $0 + $1.receivedBytes },
            sentBytes: selected.reduce(0) { $0 + $1.sentBytes },
            lastInterruption: selected.compactMap(\.interruptionBefore).last,
            downtime: downtime(interruptions: selected.compactMap(\.interruptionBefore),
                              in: cutoff...now,
                              openSince: openSuspension)
        )
    }

    private func isSuspensionOpen(at now: Date) -> Date? {
        lock.lock()
        defer { lock.unlock() }
        guard isSuspended, resumedAt == nil else { return nil }
        return suspensionStartedAt
    }

    /// The retained lifecycle events and interruptions as one list, newest
    /// first, for the timeline screen. A gap that is still open is listed with
    /// no duration, so it cannot read as an outage that has already ended.
    func timeline(at now: Date = Date()) -> [I2PRouterTimelineEntry] {
        let events = allEvents(at: now)
        let interruptions = allSamples(at: now).compactMap(\.interruptionBefore)
        var entries: [I2PRouterTimelineEntry] = events.map { event in
            I2PRouterTimelineEntry(id: event.id.uuidString,
                                    kind: event.kind,
                                    cause: nil,
                                    startedAt: event.occurredAt,
                                    duration: nil)
        }
        for interruption in interruptions {
            entries.append(I2PRouterTimelineEntry(
                id: "gap-\(interruption.cause.rawValue)-\(interruption.startedAt.timeIntervalSince1970)",
                kind: nil,
                cause: interruption.cause,
                startedAt: interruption.startedAt,
                duration: interruption.duration))
        }
        if let openSince = isSuspensionOpen(at: now) {
            entries.append(I2PRouterTimelineEntry(
                id: "gap-open-\(openSince.timeIntervalSince1970)",
                kind: nil,
                cause: .appSuspended,
                startedAt: openSince,
                duration: nil))
        }
        return entries.sorted { $0.startedAt > $1.startedAt }
    }

    /// Attributes each interruption to one cause, clipping to the window and
    /// subtracting time already attributed, so the totals never double-count an
    /// overlap. The order is the most specific cause first: an intentional
    /// shutdown outranks an app suspension, which outranks a fallback sampling
    /// gap. A cause whose gap is still open reports no duration.
    func downtime(interruptions: [I2PRouterHealthInterruption],
                  in range: ClosedRange<Date>,
                  openSince: Date? = nil) -> [I2PRouterHealthDowntime] {
        var claimed: [(start: Date, end: Date)] = []
        var breakdown: [I2PRouterHealthDowntime] = []

        for cause in [I2PRouterHealthInterruption.Cause.routerStopped, .appSuspended, .samplingPaused] {
            var count = 0
            var seconds: TimeInterval = 0

            for interruption in interruptions where interruption.cause == cause {
                let start = max(range.lowerBound, interruption.startedAt)
                let end = min(range.upperBound, interruption.startedAt.addingTimeInterval(interruption.duration))
                guard end > start else { continue }
                count += 1
                for slice in Self.unclaimed(from: start, to: end, claimed: claimed) {
                    seconds += slice.end.timeIntervalSince(slice.start)
                    claimed.append(slice)
                }
            }

            var open = false
            if cause == .appSuspended, let openSince, range.contains(openSince) {
                count += 1
                open = true
            }

            guard count > 0 else { continue }
            breakdown.append(I2PRouterHealthDowntime(cause: cause,
                                                    count: count,
                                                    seconds: open ? nil : seconds))
        }
        return breakdown
    }

    /// The parts of [start, end] that no claimed interval already covers.
    private static func unclaimed(from start: Date,
                                  to end: Date,
                                  claimed: [(start: Date, end: Date)]) -> [(start: Date, end: Date)] {
        var pieces = [(start: start, end: end)]
        for taken in claimed {
            pieces = pieces.flatMap { piece -> [(start: Date, end: Date)] in
                guard taken.start < piece.end, taken.end > piece.start else { return [piece] }
                var result: [(start: Date, end: Date)] = []
                if taken.start > piece.start {
                    result.append((piece.start, taken.start))
                }
                if taken.end < piece.end {
                    result.append((taken.end, piece.end))
                }
                return result
            }
        }
        return pieces
    }

    private func allEvents(at now: Date) -> [I2PRouterHealthEvent] {
        lock.lock()
        defer { lock.unlock() }
        pruneLocked(at: now)
        return events
    }

    private func pruneLocked(at now: Date) {
        let cutoff = now.addingTimeInterval(-Self.retention)
        samples.removeAll { $0.sampledAt < cutoff }
        events.removeAll { $0.occurredAt < cutoff }
        if samples.count > Self.maximumSamples {
            samples.removeFirst(samples.count - Self.maximumSamples)
        }
    }

    private func persistLocked() {
        let state = StoredState(samples: samples,
                                isSuspended: isSuspended,
                                suspensionStartedAt: suspensionStartedAt,
                                resumedAt: resumedAt,
                                lastCumulativeReceivedBytes: lastCumulativeReceivedBytes,
                                lastCumulativeSentBytes: lastCumulativeSentBytes,
                                events: events)
        guard let data = try? JSONEncoder().encode(state) else { return }
        defaults.set(data, forKey: Self.storageKey)
    }
}

// MARK: - Self-test

enum I2PRouterHealthHistorySelfTest {
    static func runAll() -> [I2PSelfTestResult] {
        var results: [I2PSelfTestResult] = []
        func check(_ name: String, _ body: () -> String?) {
            if let detail = body() {
                results.append(I2PSelfTestResult(name: name, passed: true, detail: detail))
            } else {
                results.append(I2PSelfTestResult(name: name, passed: false,
                                                 detail: "router health history did not match the expected reading"))
            }
        }

        check("Router health: one-minute samples summarize uptime and traffic") {
            let suite = "i2p.health.test.\(UUID().uuidString)"
            let defaults = UserDefaults(suiteName: suite)!
            defer { defaults.removePersistentDomain(forName: suite) }
            let history = I2PRouterHealthHistory(defaults: defaults)
            let start = Date(timeIntervalSince1970: 1_700_000_000)
            history.record(available: true, activePeers: 2, readyTunnels: 3,
                           cumulativeReceivedBytes: 100, cumulativeSentBytes: 50, at: start)
            history.record(available: true, activePeers: 4, readyTunnels: 5,
                           cumulativeReceivedBytes: 1_124, cumulativeSentBytes: 562,
                           at: start.addingTimeInterval(60))
            let reading = history.reading(window: .sixHours, at: start.addingTimeInterval(60))
            guard reading.samples.count == 2,
                  reading.uptimePercent == 100,
                  reading.onlineSeconds == 60,
                  reading.receivedBytes == 1_024,
                  reading.sentBytes == 512,
                  reading.samples.last?.activePeers == 4,
                  reading.samples.last?.readyTunnels == 5 else { return nil }
            return "2 samples · 100% · 1,024 B received / 512 B sent"
        }

        check("Router health: app suspension is kept as a visible chart gap") {
            let suite = "i2p.health.suspension.test.\(UUID().uuidString)"
            let defaults = UserDefaults(suiteName: suite)!
            defer { defaults.removePersistentDomain(forName: suite) }
            let history = I2PRouterHealthHistory(defaults: defaults)
            let start = Date(timeIntervalSince1970: 1_700_000_000)
            history.recordRouterStart(at: start)
            history.record(available: true, activePeers: 1, readyTunnels: 1,
                           cumulativeReceivedBytes: 10, cumulativeSentBytes: 10, at: start)
            history.record(available: true, activePeers: 1, readyTunnels: 1,
                           cumulativeReceivedBytes: 10, cumulativeSentBytes: 10,
                           at: start.addingTimeInterval(60))
            let suspendedAt = start.addingTimeInterval(70)
            let resumedAt = start.addingTimeInterval(250)
            history.markAppSuspended(at: suspendedAt)
            history.resumeSampling(at: resumedAt)
            history.record(available: true, activePeers: 3, readyTunnels: 2,
                           cumulativeReceivedBytes: 110, cumulativeSentBytes: 30, at: resumedAt)
            let reading = history.reading(window: .sixHours, at: resumedAt)
            guard let interruption = reading.lastInterruption,
                  interruption.cause == .appSuspended,
                  interruption.startedAt == suspendedAt,
                  interruption.duration == 180,
                  reading.chartPoints.map({ $0.sample.activePeers }) == [1, 1, 3],
                  reading.chartPoints.map({ $0.sample.readyTunnels }) == [1, 1, 2],
                  reading.chartPoints.map(\.segment) == [0, 0, 1] else { return nil }
            return "App suspended · peer and ready-tunnel samples retain values and restart as separate chart segments"
        }

        check("Router health: downtime is broken down by cause without double-counting an overlap") {
            let start = Date(timeIntervalSince1970: 1_700_200_000)
            let range = start...(start.addingTimeInterval(600))
            // An app suspension 0–300 s and a clean shutdown 120–180 s inside it.
            let suspended = I2PRouterHealthInterruption(startedAt: start, duration: 300,
                                                       cause: .appSuspended)
            let stopped = I2PRouterHealthInterruption(startedAt: start.addingTimeInterval(120),
                                                     duration: 60, cause: .routerStopped)
            let gap = I2PRouterHealthInterruption(startedAt: start.addingTimeInterval(400),
                                                 duration: 40, cause: .samplingPaused)
            let history = I2PRouterHealthHistory(defaults: UserDefaults(suiteName:
                "i2p.health.downtime.\(UUID().uuidString)")!)
            let breakdown = history.downtime(interruptions: [suspended, stopped, gap], in: range)
            guard breakdown.map(\.cause) == [.routerStopped, .appSuspended, .samplingPaused],
                  breakdown[0].seconds == 60, breakdown[0].count == 1,
                  // 300 s of suspension minus the 60 s already attributed to
                  // the router stop: the overlap is counted once.
                  breakdown[1].seconds == 240, breakdown[1].count == 1,
                  breakdown[2].seconds == 40, breakdown[2].count == 1,
                  breakdown.allSatisfy(\.isMeasurable) else { return nil }

            // An interruption outside the window contributes nothing.
            let old = I2PRouterHealthInterruption(startedAt: start.addingTimeInterval(-500),
                                                  duration: 120, cause: .samplingPaused)
            guard history.downtime(interruptions: [old], in: range).isEmpty else { return nil }

            // An open suspension has no measurable total yet.
            let open = history.downtime(interruptions: [],
                                        in: range,
                                        openSince: start.addingTimeInterval(560))
            guard open.count == 1,
                  open[0].cause == .appSuspended,
                  open[0].count == 1,
                  open[0].seconds == nil,
                  !open[0].isMeasurable else { return nil }
            return "0–300 s suspension and 120–180 s stop read as 240 s and 60 s (overlap counted once), the 40 s gap stays separate, and an open suspension reads as unmeasurable"
        }

        check("Router health: the lifecycle timeline lists events and interruptions newest first") {
            let suite = "i2p.health.timeline.\(UUID().uuidString)"
            let defaults = UserDefaults(suiteName: suite)!
            defer { defaults.removePersistentDomain(forName: suite) }
            let history = I2PRouterHealthHistory(defaults: defaults)
            let start = Date(timeIntervalSince1970: 1_700_300_000)
            history.recordRouterStart(at: start)
            history.record(available: true, activePeers: 1, readyTunnels: 1,
                           cumulativeReceivedBytes: 10, cumulativeSentBytes: 10, at: start)
            let suspendedAt = start.addingTimeInterval(70)
            let resumedAt = start.addingTimeInterval(250)
            history.markAppSuspended(at: suspendedAt)
            history.resumeSampling(at: resumedAt)
            history.record(available: true, activePeers: 1, readyTunnels: 1,
                           cumulativeReceivedBytes: 10, cumulativeSentBytes: 10, at: resumedAt)
            let stopped = start.addingTimeInterval(400)
            history.recordRouterCleanStop(at: stopped)

            let timeline = history.timeline(at: start.addingTimeInterval(500))
            // The suspension is recorded on the sample that follows it, so its
            // entry starts where the gap did: three entries, newest first.
            guard timeline.count == 3,
                  timeline.map(\.startedAt) == [stopped, suspendedAt, start],
                  timeline.map(\.isEvent) == [true, false, true],
                  timeline[0].kind == .cleanStop,
                  timeline[1].kind == nil,
                  timeline[1].cause == .appSuspended,
                  timeline[1].duration == 180,
                  timeline[2].kind == .started,
                  timeline.map({ $0.id }).count == Set(timeline.map(\.id)).count else { return nil }
            return "3 entries newest first: clean stop, the suspension gap, the router start; ids are unique"
        }

        check("Router health: explicit router lifecycle events distinguish clean shutdowns from suspension") {
            let suite = "i2p.health.lifecycle.selftest.\(UUID().uuidString)"
            let defaults = UserDefaults(suiteName: suite)!
            defer { defaults.removePersistentDomain(forName: suite) }
            let history = I2PRouterHealthHistory(defaults: defaults)
            let start = Date(timeIntervalSince1970: 1_700_100_000)
            history.recordRouterStart(at: start)
            history.record(available: true, activePeers: 1, readyTunnels: 1,
                           cumulativeReceivedBytes: 10, cumulativeSentBytes: 10, at: start)
            history.record(available: true, activePeers: 1, readyTunnels: 1,
                           cumulativeReceivedBytes: 20, cumulativeSentBytes: 20,
                           at: start.addingTimeInterval(60))
            let stopped = start.addingTimeInterval(70)
            let restarted = start.addingTimeInterval(190)
            history.recordRouterCleanStop(at: stopped)
            history.recordRouterStart(at: restarted)
            history.record(available: true, activePeers: 2, readyTunnels: 2,
                           cumulativeReceivedBytes: 30, cumulativeSentBytes: 30,
                           at: start.addingTimeInterval(200))
            let reading = history.reading(window: .sixHours, at: start.addingTimeInterval(200))
            guard reading.events.map(\.kind) == [.started, .cleanStop, .started],
                  let interruption = reading.lastInterruption,
                  interruption.cause == .routerStopped,
                  interruption.startedAt == stopped,
                  interruption.duration == 120,
                  reading.chartPoints.map(\.segment) == [0, 0, 1] else { return nil }
            return "Start and clean-stop events persist alongside samples; shutdown is solid-marked and separate from app-suspension gaps"
        }

        check("Router health: seven-day range includes retained samples, totals and gaps") {
            let suite = "i2p.health.week.test.\(UUID().uuidString)"
            let defaults = UserDefaults(suiteName: suite)!
            defer { defaults.removePersistentDomain(forName: suite) }
            let history = I2PRouterHealthHistory(defaults: defaults)
            let now = Date(timeIntervalSince1970: 1_700_000_000)
            let weekStart = now.addingTimeInterval(-I2PRouterHealthHistory.retention + 120)
            history.record(available: true, activePeers: 1, readyTunnels: 1,
                           cumulativeReceivedBytes: 100, cumulativeSentBytes: 50, at: weekStart)
            history.record(available: true, activePeers: 2, readyTunnels: 2,
                           cumulativeReceivedBytes: 200, cumulativeSentBytes: 100,
                           at: weekStart.addingTimeInterval(60))
            history.record(available: true, activePeers: 3, readyTunnels: 3,
                           cumulativeReceivedBytes: 500, cumulativeSentBytes: 250,
                           at: now.addingTimeInterval(-7 * 60 * 60))
            history.record(available: true, activePeers: 4, readyTunnels: 4,
                           cumulativeReceivedBytes: 900, cumulativeSentBytes: 450,
                           at: now.addingTimeInterval(-30 * 60))
            history.record(available: true, activePeers: 5, readyTunnels: 5,
                           cumulativeReceivedBytes: 1_500, cumulativeSentBytes: 750, at: now)

            let week = history.reading(window: .sevenDays, at: now)
            let day = history.reading(window: .twentyFourHours, at: now)
            let sixHours = history.reading(window: .sixHours, at: now)
            guard let weekUptime = week.uptimePercent,
                  I2PRouterHealthWindow.sevenDays.duration == I2PRouterHealthHistory.retention,
                  week.samples.count == 5,
                  week.chartPoints.count == 5,
                  week.chartPoints.last?.segment == 3,
                  week.samples.compactMap(\.interruptionBefore).count == 3,
                  week.onlineSeconds == 60,
                  weekUptime > 0, weekUptime < 1,
                  week.receivedBytes == 1_400,
                  week.sentBytes == 700,
                  week.lastInterruption != nil,
                  day.samples.count == 3,
                  day.receivedBytes == 1_300,
                  sixHours.samples.count == 2,
                  sixHours.receivedBytes == 1_000 else { return nil }
            return "7 days · 5 samples · 1,400 B received · interruption retained; 24-hour and 6-hour totals unchanged"
        }

        check("Router health: samples older than seven days are pruned") {
            let suite = "i2p.health.retention.test.\(UUID().uuidString)"
            let defaults = UserDefaults(suiteName: suite)!
            defer { defaults.removePersistentDomain(forName: suite) }
            let history = I2PRouterHealthHistory(defaults: defaults)
            let start = Date(timeIntervalSince1970: 1_700_000_000)
            history.record(available: true, activePeers: 1, readyTunnels: 1,
                           cumulativeReceivedBytes: 0, cumulativeSentBytes: 0, at: start)
            history.record(available: true, activePeers: 1, readyTunnels: 1,
                           cumulativeReceivedBytes: 0, cumulativeSentBytes: 0,
                           at: start.addingTimeInterval(I2PRouterHealthHistory.retention + 60))
            let retained = history.allSamples(at: start.addingTimeInterval(I2PRouterHealthHistory.retention + 60))
            guard retained.count == 1, retained[0].sampledAt > start else { return nil }
            return "history older than seven days removed"
        }

        return results
    }
}
