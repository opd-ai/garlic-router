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

        var title: String {
            switch self {
            case .appSuspended: return "App suspended"
            case .samplingPaused: return "Sampling paused"
            }
        }
    }

    let startedAt: Date
    let duration: TimeInterval
    let cause: Cause

    var id: Int64 { Int64(startedAt.timeIntervalSince1970) }
    var midpoint: Date { startedAt.addingTimeInterval(duration / 2) }
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

struct I2PRouterHealthReading {
    let samples: [I2PRouterHealthSample]
    let chartPoints: [I2PRouterHealthChartPoint]
    let uptimePercent: Double?
    let onlineSeconds: TimeInterval
    let receivedBytes: Int
    let sentBytes: Int
    let lastInterruption: I2PRouterHealthInterruption?

    var hasSamples: Bool { !samples.isEmpty }
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
    }

    private static let storageKey = "i2p.router.health.history.v1"
    private let lock = NSLock()
    private let defaults: UserDefaults
    private var samples: [I2PRouterHealthSample]
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
            isSuspended = state.isSuspended
            suspensionStartedAt = state.suspensionStartedAt
            resumedAt = state.resumedAt
            lastCumulativeReceivedBytes = state.lastCumulativeReceivedBytes
            lastCumulativeSentBytes = state.lastCumulativeSentBytes
            forceNextSample = state.resumedAt != nil && !state.isSuspended
        } else {
            samples = []
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
        var segment = 0
        let points = selected.map { sample -> I2PRouterHealthChartPoint in
            if sample.interruptionBefore != nil { segment += 1 }
            return I2PRouterHealthChartPoint(sample: sample, segment: segment)
        }

        guard let first = selected.first, let last = selected.last else {
            return I2PRouterHealthReading(samples: [], chartPoints: [], uptimePercent: nil,
                                          onlineSeconds: 0, receivedBytes: 0, sentBytes: 0,
                                          lastInterruption: nil)
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
            uptimePercent: span > 0 ? min(100, onlineSeconds / span * 100) : nil,
            onlineSeconds: onlineSeconds,
            receivedBytes: selected.reduce(0) { $0 + $1.receivedBytes },
            sentBytes: selected.reduce(0) { $0 + $1.sentBytes },
            lastInterruption: selected.compactMap(\.interruptionBefore).last
        )
    }

    private func pruneLocked(at now: Date) {
        let cutoff = now.addingTimeInterval(-Self.retention)
        samples.removeAll { $0.sampledAt < cutoff }
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
                                lastCumulativeSentBytes: lastCumulativeSentBytes)
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
