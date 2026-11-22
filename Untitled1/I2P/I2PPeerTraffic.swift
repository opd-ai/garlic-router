//
//  I2PPeerTraffic.swift
//  Per-peer session traffic history for the peer inspector. The status engine
//  samples each live session's cumulative byte counters once a second and keeps
//  the derived per-second rates for the last 15 minutes, so a peer that has gone
//  quiet or started flooding is obvious at a glance. The history lives in memory
//  only, so a relaunch starts a fresh window.
//

import Foundation

// MARK: - Readings

/// One per-second traffic reading of a single peer session, in bytes per second
/// per direction.
struct I2PPeerTrafficSample: Identifiable {
    let id: Int
    let at: Date
    let bytesInPerSecond: Double
    let bytesOutPerSecond: Double
}

/// A peer's average traffic over a window — the reading the inspector names
/// under the chart as "the last minute's average".
struct I2PPeerTrafficAverage {
    let bytesInPerSecond: Double
    let bytesOutPerSecond: Double

    static let zero = I2PPeerTrafficAverage(bytesInPerSecond: 0, bytesOutPerSecond: 0)

    /// Whether the window carried no meaningful traffic at all.
    var isQuiet: Bool { bytesInPerSecond < 0.5 && bytesOutPerSecond < 0.5 }
}

/// A drawing bucket: a run of consecutive per-second samples averaged into one
/// point, so a 15-minute series still draws as a thin line in a small chart.
struct I2PPeerTrafficPoint: Identifiable {
    let id: Int
    let at: Date
    let receivedBytesPerSecond: Double
    let sentBytesPerSecond: Double

    var receivedKBPerSecond: Double { receivedBytesPerSecond / 1024 }
    var sentKBPerSecond: Double { sentBytesPerSecond / 1024 }
}

// MARK: - Recorder

/// Keeps the per-second traffic of each peer session, derived from the
/// cumulative counters the transports report.
///
/// The tracker is deliberately tolerant of how often it is asked: the dashboard,
/// the participation screen and the peer inspector all poll the status engine
/// each second, so readings that arrive too close together fold into the next
/// sample (their bytes are kept, not dropped) and only the first reading of a
/// fresh session seeds the baseline.
final class I2PPeerTrafficRecorder: @unchecked Sendable {
    /// The window the history covers — the sparkline's 15 minutes.
    static let window: TimeInterval = 15 * 60
    /// Readings closer together than this fold into the next sample, so several
    /// views polling each second still yield roughly one sample per second.
    static let minimumInterval: TimeInterval = 0.75
    /// Bound on the tracked set: a long run over churning sessions can never
    /// grow the recorder without limit.
    static let maxTrackedPeers = 256
    /// A session that has moved no bytes for this long reads as quiet.
    static let quietAfter: TimeInterval = 3 * 60
    /// A received rate this many times the peer's own median reads as flooding
    /// once it has held for `floodSustain`.
    static let floodMultiple: Double = 4
    /// How long the elevated rate must hold before it reads as flooding.
    static let floodSustain: TimeInterval = 30
    /// A median below this is no measurable baseline to be a multiple of: a
    /// peer that has received essentially nothing and then trickles a few bytes
    /// would otherwise read as flooding the moment it is used at all.
    static let minimumFloodBaseline: Double = 1

    private struct Baseline {
        var bytesIn: Int
        var bytesOut: Int
        var at: Date
    }

    private struct Series {
        var baseline: Baseline
        var samples: [(at: Date, inRate: Double, outRate: Double)]
        /// When bytes last moved through this session — the quiet flag's clock.
        /// Seeded when the session is first read and refreshed by every reading
        /// that shows the counters advancing.
        var lastTrafficAt: Date
    }

    private let lock = NSLock()
    private var series: [String: Series] = [:]

    /// Records a peer's cumulative counters as one status snapshot read them.
    func record(peerID: String, bytesIn: Int, bytesOut: Int, at now: Date = Date()) {
        let key = peerID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !key.isEmpty else { return }
        lock.lock()
        defer { lock.unlock() }

        guard var current = series[key] else {
            series[key] = Series(baseline: Baseline(bytesIn: bytesIn, bytesOut: bytesOut, at: now),
                                 samples: [],
                                 lastTrafficAt: now)
            prunePeersLocked(keeping: key)
            return
        }

        // A counter that went backwards belongs to a session that was replaced:
        // rebase on the new reading rather than reporting a negative spike, and
        // restart the quiet clock with the new session.
        if bytesIn < current.baseline.bytesIn || bytesOut < current.baseline.bytesOut {
            current.baseline = Baseline(bytesIn: bytesIn, bytesOut: bytesOut, at: now)
            current.lastTrafficAt = now
            series[key] = current
            return
        }

        // Bytes that moved since the last reading keep the quiet clock fresh,
        // even when the interval is too short to become a sample of its own.
        let moved = bytesIn > current.baseline.bytesIn || bytesOut > current.baseline.bytesOut

        let elapsed = now.timeIntervalSince(current.baseline.at)
        guard elapsed >= Self.minimumInterval else {
            // Too soon for a sample of its own: leave the baseline alone, so
            // this interval's bytes are counted in the next sample.
            if moved { current.lastTrafficAt = now }
            series[key] = current
            return
        }

        let seconds = max(elapsed, 0.001)
        current.samples.append((
            at: now,
            inRate: Double(bytesIn - current.baseline.bytesIn) / seconds,
            outRate: Double(bytesOut - current.baseline.bytesOut) / seconds
        ))
        current.baseline = Baseline(bytesIn: bytesIn, bytesOut: bytesOut, at: now)
        if moved { current.lastTrafficAt = now }

        let cutoff = now.addingTimeInterval(-Self.window)
        if let firstKept = current.samples.firstIndex(where: { $0.at >= cutoff }) {
            if firstKept > 0 { current.samples.removeFirst(firstKept) }
        } else {
            current.samples.removeAll()
        }
        series[key] = current
    }

    /// The peer's readings, oldest first, within the recorder's window.
    func samples(for peerID: String) -> [I2PPeerTrafficSample] {
        rawSamples(for: peerID).enumerated().map { index, sample in
            I2PPeerTrafficSample(id: index,
                                 at: sample.at,
                                 bytesInPerSecond: sample.inRate,
                                 bytesOutPerSecond: sample.outRate)
        }
    }

    /// The peer's average per-second rates over the last `seconds` (a minute
    /// unless asked otherwise). A peer with no reading in that window reads as
    /// zero rather than as its last burst.
    func average(for peerID: String,
                 over seconds: TimeInterval = 60,
                 now: Date = Date()) -> I2PPeerTrafficAverage {
        let cutoff = now.addingTimeInterval(-seconds)
        let windowed = rawSamples(for: peerID).filter { $0.at >= cutoff }
        guard !windowed.isEmpty else { return .zero }
        let count = Double(windowed.count)
        return I2PPeerTrafficAverage(
            bytesInPerSecond: windowed.reduce(0) { $0 + $1.inRate } / count,
            bytesOutPerSecond: windowed.reduce(0) { $0 + $1.outRate } / count
        )
    }

    /// How many peers the recorder currently holds readings for.
    var trackedPeerCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return series.count
    }

    /// The traffic condition this session shows right now, recomputed from the
    /// readings every time it is asked for: quiet once it has moved no bytes for
    /// three minutes, flooding once its received rate has held above four times
    /// its own 15-minute median for half a minute. Both clear on their own when
    /// the readings return to normal, and neither is stored or configured.
    func flag(for peerID: String, now: Date = Date()) -> I2PPeerTrafficFlag? {
        let key = peerID.trimmingCharacters(in: .whitespacesAndNewlines)
        lock.lock()
        let current = series[key]
        lock.unlock()

        guard let current else { return nil }

        if now.timeIntervalSince(current.lastTrafficAt) >= Self.quietAfter {
            return .quiet(for: now.timeIntervalSince(current.lastTrafficAt))
        }

        let cutoff = now.addingTimeInterval(-Self.window)
        let windowed = current.samples.filter { $0.at >= cutoff }
        guard !windowed.isEmpty else { return nil }

        let median = Self.median(of: windowed.map { $0.inRate })
        guard median >= Self.minimumFloodBaseline else { return nil }
        let threshold = median * Self.floodMultiple

        // The run of consecutive newest readings sitting above the threshold:
        // its oldest member dates the start of the elevated rate.
        var runStart: Date?
        var runSum = 0.0
        var runCount = 0
        for sample in windowed.reversed() {
            guard sample.inRate > threshold else { break }
            runStart = sample.at
            runSum += sample.inRate
            runCount += 1
        }

        guard let runStart, runCount > 0 else { return nil }
        let sustained = now.timeIntervalSince(runStart)
        guard sustained >= Self.floodSustain else { return nil }
        return .flooding(rate: runSum / Double(runCount),
                         median: median,
                         sustained: sustained)
    }

    /// The middle of a set of readings (the mean of the two middle values for an
    /// even count), so a single burst cannot move it the way a mean would.
    static func median(of values: [Double]) -> Double {
        guard !values.isEmpty else { return 0 }
        let sorted = values.sorted()
        let middle = sorted.count / 2
        if sorted.count % 2 == 0 {
            return (sorted[middle - 1] + sorted[middle]) / 2
        }
        return sorted[middle]
    }

    // MARK: Internals

    private func rawSamples(for peerID: String) -> [(at: Date, inRate: Double, outRate: Double)] {
        let key = peerID.trimmingCharacters(in: .whitespacesAndNewlines)
        lock.lock()
        defer { lock.unlock() }
        return series[key]?.samples ?? []
    }

    /// Drops the least recently sampled peers once the tracked set is over its
    /// bound, never the peer being recorded.
    private func prunePeersLocked(keeping key: String) {
        guard series.count > Self.maxTrackedPeers else { return }
        let overflow = series.count - Self.maxTrackedPeers
        let stale = series
            .filter { $0.key != key }
            .sorted { $0.value.baseline.at < $1.value.baseline.at }
            .prefix(overflow)
        for entry in stale { series[entry.key] = nil }
    }
}

// MARK: - Chart bucketing

extension I2PPeerTrafficRecorder {
    /// Buckets a series into at most `maxPoints` points by averaging runs of
    /// consecutive samples, so the chart stays a thin line whatever the window
    /// length. Both directions are bucketed together, keeping the two lines
    /// aligned on the same time axis.
    static func points(from samples: [I2PPeerTrafficSample],
                       maxPoints: Int = 90) -> [I2PPeerTrafficPoint] {
        guard !samples.isEmpty else { return [] }
        let limit = max(1, maxPoints)
        guard samples.count > limit else {
            return samples.enumerated().map { index, sample in
                I2PPeerTrafficPoint(id: index,
                                    at: sample.at,
                                    receivedBytesPerSecond: sample.bytesInPerSecond,
                                    sentBytesPerSecond: sample.bytesOutPerSecond)
            }
        }

        let bucketSize = Int((Double(samples.count) / Double(limit)).rounded(.up))
        var points: [I2PPeerTrafficPoint] = []
        var index = 0
        while index < samples.count {
            let end = min(index + bucketSize, samples.count)
            let run = samples[index..<end]
            let count = Double(run.count)
            points.append(I2PPeerTrafficPoint(
                id: points.count,
                at: run[run.startIndex].at,
                receivedBytesPerSecond: run.reduce(0) { $0 + $1.bytesInPerSecond } / count,
                sentBytesPerSecond: run.reduce(0) { $0 + $1.bytesOutPerSecond } / count
            ))
            index = end
        }
        return points
    }
}

// MARK: - Labels

enum I2PPeerTrafficFormat {
    /// "412 B/s", "12.3 KB/s" or "1.2 MB/s" for a measured rate.
    static func rate(_ bytesPerSecond: Double) -> String {
        let value = max(0, bytesPerSecond)
        if value >= 1_048_576 { return String(format: "%.1f MB/s", value / 1_048_576) }
        if value >= 1024 { return String(format: "%.1f KB/s", value / 1024) }
        return String(format: "%.0f B/s", value)
    }

    /// "512 B", "12 KB" or "1.2 MB" for the expanded chart's KB/s scale.
    static func scaleLabel(_ kbPerSecond: Double) -> String {
        let value = max(0, kbPerSecond)
        if value >= 1024 { return String(format: "%.1f MB", value / 1024) }
        if value >= 1 { return String(format: "%.0f KB", value) }
        return String(format: "%.0f B", value * 1024)
    }
}

// MARK: - Self-test

enum I2PPeerTrafficSelfTest {
    static func runAll() -> [I2PSelfTestResult] {
        var results: [I2PSelfTestResult] = []
        func run(_ name: String, _ body: () throws -> String) {
            do {
                results.append(I2PSelfTestResult(name: name, passed: true, detail: try body()))
            } catch {
                results.append(I2PSelfTestResult(name: name, passed: false, detail: "\(error)"))
            }
        }

        let start = Date(timeIntervalSince1970: 1_700_000_000)

        run("Peer traffic · per-second rates come from the cumulative counters") {
            let recorder = I2PPeerTrafficRecorder()
            recorder.record(peerID: "peer-a", bytesIn: 0, bytesOut: 0, at: start)
            guard recorder.samples(for: "peer-a").isEmpty else { throw I2PWireError.invalidFormat }

            recorder.record(peerID: "peer-a", bytesIn: 1024, bytesOut: 256,
                            at: start.addingTimeInterval(1))
            recorder.record(peerID: "peer-a", bytesIn: 4096, bytesOut: 512,
                            at: start.addingTimeInterval(2))

            let samples = recorder.samples(for: "peer-a")
            guard samples.count == 2,
                  abs(samples[0].bytesInPerSecond - 1024) < 1,
                  abs(samples[0].bytesOutPerSecond - 256) < 1,
                  abs(samples[1].bytesInPerSecond - 3072) < 1,
                  abs(samples[1].bytesOutPerSecond - 256) < 1 else {
                throw I2PWireError.invalidFormat
            }
            return "1 KB/s then 3 KB/s received, each derived from the counters one second apart"
        }

        run("Peer traffic · a replaced session reads as zero, not a negative spike") {
            let recorder = I2PPeerTrafficRecorder()
            recorder.record(peerID: "peer", bytesIn: 100_000, bytesOut: 50_000, at: start)
            recorder.record(peerID: "peer", bytesIn: 102_000, bytesOut: 51_000,
                            at: start.addingTimeInterval(1))
            // The old session drops and a new one starts from a low counter.
            recorder.record(peerID: "peer", bytesIn: 40, bytesOut: 20,
                            at: start.addingTimeInterval(2))
            recorder.record(peerID: "peer", bytesIn: 1040, bytesOut: 520,
                            at: start.addingTimeInterval(3))

            let samples = recorder.samples(for: "peer")
            guard samples.count == 2,
                  samples.allSatisfy({ $0.bytesInPerSecond >= 0 && $0.bytesOutPerSecond >= 0 }),
                  abs(samples[1].bytesInPerSecond - 1000) < 1,
                  abs(samples[1].bytesOutPerSecond - 500) < 1 else {
                throw I2PWireError.invalidFormat
            }
            return "the restart rebased the counters and the new session measured from its own first reading"
        }

        run("Peer traffic · readings closer than the minimum interval fold into the next") {
            let recorder = I2PPeerTrafficRecorder()
            recorder.record(peerID: "peer", bytesIn: 0, bytesOut: 0, at: start)
            // A second poll 200 ms later must not become a sample of its own.
            recorder.record(peerID: "peer", bytesIn: 100, bytesOut: 50,
                            at: start.addingTimeInterval(0.2))
            recorder.record(peerID: "peer", bytesIn: 1100, bytesOut: 550,
                            at: start.addingTimeInterval(1.0))

            let samples = recorder.samples(for: "peer")
            guard samples.count == 1,
                  abs(samples[0].bytesInPerSecond - 1100) < 1,
                  abs(samples[0].bytesOutPerSecond - 550) < 1 else {
                throw I2PWireError.invalidFormat
            }
            return "the folded interval kept all 1 100 bytes in one one-second sample"
        }

        run("Peer traffic · the history keeps only the last 15 minutes") {
            let recorder = I2PPeerTrafficRecorder()
            var cumulative = 0
            recorder.record(peerID: "peer", bytesIn: 0, bytesOut: 0, at: start)
            // 20 one-minute readings: the four oldest fall outside the window.
            for step in 1...20 {
                cumulative += 600
                recorder.record(peerID: "peer", bytesIn: cumulative, bytesOut: cumulative / 2,
                                at: start.addingTimeInterval(Double(step) * 60))
            }

            let samples = recorder.samples(for: "peer")
            guard let newest = samples.last,
                  samples.count == 16,
                  samples.allSatisfy({
                      newest.at.timeIntervalSince($0.at) <= I2PPeerTrafficRecorder.window
                  }),
                  abs(newest.bytesInPerSecond - 10) < 0.01,
                  abs(newest.bytesOutPerSecond - 5) < 0.01,
                  zip(samples, samples.dropFirst()).allSatisfy({ pair in
                      abs(pair.1.at.timeIntervalSince(pair.0.at) - 60) < 0.001
                  }) else {
                throw I2PWireError.invalidFormat
            }
            return "the newest 16 one-minute readings stayed, each a steady 10 B/s received"
        }

        run("Peer traffic · the last minute's average, and a quiet peer") {
            let recorder = I2PPeerTrafficRecorder()
            recorder.record(peerID: "peer", bytesIn: 0, bytesOut: 0, at: start)
            recorder.record(peerID: "peer", bytesIn: 1024, bytesOut: 0,
                            at: start.addingTimeInterval(1))
            recorder.record(peerID: "peer", bytesIn: 3072, bytesOut: 0,
                            at: start.addingTimeInterval(2))
            recorder.record(peerID: "peer", bytesIn: 3072, bytesOut: 0,
                            at: start.addingTimeInterval(3))

            let average = recorder.average(for: "peer", over: 60,
                                           now: start.addingTimeInterval(3))
            guard abs(average.bytesInPerSecond - 1024) < 1,
                  average.bytesOutPerSecond == 0,
                  !average.isQuiet else {
                throw I2PWireError.invalidFormat
            }

            // A peer that stops moving bytes reads flat, not as its last burst.
            recorder.record(peerID: "peer", bytesIn: 3072, bytesOut: 0,
                            at: start.addingTimeInterval(200))
            let quiet = recorder.average(for: "peer", over: 60,
                                         now: start.addingTimeInterval(201))
            guard quiet.isQuiet,
                  quiet.bytesInPerSecond == 0,
                  recorder.average(for: "never-seen", over: 60).isQuiet else {
                throw I2PWireError.invalidFormat
            }
            return "1 KB/s averaged over the last minute; a peer whose readings stopped reads zero"
        }

        run("Peer traffic · the chart buckets keep the window's shape") {
            let samples = (0..<300).map { index in
                I2PPeerTrafficSample(id: index,
                                     at: start.addingTimeInterval(Double(index)),
                                     bytesInPerSecond: index < 150 ? 1024 : 4096,
                                     bytesOutPerSecond: 512)
            }
            let points = I2PPeerTrafficRecorder.points(from: samples, maxPoints: 60)
            guard points.count == 60,
                  abs((points.first?.receivedBytesPerSecond ?? 0) - 1024) < 1,
                  abs((points.last?.receivedBytesPerSecond ?? 0) - 4096) < 1,
                  points.allSatisfy({ abs($0.sentBytesPerSecond - 512) < 1 }),
                  I2PPeerTrafficRecorder.points(from: []).isEmpty,
                  I2PPeerTrafficRecorder.points(from: Array(samples.prefix(5)),
                                                maxPoints: 60).count == 5 else {
                throw I2PWireError.invalidFormat
            }
            return "300 per-second samples drew as 60 buckets, quiet half at 1 KB/s and busy half at 4 KB/s"
        }

        run("Peer traffic · labels stay short") {
            guard I2PPeerTrafficFormat.rate(412) == "412 B/s",
                  I2PPeerTrafficFormat.rate(12_595) == "12.3 KB/s",
                  I2PPeerTrafficFormat.rate(-9) == "0 B/s",
                  I2PPeerTrafficFormat.scaleLabel(0.5) == "512 B",
                  I2PPeerTrafficFormat.scaleLabel(12) == "12 KB" else {
                throw I2PWireError.invalidFormat
            }
            return "412 B/s, 12.3 KB/s, 0 B/s, 512 B, 12 KB"
        }

        return results
    }
}
