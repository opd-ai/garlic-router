//
//  I2PAlignmentHistory.swift
//  A short history of alignment-suite runs: one coverage sample per run, kept
//  in memory only, drawn as the sparkline in the alignment report's summary
//  card.
//
//  Each sample records what the truth table says at the moment of a run: the
//  rows aligned, the rows still pending wire verification, the rows with a
//  tracked defect and the table's row count. The window keeps the newest 30
//  runs and drops the oldest; nothing is written to disk, so a relaunch starts
//  a fresh window.
//

import Foundation

// MARK: - Sample

/// One alignment-suite run's coverage of the specification truth table, as the
/// summary card's sparkline draws it.
struct I2PAlignmentCoverageSample: Identifiable, Equatable {
    /// Sequence number within this launch, oldest first, so two runs in the
    /// same second stay distinct for the chart.
    let id: Int
    let ranAt: Date
    /// Rows whose status is aligned.
    let aligned: Int
    /// Rows still pending wire verification.
    let pending: Int
    /// Rows with a tracked defect.
    let defects: Int
    /// Every row in the table at the time of the run.
    let total: Int

    /// Aligned rows as a share of the table, 0...1 (0 for an empty table).
    var alignedFraction: Double {
        total > 0 ? Double(aligned) / Double(total) : 0
    }
}

// MARK: - History

/// The retained alignment-suite runs of this launch, oldest first.
enum I2PAlignmentHistory {

    /// At most this many runs are kept; the oldest is dropped first.
    static let capacity = 30

    private static let lock = NSLock()
    private static var stored: [I2PAlignmentCoverageSample] = []
    private static var nextID = 0

    /// The kept runs, oldest first.
    static var samples: [I2PAlignmentCoverageSample] {
        lock.lock()
        defer { lock.unlock() }
        return stored
    }

    /// The newest run's sample, nil before the first run.
    static var latest: I2PAlignmentCoverageSample? {
        samples.last
    }

    /// The run before the newest one, nil until two runs are in the window.
    static var previous: I2PAlignmentCoverageSample? {
        let all = samples
        guard all.count >= 2 else { return nil }
        return all[all.count - 2]
    }

    /// The oldest kept run's time — the sparkline's left label.
    static var oldestTime: Date? {
        samples.first?.ranAt
    }

    /// Records one suite run, dropping the oldest sample once the window is
    /// full. Returns the kept window, oldest first.
    ///
    /// A full suite run and a single component re-run both count as one run:
    /// either way the stored results and the report's coverage are refreshed,
    /// which is what the card's chart follows.
    @discardableResult
    static func record(ranAt: Date = Date(),
                       coverage: I2PAlignmentCoverage = I2PSpecTruthTable.coverage) -> [I2PAlignmentCoverageSample] {
        lock.lock()
        defer { lock.unlock() }
        let sample = I2PAlignmentCoverageSample(
            id: nextID,
            ranAt: ranAt,
            aligned: coverage.aligned,
            pending: coverage.pendingWireVerification,
            defects: coverage.defect,
            total: coverage.total)
        nextID += 1
        stored.append(sample)
        if stored.count > capacity {
            stored.removeFirst(stored.count - capacity)
        }
        return stored
    }

    /// Empties the window. The history is memory-only, so a relaunch does this
    /// by itself; this is for the self-tests.
    static func reset() {
        lock.lock()
        defer { lock.unlock() }
        stored = []
        nextID = 0
    }

    // MARK: Labels for the summary card

    /// The newest run's aligned rows less the previous run's, nil until two
    /// runs are in the window.
    static func alignedDelta(_ samples: [I2PAlignmentCoverageSample]) -> Int? {
        guard samples.count >= 2,
              let newest = samples.last,
              let previous = samples.dropLast().last else { return nil }
        return newest.aligned - previous.aligned
    }

    /// "+2 rows since the last run", "-1 row since the last run" or "no change
    /// since the last run"; nil until two runs are in the window.
    static func deltaLine(_ samples: [I2PAlignmentCoverageSample]) -> String? {
        guard let delta = alignedDelta(samples) else { return nil }
        guard delta != 0 else { return "no change since the last run" }
        let magnitude = abs(delta)
        let noun = magnitude == 1 ? "row" : "rows"
        return "\(delta > 0 ? "+" : "-")\(magnitude) \(noun) since the last run"
    }

    /// How pending wire verification and defects moved between the previous run
    /// and the newest one, e.g. "Pending wire verification 12 → 10 (2 fewer) ·
    /// defects unchanged at 1". Nil until two runs are in the window.
    static func movementNote(_ samples: [I2PAlignmentCoverageSample]) -> String? {
        guard samples.count >= 2,
              let newest = samples.last,
              let previous = samples.dropLast().last else { return nil }
        let pending = movement("Pending wire verification",
                               from: previous.pending, to: newest.pending)
        let defects = movement("defects",
                               from: previous.defects, to: newest.defects)
        return "\(pending) · \(defects)"
    }

    /// One tracked count's movement between two runs.
    private static func movement(_ label: String, from old: Int, to new: Int) -> String {
        guard old != new else { return "\(label) unchanged at \(new)" }
        let delta = new - old
        return "\(label) \(old) → \(new) (\(abs(delta)) \(delta > 0 ? "more" : "fewer"))"
    }
}

// MARK: - Self-test

enum I2PAlignmentHistorySelfTest {
    static func runAll() -> [I2PSelfTestResult] {
        var results: [I2PSelfTestResult] = []
        func run(_ name: String, _ body: () throws -> String) {
            do {
                results.append(I2PSelfTestResult(name: name, passed: true, detail: try body()))
            } catch {
                results.append(I2PSelfTestResult(name: name, passed: false, detail: "\(error)"))
            }
        }

        run("Alignment history · one sample per run, newest 30 kept") {
            I2PAlignmentHistory.reset()
            defer { I2PAlignmentHistory.reset() }
            guard I2PAlignmentHistory.samples.isEmpty,
                  I2PAlignmentHistory.oldestTime == nil,
                  I2PAlignmentHistory.latest == nil,
                  I2PAlignmentHistory.previous == nil else {
                throw I2PWireError.invalidFormat
            }

            let start = Date(timeIntervalSince1970: 1_700_000_000)
            for index in 0..<35 {
                I2PAlignmentHistory.record(
                    ranAt: start.addingTimeInterval(Double(index) * 60),
                    coverage: I2PAlignmentCoverage(aligned: 60 + index,
                                                   deviationDocumented: 4,
                                                   pendingWireVerification: 12,
                                                   defect: 1))
            }

            let window = I2PAlignmentHistory.samples
            guard window.count == I2PAlignmentHistory.capacity else {
                throw I2PWireError.invalidFormat
            }
            // Five oldest runs fell out; the newest run is last and carries the
            // coverage it was recorded with.
            guard window.first?.aligned == 65,
                  window.last?.aligned == 94,
                  window.last?.total == 94 + 12 + 4 + 1,
                  window.first?.ranAt == start.addingTimeInterval(5 * 60),
                  I2PAlignmentHistory.oldestTime == window.first?.ranAt,
                  I2PAlignmentHistory.latest?.id == window.last?.id,
                  I2PAlignmentHistory.previous?.id == window[window.count - 2].id else {
                throw I2PWireError.invalidFormat
            }
            // Sequence numbers keep increasing after the oldest samples drop.
            guard zip(window, window.dropFirst()).allSatisfy({ $0.id < $1.id }) else {
                throw I2PWireError.invalidFormat
            }
            return "35 runs left 30 samples, oldest dropped, aligned 65 → 94"
        }

        run("Alignment history · delta and movement note between runs") {
            I2PAlignmentHistory.reset()
            defer { I2PAlignmentHistory.reset() }
            guard I2PAlignmentHistory.deltaLine([]) == nil,
                  I2PAlignmentHistory.movementNote([]) == nil else {
                throw I2PWireError.invalidFormat
            }

            let start = Date(timeIntervalSince1970: 1_700_000_000)
            I2PAlignmentHistory.record(
                ranAt: start,
                coverage: I2PAlignmentCoverage(aligned: 60, deviationDocumented: 4,
                                               pendingWireVerification: 12, defect: 2))
            // One run is nothing to compare against yet.
            guard I2PAlignmentHistory.deltaLine(I2PAlignmentHistory.samples) == nil,
                  I2PAlignmentHistory.movementNote(I2PAlignmentHistory.samples) == nil else {
                throw I2PWireError.invalidFormat
            }

            I2PAlignmentHistory.record(
                ranAt: start.addingTimeInterval(60),
                coverage: I2PAlignmentCoverage(aligned: 62, deviationDocumented: 4,
                                               pendingWireVerification: 10, defect: 1))
            let grown = I2PAlignmentHistory.samples
            guard I2PAlignmentHistory.deltaLine(grown) == "+2 rows since the last run",
                  I2PAlignmentHistory.movementNote(grown)
                    == "Pending wire verification 12 → 10 (2 fewer) · defects 2 → 1 (1 fewer)" else {
                throw I2PWireError.invalidFormat
            }

            // A single lost row reads in the singular.
            I2PAlignmentHistory.record(
                ranAt: start.addingTimeInterval(120),
                coverage: I2PAlignmentCoverage(aligned: 61, deviationDocumented: 4,
                                               pendingWireVerification: 10, defect: 1))
            guard I2PAlignmentHistory.deltaLine(I2PAlignmentHistory.samples)
                    == "-1 row since the last run" else {
                throw I2PWireError.invalidFormat
            }

            // A flat run says so, and both tracked counts read as unchanged.
            I2PAlignmentHistory.record(
                ranAt: start.addingTimeInterval(180),
                coverage: I2PAlignmentCoverage(aligned: 61, deviationDocumented: 4,
                                               pendingWireVerification: 10, defect: 1))
            let flat = I2PAlignmentHistory.samples
            guard I2PAlignmentHistory.deltaLine(flat) == "no change since the last run",
                  I2PAlignmentHistory.movementNote(flat)
                    == "Pending wire verification unchanged at 10 · defects unchanged at 1",
                  I2PAlignmentHistory.alignedDelta(flat) == 0 else {
                throw I2PWireError.invalidFormat
            }
            return "delta reads +2, -1 and no change; the note names pending and defect movement"
        }

        run("Alignment history · the live sample follows the truth table") {
            I2PAlignmentHistory.reset()
            defer { I2PAlignmentHistory.reset() }
            let coverage = I2PSpecTruthTable.coverage
            let window = I2PAlignmentHistory.record(ranAt: Date())
            guard let sample = window.last,
                  sample.aligned == coverage.aligned,
                  sample.pending == coverage.pendingWireVerification,
                  sample.defects == coverage.defect,
                  sample.total == coverage.total,
                  sample.alignedFraction > 0,
                  sample.alignedFraction <= 1 else {
                throw I2PWireError.invalidFormat
            }
            return "\(sample.aligned) of \(sample.total) rows aligned (\(Int((sample.alignedFraction * 100).rounded()))%)"
        }

        return results
    }
}
