//
//  I2PAlignmentBaseline.swift
//  A pinned alignment baseline: a snapshot of the truth table's per-row status
//  and passing test count, taken when the user pins it on the alignment report,
//  so a later suite run that leaves a row worse than it was is flagged in place.
//
//  The baseline is held in memory only — nothing is written to disk and no
//  setting is added — so a relaunch starts with no baseline pinned. A full
//  suite run and a single component re-run both only replace results; the
//  pinned snapshot stays as it was, and the badges are recomputed from it
//  against whatever results the screen now holds.
//

import Foundation

// MARK: - Snapshot

/// One row's passing test count, as the baseline records it. A row with no
/// stored results at the moment of the pin has no count at all, which is not
/// the same as zero passing tests.
struct I2PAlignmentTestCount: Equatable {
    let passing: Int
    let total: Int

    var text: String { "\(passing)/\(total) tests" }
}

/// One truth-table row as the baseline pinned it.
struct I2PAlignmentBaselineRow: Equatable {
    let rowID: String
    let status: I2PAlignmentStatus
    /// Test counts stored for the row when the baseline was pinned; nil when
    /// the suite had not run for it.
    let counts: I2PAlignmentTestCount?
}

/// The pinned baseline itself: when it was taken and what every row looked
/// like at that moment.
struct I2PAlignmentBaselineSnapshot: Equatable {
    let pinnedAt: Date
    /// Rows keyed by truth-table row ID.
    let rows: [String: I2PAlignmentBaselineRow]

    var rowCount: Int { rows.count }
}

// MARK: - Regression

/// A row that is worse than the baseline pinned it: its status moved down the
/// severity ladder, or fewer of its tagged tests pass, or both.
struct I2PAlignmentRegression: Identifiable, Equatable {
    var id: String { rowID }
    let rowID: String
    let baselineStatus: I2PAlignmentStatus
    let currentStatus: I2PAlignmentStatus
    let baselineCounts: I2PAlignmentTestCount?
    let currentCounts: I2PAlignmentTestCount?

    /// The row's status climbed the severity ladder the truth table orders
    /// statuses by (`sortIndex`: aligned, pending, deviation, defect).
    var statusWorsened: Bool {
        currentStatus.sortIndex > baselineStatus.sortIndex
    }

    /// Fewer tests pass than at the pin. A row with no stored results any more
    /// counts as zero passing, so a component that loses its results reads as a
    /// regression rather than as a disappeared row.
    var passingDropped: Bool {
        guard let baselinePassing = baselineCounts?.passing else { return false }
        return (currentCounts?.passing ?? 0) < baselinePassing
    }

    /// The baseline values the badge names, e.g. "was aligned, had 3 of 4
    /// tests passing".
    var baselineDescription: String {
        var parts: [String] = []
        if statusWorsened {
            parts.append("was \(baselineStatus.displayName.lowercased())")
        }
        if passingDropped, let counts = baselineCounts {
            parts.append("had \(counts.passing) of \(counts.total) tests passing")
        }
        return parts.joined(separator: ", ")
    }
}

// MARK: - Baseline store

enum I2PAlignmentBaseline {

    private static let lock = NSLock()
    private static var stored: I2PAlignmentBaselineSnapshot?

    /// The pinned baseline, nil while nothing is pinned. Memory only: it is
    /// gone after a relaunch.
    static var snapshot: I2PAlignmentBaselineSnapshot? {
        lock.lock()
        defer { lock.unlock() }
        return stored
    }

    static var isPinned: Bool {
        snapshot != nil
    }

    /// Snapshots the current per-row status and passing test count, replacing
    /// any baseline already pinned, and returns the snapshot.
    @discardableResult
    static func pin(results: [I2PCrossValidationResult],
                    rows: [I2PSpecRow] = I2PSpecTruthTable.rows,
                    at pinnedAt: Date = Date()) -> I2PAlignmentBaselineSnapshot {
        let counts = currentCounts(results)
        var snapshotRows: [String: I2PAlignmentBaselineRow] = [:]
        for row in rows {
            snapshotRows[row.id] = I2PAlignmentBaselineRow(rowID: row.id,
                                                           status: row.status,
                                                           counts: counts[row.id])
        }
        let snapshot = I2PAlignmentBaselineSnapshot(pinnedAt: pinnedAt, rows: snapshotRows)
        lock.lock()
        stored = snapshot
        lock.unlock()
        return snapshot
    }

    /// Drops the pinned baseline. The rows go back to being read on their own.
    static func clear() {
        lock.lock()
        stored = nil
        lock.unlock()
    }

    /// The rows that are worse than the baseline, keyed by row ID and in truth
    /// table order. Recomputed from the stored results every time the report
    /// renders, so a suite run or a component re-run refreshes the badges in
    /// place without touching the pinned snapshot.
    static func regressions(against snapshot: I2PAlignmentBaselineSnapshot,
                            results: [I2PCrossValidationResult],
                            rows: [I2PSpecRow] = I2PSpecTruthTable.rows) -> [String: I2PAlignmentRegression] {
        let counts = currentCounts(results)
        var found: [String: I2PAlignmentRegression] = [:]
        for row in rows {
            guard let pinned = snapshot.rows[row.id] else { continue }
            let regression = I2PAlignmentRegression(rowID: row.id,
                                                   baselineStatus: pinned.status,
                                                   currentStatus: row.status,
                                                   baselineCounts: pinned.counts,
                                                   currentCounts: counts[row.id])
            if regression.statusWorsened || regression.passingDropped {
                found[row.id] = regression
            }
        }
        return found
    }

    /// Passing / total counts per row from a set of cross-validation results.
    static func currentCounts(_ results: [I2PCrossValidationResult]) -> [String: I2PAlignmentTestCount] {
        var grouped: [String: (passing: Int, total: Int)] = [:]
        for result in results {
            var group = grouped[result.rowID] ?? (0, 0)
            group.total += 1
            if result.passed { group.passing += 1 }
            grouped[result.rowID] = group
        }
        return grouped.mapValues { I2PAlignmentTestCount(passing: $0.passing, total: $0.total) }
    }

    /// The summary card's line: "no rows regressed since the baseline",
    /// "1 row regressed since the baseline" or "3 rows regressed since the
    /// baseline".
    static func summaryLine(regressedRows: Int) -> String {
        switch regressedRows {
        case 0: return "no rows regressed since the baseline"
        case 1: return "1 row regressed since the baseline"
        default: return "\(regressedRows) rows regressed since the baseline"
        }
    }
}

// MARK: - Self-test

enum I2PAlignmentBaselineSelfTest {
    static func runAll() -> [I2PSelfTestResult] {
        var results: [I2PSelfTestResult] = []
        func run(_ name: String, _ body: () throws -> String) {
            do {
                results.append(I2PSelfTestResult(name: name, passed: true, detail: try body()))
            } catch {
                results.append(I2PSelfTestResult(name: name, passed: false, detail: "\(error)"))
            }
        }

        run("Alignment baseline · pin, then flag a worse status and a dropped count") {
            I2PAlignmentBaseline.clear()
            defer { I2PAlignmentBaseline.clear() }
            guard I2PAlignmentBaseline.snapshot == nil,
                  !I2PAlignmentBaseline.isPinned else {
                throw I2PWireError.invalidFormat
            }

            let rows = I2PSpecTruthTable.rows
            guard rows.count > 2,
                  let sample = rows.first(where: { $0.status == .aligned }),
                  let other = rows.first(where: { $0.id != sample.id && $0.status == .aligned }),
                  let third = rows.first(where: { $0.id != sample.id && $0.id != other.id }) else {
                throw I2PWireError.invalidFormat
            }

            let valid = I2PCrossValidationResult(testID: "T4-BASE-1", rowID: sample.id,
                                                 name: "baseline sample", passed: true, detail: "")
            let failing = I2PCrossValidationResult(testID: "T4-BASE-2", rowID: other.id,
                                                   name: "other sample", passed: true, detail: "")
            let passedAtPin = [valid, failing]

            let pinnedAt = Date(timeIntervalSince1970: 1_700_000_000)
            let snapshot = I2PAlignmentBaseline.pin(results: passedAtPin,
                                                    rows: rows,
                                                    at: pinnedAt)
            guard I2PAlignmentBaseline.isPinned,
                  I2PAlignmentBaseline.snapshot == snapshot,
                  snapshot.pinnedAt == pinnedAt,
                  snapshot.rowCount == rows.count,
                  snapshot.rows[sample.id]?.status == .aligned,
                  snapshot.rows[sample.id]?.counts == I2PAlignmentTestCount(passing: 1, total: 1),
                  snapshot.rows[third.id]?.counts == nil else {
                throw I2PWireError.invalidFormat
            }

            // Nothing has changed yet.
            guard I2PAlignmentBaseline.regressions(against: snapshot,
                                                   results: passedAtPin,
                                                   rows: rows).isEmpty else {
                throw I2PWireError.invalidFormat
            }

            // A test that now fails on the pinned row: its passing count drops.
            let dropped = I2PCrossValidationResult(testID: "T4-BASE-1", rowID: sample.id,
                                                   name: "baseline sample", passed: false, detail: "")
            let worseCounts = I2PAlignmentBaseline.regressions(against: snapshot,
                                                               results: [dropped, failing],
                                                               rows: rows)
            guard worseCounts.count == 1,
                  let countRegression = worseCounts[sample.id],
                  !countRegression.statusWorsened,
                  countRegression.passingDropped,
                  countRegression.baselineDescription == "had 1 of 1 tests passing" else {
                throw I2PWireError.invalidFormat
            }

            // A row whose results are gone entirely counts as zero passing.
            let lostResults = I2PAlignmentBaseline.regressions(against: snapshot,
                                                               results: [failing],
                                                               rows: rows)
            guard lostResults[sample.id]?.passingDropped == true,
                  lostResults[sample.id]?.currentCounts == nil else {
                throw I2PWireError.invalidFormat
            }

            // A row whose status is worse than the pinned one is flagged even
            // when its counts are unchanged.
            var worseStatusRows = rows
            if let index = worseStatusRows.firstIndex(where: { $0.id == other.id }) {
                let original = worseStatusRows[index]
                worseStatusRows[index] = I2PSpecRow(id: original.id,
                                                    component: original.component,
                                                    requirement: original.requirement,
                                                    specSection: original.specSection,
                                                    javaReference: original.javaReference,
                                                    swiftComponent: original.swiftComponent,
                                                    wireLayout: original.wireLayout,
                                                    encodingRules: original.encodingRules,
                                                    cryptoParameters: original.cryptoParameters,
                                                    edgeCases: original.edgeCases,
                                                    status: .defect,
                                                    deviation: I2PDeviationRecord(classification: .defect,
                                                                                  description: "baseline self-test",
                                                                                  rationale: "",
                                                                                  trackingRef: "self-test"),
                                                    testIDs: original.testIDs)
            }
            guard let originalStatus = snapshot.rows[other.id]?.status,
                  originalStatus.sortIndex < I2PAlignmentStatus.defect.sortIndex else {
                throw I2PWireError.invalidFormat
            }
            let worseStatus = I2PAlignmentBaseline.regressions(against: snapshot,
                                                               results: passedAtPin,
                                                               rows: worseStatusRows)
            guard let statusRegression = worseStatus[other.id],
                  statusRegression.statusWorsened,
                  !statusRegression.passingDropped,
                  statusRegression.baselineDescription == "was \(originalStatus.displayName.lowercased())" else {
                throw I2PWireError.invalidFormat
            }

            // An improvement is never a regression.
            let improvedRows = worseStatusRows.map { row -> I2PSpecRow in
                guard row.id == other.id else { return row }
                return I2PSpecRow(id: row.id,
                                  component: row.component,
                                  requirement: row.requirement,
                                  specSection: row.specSection,
                                  javaReference: row.javaReference,
                                  swiftComponent: row.swiftComponent,
                                  wireLayout: row.wireLayout,
                                  encodingRules: row.encodingRules,
                                  cryptoParameters: row.cryptoParameters,
                                  edgeCases: row.edgeCases,
                                  status: .aligned,
                                  deviation: nil,
                                  testIDs: row.testIDs)
            }
            guard I2PAlignmentBaseline.regressions(against: snapshot,
                                                   results: passedAtPin,
                                                   rows: improvedRows).isEmpty else {
                throw I2PWireError.invalidFormat
            }

            I2PAlignmentBaseline.clear()
            guard I2PAlignmentBaseline.snapshot == nil,
                  !I2PAlignmentBaseline.isPinned else {
                throw I2PWireError.invalidFormat
            }
            return "pinned \(snapshot.rowCount) rows; a failing test, lost results and a worse status each read as a regression, an improvement does not"
        }

        run("Alignment baseline · summary line reads in the singular and plural") {
            guard I2PAlignmentBaseline.summaryLine(regressedRows: 0) == "no rows regressed since the baseline",
                  I2PAlignmentBaseline.summaryLine(regressedRows: 1) == "1 row regressed since the baseline",
                  I2PAlignmentBaseline.summaryLine(regressedRows: 3) == "3 rows regressed since the baseline" else {
                throw I2PWireError.invalidFormat
            }
            return "0, 1 and 3 regressed rows read correctly"
        }

        return results
    }
}
