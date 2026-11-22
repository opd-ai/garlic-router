//
//  I2PAlignmentReportShare.swift
//  The Alignment report as the share sheet gets it: the coverage the header
//  shows, the last suite run, one line per truth-table row (component, status
//  and passing test count) and the ids and details of any failing test — all as
//  plain text, with the app version named so an export carries its provenance.
//
//  The text says plainly when a row is pending wire verification rather than
//  passing, since such a row matches the spec structurally but has not been
//  byte-level cross-validated against reference vectors. Nothing about peers,
//  sessions or destinations is in it: the truth table and the compliance suite
//  are the only sources.
//

import Foundation

// MARK: - Payload

struct I2PAlignmentReportSharePayload: Equatable {
    /// What the share sheet shows as its subject.
    let subject: String
    /// The report itself, plain text.
    let text: String
}

// MARK: - Report

enum I2PAlignmentReportShare {

    static let appName = "garlic-router"

    /// The share payload for the current report state.
    ///
    /// `rows` is what the screen is showing: when the report is filtered, the
    /// export carries only those rows (and only their failing tests), so a
    /// shared report never claims more than the reader sees.
    static func payload(results: [I2PCrossValidationResult],
                        lastRunAt: Date?,
                        rows: [I2PSpecRow] = I2PSpecTruthTable.rows,
                        generatedAt: Date = Date(),
                        appVersion: String = I2PAlignmentReportShare.currentVersion()) -> I2PAlignmentReportSharePayload {
        I2PAlignmentReportSharePayload(
            subject: "\(appName) alignment report",
            text: text(results: results,
                       lastRunAt: lastRunAt,
                       rows: rows,
                       generatedAt: generatedAt,
                       appVersion: appVersion))
    }

    /// The app's marketing version alone ('1.0'), as the bundle carries it.
    /// The JSON export's file name uses this rather than `currentVersion`,
    /// which adds the build number for the exported report's provenance line.
    static func marketingVersion(from bundle: Bundle = .main) -> String {
        let short = bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
        return (short ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// The app's marketing version and build number, as the bundle carries
    /// them, so an exported report says which build produced it.
    static func currentVersion(from bundle: Bundle = .main) -> String {
        let build = bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String
        let version = marketingVersion(from: bundle)
        let buildNumber = (build ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        if !version.isEmpty && !buildNumber.isEmpty {
            return "\(version) (build \(buildNumber))"
        }
        if !version.isEmpty { return version }
        if !buildNumber.isEmpty { return "build \(buildNumber)" }
        return "version unavailable"
    }

    // MARK: Text

    /// The report as plain text, top to bottom: provenance, coverage and run
    /// time, every truth-table row, then the failing tests.
    static func text(results: [I2PCrossValidationResult],
                     lastRunAt: Date?,
                     rows: [I2PSpecRow] = I2PSpecTruthTable.rows,
                     generatedAt: Date = Date(),
                     appVersion: String = I2PAlignmentReportShare.currentVersion()) -> String {
        let coverage = I2PSpecTruthTable.coverage
        var lines: [String] = []

        lines.append("\(appName) — alignment report")
        lines.append("App version: \(appVersion)")
        lines.append("Exported: \(timestamp(generatedAt))")
        lines.append("")

        lines.append("Overall alignment coverage")
        lines.append("  " + [
            "\(coverage.aligned) aligned",
            "\(coverage.deviationDocumented) deviations documented",
            "\(coverage.pendingWireVerification) pending wire verification",
            "\(coverage.defect) defects",
        ].joined(separator: " · ") + " — of \(coverage.total) truth-table rows")
        if results.isEmpty {
            lines.append("  Cross-validation suite: not run")
        } else {
            let passing = results.filter(\.passed).count
            lines.append("  Cross-validation suite: \(passing) of \(results.count) tests passed")
        }
        lines.append("  Last suite run: \(lastRunAt.map { timestamp($0) } ?? "not run yet")")

        if coverage.pendingWireVerification > 0 {
            lines.append("")
            lines.append("Pending wire verification is not passing evidence. Those rows match the "
                         + "specification structurally, but they have not been byte-level cross-validated "
                         + "against reference vectors.")
        }
        lines.append("")

        lines.append("Truth table — one line per requirement row")
        if rows.count != I2PSpecTruthTable.rows.count {
            lines.append("  Showing \(rows.count) of \(I2PSpecTruthTable.rows.count) rows (filtered on screen).")
        }
        for row in rows {
            lines.append(rowLine(row, results: results))
        }
        lines.append("")

        let shownRowIDs = Set(rows.map(\.id))
        let failures = results.filter { !$0.passed && shownRowIDs.contains($0.rowID) }
        if failures.isEmpty {
            lines.append(results.isEmpty
                         ? "Failing tests: the suite has not been run."
                         : "Failing tests: none.")
        } else {
            lines.append("Failing tests (\(failures.count))")
            for failure in failures {
                lines.append("  \(failure.testID) [row \(failure.rowID)] \(failure.name)")
                let detail = failure.detail.trimmingCharacters(in: .whitespacesAndNewlines)
                lines.append("    \(detail.isEmpty ? "No detail recorded." : detail)")
            }
        }

        return lines.joined(separator: "\n")
    }

    // MARK: Rows

    /// One truth-table row: its id, its component, its status in plain words
    /// and how many of its tests pass.
    static func rowLine(_ row: I2PSpecRow, results: [I2PCrossValidationResult]) -> String {
        "  \(row.id) [\(row.component.displayName)] · \(statusText(row.status)) · \(testText(row, results: results))"
    }

    /// The status as a reader of an exported report should understand it, with
    /// a pending row never reading as a pass.
    static func statusText(_ status: I2PAlignmentStatus) -> String {
        switch status {
        case .aligned: return "aligned"
        case .deviationDocumented: return "deviation documented"
        case .pendingWireVerification: return "pending wire verification (not passing)"
        case .defect: return "defect"
        }
    }

    /// The passing test count for one row, or 'no tests run' when the suite has
    /// not run or has no test tagged with the row.
    static func testText(_ row: I2PSpecRow, results: [I2PCrossValidationResult]) -> String {
        let group = results.filter { $0.rowID == row.id }
        guard !group.isEmpty else { return "no tests run" }
        return "\(group.filter(\.passed).count) of \(group.count) tests passing"
    }

    // MARK: Formatting

    /// A fixed, locale-independent timestamp so a shared report reads the same
    /// wherever it is opened.
    private static let timestampFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd HH:mm"
        return formatter
    }()

    private static func timestamp(_ date: Date) -> String {
        timestampFormatter.string(from: date)
    }
}
