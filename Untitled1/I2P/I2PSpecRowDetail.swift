//
//  I2PSpecRowDetail.swift
//  Untitled1
//
//  The full requirement detail of one truth-table row, assembled for the spec
//  row detail sheet: the reference fields (spec section, Java reference class,
//  Swift component), the documented sections (wire layout, encoding rules,
//  cryptographic parameters, edge cases), the row's status with its deviation
//  when one is recorded, and every cross-validation test tagged with the row —
//  with its result and detail text, or as not run when the suite holds no
//  result for it.
//
//  Pure data assembly (Foundation only) so the sheet renders it directly and
//  the grouping can be reasoned about without a view.
//

import Foundation

// MARK: - Model

/// One label/value field of the sheet's reference card.
struct I2PSpecRowReference: Identifiable, Equatable {
    /// Short field label: "Spec", "Java", "Swift".
    let label: String
    /// What the row records for that field, in full.
    let value: String

    var id: String { label }
}

/// One titled prose section of the row.
struct I2PSpecRowSection: Identifiable, Equatable {
    /// Section title, e.g. "Wire layout". The sheet renders it uppercased,
    /// matching the report's card titles.
    let title: String
    let body: String

    var id: String { title }
}

/// One cross-validation test tagged with the row.
struct I2PSpecRowTestEntry: Identifiable, Equatable {
    /// The truth-table test tag, e.g. "T4-NT-M1-OBF".
    let testID: String
    /// The test's human name, when a result was recorded for it.
    let name: String?
    /// `nil` when the suite holds no result for the test.
    let passed: Bool?
    /// What the test observed: the pass detail or the failure text.
    let detail: String

    var id: String { testID }

    /// Whether the suite has run this test since it was tagged.
    var isRecorded: Bool { passed != nil }
}

/// Everything one truth-table row records, ready for the detail sheet.
struct I2PSpecRowDetail {
    let row: I2PSpecRow
    /// Every test tagged with the row: the recorded results in suite order,
    /// then the row's declared tags the suite holds no result for.
    let testEntries: [I2PSpecRowTestEntry]

    init(row: I2PSpecRow, results: [I2PCrossValidationResult]) {
        self.row = row

        var entries: [I2PSpecRowTestEntry] = results
            .filter { $0.rowID == row.id }
            .map { result in
                I2PSpecRowTestEntry(testID: result.testID,
                                    name: result.name,
                                    passed: result.passed,
                                    detail: result.detail)
            }
        let recorded = Set(entries.map(\.testID))
        for testID in row.testIDs where !recorded.contains(testID) {
            entries.append(I2PSpecRowTestEntry(
                testID: testID,
                name: nil,
                passed: nil,
                detail: "No result recorded — the cross-validation suite has not run this test."))
        }
        testEntries = entries
    }

    // MARK: Reference

    /// The row's traceability, in reading order.
    var reference: [I2PSpecRowReference] {
        [
            I2PSpecRowReference(label: "Spec", value: row.specSection),
            I2PSpecRowReference(label: "Java", value: row.javaReference),
            I2PSpecRowReference(label: "Swift", value: row.swiftComponent),
        ]
        .filter { !$0.value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
    }

    // MARK: Sections

    /// The documented sections, in the order the report lists them. A section
    /// the row leaves empty is dropped rather than shown blank.
    var sections: [I2PSpecRowSection] {
        [
            I2PSpecRowSection(title: "Wire layout", body: row.wireLayout),
            I2PSpecRowSection(title: "Encoding rules", body: row.encodingRules),
            I2PSpecRowSection(title: "Cryptographic parameters", body: row.cryptoParameters),
            I2PSpecRowSection(title: "Edge cases", body: row.edgeCases),
        ]
        .filter { !$0.body.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
    }

    // MARK: Status

    /// The status as the sheet's pill shows it, short enough to sit beside the
    /// row id.
    var statusTitle: String {
        switch row.status {
        case .aligned: return "Aligned"
        case .pendingWireVerification: return "Pending"
        case .deviationDocumented: return "Deviation"
        case .defect: return "Defect"
        }
    }

    /// What the status means, in the report's own terms: a pending row never
    /// reads as passing evidence.
    var statusExplanation: String {
        switch row.status {
        case .aligned:
            return "Aligned — matches the specification, with the cross-validation tests below covering it."
        case .pendingWireVerification:
            return "Pending wire verification — structurally per spec, but byte-level cross-validation against reference vectors has not completed, so this row is not passing evidence."
        case .deviationDocumented:
            return "Deviation documented — the implementation deliberately differs from the specification; the rationale is recorded below."
        case .defect:
            return "Defect — a known divergence from the specification, with the fix tracked below."
        }
    }

    // MARK: Tests

    var recordedTestCount: Int {
        testEntries.filter(\.isRecorded).count
    }

    var passedTestCount: Int {
        testEntries.filter { $0.passed == true }.count
    }

    var unrecordedTestCount: Int {
        testEntries.filter { !$0.isRecorded }.count
    }

    /// The pass line above the test rows, e.g. "3 of 4 tests passing · 1 not run".
    var testSummary: String {
        if testEntries.isEmpty {
            return "No cross-validation test is tagged with this row."
        }
        guard recordedTestCount > 0 else {
            return "Not run — no result recorded for the \(testEntries.count) tests tagged with this row."
        }
        var summary = "\(passedTestCount) of \(recordedTestCount) tests passing"
        if unrecordedTestCount > 0 {
            summary += " · \(unrecordedTestCount) not run"
        }
        return summary
    }
}
