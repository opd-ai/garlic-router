//
//  AuditReportCountsTests.swift
//  Untitled1Tests
//
//  The Alignment tab's severity chips are read out of the bundled report rather
//  than stored beside it, so they cannot drift from the findings a reader
//  scrolls through. These cases pin the parse, the nil it returns when there is
//  nothing to count, and the figures of the report the app actually ships.
//

import Foundation
import Testing
@testable import Untitled1

struct AuditReportCountsTests {

    /// Each finding is a heading shaped `### 5.1 F-01 — HIGH — title`. A heading
    /// naming two severities counts as the higher one, which is how the report's
    /// own summary ranks it; a heading that is not a finding is not counted.
    @Test func severityCountsAreReadFromTheFindingHeadings() {
        let markdown = """
        # Defensive end-to-end audit

        ### 5.1 F-01 — HIGH — a high finding
        ### 5.2 F-02 — MEDIUM — a medium one
        ### 5.7 F-07 — LOW/MEDIUM — a mixed one
        ### 5.10 F-10 — LOW — a tenth one

        ## 2. Specification compliance
        ### 2.1 What the specification confirms as correct (STATIC)
        """

        let counts = I2PAuditReport.severityCounts(in: markdown)
        #expect(counts == I2PAuditReport.SeverityCounts(high: 1, medium: 2, low: 1))
        #expect(counts?.total == 4)
    }

    /// Without findings there is nothing to count, and the screen says so rather
    /// than showing zeros as if the report held none.
    @Test func severityCountsAreNilWithoutFindingHeadings() {
        #expect(I2PAuditReport.severityCounts(in: "") == nil)
        #expect(I2PAuditReport.severityCounts(in: "# A title\n\nSome prose.") == nil)
    }

    /// The document the app bundles is the one the chips count, so a report that
    /// gained or lost a finding cannot leave stale figures on the screen.
    @Test func bundledReportHasTenFindings() throws {
        let markdown = try #require(I2PAuditReport.markdown(),
                                    "AUDIT-2026-11-17.md is not in the app bundle")
        let counts = try #require(I2PAuditReport.severityCounts(in: markdown))
        #expect(counts.total == 10)
        #expect(counts.high == 1)
        #expect(counts.medium == 6)
        #expect(counts.low == 3)
    }
}
