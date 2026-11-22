//
//  I2PAlignmentJSONExportTests.swift
//  Pins the Alignment screen's JSON export: the file is named for the app
//  version and the export date, and it carries the whole truth table — every
//  row with its wire layout, encoding rules, crypto parameters and edge cases —
//  with nothing about peers, sessions or destinations.
//

import Foundation
import Testing
@testable import Untitled1

struct I2PAlignmentJSONExportTests {

    @Test func fileNameCarriesVersionAndExportDate() {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd"
        let date = Date(timeIntervalSince1970: 1_763_337_600)

        let name = I2PAlignmentJSONExport.fileName(appVersion: "1.0", generatedAt: date)

        #expect(name == "garlic-router-alignment-1.0-\(formatter.string(from: date)).json")
        #expect(name.hasPrefix("garlic-router-alignment-1.0-"))
        #expect(name.hasSuffix(".json"))
    }

    @Test func versionComponentKeepsWhatAFileNameCanCarry() {
        #expect(I2PAlignmentJSONExport.versionComponent("1.0") == "1.0")
        #expect(I2PAlignmentJSONExport.versionComponent("1.0.2") == "1.0.2")
        #expect(I2PAlignmentJSONExport.versionComponent("1.0 (build 42)").hasPrefix("1.0"))
        #expect(I2PAlignmentJSONExport.versionComponent("") == "unknown")
        #expect(I2PAlignmentJSONExport.versionComponent("   ") == "unknown")
    }

    @Test func exportCarriesTheWholeTableAndNothingElse() throws {
        let export = try #require(I2PAlignmentJSONExport.export(appVersion: "1.0"))
        #expect(export.subject == "garlic-router alignment truth table")

        let json = try JSONSerialization.jsonObject(with: export.data)
        let object = try #require(json as? [String: Any])

        let rows = try #require(object["rows"] as? [[String: Any]])
        #expect(rows.count == I2PSpecTruthTable.rows.count)
        #expect(object["coverage"] != nil)
        #expect(object["intentionalDeviations"] != nil)
        #expect(object["defects"] != nil)

        for key in ["wireLayout", "encodingRules", "cryptoParameters", "edgeCases"] {
            #expect(rows.allSatisfy { $0[key] != nil }, "a row is missing \(key)")
        }
        for key in ["peers", "sessions", "destinations"] {
            #expect(object[key] == nil, "the export carries \(key)")
        }
    }
}
