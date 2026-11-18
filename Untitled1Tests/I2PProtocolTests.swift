//
//  I2PProtocolTests.swift
//  Runs the app's own I2P suites from the unit test target, so a regression in
//  the protocol layer or in the client logic fails CI instead of compiling into
//  a green build. Each suite is already a static, dependency-free function; this
//  file is only the adapter.
//

import Testing
@testable import Untitled1

struct I2PProtocolTests {

    /// Every cross-validation case, each tagged with its truth-table row.
    @Test func crossValidationSuitePasses() async {
        let results = await I2PCrossValidation.runAll()
        let failed = results.filter { !$0.passed }
        #expect(failed.isEmpty,
                "failing cases: \(failed.map { "\($0.testID) — \($0.detail)" })")
    }

    /// The core crypto, structure and wire-format checks.
    @Test func coreSuitePasses() {
        let failed = I2PSelfTest.runCoreTests().filter { !$0.passed }
        #expect(failed.isEmpty,
                "failing checks: \(failed.map { "\($0.name) — \($0.detail)" })")
    }

    /// The pure client logic: the IRC grammar and chat state, the latency
    /// reading, history, snoozes, and the browser's bookmarks. No sockets and no
    /// router, so they are deterministic in CI.
    @Test func clientLogicSuitesPass() {
        var results: [I2PSelfTestResult] = []
        results += I2PIRCProtocolSelfTest.runAll()
        results += I2PIRCChatStateSelfTest.runAll()
        results += I2PIRCMemberListSelfTest.runAll()
        results += I2PIRCLatencySelfTest.runAll()
        results += I2PIRCHistorySelfTest.runAll()
        results += I2PIRCSnoozeSelfTest.runAll()
        results += I2PSavedHostsSelfTest.runAll()
        results += I2PRouterPlainStatusSelfTest.runAll()
        results += I2PLiveInteropSelfTest.runAll()
        let failed = results.filter { !$0.passed }
        #expect(failed.isEmpty,
                "failing checks: \(failed.map { "\($0.name) — \($0.detail)" })")
    }

    /// The truth table and the code it describes must not drift apart: the rows
    /// that name wire layouts read their type codes from `I2NPMessageType`, and
    /// the enum itself is pinned to the spec's table here.
    @Test func truthTableNamesTheSpecTypeCodes() {
        #expect(I2NPMessageType.tunnelGateway.rawValue == 19)
        #expect(I2NPMessageType.dataMessage.rawValue == 20)
        #expect(I2NPMessageType.garlic.rawValue == 11)
        for (rowID, testID) in [("NP-TUNGW", "T4-NP-TUNGW-RT"), ("NP-DATA", "T4-NP-DATA-RT")] {
            guard let row = I2PSpecTruthTable.row(id: rowID) else {
                Issue.record("truth table has no \(rowID) row")
                continue
            }
            #expect(row.testIDs.contains(testID), "\(rowID) does not list \(testID)")
        }
    }
}
