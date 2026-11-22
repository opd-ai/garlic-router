//
//  I2PProtocolTests.swift
//  Runs the app's own I2P suites from the unit test target, so a regression in
//  the protocol layer or in the client logic fails CI instead of compiling into
//  a green build. Each suite is already a static, dependency-free function; this
//  file is only the adapter.
//

import Darwin
import Foundation
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
        results += I2PEepsiteContentsSelfTest.runAll()
        results += I2PRouterPlainStatusSelfTest.runAll()
        results += I2PLiveInteropSelfTest.runAll()
        results += I2PIRCServerBookSelfTest.runAll()
        results += I2PPeerNicknamesSelfTest.runAll()
        let failed = results.filter { !$0.passed }
        #expect(failed.isEmpty,
                "failing checks: \(failed.map { "\($0.name) — \($0.detail)" })")
    }

    @Test func netDBEntryBrowserProjectionPasses() {
        let failed = I2PNetDBEntriesSelfTest.runAll().filter { !$0.passed }
        #expect(failed.isEmpty,
                "failing checks: \(failed.map { "\($0.name) — \($0.detail)" })")
    }

    /// Tunnel-pool and router-status loopback suites cover the totals shown on
    /// the dashboard as well as the live snapshot stream.
    @Test func tunnelPoolSuitePasses() async {
        let failed = await I2PTunnelSelfTest.runAll().filter { !$0.passed }
        #expect(failed.isEmpty,
                "failing checks: \(failed.map { "\($0.name) — \($0.detail)" })")
    }

    @Test func routerStatusSuitePasses() async {
        let failed = await I2PRouterStatusSelfTest.runAll().filter { !$0.passed }
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

    @Test func crashSignalRecordAndReportAreBoundedAndHonest() {
        let signal = Int32(SIGABRT)
        let validMarker = Data([UInt8(truncatingIfNeeded: signal)])
        #expect(I2PCrashReporter.signalNumber(from: validMarker) == signal)
        #expect(I2PCrashReporter.signalNumber(from: Data()) == nil)
        #expect(I2PCrashReporter.signalNumber(from: Data([validMarker[0], 0])) == nil)
        #expect(I2PCrashReporter.signalNumber(from: Data([0])) == nil)

        let capturedAt = Date(timeIntervalSince1970: 1_700_000_000)
        let report = I2PCrashReporter.formatSignalReport(
            signalNumber: signal,
            capturedAt: capturedAt,
            activeProbe: "NTCP2 handshake"
        )
        #expect(report.contains("Signal \(signal) at 2023-11-14 22:13:20 +0000"))
        #expect(report.contains("active probe: NTCP2 handshake"))
        #expect(report.contains("Backtrace unavailable in the signal-safe report"))
        #expect(!report.contains("thread: main"))
    }
}
