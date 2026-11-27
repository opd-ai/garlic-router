//
//  SelfTestProbe/main.swift
//  Off-device harness for the I2P self-test suites: compiles the I2P sources
//  with `swiftc` on a Mac and prints every result, so a failing suite can be
//  reproduced without the simulator. See INTEROP_REPORT.md for the workflow.
//
//    swiftc -swift-version 5 -o .probe-build/selftestprobe \
//        Untitled1/I2P/*.swift SelfTestProbe/main.swift
//    ./.probe-build/selftestprobe --all
//
//  Every suite the app runs now lives under I2P/ — including the eepsite
//  browser's navigation and share suites — so this harness covers all of them
//  and needs no stand-ins. Any failed check also makes the process exit nonzero,
//  so a shell or CI job cannot mistake printed failures for a successful run.
//

import Darwin
import Foundation

var results: [I2PSelfTestResult] = []

// `--progress` names each suite group before it runs and writes it straight out,
// so when the process traps or segfaults mid-run the group it died in is visible
// instead of the whole run's output being lost with the buffered results.
let progress: ((String) -> Void)? = CommandLine.arguments.contains("--progress")
    ? { name in FileHandle.standardOutput.write(Data("· \(name)\n".utf8)) }
    : nil

if CommandLine.arguments.contains("--all") {
    results += await I2PSelfTest.runAll(progress: progress)
}
if CommandLine.arguments.contains("--router-health") {
    results += I2PRouterHealthHistorySelfTest.runAll()
}
if CommandLine.arguments.contains("--netdb") {
    results += await I2PNetDBSelfTest.runAll()
}
if CommandLine.arguments.contains("--netdb-entries") {
    results += I2PNetDBEntriesSelfTest.runAll()
}
if CommandLine.arguments.contains("--ntcp2") {
    results += await I2PNTCP2SelfTest.runAll()
}
if CommandLine.arguments.contains("--tunnel") {
    results += await I2PTunnelSelfTest.runAll()
}
if CommandLine.arguments.contains("--i2np") {
    results += await I2NPSelfTest.runAll()
}
if CommandLine.arguments.contains("--garlic") {
    results += await I2PGarlicSelfTest.runAll()
}
if CommandLine.arguments.contains("--b33") {
    results += await I2PB33BlindingSelfTest.runAll()
}
if CommandLine.arguments.contains("--sam") {
    results += await I2PSAMConformanceTest.runAll()
}
if CommandLine.arguments.contains("--alignment") {
    // The Alignment tab's suite: run it directly, since the self-test card only
    // surfaces whatever an earlier alignment run left behind.
    let crossResults = await I2PCrossValidation.runAll()
    results += crossResults.map { result in
        I2PSelfTestResult(name: "[\(result.rowID)] \(result.name)",
                          passed: result.passed,
                          detail: "\(result.testID) · \(result.detail)")
    }
}
if CommandLine.arguments.contains("--spec") {
    // The I2P Core tab's spec conformance probes, runnable off-device.
    results += await I2PSpecConformanceAudit.runAll()
}

for result in results {
    print("\(result.passed ? "PASS" : "FAIL")  \(result.name)  — \(result.detail)")
}

let failures = results.filter { !$0.passed }.count
print("\n\(results.count - failures) passed, \(failures) failed")
if failures > 0 {
    exit(EXIT_FAILURE)
}
