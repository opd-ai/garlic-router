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

import Foundation

var results: [I2PSelfTestResult] = []
if CommandLine.arguments.contains("--all") {
    results += await I2PSelfTest.runAll()
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

for result in results {
    print("\(result.passed ? "PASS" : "FAIL")  \(result.name)  — \(result.detail)")
}

let failures = results.filter { !$0.passed }.count
print("\n\(results.count - failures) passed, \(failures) failed")
