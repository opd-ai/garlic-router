// Offline CI harness: runs the live mainnet suite against the real code on a
// machine with network access, so failures can be inspected without a device.
// Not part of the app target (it lives outside Untitled1/).
//
// Top-level code on purpose: this file is named main.swift, which already
// provides the entry point, so an `@main` type here does not compile.

import Foundation

let started = Date()
let results = await I2PMainnetVerification.runAll { _, result in
    if let result {
        print("[\(result.passed ? "PASS" : "FAIL")] \(result.name)")
        print("       \(result.detail)")
    }
}
print("----")
let passed = results.filter(\.passed).count
print("summary: \(passed)/\(results.count) in \(Int(Date().timeIntervalSince(started)))s")
exit(0)
