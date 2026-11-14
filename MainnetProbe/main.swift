// Offline CI harness: runs the live mainnet suite against the real code on a
// machine with network access, so failures can be inspected without a device.
// Not part of the app target (it lives outside Untitled1/).

import Foundation

@main
struct MainnetProbe {
    static func main() async {
        let started = Date()
        let results = await I2PMainnetVerification.runAll { _, result in
            if let result {
                print("[\(result.passed ? "PASS" : "FAIL")] \(runnableName(result))")
                print("       \(result.detail)")
            }
        }
        print("----")
        var passed = 0
        for result in results where result.passed { passed += 1 }
        print("summary: \(passed)/\(results.count) in \(Int(Date().timeIntervalSince(started)))s")
        exit(0)
    }

    static func runnableName(_ result: I2PSelfTestResult) -> String {
        result.name
    }
}
