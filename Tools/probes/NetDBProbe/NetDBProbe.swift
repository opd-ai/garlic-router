// NetDB regression harness: runs the in-process netdb suite against the real
// code after the routing-index fixes. Not part of the app target.

import Foundation

@main
struct NetDBProbe {
    static func main() async {
        let results = await I2PNetDBSelfTest.runAll()
        var passed = 0
        for result in results {
            print("[\(result.passed ? "PASS" : "FAIL")] \(result.name)")
            if !result.passed || true { print("       \(result.detail)") }
            if result.passed { passed += 1 }
        }
        print("summary: \(passed)/\(results.count)")
        exit(0)
    }
}
