//
//  LiveProbe/run.swift
//  Off-device harness for the live mainnet suite: compiles the I2P sources with
//  `swiftc` on a Mac and prints every row, so a failing check can be reproduced
//  and inspected without a device. Not part of the app target.
//
//  `@main` is legal here because this file is not named main.swift; the probes
//  that are named main.swift carry top-level code instead.
//
//    swiftc -swift-version 5 -o .probe-build/live \
//        Untitled1/I2P/*.swift LiveProbe/run.swift
//    ./.probe-build/live
//

import Foundation

@main
struct LiveProbe {
    static func main() async {
        let started = Date()
        let results = await I2PMainnetVerification.runAll { _, result in
            guard let result else { return }
            print("[\(result.passed ? "PASS" : "FAIL")] \(result.name)")
            print("       \(result.detail)")
        }
        print("----")
        print("summary: \(results.filter(\.passed).count)/\(results.count) in \(Int(Date().timeIntervalSince(started)))s")
        exit(0)
    }
}
