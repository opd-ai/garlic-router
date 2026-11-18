//
//  ProbeStubs.swift
//  Stand-ins for the two self-test suites that live inside a SwiftUI view file
//  (EepsiteBrowserView.swift), which the Foundation-only probe build cannot
//  compile.
//
//  They exist so the documented off-device command works as written:
//
//    swiftc -swift-version 5 -o .probe-build/selftestprobe \
//        Untitled1/I2P/*.swift SelfTestProbe/ProbeStubs.swift SelfTestProbe/main.swift
//
//  The real suites still run in the app and in the unit test target; only the
//  off-device harness skips them.
//

import Foundation

enum I2PEepsiteVisitStackSelfTest {
    static func runAll() -> [I2PSelfTestResult] { [] }
}

enum I2PEepsiteShareSelfTest {
    static func runAll() -> [I2PSelfTestResult] { [] }
}
