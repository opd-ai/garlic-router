//
//  I2PReadinessAudit.swift
//  Runs the production probes serially and checkpoints progress for diagnosis.
//

import Foundation

/// Production-readiness checks deliberately reuse the executable probes from
/// the dedicated production audit. The previous implementation nested the full
/// cross-validation, SAM, transport and self-test suites inside one tap and then
/// repeated several checks again. That created a large, redundant crypto/socket
/// workload with no intermediate results. This wrapper runs the production
/// probes once, serially, and persists the active probe so an OS termination is
/// diagnosable on the next launch.
enum I2PReadinessAudit {
    private static let checkpointKey = "i2p.readinessAudit.activeProbe"

    static var interruptedPhase: String? {
        UserDefaults.standard.string(forKey: checkpointKey)
    }

    static func runAll(
        onProgress: (String, I2PSelfTestResult?) async -> Void = { _, _ in }
    ) async -> [I2PSelfTestResult] {
        let productionResults = await I2PProductionAudit.runAll { phase, result in
            if result == nil {
                UserDefaults.standard.set(phase, forKey: checkpointKey)
                UserDefaults.standard.synchronize()
            }
            await onProgress(phase, result)
        }

        UserDefaults.standard.removeObject(forKey: checkpointKey)
        UserDefaults.standard.synchronize()

        return productionResults.map { result in
            I2PSelfTestResult(
                name: "Readiness · \(result.name)",
                passed: result.passed,
                detail: result.detail)
        }
    }
}
