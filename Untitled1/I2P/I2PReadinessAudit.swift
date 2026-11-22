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
/// probes once, serially, and persists the active probe (plus the moment it
/// became active) so an OS termination is diagnosable on the next launch.
enum I2PReadinessAudit {
    /// The phase the audit was interrupted in, plus when the checkpoint was
    /// written. The timestamp distinguishes a fresh interruption from a stale
    /// checkpoint left behind by an older app version, which only wrote the
    /// phase without a time.
    struct Checkpoint {
        let phase: String
        let savedAt: Date?
    }

    /// Checkpoint keys live on I2PProductionAudit — the checkpointing (per-probe,
    /// timestamped) belongs to the probe engine itself, so BOTH the readiness
    /// audit and the standalone production-audit button persist durable progress
    /// under the same keys.
    static var interruptedCheckpoint: Checkpoint? {
        guard let phase = UserDefaults.standard.string(forKey: I2PProductionAudit.checkpointKey) else {
            return nil
        }
        let savedAt = UserDefaults.standard.object(forKey: I2PProductionAudit.checkpointTimeKey) as? Date
        return Checkpoint(phase: phase, savedAt: savedAt)
    }

    /// Backwards-compatible accessor for the raw interrupted phase.
    static var interruptedPhase: String? {
        UserDefaults.standard.string(forKey: I2PProductionAudit.checkpointKey)
    }

    /// A user-facing notice describing the interrupted run. When the checkpoint
    /// carries a save time it is shown; a checkpoint without one was written by
    /// an earlier app version and says so, so a leftover banner cannot be
    /// mistaken for a fresh failure.
    static func interruptionNotice() -> String? {
        guard let checkpoint = interruptedCheckpoint else { return nil }
        if let savedAt = checkpoint.savedAt {
            let formatter = DateFormatter()
            formatter.dateStyle = .short
            formatter.timeStyle = .short
            return "The previous run stopped during: \(checkpoint.phase), saved \(formatter.string(from: savedAt)). The active probe is saved so interruptions can be diagnosed."
        }
        return "An earlier app version left a checkpoint from a run that stopped during: \(checkpoint.phase). Run the audit again on this version to refresh the diagnosis."
    }

    static func runAll(
        onProgress: (String, I2PSelfTestResult?) async -> Void = { _, _ in }
    ) async -> [I2PSelfTestResult] {
        // Per-probe timestamped checkpointing happens inside the shared audit
        // engine; launch diagnostics associate it with a signal marker safely.
        let productionResults = await I2PProductionAudit.runAll { phase, result in
            await onProgress(phase, result)
        }

        return productionResults.map { result in
            I2PSelfTestResult(
                name: "Readiness · \(result.name)",
                passed: result.passed,
                detail: result.detail)
        }
    }
}