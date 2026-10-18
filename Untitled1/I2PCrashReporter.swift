//
//  I2PCrashReporter.swift
//  Persists the faulting context of a crash (signal + symbolicated backtrace)
//  so the next launch can surface the exact failure point in the crash-diagnostics
//  card — the equivalent of reading the crash log when no debugger is attached.
//

import Darwin
import Foundation

enum I2PCrashReporter {
    /// Installs handlers for every fatal-signal class. Idempotent.
    static func install() {
        for signalNumber in [SIGABRT, SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGTRAP] {
            var action = sigaction()
            sigemptyset(&action.sa_mask)
            action.sa_flags = 0
            // C function pointers cannot capture context; the signal number
            // arrives as the handler's argument and the log name is inlined.
            action.__sigaction_u.__sa_handler = { number in
                // Best-effort persistence of the faulting context. Foundation
                // calls here are not strictly async-signal-safe, but Swift
                // runtime traps (preconditions, out-of-bounds, force unwraps)
                // land after the faulting state is stable, so the report
                // virtually always gets out for the trap-class crashes.
                let stack = Thread.callStackSymbols.joined(separator: "\n")
                // Name the probe that was executing, when the crash happened
                // inside an audit run — the backtrace alone can be ambiguous
                // between audits, and a stale checkpoint from an older build
                // can point at the wrong probe entirely.
                let probeContext: String
                if let probe = I2PProductionAudit.activeProbeName {
                    probeContext = "\nactive probe: \(probe)"
                } else {
                    probeContext = ""
                }
                let report = """
                Signal \(number) at \(Date())
                thread: \(Thread.current.name ?? "unnamed")\(probeContext)
                \(stack)
                """
                let url = FileManager.default.temporaryDirectory
                    .appendingPathComponent("i2p-last-crash.log")
                try? report.write(to: url, atomically: true, encoding: .utf8)
                // Restore the default disposition and re-raise so the OS crash
                // pipeline still records the crash as well.
                signal(number, SIG_DFL)
                raise(number)
            }
            sigaction(signalNumber, &action, nil)
        }
    }

    /// Returns and retires the previous session's crash report, if any. The
    /// retired copy stays on disk until the next crash overwrites the slot.
    static func consumeLastCrashReport() -> String? {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("i2p-last-crash.log")
        guard let report = try? String(contentsOf: url, encoding: .utf8),
              !report.isEmpty else { return nil }
        let seen = url.deletingLastPathComponent()
            .appendingPathComponent("i2p-last-crash-seen.log")
        try? FileManager.default.removeItem(at: seen)
        try? FileManager.default.moveItem(at: url, to: seen)
        return report
    }

    /// Non-destructive read: surfaces the current crash report without
    /// retiring it, so an interrupted audit's banner can show the exact
    /// faulting context while the stability audit's diagnostics card still
    /// consumes the report on its own.
    static func peekLastCrashReport() -> String? {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("i2p-last-crash.log")
        guard let report = try? String(contentsOf: url, encoding: .utf8),
              !report.isEmpty else { return nil }
        return report
    }
}