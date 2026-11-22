//
//  I2PCrashReporter.swift
//  Persists a minimal fatal-signal marker for the next launch. The signal
//  handler uses only async-signal-safe operations; detailed backtraces remain
//  available from the operating system's crash-reporting tools.
//

import Darwin
import Foundation

private var i2pCrashSignalFileDescriptor: Int32 = -1

private func i2pFatalSignalHandler(_ number: Int32) {
    // Do not call Foundation, Swift runtime helpers, locks, or audit state from
    // a signal handler. A single-byte write is async-signal-safe and leaves the
    // OS's normal crash pipeline intact for the full symbolicated backtrace.
    let descriptor = i2pCrashSignalFileDescriptor
    if descriptor >= 0 {
        var signalByte = UInt8(truncatingIfNeeded: number)
        _ = Darwin.write(descriptor, &signalByte, MemoryLayout<UInt8>.size)
    }
    _ = Darwin.signal(number, SIG_DFL)
    _ = Darwin.raise(number)
}

enum I2PCrashReporter {
    private static let signalRecordName = "i2p-active-crash.signal"
    private static let lastSignalRecordName = "i2p-last-crash.signal"
    private static let legacyReportName = "i2p-last-crash.log"
    private static let seenSignalRecordName = "i2p-last-crash-seen.signal"
    private static let seenLegacyReportName = "i2p-last-crash-seen.log"
    private static let supportedSignals: [Int32] = [SIGABRT, SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGTRAP]

    /// Installs handlers for fatal signals. A prior run's marker is rotated
    /// before the active file is truncated, so launch diagnostics are retained.
    /// Repeated calls are harmless.
    static func install() {
        guard i2pCrashSignalFileDescriptor < 0 else { return }

        let directory = FileManager.default.temporaryDirectory
        let activeURL = directory.appendingPathComponent(signalRecordName)
        let lastURL = directory.appendingPathComponent(lastSignalRecordName)
        if let previousRecord = try? Data(contentsOf: activeURL),
           signalNumber(from: previousRecord) != nil {
            _ = unlink(lastURL.path)
            _ = rename(activeURL.path, lastURL.path)
        }

        let descriptor = activeURL.path.withCString {
            Darwin.open($0, O_CREAT | O_WRONLY | O_TRUNC | O_APPEND, S_IRUSR | S_IWUSR)
        }
        guard descriptor >= 0 else { return }
        i2pCrashSignalFileDescriptor = descriptor

        for signalNumber in supportedSignals {
            var action = sigaction()
            sigemptyset(&action.sa_mask)
            action.sa_flags = SA_RESETHAND
            action.__sigaction_u.__sa_handler = i2pFatalSignalHandler
            _ = sigaction(signalNumber, &action, nil)
        }
    }

    /// Returns and retires the previous session's crash report, if any. The
    /// retired copy stays on disk until the next crash overwrites the slot.
    static func consumeLastCrashReport() -> String? {
        guard let report = peekLastCrashReport() else { return nil }
        let directory = FileManager.default.temporaryDirectory
        let signalURL = directory.appendingPathComponent(lastSignalRecordName)
        if readSignalNumber(at: signalURL) != nil {
            let seenURL = directory.appendingPathComponent(seenSignalRecordName)
            _ = unlink(seenURL.path)
            _ = rename(signalURL.path, seenURL.path)
        } else {
            let legacyURL = directory.appendingPathComponent(legacyReportName)
            let seenURL = directory.appendingPathComponent(seenLegacyReportName)
            _ = unlink(seenURL.path)
            _ = rename(legacyURL.path, seenURL.path)
        }
        return report
    }

    /// Non-destructive read: surfaces the current crash report without
    /// retiring it, so an interrupted audit's banner can show the signal and
    /// its saved probe context.
    static func peekLastCrashReport() -> String? {
        let directory = FileManager.default.temporaryDirectory
        let signalURL = directory.appendingPathComponent(lastSignalRecordName)
        if let signalNumber = readSignalNumber(at: signalURL) {
            let capturedAt = (try? signalURL.resourceValues(forKeys: [.contentModificationDateKey]))?
                .contentModificationDate ?? .distantPast
            let checkpointTime = UserDefaults.standard.object(forKey: I2PProductionAudit.checkpointTimeKey) as? Date
            let activeProbe: String?
            if let checkpointTime,
               checkpointTime <= capturedAt,
               capturedAt.timeIntervalSince(checkpointTime) <= 15 * 60 {
                activeProbe = UserDefaults.standard.string(forKey: I2PProductionAudit.checkpointKey)
            } else {
                activeProbe = nil
            }
            return formatSignalReport(signalNumber: signalNumber, capturedAt: capturedAt,
                                      activeProbe: activeProbe)
        }

        // Preserve reports produced by earlier versions, which used a text file.
        let legacyURL = directory.appendingPathComponent(legacyReportName)
        guard let report = try? String(contentsOf: legacyURL, encoding: .utf8),
              !report.isEmpty else { return nil }
        return report
    }

    /// Formats the signal marker outside the signal context. Kept pure so the
    /// format and its edge cases can be exercised without crashing a test run.
    static func formatSignalReport(signalNumber: Int32, capturedAt: Date,
                                   activeProbe: String?) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss Z"
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)

        var lines = [
            "Signal \(signalNumber) at \(formatter.string(from: capturedAt))",
            "thread: unavailable"
        ]
        if let activeProbe, !activeProbe.isEmpty {
            lines.append("active probe: \(activeProbe)")
        }
        lines.append("Backtrace unavailable in the signal-safe report; see the device's system crash report for stack details.")
        return lines.joined(separator: "\n")
    }

    /// Extracts a supported signal number from the one-byte on-disk record.
    static func signalNumber(from record: Data) -> Int32? {
        guard record.count == 1, let byte = record.first else { return nil }
        let number = Int32(byte)
        return supportedSignals.contains(number) ? number : nil
    }

    private static func readSignalNumber(at url: URL) -> Int32? {
        guard let record = try? Data(contentsOf: url) else { return nil }
        return signalNumber(from: record)
    }

    /// The banner-relevant slice of the report: signal and saved probe context,
    /// plus the explicit note explaining where the backtrace can be found.
    static func diagnosticHead(maxFrames: Int = 6) -> String {
        guard let report = peekLastCrashReport() else { return "" }
        let lines = report.split(separator: "\n").map(String.init)
        var head: [String] = []
        for line in lines {
            if line.hasPrefix("Signal ") || line.hasPrefix("thread:")
                || line.hasPrefix("active probe: ") {
                head.append(line)
            } else {
                break
            }
        }
        let appFrames = lines.filter {
            $0.contains("Untitled1") && !$0.contains("I2PCrashReporter")
        }.prefix(maxFrames)
        if appFrames.isEmpty {
            if let note = lines.first(where: { $0.hasPrefix("Backtrace unavailable") }) {
                head.append(note)
            }
        } else {
            head.append(contentsOf: appFrames)
        }
        return head.joined(separator: "\n")
    }

    /// Structured view of the current crash report: when it was captured and
    /// which audit probe was active, when that checkpoint is current.
    static func lastCrashContext() -> (date: Date, activeProbe: String?)? {
        guard let report = peekLastCrashReport() else { return nil }
        let lines = report.split(separator: "\n").map(String.init)

        var date: Date?
        if let header = lines.first, header.hasPrefix("Signal "),
           let atRange = header.range(of: " at ") {
            let timestamp = String(header[atRange.upperBound...])
            let formatter = DateFormatter()
            formatter.dateFormat = "yyyy-MM-dd HH:mm:ss Z"
            formatter.locale = Locale(identifier: "en_US_POSIX")
            formatter.timeZone = TimeZone(secondsFromGMT: 0)
            date = formatter.date(from: timestamp)
        }

        var activeProbe: String?
        for line in lines where line.hasPrefix("active probe: ") {
            activeProbe = String(line.dropFirst("active probe: ".count)).trimmingCharacters(in: .whitespaces)
        }

        guard let capturedAt = date ?? lines.first.map({ _ in Date.distantPast }) else { return nil }
        return (capturedAt, activeProbe)
    }
}
