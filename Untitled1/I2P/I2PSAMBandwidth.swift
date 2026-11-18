//
//  I2PSAMBandwidth.swift
//  Per-session bandwidth ceilings for SAM sessions: the cap a single client's
//  stream and datagram sends may ride, saved per session key so the same
//  client comes back to the same ceiling, plus the bridge's rate labels.
//

import Foundation

/// The saved per-session ceilings of the SAM bridge, in KB/s, keyed by the
/// session key the bridge knows a session by (its SAM session ID). A cap of
/// zero means the session is uncapped, which is also what an unknown key
/// reports.
final class I2PSAMSessionCaps: @unchecked Sendable {
    static let shared = I2PSAMSessionCaps()

    /// A session cap runs from off (0) up to the router-wide cap ceiling.
    static let maxCapKBps = I2PParticipationSettings.maxCapKBps

    private static let storageKey = "i2p.sam.sessionCapsKBps"

    private let defaults: UserDefaults
    private let lock = NSLock()
    private var caps: [String: Int]

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        let stored = defaults.dictionary(forKey: Self.storageKey) ?? [:]
        var loaded: [String: Int] = [:]
        for (key, value) in stored {
            if let number = value as? Int {
                loaded[key] = Self.clamp(number)
            } else if let number = value as? NSNumber {
                loaded[key] = Self.clamp(number.intValue)
            }
        }
        self.caps = loaded
    }

    /// The saved ceiling for a session key, in KB/s (0 = uncapped).
    func capKBps(for key: String) -> Int {
        let trimmed = Self.normalize(key)
        lock.lock()
        defer { lock.unlock() }
        return caps[trimmed] ?? 0
    }

    /// Saves a session key's ceiling. Zero clears it: an uncapped session keeps
    /// no entry, so an unknown and a cleared key read the same.
    func setCapKBps(_ value: Int, for key: String) {
        let trimmed = Self.normalize(key)
        guard !trimmed.isEmpty else { return }
        let clamped = Self.clamp(value)
        lock.lock()
        if clamped == 0 {
            caps[trimmed] = nil
        } else {
            caps[trimmed] = clamped
        }
        persistLocked()
        lock.unlock()
    }

    /// Every saved ceiling, as an overview of what the bridge remembers.
    func all() -> [String: Int] {
        lock.lock()
        defer { lock.unlock() }
        return caps
    }

    func removeCap(for key: String) {
        let trimmed = Self.normalize(key)
        lock.lock()
        caps[trimmed] = nil
        persistLocked()
        lock.unlock()
    }

    // MARK: Internals

    private func persistLocked() {
        defaults.set(caps, forKey: Self.storageKey)
    }

    private static func normalize(_ key: String) -> String {
        key.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Clamps a typed or saved cap into the supported range.
    static func clamp(_ value: Int) -> Int {
        min(max(value, 0), maxCapKBps)
    }
}

/// Rate and cap labels for the SAM screen's session rows.
enum I2PSAMBandwidthFormat {
    /// "405 B/s" or "12.3 KB/s" for a measured rate.
    static func rate(_ bytesPerSecond: Double) -> String {
        let value = max(0, bytesPerSecond)
        guard value >= 1024 else {
            return String(format: "%.0f B/s", value)
        }
        return String(format: "%.1f KB/s", value / 1024)
    }

    /// "64 KB/s" or "off" for a ceiling in KB/s.
    static func cap(_ capKBps: Int) -> String {
        capKBps > 0 ? "\(capKBps) KB/s" : "off"
    }
}

// MARK: - Self-test

enum I2PSAMBandwidthSelfTest {
    static func runAll() async -> [I2PSelfTestResult] {
        var results: [I2PSelfTestResult] = []
        func run(_ name: String, _ body: () async throws -> String) async {
            do {
                results.append(I2PSelfTestResult(name: name, passed: true, detail: try await body()))
            } catch {
                results.append(I2PSelfTestResult(name: name, passed: false, detail: "\(error)"))
            }
        }

        await run("SAM session caps · saved per session key") {
            let name = "i2p.sam.caps.selftest.\(UUID().uuidString)"
            guard let defaults = UserDefaults(suiteName: name) else { throw I2PWireError.invalidFormat }
            defer { UserDefaults.standard.removePersistentDomain(forName: name) }

            let caps = I2PSAMSessionCaps(defaults: defaults)
            guard caps.capKBps(for: "s1") == 0, caps.all().isEmpty else {
                throw I2PWireError.invalidFormat
            }
            caps.setCapKBps(64, for: "s1")
            caps.setCapKBps(24, for: "d1")
            caps.setCapKBps(4096, for: "big")
            caps.setCapKBps(-8, for: "off")

            // A fresh instance over the same defaults is what a relaunch sees.
            let reloaded = I2PSAMSessionCaps(defaults: defaults)
            guard reloaded.capKBps(for: "s1") == 64,
                  reloaded.capKBps(for: "d1") == 24,
                  reloaded.capKBps(for: "big") == I2PSAMSessionCaps.maxCapKBps,
                  reloaded.capKBps(for: "off") == 0,
                  reloaded.capKBps(for: "never-set") == 0,
                  reloaded.all().count == 3 else {
                throw I2PWireError.invalidFormat
            }

            // Clearing a cap forgets the key instead of saving a zero.
            reloaded.setCapKBps(0, for: "s1")
            let cleared = I2PSAMSessionCaps(defaults: defaults)
            guard cleared.capKBps(for: "s1") == 0, cleared.all()["s1"] == nil else {
                throw I2PWireError.invalidFormat
            }
            return "caps survive a relaunch per session key, out-of-range values clamp, and clearing one removes the entry"
        }

        await run("SAM session caps · per-session bucket shapes one session's sends") {
            let governor = I2PBandwidthGovernor()
            governor.configureSession("client-a", bytesPerSecond: 8 * 1024)
            let chunk = I2PSAMChunker.maxFrameBytes

            let started = Date()
            for _ in 0..<32 { await governor.admitSessionSend("client-a", bytes: chunk) }
            let elapsed = Date().timeIntervalSince(started)
            // 32 chunks = 24 320 B against a 16 KiB bucket at 8 KB/s: the burst
            // covers the first ~21 and the rest waits on the session's cap.
            guard elapsed >= 0.4, elapsed < 10 else { throw I2PWireError.invalidFormat }

            // The same traffic on an uncapped session is admitted at once.
            let open = Date()
            for _ in 0..<32 { await governor.admitSessionSend("client-b", bytes: chunk) }
            guard Date().timeIntervalSince(open) < 0.2 else { throw I2PWireError.invalidFormat }

            let reading = governor.sessionReading("client-a")
            guard reading.capBytesPerSecond == 8 * 1024,
                  reading.bytesPerSecond > 0,
                  governor.sessionReading("client-b").capBytesPerSecond == 0 else {
                throw I2PWireError.invalidFormat
            }
            return "a 8 KB/s session spent its 2 s burst then rode its cap; an uncapped one never waited; the reading reports \(I2PSAMBandwidthFormat.rate(reading.bytesPerSecond)) against its cap"
        }

        await run("SAM session caps · editing the cap applies to the running session") {
            let governor = I2PBandwidthGovernor()
            governor.configureSession("live", bytesPerSecond: 4 * 1024)

            // Spend the 8 KiB burst.
            for _ in 0..<14 { await governor.admitSessionSend("live", bytes: 760) }
            let underCap = Date()
            for _ in 0..<4 { await governor.admitSessionSend("live", bytes: 760) }
            guard Date().timeIntervalSince(underCap) >= 0.1 else { throw I2PWireError.invalidFormat }

            // Lifting the ceiling lets the next sends through at once.
            governor.configureSession("live", bytesPerSecond: 0)
            let lifted = Date()
            for _ in 0..<32 { await governor.admitSessionSend("live", bytes: 760) }
            guard Date().timeIntervalSince(lifted) < 0.2 else { throw I2PWireError.invalidFormat }
            guard governor.sessionCap("live") == 0 else { throw I2PWireError.invalidFormat }

            // Lowering it again shapes the very next send, with no restart.
            governor.configureSession("live", bytesPerSecond: 4 * 1024)
            let lowered = Date()
            for _ in 0..<14 { await governor.admitSessionSend("live", bytes: 760) }
            guard Date().timeIntervalSince(lowered) >= 0.1 else { throw I2PWireError.invalidFormat }
            return "raising the cap to off admitted 32 sends instantly; lowering it back to 4 KB/s shaped the next 14; a closed session's bucket can be dropped"
        }

        await run("SAM session caps · one send-rate sample per minute per session") {
            let governor = I2PBandwidthGovernor()

            // A session the governor has never seen still gets a full window:
            // idle minutes are zero samples, so the row draws a flat line.
            let idle = governor.sessionMinuteHistory("idle", minutes: 15)
            guard idle.count == 15,
                  idle.allSatisfy({ $0.bytesPerSecond == 0 }) else {
                throw I2PWireError.invalidFormat
            }
            guard zip(idle, idle.dropFirst()).allSatisfy({ pair in
                abs(pair.1.minute.timeIntervalSince(pair.0.minute) - 60) < 0.001
            }) else {
                throw I2PWireError.invalidFormat
            }

            governor.configureSession("chatty", bytesPerSecond: 0)
            for _ in 0..<4 { await governor.admitSessionSend("chatty", bytes: 1024) }

            let window = governor.sessionMinuteHistory("chatty", minutes: 15)
            guard window.count == 15,
                  window[window.count - 1].bytesPerSecond > 0,
                  window.dropLast().allSatisfy({ $0.bytesPerSecond == 0 }) else {
                throw I2PWireError.invalidFormat
            }

            // The window is exactly as long as asked for, and the newest
            // sample is the minute in progress.
            let short = governor.sessionMinuteHistory("chatty", minutes: 1)
            guard short.count == 1, short[0].bytesPerSecond > 0 else {
                throw I2PWireError.invalidFormat
            }

            // Dropping a closed session takes its history with it.
            governor.forgetSession("chatty")
            guard governor.sessionMinuteHistory("chatty").allSatisfy({
                $0.bytesPerSecond == 0
            }) else {
                throw I2PWireError.invalidFormat
            }
            return "an unseen session reads as 15 flat zero minutes one minute apart; a session's sends land in the in-progress minute; a closed session's history is gone"
        }

        return results
    }
}
