//
//  I2PPeerTrafficFlags.swift
//  What a peer's recent traffic says about it: a session that has moved no
//  bytes for three minutes reads as quiet, and one whose received rate has held
//  above four times its own 15-minute median for half a minute reads as
//  flooding. Both are derived from the recorder's readings each time they are
//  asked for — nothing is stored beyond the readings themselves and no setting
//  exists, so a badge clears on its own as soon as traffic returns to normal.
//

import Foundation

// MARK: - Flag

/// One traffic condition worth pointing out about a peer session.
enum I2PPeerTrafficFlag: Equatable {
    /// No bytes have moved in either direction for `for` seconds.
    case quiet(for: TimeInterval)
    /// The received rate has been `rate` bytes per second for `sustained`
    /// seconds, four times the peer's own 15-minute median of `median`.
    case flooding(rate: Double, median: Double, sustained: TimeInterval)
}

// MARK: - Labels

enum I2PPeerTrafficFlagFormat {
    /// The short word the dashboard's session row shows as a badge.
    static func badgeTitle(_ flag: I2PPeerTrafficFlag) -> String {
        switch flag {
        case .quiet: return "Quiet"
        case .flooding: return "Flooding"
        }
    }

    /// The glyph beside the badge and on the inspector's line.
    static func badgeSystemImage(_ flag: I2PPeerTrafficFlag) -> String {
        switch flag {
        case .quiet: return "bell.slash"
        case .flooding: return "arrow.up.right.circle"
        }
    }

    /// The inspector's line: what the readings measured and how long it has
    /// been going on. It names the measured value only — no guess at why the
    /// peer stopped or what it is sending.
    static func inspectorLine(_ flag: I2PPeerTrafficFlag) -> String {
        switch flag {
        case .quiet(let duration):
            return "Quiet for \(durationText(duration)) — no bytes have moved in either direction. The badge clears on its own when traffic returns."
        case .flooding(let rate, let median, let sustained):
            let received = I2PPeerTrafficFormat.rate(rate)
            let baseline = I2PPeerTrafficFormat.rate(median)
            return "Flooding · received \(received) sustained for \(durationText(sustained)) — four times this peer's 15-minute median of \(baseline). The badge clears on its own when the rate falls back."
        }
    }

    /// "42s", "3m 19s" or "1h 4m" for a measured duration.
    static func durationText(_ seconds: TimeInterval) -> String {
        let total = max(0, Int(seconds.rounded(.down)))
        if total >= 3600 { return "\(total / 3600)h \((total % 3600) / 60)m" }
        if total >= 60 { return "\(total / 60)m \(total % 60)s" }
        return "\(total)s"
    }
}

// MARK: - Self-test

enum I2PPeerTrafficFlagSelfTest {
    static func runAll() -> [I2PSelfTestResult] {
        var results: [I2PSelfTestResult] = []
        func run(_ name: String, _ body: () throws -> String) {
            do {
                results.append(I2PSelfTestResult(name: name, passed: true, detail: try body()))
            } catch {
                results.append(I2PSelfTestResult(name: name, passed: false, detail: "\(error)"))
            }
        }

        let start = Date(timeIntervalSince1970: 1_700_000_000)

        run("Peer flags · a peer with no traffic for three minutes reads as quiet") {
            let recorder = I2PPeerTrafficRecorder()
            recorder.record(peerID: "peer", bytesIn: 0, bytesOut: 0, at: start)
            recorder.record(peerID: "peer", bytesIn: 2048, bytesOut: 1024,
                            at: start.addingTimeInterval(1))

            // Two minutes on, the silence is not long enough to call out.
            guard recorder.flag(for: "peer", now: start.addingTimeInterval(120)) == nil else {
                throw I2PWireError.invalidFormat
            }
            guard case .quiet(let quietFor)? = recorder.flag(for: "peer",
                                                             now: start.addingTimeInterval(200)),
                  abs(quietFor - 199) < 2 else {
                throw I2PWireError.invalidFormat
            }
            return "silent for 199s after its last byte, badged as quiet for 3m 19s"
        }

        run("Peer flags · traffic returning clears the quiet badge by itself") {
            let recorder = I2PPeerTrafficRecorder()
            recorder.record(peerID: "peer", bytesIn: 0, bytesOut: 0, at: start)
            recorder.record(peerID: "peer", bytesIn: 4096, bytesOut: 0,
                            at: start.addingTimeInterval(1))
            guard recorder.flag(for: "peer", now: start.addingTimeInterval(400)) != nil else {
                throw I2PWireError.invalidFormat
            }
            recorder.record(peerID: "peer", bytesIn: 8192, bytesOut: 0,
                            at: start.addingTimeInterval(401))
            guard recorder.flag(for: "peer", now: start.addingTimeInterval(402)) == nil else {
                throw I2PWireError.invalidFormat
            }
            return "a reading that moved 4 KB cleared the badge without any other change"
        }

        run("Peer flags · a received rate above four times the median floods") {
            let recorder = I2PPeerTrafficRecorder()
            recorder.record(peerID: "peer", bytesIn: 0, bytesOut: 0, at: start)
            var cumulative = 0
            var elapsed = 0.0
            // Two minutes of a steady 1 KB/s baseline.
            for _ in 0..<120 {
                elapsed += 1
                cumulative += 1024
                recorder.record(peerID: "peer", bytesIn: cumulative, bytesOut: 0,
                                at: start.addingTimeInterval(elapsed))
            }
            guard recorder.flag(for: "peer", now: start.addingTimeInterval(elapsed)) == nil else {
                throw I2PWireError.invalidFormat
            }
            // The peer starts receiving 8 KB/s: too short at first to call out.
            for _ in 0..<20 {
                elapsed += 1
                cumulative += 8192
                recorder.record(peerID: "peer", bytesIn: cumulative, bytesOut: 0,
                                at: start.addingTimeInterval(elapsed))
            }
            guard recorder.flag(for: "peer", now: start.addingTimeInterval(elapsed)) == nil else {
                throw I2PWireError.invalidFormat
            }
            for _ in 0..<20 {
                elapsed += 1
                cumulative += 8192
                recorder.record(peerID: "peer", bytesIn: cumulative, bytesOut: 0,
                                at: start.addingTimeInterval(elapsed))
            }
            guard case .flooding(let rate, let median, let sustained)? = recorder.flag(
                    for: "peer", now: start.addingTimeInterval(elapsed)),
                  abs(rate - 8192) < 1,
                  abs(median - 1024) < 1,
                  sustained >= I2PPeerTrafficRecorder.floodSustain else {
                throw I2PWireError.invalidFormat
            }
            // Back to the baseline: the run breaks and the badge clears.
            for _ in 0..<5 {
                elapsed += 1
                cumulative += 1024
                recorder.record(peerID: "peer", bytesIn: cumulative, bytesOut: 0,
                                at: start.addingTimeInterval(elapsed))
            }
            guard recorder.flag(for: "peer", now: start.addingTimeInterval(elapsed)) == nil else {
                throw I2PWireError.invalidFormat
            }
            return "8 KB/s against a 1 KB/s median flagged after 30s and cleared once the burst ended"
        }

        run("Peer flags · a peer with no baseline is never called a flooder") {
            let recorder = I2PPeerTrafficRecorder()
            recorder.record(peerID: "idle", bytesIn: 0, bytesOut: 0, at: start)
            var elapsed = 0.0
            var cumulative = 0
            for _ in 0..<60 {
                elapsed += 1
                recorder.record(peerID: "idle", bytesIn: 0, bytesOut: 0,
                                at: start.addingTimeInterval(elapsed))
            }
            for _ in 0..<60 {
                elapsed += 1
                cumulative += 51_200
                recorder.record(peerID: "idle", bytesIn: cumulative, bytesOut: 0,
                                at: start.addingTimeInterval(elapsed))
            }
            guard recorder.flag(for: "idle", now: start.addingTimeInterval(elapsed)) == nil,
                  I2PPeerTrafficRecorder.median(of: []) == 0,
                  I2PPeerTrafficRecorder.median(of: [10, 20]) == 15,
                  I2PPeerTrafficRecorder.median(of: [30, 10, 20]) == 20 else {
                throw I2PWireError.invalidFormat
            }
            return "a zero median leaves nothing to be four times of, so 50 KB/s after silence stays unflagged"
        }

        run("Peer flags · labels name the measurement, not a cause") {
            let quiet = I2PPeerTrafficFlag.quiet(for: 200)
            let flooding = I2PPeerTrafficFlag.flooding(rate: 524_288,
                                                       median: 12_698,
                                                       sustained: 42)
            let quietLine = I2PPeerTrafficFlagFormat.inspectorLine(.quiet(for: 199))
            let floodLine = I2PPeerTrafficFlagFormat.inspectorLine(flooding)
            guard I2PPeerTrafficFlagFormat.badgeTitle(quiet) == "Quiet",
                  I2PPeerTrafficFlagFormat.badgeTitle(flooding) == "Flooding",
                  I2PPeerTrafficFlagFormat.badgeSystemImage(quiet) == "bell.slash",
                  I2PPeerTrafficFlagFormat.badgeSystemImage(flooding) == "arrow.up.right.circle",
                  I2PPeerTrafficFlagFormat.durationText(42) == "42s",
                  I2PPeerTrafficFlagFormat.durationText(199) == "3m 19s",
                  I2PPeerTrafficFlagFormat.durationText(-5) == "0s",
                  I2PPeerTrafficFlagFormat.durationText(3_930) == "1h 5m",
                  quietLine.contains("3m 19s"),
                  quietLine.contains("no bytes have moved"),
                  floodLine.contains("512.0 KB/s"),
                  floodLine.contains("12.4 KB/s"),
                  floodLine.contains("42s") else {
                throw I2PWireError.invalidFormat
            }
            return "Quiet · 3m 19s and Flooding · 512.0 KB/s from a 12.4 KB/s median"
        }

        return results
    }
}
