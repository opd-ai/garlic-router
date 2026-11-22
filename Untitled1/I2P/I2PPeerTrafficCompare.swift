//
//  I2PPeerTrafficCompare.swift
//  Two peers side by side: the peak of each one's 15-minute traffic window,
//  which live sessions the picker offers as the other side, and whether the
//  picked session is still live. Pure logic only — the screen itself lives in
//  PeerTrafficCompareView.swift.
//

import Foundation

// MARK: - Peak

/// The highest rate a single bucket of one peer's readings reached, and the
/// direction that carried it. The two directions are compared separately, so a
/// peer that is busy both ways never reads as a peak neither direction hit.
struct I2PPeerTrafficPeak: Equatable {
    let bytesPerSecond: Double
    /// True when the received direction carried the peak.
    let isReceived: Bool

    var direction: String { isReceived ? "received" : "sent" }
}

// MARK: - Comparison

enum I2PPeerTrafficCompare {
    /// The window both sides are drawn over — the recorder's 15 minutes.
    static let window: TimeInterval = I2PPeerTrafficRecorder.window

    /// The peak of the readings, or nil when the window holds nothing yet.
    static func peak(in points: [I2PPeerTrafficPoint]) -> I2PPeerTrafficPeak? {
        var best: I2PPeerTrafficPeak?
        for point in points {
            let received = point.receivedBytesPerSecond
            let sent = point.sentBytesPerSecond
            let candidate = I2PPeerTrafficPeak(bytesPerSecond: max(received, sent),
                                               isReceived: received >= sent)
            if let current = best, current.bytesPerSecond >= candidate.bytesPerSecond {
                continue
            }
            best = candidate
        }
        return best
    }

    /// The first `length` characters of an identity hash, so a legend row reads
    /// as one peer and not as a wall of hex.
    static func shortID(_ hex: String, length: Int = 8) -> String {
        let trimmed = hex.trimmingCharacters(in: .whitespacesAndNewlines)
        let keep = max(4, length)
        guard trimmed.count > keep else { return trimmed }
        return "\(trimmed.prefix(keep))…"
    }

    /// Whether a session with this identity is still among the live sessions.
    static func isLive(_ peerID: String, among peers: [I2PPeerSummary]) -> Bool {
        peers.contains { $0.id == peerID }
    }

    /// The sessions the picker offers as the other side: every live session
    /// except the one already on the left, busiest first.
    static func pickerChoices(inspected peerID: String,
                              among peers: [I2PPeerSummary]) -> [I2PPeerSummary] {
        peers
            .filter { $0.id != peerID }
            .sorted { $0.bytesIn + $0.bytesOut > $1.bytesIn + $1.bytesOut }
    }

    /// The line the screen shows when the picked session is gone.
    static func endedMessage(picked peerID: String) -> String {
        "The session with \(shortID(peerID)) ended, so there is nothing live left on the teal side. Pick another live session below to keep comparing."
    }
}

// MARK: - Self-test

enum I2PPeerTrafficCompareSelfTest {
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

        run("Peer compare · the peak is one direction's highest bucket, not a sum") {
            let points = [
                I2PPeerTrafficPoint(id: 0, at: start,
                                    receivedBytesPerSecond: 5000, sentBytesPerSecond: 5000),
                I2PPeerTrafficPoint(id: 1, at: start.addingTimeInterval(1),
                                    receivedBytesPerSecond: 8192, sentBytesPerSecond: 100)
            ]
            guard let peak = I2PPeerTrafficCompare.peak(in: points),
                  abs(peak.bytesPerSecond - 8192) < 0.01,
                  peak.isReceived,
                  peak.direction == "received",
                  I2PPeerTrafficCompare.peak(in: []) == nil else {
                throw I2PWireError.invalidFormat
            }
            return "8 KB/s received beat a 5 KB/s + 5 KB/s bucket, and an empty window has no peak"
        }

        run("Peer compare · a sent-heavy bucket names the sent direction") {
            let points = [
                I2PPeerTrafficPoint(id: 0, at: start,
                                    receivedBytesPerSecond: 1024, sentBytesPerSecond: 4096),
                I2PPeerTrafficPoint(id: 1, at: start.addingTimeInterval(1),
                                    receivedBytesPerSecond: 2048, sentBytesPerSecond: 512)
            ]
            guard let peak = I2PPeerTrafficCompare.peak(in: points),
                  abs(peak.bytesPerSecond - 4096) < 0.01,
                  !peak.isReceived,
                  peak.direction == "sent" else {
                throw I2PWireError.invalidFormat
            }
            return "4 KB/s sent in the first bucket was the window's peak"
        }

        run("Peer compare · the picker offers the other live sessions, busiest first") {
            let peers = [
                summary("aaaa", bytesIn: 1024, bytesOut: 512),
                summary("bbbb", bytesIn: 90_000, bytesOut: 10_000),
                summary("cccc", bytesIn: 3000, bytesOut: 1000)
            ]
            let choices = I2PPeerTrafficCompare.pickerChoices(inspected: "aaaa", among: peers)
            guard choices.map(\.id) == ["bbbb", "cccc"],
                  I2PPeerTrafficCompare.pickerChoices(inspected: "zzzz", among: peers).count == 3 else {
                throw I2PWireError.invalidFormat
            }
            return "the inspected peer was left out and the busiest session came first"
        }

        run("Peer compare · an ended session is named and no longer live") {
            let peers = [summary("aaaa", bytesIn: 10, bytesOut: 20)]
            let gone = "bbbbbbbbcccc"
            guard I2PPeerTrafficCompare.isLive("aaaa", among: peers),
                  !I2PPeerTrafficCompare.isLive(gone, among: peers) else {
                throw I2PWireError.invalidFormat
            }
            let line = I2PPeerTrafficCompare.endedMessage(picked: gone)
            guard line.contains(I2PPeerTrafficCompare.shortID(gone)) else {
                throw I2PWireError.invalidFormat
            }
            return "the live peer stayed live, the ended one was reported with its short hash"
        }

        run("Peer compare · short hashes stay short") {
            guard I2PPeerTrafficCompare.shortID("0123456789abcdef") == "01234567…",
                  I2PPeerTrafficCompare.shortID("01234567") == "01234567",
                  I2PPeerTrafficCompare.shortID(" abcdef012345 ") == "abcdef01…",
                  I2PPeerTrafficCompare.window == I2PPeerTrafficRecorder.window else {
                throw I2PWireError.invalidFormat
            }
            return "16 hex characters flattened to 8 plus an ellipsis, and the window stayed 15 minutes"
        }

        return results
    }

    /// A session reading with only the fields the comparison reads filled in.
    private static func summary(_ id: String, bytesIn: Int, bytesOut: Int) -> I2PPeerSummary {
        I2PPeerSummary(id: id,
                       transport: "NTCP2",
                       establishedAt: Date(timeIntervalSince1970: 1_700_000_000),
                       bytesIn: bytesIn,
                       bytesOut: bytesOut,
                       xorDistanceHex: "",
                       kademliaBucket: 0,
                       isFloodfill: false,
                       tunnelRole: nil,
                       handshakeBackoff: nil,
                       trafficFlag: nil)
    }
}
