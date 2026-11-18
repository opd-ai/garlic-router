//
//  I2PIRCLatency.swift
//  The IRC stream's round-trip measurement: a PING carrying a token every
//  minute, matched against the server's PONG, so the live header can say how
//  long the stream takes to answer.
//
//  The probe rides the same outbox the chat uses — one line queued behind
//  whatever the user is sending — so it never delays or reorders a message.
//  The timing itself is pure bookkeeping, verified by the self-test suite
//  without a connection.
//

import Foundation

// MARK: - Round-trip tracker

struct I2PIRCLatency {
    /// How often the client sends a probe.
    static let probeInterval: TimeInterval = 60
    /// A round trip slower than this is reported as a warning.
    static let slowThreshold: TimeInterval = 2
    /// How long a probe waits for its PONG before it is forgotten, so a reply
    /// that never comes cannot linger and be timed against a later line.
    static let probeLifetime: TimeInterval = 5 * 60
    /// The prefix every token carries, so a PONG can be recognised as the
    /// answer to a probe rather than the reply to a plain keep-alive.
    static let tokenPrefix = "i2p-rtt-"

    /// A probe on its way, and when it left.
    private struct Probe: Equatable {
        let token: String
        let sentAt: Date
    }

    /// The probes whose PONG has not come back yet, oldest first.
    private var pending: [Probe] = []
    /// The last round trip in milliseconds; nil until the first PONG arrives.
    private(set) var milliseconds: Int?

    /// The read-out the status line carries: "RTT 240 ms", or "RTT —" before
    /// the first measurement.
    var reading: String {
        guard let milliseconds else { return "RTT —" }
        return "RTT \(milliseconds) ms"
    }

    /// Whether the last measurement is slower than the two-second threshold.
    var isSlow: Bool {
        guard let milliseconds else { return false }
        // The reading is whole milliseconds while the threshold is stated in
        // seconds: comparing the two numbers directly made every reading amber.
        return milliseconds > Int(Self.slowThreshold * 1000)
    }

    /// A fresh token for one probe: the prefix, the moment it was sent and a
    /// nonce that keeps two probes of the same millisecond apart.
    static func token(at date: Date, nonce: String) -> String {
        let stamp = Int(date.timeIntervalSince1970 * 1000)
        return "\(tokenPrefix)\(stamp)-\(nonce)"
    }

    /// Whether a PONG parameter is a token of ours, so the answer to the plain
    /// keep-alive PING is never mistaken for a measurement.
    static func isToken(_ param: String) -> Bool {
        param.hasPrefix(tokenPrefix)
    }

    /// Records a probe in flight, dropping the ones old enough to be lost.
    mutating func beginProbe(token: String, at date: Date) {
        pending.removeAll { date.timeIntervalSince($0.sentAt) > Self.probeLifetime }
        pending.append(Probe(token: token, sentAt: date))
    }

    /// Matches a PONG's parameters against the probes in flight. A match is
    /// timed and removed, so a replayed PONG measures nothing; a PONG that
    /// answers something else of ours is left alone.
    @discardableResult
    mutating func fulfill(params: [String], at date: Date) -> Bool {
        guard let token = params.first(where: Self.isToken),
              let index = pending.firstIndex(where: { $0.token == token }) else {
            return false
        }
        let probe = pending.remove(at: index)
        milliseconds = Self.milliseconds(from: date.timeIntervalSince(probe.sentAt))
        return true
    }

    /// Forgets the reading and every probe in flight: what a connect, a
    /// disconnect and a reconnect attempt each do, so a new session never shows
    /// the old stream's number.
    mutating func clear() {
        pending.removeAll()
        milliseconds = nil
    }

    /// A round trip of a fraction of a millisecond is reported as one rather
    /// than as zero.
    private static func milliseconds(from interval: TimeInterval) -> Int {
        max(1, Int((interval * 1000).rounded()))
    }
}

// MARK: - Self-test suite (IRC latency)

enum I2PIRCLatencySelfTest {
    static func runAll() -> [I2PSelfTestResult] {
        var results: [I2PSelfTestResult] = []
        func run(_ name: String, _ body: () throws -> String) {
            do {
                results.append(I2PSelfTestResult(name: name, passed: true, detail: try body()))
            } catch {
                results.append(I2PSelfTestResult(name: name, passed: false,
                                                 detail: String(describing: error)))
            }
        }

        run("irc · the round-trip reading waits for a measurement and reports whole milliseconds") {
            var latency = I2PIRCLatency()
            guard latency.reading == "RTT —", !latency.isSlow else {
                throw I2PWireError.invalidFormat
            }
            let start = Date(timeIntervalSince1970: 1_700_000_000)
            let token = I2PIRCLatency.token(at: start, nonce: "a")
            latency.beginProbe(token: token, at: start)
            // A pending probe does not show a number: there is nothing to show.
            guard latency.reading == "RTT —" else { throw I2PWireError.invalidFormat }
            // The answer to the plain keep-alive PING measures nothing.
            guard !latency.fulfill(params: ["irc.example.i2p"],
                                   at: start.addingTimeInterval(3)) else {
                throw I2PWireError.invalidFormat
            }
            // The matching PONG lands, however the server frames it.
            guard latency.fulfill(params: ["irc.example.i2p", token],
                                  at: start.addingTimeInterval(0.24)),
                  latency.reading == "RTT 240 ms",
                  !latency.isSlow else {
                throw I2PWireError.invalidFormat
            }
            return "the header reads 'RTT —' until the matching PONG arrives, then 240 ms for a 240 ms round trip; the keep-alive's own PONG is not timed"
        }

        run("irc · a round trip over two seconds is reported as a warning, and only once") {
            var latency = I2PIRCLatency()
            let start = Date(timeIntervalSince1970: 1_700_000_000)
            // Exactly two seconds is the threshold itself, not above it.
            let edge = I2PIRCLatency.token(at: start, nonce: "b")
            latency.beginProbe(token: edge, at: start)
            guard latency.fulfill(params: [edge], at: start.addingTimeInterval(2.0)),
                  latency.reading == "RTT 2000 ms",
                  !latency.isSlow else {
                throw I2PWireError.invalidFormat
            }
            let slow = I2PIRCLatency.token(at: start, nonce: "c")
            latency.beginProbe(token: slow, at: start)
            guard latency.fulfill(params: [slow], at: start.addingTimeInterval(2.5)),
                  latency.reading == "RTT 2500 ms",
                  latency.isSlow else {
                throw I2PWireError.invalidFormat
            }
            // A replayed PONG cannot time the same probe twice.
            guard !latency.fulfill(params: [slow], at: start.addingTimeInterval(9)),
                  latency.reading == "RTT 2500 ms" else {
                throw I2PWireError.invalidFormat
            }
            return "a slow round trip turns the reading amber above 2 s, the threshold itself stays quiet, and a replayed PONG is ignored"
        }

        run("irc · clearing forgets the reading and the probe in flight") {
            var latency = I2PIRCLatency()
            let start = Date(timeIntervalSince1970: 1_700_000_000)
            let token = I2PIRCLatency.token(at: start, nonce: "d")
            latency.beginProbe(token: token, at: start)
            guard latency.fulfill(params: [token], at: start.addingTimeInterval(0.4)),
                  latency.reading == "RTT 400 ms" else {
                throw I2PWireError.invalidFormat
            }
            latency.clear()
            guard latency.reading == "RTT —", !latency.isSlow else {
                throw I2PWireError.invalidFormat
            }
            // The probe went with the session: its late PONG measures nothing.
            let late = I2PIRCLatency.token(at: start, nonce: "e")
            latency.beginProbe(token: late, at: start)
            latency.clear()
            guard !latency.fulfill(params: [late], at: start.addingTimeInterval(0.5)),
                  latency.reading == "RTT —" else {
                throw I2PWireError.invalidFormat
            }
            // Each probe's token is its own, and a server name is not one.
            guard I2PIRCLatency.token(at: start, nonce: "f") != I2PIRCLatency.token(at: start, nonce: "g"),
                  I2PIRCLatency.isToken(token),
                  !I2PIRCLatency.isToken("irc.example.i2p") else {
                throw I2PWireError.invalidFormat
            }
            return "clearing reads 'RTT —' and drops the probes in flight, tokens are unique per probe, and a bare server name is never taken for one"
        }

        return results
    }
}
