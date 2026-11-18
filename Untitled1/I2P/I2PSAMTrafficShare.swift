//
//  I2PSAMTrafficShare.swift
//  Who is spending the router's outbound cap: the last minute of SAM client
//  send rates stacked against the rest of the router's outbound traffic, with
//  the cap marked across the bar.
//

import Foundation

/// One SAM client's slice of the router's outbound traffic over the last
/// minute, as the SAM screen's share card draws it.
struct I2PSAMClientShare: Identifiable {
    /// The session key (nickname) the bridge knows the client by.
    var id: String { key }
    let key: String
    /// The client's measured send rate over the last minute, bytes per second.
    let bytesPerSecond: Double
    /// That rate against the outbound cap, 0...1 (0 when the path is uncapped).
    let fractionOfCap: Double
}

/// The last minute of SAM traffic broken down by client, stacked against the
/// rest of the router's outbound traffic and measured against the outbound cap.
struct I2PSAMCapShare {
    /// The ceiling the bar's cap line marks, bytes per second; 0 = uncapped.
    let capBytesPerSecond: Double
    /// Every live session's share, heaviest first.
    let clients: [I2PSAMClientShare]
    /// All SAM clients' measured send traffic added up.
    let samBytesPerSecond: Double
    /// What the rest of the router sent over the same minute.
    let otherBytesPerSecond: Double
    /// The router's measured outbound traffic in total.
    let totalBytesPerSecond: Double

    /// What the card shows before its first reading.
    static let empty = I2PSAMCapShare(capBytesPerSecond: 0,
                                      clients: [],
                                      samBytesPerSecond: 0,
                                      otherBytesPerSecond: 0,
                                      totalBytesPerSecond: 0)

    /// Whether any client sent anything: without that the card shows its empty
    /// state instead of the bar.
    var hasClientTraffic: Bool { samBytesPerSecond > 0 }

    /// The client using the most of the cap.
    var heaviest: I2PSAMClientShare? {
        clients.first { $0.bytesPerSecond > 0 }
    }

    /// The rate the full width of the bar stands for: whatever moved, or the
    /// cap when the router had headroom, plus a sliver so the cap line never
    /// sits on the very edge of the bar.
    var scaleBytesPerSecond: Double {
        max(max(totalBytesPerSecond, capBytesPerSecond), 1) * 1.06
    }

    /// Where the outbound cap falls across the bar, 0...1. Nil when uncapped.
    var capFraction: Double? {
        capBytesPerSecond > 0 ? min(1, capBytesPerSecond / scaleBytesPerSecond) : nil
    }

    /// A rate as its share of the bar's width, 0...1.
    func barFraction(_ bytesPerSecond: Double) -> Double {
        min(1, max(0, bytesPerSecond / scaleBytesPerSecond))
    }

    /// The cap as "256 KB/s", or "uncapped" when there is no ceiling.
    var capLabel: String {
        guard capBytesPerSecond > 0 else { return "uncapped" }
        return String(format: "%.0f KB/s", capBytesPerSecond / 1024)
    }

    /// The one line the card leads with: who is heaviest, and how much of the
    /// cap they are using.
    var headline: String? {
        guard let heaviest else { return nil }
        guard capBytesPerSecond > 0 else {
            return "\(heaviest.key) is sending "
                + "\(I2PSAMBandwidthFormat.rate(heaviest.bytesPerSecond)) with no outbound cap"
        }
        return "\(heaviest.key) is using \(Self.percent(heaviest.fractionOfCap))"
            + " of the \(capLabel) outbound cap"
    }

    /// A rate as its share of the cap ("62% of cap"), for the legend rows.
    func shareLabel(bytesPerSecond: Double) -> String {
        guard capBytesPerSecond > 0 else {
            return I2PSAMBandwidthFormat.rate(bytesPerSecond)
        }
        return "\(Self.percent(bytesPerSecond / capBytesPerSecond)) of cap"
    }

    /// One client's share of the cap, as its legend row reads it.
    func shareLabel(for client: I2PSAMClientShare) -> String {
        shareLabel(bytesPerSecond: client.bytesPerSecond)
    }

    /// "62%" for 0.62 of the cap; a trace too small to round keeps "<1%".
    static func percent(_ fraction: Double) -> String {
        let value = max(0, fraction) * 100
        if value > 0 && value.rounded() == 0 { return "<1%" }
        return "\(Int(value.rounded()))%"
    }

    /// Builds the breakdown from one minute of readings: the outbound cap, each
    /// live session's measured send rate and the router's measured outbound
    /// rate. Every session keeps a row even when it is idle, so the list under
    /// the bar covers the whole bridge.
    static func build(capBytesPerSecond: Double,
                      sessions: [(key: String, bytesPerSecond: Double)],
                      routerOutboundBytesPerSecond: Double) -> I2PSAMCapShare {
        let cap = max(0, capBytesPerSecond)
        // One row per session key; a key appearing twice keeps its heaviest rate.
        var rates: [String: Double] = [:]
        for session in sessions where !session.key.isEmpty {
            let rate = max(0, session.bytesPerSecond)
            rates[session.key] = max(rates[session.key] ?? 0, rate)
        }
        let sam = rates.values.reduce(0.0, +)
        // The router's own reading is the wider truth; if the SAM clients add up
        // to more than it (the two windows are measured separately), the stack
        // is what the bar is scaled to and nothing is left over.
        let total = max(max(0, routerOutboundBytesPerSecond), sam)
        let clients = rates
            .map { key, rate in
                I2PSAMClientShare(key: key,
                                  bytesPerSecond: rate,
                                  fractionOfCap: cap > 0 ? rate / cap : 0)
            }
            .sorted { lhs, rhs in
                if lhs.bytesPerSecond != rhs.bytesPerSecond {
                    return lhs.bytesPerSecond > rhs.bytesPerSecond
                }
                return lhs.key < rhs.key
            }
        return I2PSAMCapShare(capBytesPerSecond: cap,
                              clients: clients,
                              samBytesPerSecond: sam,
                              otherBytesPerSecond: max(0, total - sam),
                              totalBytesPerSecond: total)
    }

    /// The card's live reading: the governor's outbound cap and measured
    /// outbound rate for the whole router, and each live session's measured
    /// send rate over the same minute.
    static func live(sessions: [I2PSAMSessionSummary],
                     governor: I2PBandwidthGovernor = .shared,
                     settings: I2PParticipationSettings = .shared) -> I2PSAMCapShare {
        let governorCap = governor.currentCaps.outbound
        // The governor carries the applied cap; before it is configured the
        // saved setting is what the router is about to run with.
        let cap = governorCap > 0 ? governorCap : settings.outboundCapKBps * 1024
        return build(capBytesPerSecond: Double(cap),
                     sessions: sessions.map { session in
                         (key: session.nickname, bytesPerSecond: session.sendBytesPerSecond)
                     },
                     routerOutboundBytesPerSecond: governor.reading().outboundBytesPerSecond)
    }
}

// MARK: - Self-test

enum I2PSAMCapShareTests {
    static func runAll() -> [I2PSelfTestResult] {
        var results: [I2PSelfTestResult] = []
        func run(_ name: String, _ body: () throws -> String) {
            do {
                results.append(I2PSelfTestResult(name: name, passed: true, detail: try body()))
            } catch {
                results.append(I2PSelfTestResult(name: name, passed: false, detail: "\(error)"))
            }
        }

        run("SAM cap share · the heaviest client and its share of the cap") {
            let share = I2PSAMCapShare.build(
                capBytesPerSecond: 200 * 1024,
                sessions: [(key: "s2", bytesPerSecond: 40 * 1024),
                           (key: "s1", bytesPerSecond: 124 * 1024),
                           (key: "idle", bytesPerSecond: 0)],
                routerOutboundBytesPerSecond: 180 * 1024)
            guard share.hasClientTraffic,
                  share.heaviest?.key == "s1",
                  share.headline == "s1 is using 62% of the 200 KB/s outbound cap" else {
                throw I2PWireError.invalidFormat
            }
            // The stack: the sending clients heaviest first, then what the rest
            // of the router moved against the same cap.
            guard share.clients.map(\.key) == ["s1", "s2", "idle"],
                  abs(share.samBytesPerSecond - 164 * 1024) < 1,
                  abs(share.otherBytesPerSecond - 16 * 1024) < 1,
                  abs(share.totalBytesPerSecond - 180 * 1024) < 1,
                  share.shareLabel(for: share.clients[1]) == "20% of cap",
                  share.shareLabel(for: share.clients[2]) == "0% of cap" else {
                throw I2PWireError.invalidFormat
            }
            return "s1's 124 KB/s against a 200 KB/s cap reads 62%, an idle session still lists at 0%, and the rest of the router's traffic leaves a 16 KB/s remainder"
        }

        run("SAM cap share · the cap line sits across the bar") {
            let under = I2PSAMCapShare.build(capBytesPerSecond: 256 * 1024,
                                             sessions: [(key: "s1", bytesPerSecond: 128 * 1024)],
                                             routerOutboundBytesPerSecond: 160 * 1024)
            guard let capLine = under.capFraction,
                  under.barFraction(under.totalBytesPerSecond) < capLine,
                  capLine < 1 else {
                throw I2PWireError.invalidFormat
            }
            let over = I2PSAMCapShare.build(capBytesPerSecond: 256 * 1024,
                                            sessions: [(key: "s1", bytesPerSecond: 300 * 1024)],
                                            routerOutboundBytesPerSecond: 380 * 1024)
            guard let overLine = over.capFraction,
                  over.barFraction(over.totalBytesPerSecond) > overLine,
                  over.barFraction(over.totalBytesPerSecond) <= 1 else {
                throw I2PWireError.invalidFormat
            }
            guard under.capLabel == "256 KB/s", over.capLabel == "256 KB/s" else {
                throw I2PWireError.invalidFormat
            }
            return "with headroom the stack stops short of the cap line at \(I2PSAMCapShare.percent(capLine)) of the bar; past the cap it runs over the line instead"
        }

        run("SAM cap share · an idle bridge shows its empty state") {
            let idle = I2PSAMCapShare.build(capBytesPerSecond: 256 * 1024,
                                            sessions: [(key: "s1", bytesPerSecond: 0),
                                                       (key: "d1", bytesPerSecond: 0)],
                                            routerOutboundBytesPerSecond: 64 * 1024)
            guard !idle.hasClientTraffic,
                  idle.headline == nil,
                  idle.capFraction != nil,
                  abs(idle.otherBytesPerSecond - 64 * 1024) < 1 else {
                throw I2PWireError.invalidFormat
            }
            guard !I2PSAMCapShare.empty.hasClientTraffic,
                  I2PSAMCapShare.empty.headline == nil else {
                throw I2PWireError.invalidFormat
            }
            // A client whose sends are a trace of the cap keeps a "<1%" label
            // rather than rounding away to nothing.
            let trace = I2PSAMCapShare.build(capBytesPerSecond: 256 * 1024,
                                             sessions: [(key: "s1", bytesPerSecond: 200)],
                                             routerOutboundBytesPerSecond: 8 * 1024)
            guard trace.headline == "s1 is using <1% of the 256 KB/s outbound cap" else {
                throw I2PWireError.invalidFormat
            }
            return "with no client sending the card falls back to its empty state while the rest-of-router remainder stays whole; a 200 B/s client reads <1%"
        }

        return results
    }
}
