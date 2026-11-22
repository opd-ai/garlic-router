//
//  I2PRouterLifetimeTotals.swift
//  What this run of the router has done since it started: the cumulative
//  counters behind the dashboard's quiet totals card. Every figure is a
//  running total the status engine recomputes from the live components on
//  each snapshot, so nothing here is a rate, a window or a stored sample.
//
//  The counts begin when the router starts and are never written anywhere:
//  a relaunch starts them again from zero, which the card's caption says
//  plainly rather than letting "lifetime" read as "kept".
//

import Foundation

/// Cumulative totals for one run of the router.
struct I2PRouterLifetimeTotals: Equatable {
    /// Bytes received across every session this transport has carried —
    /// closed sessions included, so the figure never falls when one ends.
    let bytesIn: Int
    /// Bytes sent across every session, on the same rules.
    let bytesOut: Int
    /// Sessions that reached the established state, NTCP2 and SSU2 together.
    let sessionsEstablished: Int
    /// Tunnels this router built as their creator.
    let tunnelsBuilt: Int
    /// Tunnels this router carried as a hop for another participant.
    let tunnelsCarried: Int
    /// I2NP messages routed in and out over the same run.
    let messagesIn: Int
    let messagesOut: Int

    /// A router that has just started, before anything is counted.
    static let zero = I2PRouterLifetimeTotals(bytesIn: 0, bytesOut: 0,
                                              sessionsEstablished: 0,
                                              tunnelsBuilt: 0, tunnelsCarried: 0,
                                              messagesIn: 0, messagesOut: 0)

    /// The line under the figures: where the counts start and that they are
    /// not persisted. Kept in the model so the card, its VoiceOver value and
    /// the self-test all say the same thing.
    static let caption = "Counted since the router started. Nothing here is kept after it stops."

    /// One figure on the card: a short title, its total and a caption naming
    /// what is being counted.
    struct Figure: Identifiable, Equatable {
        let id: String
        let title: String
        let value: String
        let caption: String
    }

    /// The figures in the order the card draws them: traffic, then the
    /// sessions and tunnels that carried it, then the messages themselves.
    var figures: [Figure] {
        [
            Figure(id: "bytes-in", title: "Received",
                   value: Self.byteText(bytesIn), caption: "bytes, every session"),
            Figure(id: "bytes-out", title: "Sent",
                   value: Self.byteText(bytesOut), caption: "bytes, every session"),
            Figure(id: "sessions", title: "Sessions",
                   value: Self.countText(sessionsEstablished), caption: "established"),
            Figure(id: "tunnels-built", title: "Tunnels built",
                   value: Self.countText(tunnelsBuilt), caption: "as creator"),
            Figure(id: "tunnels-carried", title: "Tunnels carried",
                   value: Self.countText(tunnelsCarried), caption: "as a hop"),
            Figure(id: "messages", title: "I2NP messages",
                   value: "\(Self.countText(messagesIn)) / \(Self.countText(messagesOut))",
                   caption: "in / out")
        ]
    }

    /// The whole card as one sentence, so VoiceOver reads a statement rather
    /// than six fragments with their captions between them.
    var accessibilitySummary: String {
        "\(Self.byteText(bytesIn)) received and \(Self.byteText(bytesOut)) sent across every session. "
        + "\(Self.countText(sessionsEstablished)) sessions established. "
        + "\(Self.countText(tunnelsBuilt)) tunnels built as creator, "
        + "\(Self.countText(tunnelsCarried)) carried as a hop. "
        + "\(Self.countText(messagesIn)) I2NP messages received and "
        + "\(Self.countText(messagesOut)) sent. \(Self.caption)"
    }

    /// "0 B", "820 B", "1.5 KB", "2.5 MB", "1.20 GB" — short enough for a
    /// half-width tile, and never wider than the tile's monospaced line.
    static func byteText(_ bytes: Int) -> String {
        let value = Double(max(0, bytes))
        if value >= 1_073_741_824 { return String(format: "%.2f GB", value / 1_073_741_824) }
        if value >= 1_048_576 { return String(format: "%.1f MB", value / 1_048_576) }
        if value >= 1024 { return String(format: "%.1f KB", value / 1024) }
        return "\(max(0, bytes)) B"
    }

    /// Grouped digits ("1,204"), with a fixed locale so the figure reads the
    /// same whatever the device's region is.
    static func countText(_ value: Int) -> String {
        Self.countFormatter.string(from: NSNumber(value: max(0, value)))
            ?? "\(max(0, value))"
    }

    private static let countFormatter: NumberFormatter = {
        let formatter = NumberFormatter()
        formatter.numberStyle = .decimal
        formatter.usesGroupingSeparator = true
        formatter.groupingSeparator = ","
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.maximumFractionDigits = 0
        return formatter
    }()
}

// MARK: - Self-test

/// The card's figures are pure: these pin the formatting boundaries and the
/// set of figures the run is supposed to report.
enum I2PRouterLifetimeTotalsSelfTest {
    static func runAll() -> [I2PSelfTestResult] {
        var results: [I2PSelfTestResult] = []
        func check(_ name: String, _ body: () -> String?) {
            if let detail = body() {
                results.append(I2PSelfTestResult(name: name, passed: true, detail: detail))
            } else {
                results.append(I2PSelfTestResult(
                    name: name,
                    passed: false,
                    detail: "lifetime totals did not match the expected reading"))
            }
        }

        check("Lifetime totals: byte and count formatting stays compact") {
            guard I2PRouterLifetimeTotals.byteText(0) == "0 B",
                  I2PRouterLifetimeTotals.byteText(820) == "820 B",
                  I2PRouterLifetimeTotals.byteText(1536) == "1.5 KB",
                  I2PRouterLifetimeTotals.byteText(2_621_440) == "2.5 MB",
                  I2PRouterLifetimeTotals.byteText(1_288_490_188) == "1.20 GB",
                  I2PRouterLifetimeTotals.countText(1_204) == "1,204",
                  I2PRouterLifetimeTotals.countText(0) == "0" else { return nil }
            return "0 B / 820 B / 1.5 KB / 2.5 MB / 1.20 GB · 1,204"
        }

        check("Lifetime totals: a fresh run reads as zeros, not blank tiles") {
            let figures = I2PRouterLifetimeTotals.zero.figures
            guard figures.count == 6,
                  figures[0].value == "0 B",
                  figures[1].value == "0 B",
                  figures[2].value == "0",
                  figures[3].value == "0",
                  figures[4].value == "0",
                  figures[5].value == "0 / 0" else { return nil }
            return figures.map(\.value).joined(separator: " · ")
        }

        check("Lifetime totals: the card reports every figure the run counts") {
            let totals = I2PRouterLifetimeTotals(
                bytesIn: 4096, bytesOut: 2048, sessionsEstablished: 12,
                tunnelsBuilt: 3, tunnelsCarried: 7, messagesIn: 1204, messagesOut: 1188)
            let figures = totals.figures
            guard figures.map(\.id) == ["bytes-in", "bytes-out", "sessions",
                                        "tunnels-built", "tunnels-carried", "messages"],
                  figures[0].value == "4.0 KB",
                  figures[2].value == "12",
                  figures[4].caption == "as a hop",
                  figures[5].value == "1,204 / 1,188",
                  totals.accessibilitySummary.contains(I2PRouterLifetimeTotals.caption),
                  I2PRouterLifetimeTotals.caption.contains("started"),
                  I2PRouterLifetimeTotals.caption.contains("kept") else { return nil }
            return "6 figures · \(figures[5].value)"
        }

        return results
    }
}
