//
//  I2PSessionSort.swift
//  The order the Router dashboard's session list is drawn in: by session start
//  (the default), by the bytes the peer has received or sent, or by the peer's
//  hash. The chosen order lives in memory for the life of the app run, so a
//  relaunch starts again at "recent", and sorting never touches a row's
//  readings or the link into the peer inspector.
//
//  The order governs the unpinned rows only: a pinned identity
//  (I2PPeerPins) is lifted above every other row whatever order is in effect.
//

import Foundation

// MARK: - Order

/// One way of ordering the dashboard's session rows.
enum I2PSessionSortOrder: String, CaseIterable, Identifiable {
    /// The default: the most recently established session first.
    case recent
    /// The peer that has received the most bytes first.
    case received
    /// The peer that has sent the most bytes first.
    case sent
    /// The peer's identity hash, ascending — a fixed order of its own.
    case peerHash

    var id: String { rawValue }

    /// The default order, so nothing moves until the user asks.
    static let `default`: I2PSessionSortOrder = .recent

    /// The name the sort control offers for this order.
    var title: String {
        switch self {
        case .recent: return "Recent"
        case .received: return "Received"
        case .sent: return "Sent"
        case .peerHash: return "Peer hash"
        }
    }

    /// The glyph beside the choice in the control's menu.
    var systemImage: String {
        switch self {
        case .recent: return "clock"
        case .received: return "arrow.down.circle"
        case .sent: return "arrow.up.circle"
        case .peerHash: return "number"
        }
    }

    /// The one short line under the list header naming the order in effect.
    var summaryLine: String {
        switch self {
        case .recent: return "Recent · newest sessions first"
        case .received: return "Received · most bytes in first"
        case .sent: return "Sent · most bytes out first"
        case .peerHash: return "Peer hash · ascending"
        }
    }
}

// MARK: - Sorting

enum I2PSessionSorter {
    /// Applies `order` to the session rows. Identities in `pinned` sort above
    /// every other row — the chosen order then applies among the pinned rows and,
    /// unchanged, to the rest of the list below them. Rows with equal values fall
    /// back to the peer hash so the list never shuffles places between two
    /// readings that measured the same thing.
    static func sorted(_ peers: [I2PPeerSummary],
                       by order: I2PSessionSortOrder,
                       pinned: Set<String> = []) -> [I2PPeerSummary] {
        let pinnedIDs = Set(pinned.map { $0.lowercased() })
        return peers.sorted { lhs, rhs in
            if !pinnedIDs.isEmpty {
                let lhsPinned = pinnedIDs.contains(lhs.id.lowercased())
                let rhsPinned = pinnedIDs.contains(rhs.id.lowercased())
                if lhsPinned != rhsPinned { return lhsPinned }
            }
            switch order {
            case .recent:
                if lhs.establishedAt != rhs.establishedAt {
                    return lhs.establishedAt > rhs.establishedAt
                }
            case .received:
                if lhs.bytesIn != rhs.bytesIn { return lhs.bytesIn > rhs.bytesIn }
            case .sent:
                if lhs.bytesOut != rhs.bytesOut { return lhs.bytesOut > rhs.bytesOut }
            case .peerHash:
                let left = lhs.id.lowercased()
                let right = rhs.id.lowercased()
                if left != right { return left < right }
            }
            return tieBreak(lhs, rhs)
        }
    }

    /// The stable fallback behind every order: the peer's hash, ascending.
    private static func tieBreak(_ lhs: I2PPeerSummary, _ rhs: I2PPeerSummary) -> Bool {
        let left = lhs.id.lowercased()
        let right = rhs.id.lowercased()
        if left != right { return left < right }
        return lhs.transport < rhs.transport
    }
}

// MARK: - Store

/// The order in effect for this app run. Deliberately memory only: the choice
/// lasts while the app is running and a relaunch starts at `recent`.
final class I2PSessionSortStore: @unchecked Sendable {
    static let shared = I2PSessionSortStore()

    private let lock = NSLock()
    private var stored: I2PSessionSortOrder = .default

    /// The order the session list is drawn in right now.
    var current: I2PSessionSortOrder {
        get {
            lock.lock()
            defer { lock.unlock() }
            return stored
        }
        set {
            lock.lock()
            stored = newValue
            lock.unlock()
        }
    }
}

// MARK: - Self-test

enum I2PSessionSortSelfTest {
    private static func peer(id: String,
                             establishedAt: Date,
                             bytesIn: Int,
                             bytesOut: Int,
                             transport: String = "NTCP2") -> I2PPeerSummary {
        I2PPeerSummary(id: id,
                       transport: transport,
                       establishedAt: establishedAt,
                       bytesIn: bytesIn,
                       bytesOut: bytesOut,
                       xorDistanceHex: String(repeating: "0f", count: 32),
                       kademliaBucket: 4,
                       isFloodfill: false,
                       tunnelRole: nil,
                       handshakeBackoff: nil,
                       trafficFlag: nil)
    }

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
        let peerA = peer(id: "aa" + String(repeating: "0", count: 62),
                         establishedAt: start.addingTimeInterval(30),
                         bytesIn: 100, bytesOut: 900)
        let peerB = peer(id: "bb" + String(repeating: "0", count: 62),
                         establishedAt: start.addingTimeInterval(10),
                         bytesIn: 5_000, bytesOut: 200)
        let peerC = peer(id: "cc" + String(repeating: "0", count: 62),
                         establishedAt: start.addingTimeInterval(20),
                         bytesIn: 700, bytesOut: 3_000)
        let peers = [peerB, peerC, peerA]

        run("Session sort · the default stays recent") {
            guard I2PSessionSortOrder.default == .recent,
                  I2PSessionSortStore.shared.current == .recent else {
                throw I2PWireError.invalidFormat
            }
            return "a fresh run orders the session list by session start"
        }

        run("Session sort · recent puts the newest session first") {
            let sorted = I2PSessionSorter.sorted(peers, by: .recent)
            guard sorted.map(\.id) == [peerA.id, peerC.id, peerB.id] else {
                throw I2PWireError.invalidFormat
            }
            return "established 30s, 20s and 10s ago drawn in that order"
        }

        run("Session sort · received and sent each name their own direction") {
            let received = I2PSessionSorter.sorted(peers, by: .received)
            let sent = I2PSessionSorter.sorted(peers, by: .sent)
            guard received.map(\.id) == [peerB.id, peerC.id, peerA.id],
                  sent.map(\.id) == [peerC.id, peerA.id, peerB.id] else {
                throw I2PWireError.invalidFormat
            }
            return "5 KB in · 3 KB out · 100 B in drawn in their own directions"
        }

        run("Session sort · peer hash is an ascending order of its own") {
            let sorted = I2PSessionSorter.sorted(peers, by: .peerHash)
            guard sorted.map(\.id) == [peerA.id, peerB.id, peerC.id] else {
                throw I2PWireError.invalidFormat
            }
            return "aa…, bb… and cc… kept in hash order whatever their bytes"
        }

        run("Session sort · equal readings fall back to the peer hash") {
            let same = start
            let first = peer(id: "bb" + String(repeating: "0", count: 62),
                             establishedAt: same, bytesIn: 1_024, bytesOut: 512)
            let second = peer(id: "aa" + String(repeating: "0", count: 62),
                              establishedAt: same, bytesIn: 1_024, bytesOut: 512)
            for order in I2PSessionSortOrder.allCases {
                let sorted = I2PSessionSorter.sorted([first, second], by: order)
                let again = I2PSessionSorter.sorted([second, first], by: order)
                guard sorted.map(\.id) == again.map(\.id),
                      sorted.map(\.id) == [second.id, first.id] else {
                    throw I2PWireError.invalidFormat
                }
            }
            return "two identical rows land in the same places from either input"
        }

        run("Session sort · sorting keeps every reading and the inspector's link") {
            let sorted = I2PSessionSorter.sorted(peers, by: .received)
            guard sorted.count == peers.count,
                  Set(sorted.map(\.id)) == Set(peers.map(\.id)),
                  let moved = sorted.first,
                  moved.id == peerB.id,
                  moved.bytesIn == 5_000,
                  moved.bytesOut == 200,
                  moved.establishedAt == peerB.establishedAt else {
                throw I2PWireError.invalidFormat
            }
            return "the row that moved to the top still carries its own counters and start time"
        }

        run("Session sort · the store keeps the choice for this run") {
            let order = I2PSessionSortOrder.sent
            I2PSessionSortStore.shared.current = order
            guard I2PSessionSortStore.shared.current == order,
                  I2PSessionSortOrder.peerHash.summaryLine == "Peer hash · ascending",
                  I2PSessionSortOrder.recent.title == "Recent",
                  I2PSessionSortOrder.received.title == "Received",
                  I2PSessionSortOrder.sent.title == "Sent",
                  I2PSessionSortOrder.peerHash.title == "Peer hash",
                  I2PSessionSortOrder.received.summaryLine.hasPrefix("Received") else {
                throw I2PWireError.invalidFormat
            }
            // Put the shared store back so the dashboard's list starts as it
            // did before the suite ran.
            I2PSessionSortStore.shared.current = .recent
            return "Sent kept until something else is chosen, then the default restored"
        }

        return results
    }
}
