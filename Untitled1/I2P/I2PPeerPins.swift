//
//  I2PPeerPins.swift
//  The peers the user pinned from the peer inspector: their identity sort above
//  every other row of the Router dashboard's session list, whatever order is in
//  effect. A pin belongs to the identity, not to a session, so it is still there
//  when the peer ends its session and connects again. Persisted across launches
//  in user defaults, in the same shape as the peer blocklist.
//

import Foundation

/// One pinned peer: its identity hash and when it was pinned.
struct I2PPinnedPeer: Identifiable, Codable, Equatable {
    let identityHex: String
    let pinnedAt: Date

    var id: String { identityHex }

    /// The identity as listed in the UI: first and last few hex characters.
    var shortIdentity: String {
        guard identityHex.count > 20 else { return identityHex }
        return "\(identityHex.prefix(10))…\(identityHex.suffix(8))"
    }
}

/// The persisted set of pinned peer identities.
///
/// Reads are keyed by identity hash, so the pin does not know about sessions: a
/// peer that drops its session and reconnects still arrives at the top of the
/// session list. The store is deliberately independent of the sort order — the
/// order finishes below the pinned rows, it is never overruled by them.
final class I2PPeerPins: @unchecked Sendable {
    static let shared = I2PPeerPins()

    private static let storageKey = "i2p.pinned.peers"

    private let defaults: UserDefaults
    private let lock = NSLock()
    private var entries: [I2PPinnedPeer] = []

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        load()
    }

    /// Every pinned peer, newest pin first.
    func all() -> [I2PPinnedPeer] {
        lock.lock()
        defer { lock.unlock() }
        return entries.sorted { $0.pinnedAt > $1.pinnedAt }
    }

    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return entries.count
    }

    /// The pinned identities in the form the session sorter matches on:
    /// normalized hex.
    func pinnedIdentities() -> Set<String> {
        lock.lock()
        defer { lock.unlock() }
        return Set(entries.map(\.identityHex))
    }

    func isPinned(_ hash: Data) -> Bool {
        isPinned(identityHex: Self.hex(hash))
    }

    func isPinned(identityHex: String) -> Bool {
        let normalized = Self.normalize(identityHex)
        lock.lock()
        defer { lock.unlock() }
        return entries.contains { $0.identityHex == normalized }
    }

    /// Pins a peer. Pinning again only refreshes the timestamp, so the store
    /// never holds an identity twice.
    func pin(identityHex: String, at date: Date = Date()) {
        let normalized = Self.normalize(identityHex)
        guard !normalized.isEmpty else { return }
        let entry = I2PPinnedPeer(identityHex: normalized, pinnedAt: date)
        lock.lock()
        entries.removeAll { $0.identityHex == normalized }
        entries.append(entry)
        persistLocked()
        lock.unlock()
    }

    func pin(_ hash: Data, at date: Date = Date()) {
        pin(identityHex: Self.hex(hash), at: date)
    }

    func unpin(identityHex: String) {
        let normalized = Self.normalize(identityHex)
        lock.lock()
        entries.removeAll { $0.identityHex == normalized }
        persistLocked()
        lock.unlock()
    }

    func unpin(_ hash: Data) {
        unpin(identityHex: Self.hex(hash))
    }

    /// Flips the pin and returns the state it now has, which is what the
    /// inspector's control reads back.
    @discardableResult
    func toggle(identityHex: String, at date: Date = Date()) -> Bool {
        if isPinned(identityHex: identityHex) {
            unpin(identityHex: identityHex)
            return false
        }
        pin(identityHex: identityHex, at: date)
        return true
    }

    @discardableResult
    func toggle(_ hash: Data, at date: Date = Date()) -> Bool {
        toggle(identityHex: Self.hex(hash), at: date)
    }

    // MARK: Internals

    private func load() {
        guard let data = defaults.data(forKey: Self.storageKey),
              let decoded = try? JSONDecoder().decode([I2PPinnedPeer].self, from: data) else {
            return
        }
        lock.lock()
        entries = decoded
        lock.unlock()
    }

    private func persistLocked() {
        guard let data = try? JSONEncoder().encode(entries) else { return }
        defaults.set(data, forKey: Self.storageKey)
    }

    private static func normalize(_ hex: String) -> String {
        hex.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - Labels

enum I2PPeerPinFormat {
    /// The small badge a pinned peer's session row carries.
    static let badgeTitle = "Pinned"
    static let badgeSystemImage = "pin.fill"
    static let controlSystemImage = "pin"

    /// What the inspector's control says about the peer's current state.
    static func controlTitle(pinned: Bool) -> String {
        pinned ? "Pinned" : "Not pinned"
    }

    /// The line under the inspector's header saying what the pin does.
    static func inspectorLine(pinned: Bool) -> String {
        if pinned {
            return "Kept at the top of the dashboard's session list, whatever the sort order. The pin belongs to this identity, so it is still here when the peer reconnects."
        }
        return "Pin this identity to keep it at the top of the dashboard's session list, whatever the sort order."
    }

    /// The dashboard's line under the list header, naming that the chosen order
    /// only governs the rows below the pins.
    static func orderLine(_ order: I2PSessionSortOrder, pinnedCount: Int) -> String {
        guard pinnedCount > 0 else { return order.summaryLine }
        let noun = pinnedCount == 1 ? "pinned peer" : "pinned peers"
        return "\(order.summaryLine) · \(pinnedCount) \(noun) first"
    }
}

// MARK: - Self-test

enum I2PPeerPinsSelfTest {
    private static func peer(id: String,
                             establishedAt: Date,
                             bytesIn: Int,
                             bytesOut: Int) -> I2PPeerSummary {
        I2PPeerSummary(id: id,
                       transport: "NTCP2",
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

        run("Peer pins · pin, persist across instances, unpin") {
            let name = "i2p.pins.selftest.\(UUID().uuidString)"
            guard let defaults = UserDefaults(suiteName: name) else { throw I2PWireError.invalidFormat }
            defer { UserDefaults.standard.removePersistentDomain(forName: name) }

            let store = I2PPeerPins(defaults: defaults)
            let hash = I2PCrypto.randomBytes(32)
            guard !store.isPinned(hash), store.all().isEmpty, store.pinnedIdentities().isEmpty else {
                throw I2PWireError.invalidFormat
            }

            let pinnedAt = Date(timeIntervalSince1970: 1_700_000_000)
            store.pin(hash, at: pinnedAt)
            guard store.isPinned(hash),
                  store.isPinned(identityHex: I2PPeerPins.hex(hash)),
                  store.count == 1,
                  store.all().first?.pinnedAt == pinnedAt,
                  store.pinnedIdentities() == [I2PPeerPins.hex(hash)] else {
                throw I2PWireError.invalidFormat
            }

            // A fresh instance over the same defaults is what a relaunch sees.
            let reloaded = I2PPeerPins(defaults: defaults)
            guard reloaded.isPinned(hash), reloaded.all().count == 1 else {
                throw I2PWireError.invalidFormat
            }

            // Pinning again replaces the entry instead of duplicating it.
            reloaded.pin(hash, at: pinnedAt.addingTimeInterval(60))
            guard reloaded.count == 1,
                  reloaded.all().first?.pinnedAt == pinnedAt.addingTimeInterval(60) else {
                throw I2PWireError.invalidFormat
            }

            reloaded.unpin(hash)
            guard !reloaded.isPinned(hash),
                  I2PPeerPins(defaults: defaults).all().isEmpty else {
                throw I2PWireError.invalidFormat
            }
            return "a pinned identity survives a relaunch, re-pinning refreshes it, unpinning empties the store"
        }

        run("Peer pins · the toggle returns the state it just took") {
            let name = "i2p.pins.selftest.\(UUID().uuidString)"
            guard let defaults = UserDefaults(suiteName: name) else { throw I2PWireError.invalidFormat }
            defer { UserDefaults.standard.removePersistentDomain(forName: name) }

            let store = I2PPeerPins(defaults: defaults)
            // A mixed-case hash pins the same identity as its lowercase form.
            let hash = Data(repeating: 0xab, count: 32)
            let upper = I2PPeerPins.hex(hash).uppercased()
            guard store.toggle(identityHex: upper),
                  store.isPinned(hash),
                  I2PPeerPinFormat.controlTitle(pinned: true) == "Pinned" else {
                throw I2PWireError.invalidFormat
            }
            guard !store.toggle(identityHex: upper),
                  !store.isPinned(hash),
                  I2PPeerPinFormat.controlTitle(pinned: false) == "Not pinned" else {
                throw I2PWireError.invalidFormat
            }
            return "AB… pinned by its uppercase hex, then unpinned by the same string"
        }

        run("Peer pins · a pinned peer sorts above every order") {
            let name = "i2p.pins.selftest.\(UUID().uuidString)"
            guard let defaults = UserDefaults(suiteName: name) else { throw I2PWireError.invalidFormat }
            defer { UserDefaults.standard.removePersistentDomain(forName: name) }

            let store = I2PPeerPins(defaults: defaults)
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
            store.pin(identityHex: peerA.id)

            for order in I2PSessionSortOrder.allCases {
                // Without pins every order is the plain one it always was.
                guard I2PSessionSorter.sorted(peers, by: order).map(\.id)
                        == I2PSessionSorter.sorted(peers, by: order, pinned: []).map(\.id) else {
                    throw I2PWireError.invalidFormat
                }
                let sorted = I2PSessionSorter.sorted(peers, by: order,
                                                     pinned: store.pinnedIdentities())
                let below = I2PSessionSorter.sorted([peerB, peerC], by: order).map(\.id)
                guard sorted.first?.id == peerA.id,
                      sorted.dropFirst().map(\.id) == below else {
                    throw I2PWireError.invalidFormat
                }
            }
            return "aa… stayed first under recent, received, sent and peer hash while the other two kept the chosen order"
        }

        run("Peer pins · a peer that ended its session keeps its pin") {
            let name = "i2p.pins.selftest.\(UUID().uuidString)"
            guard let defaults = UserDefaults(suiteName: name) else { throw I2PWireError.invalidFormat }
            defer { UserDefaults.standard.removePersistentDomain(forName: name) }

            let store = I2PPeerPins(defaults: defaults)
            let start = Date(timeIntervalSince1970: 1_700_000_000)
            let peerA = peer(id: "aa" + String(repeating: "0", count: 62),
                             establishedAt: start, bytesIn: 10, bytesOut: 20)
            let peerB = peer(id: "bb" + String(repeating: "0", count: 62),
                             establishedAt: start, bytesIn: 30, bytesOut: 40)
            store.pin(identityHex: peerB.id)

            // The session ends: the pinned peer is simply not in the live list.
            let whileGone = I2PSessionSorter.sorted([peerA], by: .recent,
                                                    pinned: store.pinnedIdentities())
            guard whileGone.map(\.id) == [peerA.id],
                  store.isPinned(identityHex: peerB.id) else {
                throw I2PWireError.invalidFormat
            }

            // It reconnects, and the pin held in the store puts it back on top.
            let afterReconnect = I2PSessionSorter.sorted([peerA, peerB], by: .recent,
                                                        pinned: I2PPeerPins(defaults: defaults).pinnedIdentities())
            guard afterReconnect.map(\.id) == [peerB.id, peerA.id],
                  I2PPeerPinFormat.badgeTitle == "Pinned",
                  I2PPeerPinFormat.badgeSystemImage == "pin.fill",
                  I2PPeerPinFormat.orderLine(.recent, pinnedCount: 0) == I2PSessionSortOrder.recent.summaryLine,
                  I2PPeerPinFormat.orderLine(.received, pinnedCount: 1).hasSuffix("· 1 pinned peer first") else {
                throw I2PWireError.invalidFormat
            }
            return "bb… dropped out of the list with its pin intact and returned to the top on reconnect"
        }

        return results
    }
}
