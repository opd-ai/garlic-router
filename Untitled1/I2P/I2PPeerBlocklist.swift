//
//  I2PPeerBlocklist.swift
//  The user's peer blocklist: identities the router must never select as a
//  tunnel hop or a netdb lookup target, and whose session it closes on the
//  next maintenance tick. Persisted across launches in user defaults.
//

import Foundation

/// One blocked peer: its identity hash, why it was blocked and when.
struct I2PBlockedPeer: Identifiable, Codable, Equatable {
    let identityHex: String
    let reason: String
    let blockedAt: Date

    var id: String { identityHex }

    /// The identity as listed in the UI: first and last few hex characters.
    var shortIdentity: String {
        guard identityHex.count > 20 else { return identityHex }
        return "\(identityHex.prefix(10))…\(identityHex.suffix(8))"
    }
}

/// The persisted peer blocklist.
///
/// A blocked peer is excluded from tunnel hop selection and from netdb
/// floodfill targeting, its live session is closed on the next maintenance
/// tick, and the router never dials it again — the demand-dial path refuses a
/// blocked hash too.
final class I2PPeerBlocklist: @unchecked Sendable {
    static let shared = I2PPeerBlocklist()

    private static let storageKey = "i2p.blocklist.peers"

    private let defaults: UserDefaults
    private let lock = NSLock()
    private var entries: [I2PBlockedPeer] = []

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        load()
    }

    /// Every blocked peer, newest first.
    func all() -> [I2PBlockedPeer] {
        lock.lock()
        defer { lock.unlock() }
        return entries.sorted { $0.blockedAt > $1.blockedAt }
    }

    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return entries.count
    }

    func isBlocked(_ hash: Data) -> Bool {
        isBlocked(identityHex: Self.hex(hash))
    }

    func isBlocked(identityHex: String) -> Bool {
        let normalized = Self.normalize(identityHex)
        lock.lock()
        defer { lock.unlock() }
        return entries.contains { $0.identityHex == normalized }
    }

    /// Blocks a peer. Blocking an already-blocked peer replaces its reason and
    /// timestamp, so the list never holds duplicates.
    func block(identityHex: String, reason: String, at date: Date = Date()) {
        let normalized = Self.normalize(identityHex)
        guard !normalized.isEmpty else { return }
        let entry = I2PBlockedPeer(identityHex: normalized,
                                   reason: reason.trimmingCharacters(in: .whitespacesAndNewlines),
                                   blockedAt: date)
        lock.lock()
        entries.removeAll { $0.identityHex == normalized }
        entries.append(entry)
        persistLocked()
        lock.unlock()
    }

    func block(_ hash: Data, reason: String, at date: Date = Date()) {
        block(identityHex: Self.hex(hash), reason: reason, at: date)
    }

    func unblock(identityHex: String) {
        let normalized = Self.normalize(identityHex)
        lock.lock()
        entries.removeAll { $0.identityHex == normalized }
        persistLocked()
        lock.unlock()
    }

    func unblock(_ hash: Data) {
        unblock(identityHex: Self.hex(hash))
    }

    // MARK: Internals

    private func load() {
        guard let data = defaults.data(forKey: Self.storageKey),
              let decoded = try? JSONDecoder().decode([I2PBlockedPeer].self, from: data) else {
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

// MARK: - Self-test

enum I2PPeerBlocklistSelfTest {
    static func runAll() -> [I2PSelfTestResult] {
        var results: [I2PSelfTestResult] = []
        func run(_ name: String, _ body: () throws -> String) {
            do {
                results.append(I2PSelfTestResult(name: name, passed: true, detail: try body()))
            } catch {
                results.append(I2PSelfTestResult(name: name, passed: false, detail: "\(error)"))
            }
        }

        run("Peer blocklist · block, persist across instances, unblock") {
            let name = "i2p.blocklist.selftest.\(UUID().uuidString)"
            guard let defaults = UserDefaults(suiteName: name) else { throw I2PWireError.invalidFormat }
            defer { UserDefaults.standard.removePersistentDomain(forName: name) }

            let list = I2PPeerBlocklist(defaults: defaults)
            let hash = I2PCrypto.randomBytes(32)
            guard !list.isBlocked(hash), list.all().isEmpty else { throw I2PWireError.invalidFormat }

            let blockedAt = Date(timeIntervalSince1970: 1_700_000_000)
            list.block(hash, reason: "  repeated bad builds  ", at: blockedAt)
            guard list.isBlocked(hash),
                  list.isBlocked(identityHex: I2PPeerBlocklist.hex(hash)),
                  list.count == 1,
                  list.all().first?.reason == "repeated bad builds",
                  list.all().first?.blockedAt == blockedAt else {
                throw I2PWireError.invalidFormat
            }

            // A fresh instance over the same defaults is what a relaunch sees.
            let reloaded = I2PPeerBlocklist(defaults: defaults)
            guard reloaded.isBlocked(hash), reloaded.all().count == 1 else { throw I2PWireError.invalidFormat }

            // Blocking again replaces the entry instead of duplicating it.
            reloaded.block(hash, reason: "changed my mind")
            guard reloaded.count == 1, reloaded.all().first?.reason == "changed my mind" else {
                throw I2PWireError.invalidFormat
            }

            reloaded.unblock(hash)
            guard !reloaded.isBlocked(hash),
                  I2PPeerBlocklist(defaults: defaults).all().isEmpty else {
                throw I2PWireError.invalidFormat
            }
            return "blocked identity survives a relaunch, re-blocking replaces the entry, unblocking empties it"
        }

        return results
    }
}
