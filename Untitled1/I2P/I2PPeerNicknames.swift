//
//  I2PPeerNicknames.swift
//  The label the user gives a peer for their own benefit: it replaces the
//  shortened identity hash in the router dashboard's session list and in the
//  peer inspector's title, with the short hash still shown one line below.
//  A label belongs to the identity, not to a session, so it is still there
//  when the peer ends its session and connects again. It lives in user
//  defaults on this device only and never reaches the network — nothing here
//  is read by a dial, a handshake or a message.
//

import Foundation

/// One labelled peer: its identity hash, the label and when it was last set.
struct I2PPeerNickname: Identifiable, Codable, Equatable {
    let identityHex: String
    let label: String
    let updatedAt: Date

    var id: String { identityHex }

    /// The identity as the app prints it: first and last few hex characters.
    var shortIdentity: String { I2PPeerNicknameFormat.shortHash(identityHex) }
}

/// The persisted set of peer labels, keyed by identity hash.
///
/// Setting a label replaces the one the identity already had, so the store
/// never holds an identity twice; setting it to nothing (or to whitespace)
/// removes it, which is what emptying the inspector's field does. Only the
/// identity, the text and the time are kept — no session, address or key
/// material — and the whole store is a local convenience that the router
/// itself never reads.
final class I2PPeerNicknames: @unchecked Sendable {
    static let shared = I2PPeerNicknames()

    /// The longest label the store keeps, in characters.
    static let maxLabelLength = 32

    private static let storageKey = "i2p.peer.nicknames"

    private let defaults: UserDefaults
    private let lock = NSLock()
    private var entries: [I2PPeerNickname] = []

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        load()
    }

    /// Every label, most recently set first.
    func all() -> [I2PPeerNickname] {
        lock.lock()
        defer { lock.unlock() }
        return entries.sorted { $0.updatedAt > $1.updatedAt }
    }

    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return entries.count
    }

    /// Every label keyed by normalized identity hex — the form the session
    /// list and the inspector look up.
    func labels() -> [String: String] {
        lock.lock()
        defer { lock.unlock() }
        var map: [String: String] = [:]
        for entry in entries { map[entry.identityHex] = entry.label }
        return map
    }

    func label(for hash: Data) -> String? {
        label(identityHex: Self.hex(hash))
    }

    /// The label for one identity, or nil while it has none — which is when
    /// every screen keeps reading the peer exactly as it did before.
    func label(identityHex: String) -> String? {
        let normalized = Self.normalize(identityHex)
        lock.lock()
        defer { lock.unlock() }
        return entries.first { $0.identityHex == normalized }?.label
    }

    /// Saves the label the user typed for an identity and returns what was
    /// stored: the trimmed, capped text, or nil when the field was emptied.
    @discardableResult
    func setLabel(_ raw: String, for identityHex: String, at date: Date = Date()) -> String? {
        let normalized = Self.normalize(identityHex)
        guard !normalized.isEmpty else { return nil }
        let label = Self.normalizeLabel(raw)
        lock.lock()
        entries.removeAll { $0.identityHex == normalized }
        if let label {
            entries.append(I2PPeerNickname(identityHex: normalized,
                                           label: label,
                                           updatedAt: date))
        }
        persistLocked()
        lock.unlock()
        return label
    }

    @discardableResult
    func setLabel(_ raw: String, for hash: Data, at date: Date = Date()) -> String? {
        setLabel(raw, for: Self.hex(hash), at: date)
    }

    /// Empties the field: the peer reads by its shortened hash again.
    func clear(identityHex: String) {
        setLabel("", for: identityHex)
    }

    func clear(_ hash: Data) {
        setLabel("", for: Self.hex(hash))
    }

    // MARK: Internals

    /// The label as the store keeps it: trimmed, capped at
    /// `maxLabelLength` characters, and nil when nothing is left.
    static func normalizeLabel(_ raw: String) -> String? {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        let capped = String(trimmed.prefix(maxLabelLength))
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return capped.isEmpty ? nil : capped
    }

    private func load() {
        guard let data = defaults.data(forKey: Self.storageKey),
              let decoded = try? JSONDecoder().decode([I2PPeerNickname].self, from: data) else {
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

enum I2PPeerNicknameFormat {
    /// The cap the field enforces while typing and the store enforces on save.
    static let maxLength = I2PPeerNicknames.maxLabelLength

    /// The inspector section's title, its field and its clear control.
    static let cardTitle = "Your label"
    static let fieldPlaceholder = "Nickname"
    static let clearTitle = "Clear label"

    /// The identifier as the app has always printed it: the shortened hash.
    /// Used for a peer without a label and as the line under a labelled one.
    static func shortHash(_ hex: String) -> String {
        guard hex.count > 20 else { return hex }
        return "\(hex.prefix(10))…\(hex.suffix(10))"
    }

    /// Cuts the draft to what the store would keep, without trimming: what the
    /// field shows as the user types.
    static func clamp(_ raw: String) -> String {
        raw.count > maxLength ? String(raw.prefix(maxLength)) : raw
    }

    /// The row's primary line: the user's label when there is one, otherwise
    /// the shortened hash exactly as before.
    static func displayName(label: String?, identityHex: String) -> String {
        if let label, !label.isEmpty { return label }
        return shortHash(identityHex)
    }

    /// The line one below a labelled row's name: the shortened hash, so a
    /// labelled peer stays identifiable. Nil without a label, which is what
    /// keeps an unlabelled row reading exactly as it always has.
    static func hashLine(label: String?, identityHex: String) -> String? {
        guard let label, !label.isEmpty else { return nil }
        return shortHash(identityHex)
    }

    /// The peer inspector's title: the label when there is one.
    static func inspectorTitle(label: String?) -> String {
        if let label, !label.isEmpty { return label }
        return "Peer"
    }

    /// The line under the inspector's field naming what the label does now.
    static func savedLine(label: String?, identityHex: String) -> String {
        if let label, !label.isEmpty {
            return "Shown instead of \(shortHash(identityHex)) in the session list and in this screen's title, with the hash kept one line below."
        }
        return "Empty, so this peer reads by its shortened hash \(shortHash(identityHex)) everywhere."
    }

    /// How much of the cap the field is using: "12 of 32 characters".
    static func counter(_ draft: String) -> String {
        "\(draft.count) of \(maxLength) characters"
    }
}

// MARK: - Self-test

enum I2PPeerNicknamesSelfTest {
    static func runAll() -> [I2PSelfTestResult] {
        var results: [I2PSelfTestResult] = []
        func run(_ name: String, _ body: () throws -> String) {
            do {
                results.append(I2PSelfTestResult(name: name, passed: true, detail: try body()))
            } catch {
                results.append(I2PSelfTestResult(name: name, passed: false, detail: "\(error)"))
            }
        }

        run("Peer nicknames · trimmed, capped, persisted per identity and cleared") {
            let name = "i2p.nicknames.selftest.\(UUID().uuidString)"
            guard let defaults = UserDefaults(suiteName: name) else { throw I2PWireError.invalidFormat }
            defer { UserDefaults.standard.removePersistentDomain(forName: name) }

            let store = I2PPeerNicknames(defaults: defaults)
            let hash = I2PCrypto.randomBytes(32)
            let other = I2PCrypto.randomBytes(32)
            let firstSavedAt = Date(timeIntervalSince1970: 1_700_000_000)
            guard store.label(for: hash) == nil, store.count == 0 else { throw I2PWireError.invalidFormat }

            // Whitespace around the label is trimmed on the way in.
            guard store.setLabel("  Alice's relay \n", for: hash, at: firstSavedAt) == "Alice's relay" else {
                throw I2PWireError.invalidFormat
            }
            guard store.label(for: hash) == "Alice's relay",
                  store.label(identityHex: I2PPeerNicknames.hex(hash).uppercased()) == "Alice's relay",
                  store.label(for: other) == nil,
                  store.count == 1 else {
                throw I2PWireError.invalidFormat
            }

            // A fresh instance over the same defaults is what a relaunch sees.
            let reloaded = I2PPeerNicknames(defaults: defaults)
            guard reloaded.label(for: hash) == "Alice's relay", reloaded.count == 1 else {
                throw I2PWireError.invalidFormat
            }

            // Anything past the cap is dropped, not stored and shortened later.
            let long = String(repeating: "a", count: 40)
            let otherSavedAt = firstSavedAt.addingTimeInterval(1)
            let capped = reloaded.setLabel(long, for: other, at: otherSavedAt)
            guard capped?.count == I2PPeerNicknames.maxLabelLength,
                  capped == String(long.prefix(I2PPeerNicknames.maxLabelLength)),
                  reloaded.label(for: other) == capped,
                  reloaded.count == 2 else {
                throw I2PWireError.invalidFormat
            }

            // Re-labelling replaces the entry instead of adding a second one.
            reloaded.setLabel("Bob", for: other, at: otherSavedAt.addingTimeInterval(1))
            guard reloaded.count == 2,
                  reloaded.label(for: other) == "Bob",
                  reloaded.all().first?.identityHex == I2PPeerNicknames.hex(other),
                  I2PPeerNicknames(defaults: defaults).label(for: other) == "Bob" else {
                throw I2PWireError.invalidFormat
            }

            // Emptying the field clears the label; so does whitespace alone.
            reloaded.setLabel("   ", for: hash)
            guard reloaded.label(for: hash) == nil, reloaded.count == 1 else {
                throw I2PWireError.invalidFormat
            }
            reloaded.clear(other)
            guard reloaded.label(for: other) == nil,
                  reloaded.labels().isEmpty,
                  I2PPeerNicknames(defaults: defaults).count == 0 else {
                throw I2PWireError.invalidFormat
            }
            return "a label trimmed, capped at 32, replaced in place, surviving a relaunch and cleared by emptying the field"
        }

        run("Peer nicknames · a label replaces the short hash and keeps it one line below") {
            let hex = "3f" + String(repeating: "a7", count: 31)
            let short = I2PPeerNicknameFormat.shortHash(hex)
            guard short.hasPrefix("3f"), short.hasSuffix(String(repeating: "a7", count: 5)),
                  short.count < hex.count else {
                throw I2PWireError.invalidFormat
            }

            // Without a label every screen reads exactly as it did before.
            guard I2PPeerNicknameFormat.displayName(label: nil, identityHex: hex) == short,
                  I2PPeerNicknameFormat.hashLine(label: nil, identityHex: hex) == nil,
                  I2PPeerNicknameFormat.inspectorTitle(label: nil) == "Peer" else {
                throw I2PWireError.invalidFormat
            }

            // With one, the label leads and the hash sits on the line below.
            guard I2PPeerNicknameFormat.displayName(label: "Alice's relay", identityHex: hex) == "Alice's relay",
                  I2PPeerNicknameFormat.hashLine(label: "Alice's relay", identityHex: hex) == short,
                  I2PPeerNicknameFormat.inspectorTitle(label: "Alice's relay") == "Alice's relay" else {
                throw I2PWireError.invalidFormat
            }

            // An empty label counts as no label at all.
            guard I2PPeerNicknameFormat.displayName(label: "", identityHex: hex) == short,
                  I2PPeerNicknameFormat.hashLine(label: "", identityHex: hex) == nil,
                  I2PPeerNicknameFormat.inspectorTitle(label: "") == "Peer" else {
                throw I2PWireError.invalidFormat
            }

            guard I2PPeerNicknameFormat.clamp(String(repeating: "b", count: 40)).count == 32,
                  I2PPeerNicknameFormat.clamp("short") == "short",
                  I2PPeerNicknameFormat.counter("Bob") == "3 of 32 characters" else {
                throw I2PWireError.invalidFormat
            }
            return "a labelled row and title read by the label with the short hash beneath; an unlabelled one is unchanged"
        }

        run("Peer nicknames · labels are keyed by normalized identity and never leave the device") {
            let name = "i2p.nicknames.selftest.\(UUID().uuidString)"
            guard let defaults = UserDefaults(suiteName: name) else { throw I2PWireError.invalidFormat }
            defer { UserDefaults.standard.removePersistentDomain(forName: name) }

            let store = I2PPeerNicknames(defaults: defaults)
            let hash = Data(repeating: 0xab, count: 32)
            let upper = I2PPeerNicknames.hex(hash).uppercased()
            store.setLabel("Relay", for: hash)

            // The map the dashboard reads is keyed by lowercase hex, so an
            // uppercase identity from anywhere else still finds its label.
            guard store.labels() == [I2PPeerNicknames.hex(hash): "Relay"],
                  store.labels()[upper.lowercased()] == "Relay",
                  store.label(identityHex: upper) == "Relay" else {
                throw I2PWireError.invalidFormat
            }

            // The store writes one defaults key and holds nothing else — no
            // session, address or key material could be handed to the network.
            let entry = store.all().first
            guard entry?.identityHex == I2PPeerNicknames.hex(hash),
                  entry?.label == "Relay",
                  I2PPeerNickname(identityHex: entry?.identityHex ?? "", label: "Relay", updatedAt: Date()).shortIdentity == I2PPeerNicknameFormat.shortHash(I2PPeerNicknames.hex(hash)) else {
                throw I2PWireError.invalidFormat
            }
            return "AB… resolves through uppercase and lowercase hex alike; an entry carries only the identity, the label and the time"
        }

        return results
    }
}
