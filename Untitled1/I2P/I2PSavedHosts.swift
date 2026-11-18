//
//  I2PSavedHosts.swift
//  The saved eepsite hosts: the .i2p names and b33 addresses the user kept
//  from the browser, each with the time it was saved, when it was last visited
//  and how its last fetch ended. Persisted across launches in user defaults.
//

import Foundation
import Combine

// MARK: - Entry

/// Which kind of host a bookmark holds: a .i2p name (a named host, a b32
/// hostname or a typed destination) or a b33 blinded address.
enum I2PSavedHostKind: String, Codable {
    case i2pName
    case b33

    /// What the row's icon stands for when spoken.
    var label: String {
        switch self {
        case .i2pName: return ".i2p name"
        case .b33: return "b33 address"
        }
    }
}

/// How the last fetch of a saved host ended, as the row reports it.
enum I2PSavedHostFetchResult: String, Codable, CaseIterable {
    case ok
    case resolveFailed
    case connectionFailed

    /// The word the row shows after the visit time.
    var label: String {
        switch self {
        case .ok: return "ok"
        case .resolveFailed: return "resolve failed"
        case .connectionFailed: return "connection failed"
        }
    }

    var isFailure: Bool { self != .ok }
}

/// One saved host: the address the browser loads, its kind, when it was kept,
/// when it was last visited and the result of that fetch.
struct I2PSavedHostEntry: Codable, Identifiable, Equatable {
    /// The host in the browser's own canonical form — "wiki.i2p", a b32 host or
    /// "<b33>.b33.i2p" — exactly what the address bar loads.
    let host: String
    let kind: I2PSavedHostKind
    /// When the bookmark was made.
    let savedAt: Date
    /// The last time a fetch for this host ran (nil until one runs again).
    var lastVisitedAt: Date?
    /// How that fetch ended (nil until one runs).
    var lastResult: I2PSavedHostFetchResult?

    var id: String { host }
}

// MARK: - Saved hosts store

/// The bookmarked hosts, newest saved first.
///
/// The list only remembers bookmarks: a fetch result is only recorded for a
/// host that is already saved, so browsing never grows the list on its own.
/// Every mutation is driven from the main thread (SwiftUI actions and the
/// browser's `MainActor.run` completions), so the published state stays
/// consistent with the views that observe it.
final class I2PSavedHostsStore: ObservableObject {
    static let shared = I2PSavedHostsStore()
    static let defaultsKey = "i2p.savedHosts"

    @Published private(set) var entries: [I2PSavedHostEntry] = []

    private let defaults: UserDefaults
    private let storageKey: String

    init(defaults: UserDefaults = .standard,
         storageKey: String = I2PSavedHostsStore.defaultsKey) {
        self.defaults = defaults
        self.storageKey = storageKey
        self.entries = Self.load(defaults: defaults, key: storageKey)
    }

    // MARK: Saving and removing

    /// The host an address bar's text resolves to, normalized the way the
    /// browser loads it, or nil when the bar holds nothing savable (a clear-net
    /// name, a partial address, an empty field).
    static func host(in raw: String) -> (host: String, kind: I2PSavedHostKind)? {
        guard let address = try? I2PEepsiteAddress.parse(raw) else { return nil }
        let kind: I2PSavedHostKind
        if case .b33 = address.host {
            kind = .b33
        } else {
            kind = .i2pName
        }
        return (address.displayHost, kind)
    }

    func contains(_ host: String) -> Bool {
        entries.contains { $0.host == host }
    }

    /// Keeps the host the address resolves to. Returns false when the text is
    /// not a savable host or it is already in the list, so no duplicate is ever
    /// added.
    @discardableResult
    func save(_ raw: String, at date: Date = Date()) -> Bool {
        guard let candidate = Self.host(in: raw) else { return false }
        guard !contains(candidate.host) else { return false }
        entries.insert(I2PSavedHostEntry(host: candidate.host,
                                         kind: candidate.kind,
                                         savedAt: date,
                                         lastVisitedAt: nil,
                                         lastResult: nil),
                       at: 0)
        persist()
        return true
    }

    /// Records one fetch for a saved host: when it ran and how it ended. A host
    /// that is not saved is ignored; the list only keeps bookmarks.
    @discardableResult
    func recordFetch(_ raw: String,
                     result: I2PSavedHostFetchResult,
                     at date: Date = Date()) -> Bool {
        guard let host = Self.host(in: raw)?.host,
              let index = entries.firstIndex(where: { $0.host == host }) else {
            return false
        }
        entries[index].lastVisitedAt = date
        entries[index].lastResult = result
        persist()
        return true
    }

    /// Drops a host from the list (swipe to delete).
    func remove(_ host: String) {
        let before = entries.count
        entries.removeAll { $0.host == host }
        guard entries.count != before else { return }
        persist()
    }

    /// The entries matching the filter field; everything when it is empty.
    func filtered(_ query: String) -> [I2PSavedHostEntry] {
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !trimmed.isEmpty else { return entries }
        return entries.filter { $0.host.lowercased().contains(trimmed) }
    }

    // MARK: Address bar suggestions

    /// How many rows the address bar's suggestion list shows at most.
    static let suggestionLimit = 6

    /// The saved hosts whose name contains the address bar's text, most
    /// recently visited first and capped at `limit` rows. Empty text lists
    /// nothing, and only bookmarks are suggested: browsing never feeds in.
    func suggestions(for query: String,
                     limit: Int = I2PSavedHostsStore.suggestionLimit) -> [I2PSavedHostEntry] {
        Array(orderedMatches(query).prefix(max(0, limit)))
    }

    /// The host the address bar completes to while typing: the one saved host
    /// whose name starts with the typed text. Nil when nothing matches, when
    /// more than one does, or when the bar already holds that whole host — so
    /// completion never loops.
    ///
    /// The text must also have reached a label boundary — the whole label is
    /// typed, or the TLD has been started ("planet", "planet.i") — so a name
    /// that is still being typed is never overwritten in the middle of a word.
    func completion(for query: String) -> String? {
        let trimmed = Self.normalized(query)
        guard !trimmed.isEmpty else { return nil }
        // A prefix match on the label or on the whole host, so "planet.i"
        // completes as the TLD is typed while a bare "i2p" (which every saved
        // host carries in its suffix) matches many and completes nothing.
        let prefixed = entries.filter {
            Self.searchableLabel($0.host).hasPrefix(trimmed)
                || $0.host.lowercased().hasPrefix(trimmed)
        }
        guard prefixed.count == 1, let only = prefixed.first else { return nil }
        let host = only.host
        let lowered = host.lowercased()
        guard trimmed.count < lowered.count else { return nil }
        let nextIndex = lowered.index(lowered.startIndex, offsetBy: trimmed.count)
        let atBoundary = trimmed.contains(".") || lowered[nextIndex] == "."
        guard atBoundary else { return nil }
        return host
    }

    /// Every saved host containing the text, most recently visited first.
    /// Hosts never visited follow the visited ones, newest saved first.
    private func orderedMatches(_ query: String) -> [I2PSavedHostEntry] {
        let needle = Self.searchableNeedle(query)
        guard !needle.isEmpty else { return [] }
        return entries
            .filter { Self.searchableLabel($0.host).contains(needle) }
            .sorted { lhs, rhs in
                if let left = lhs.lastVisitedAt, let right = rhs.lastVisitedAt {
                    if left != right { return right < left }
                } else if lhs.lastVisitedAt != nil {
                    return true
                } else if rhs.lastVisitedAt != nil {
                    return false
                }
                return lhs.savedAt > rhs.savedAt
            }
    }

    /// The host without its ".i2p" suffix — the part the address bar's text is
    /// matched against. Matching the whole host instead made a query of "i2p"
    /// list every saved host, since they all carry that TLD.
    static func searchableLabel(_ host: String) -> String {
        let lowered = host.lowercased()
        return lowered.hasSuffix(".i2p") ? String(lowered.dropLast(4)) : lowered
    }

    /// The address bar's text in the same form, so pasting a whole host still
    /// matches.
    private static func searchableNeedle(_ query: String) -> String {
        searchableLabel(normalized(query))
    }

    private static func normalized(_ query: String) -> String {
        query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    // MARK: Persistence

    private func persist() {
        guard let data = try? JSONEncoder().encode(entries) else { return }
        defaults.set(data, forKey: storageKey)
    }

    private static func load(defaults: UserDefaults, key: String) -> [I2PSavedHostEntry] {
        guard let data = defaults.data(forKey: key),
              let decoded = try? JSONDecoder().decode([I2PSavedHostEntry].self, from: data) else {
            return []
        }
        return decoded
    }
}

// MARK: - Failure classification

extension I2PEepsiteFailure {
    /// How a saved host records this failure: resolution covers the address,
    /// lookup, blinding and lease stages; everything from the tunnel pool
    /// onwards is the connection and stream path.
    var savedHostResult: I2PSavedHostFetchResult {
        switch stage {
        case .address, .lookup, .blinding, .leases:
            return .resolveFailed
        case .tunnels, .connect, .request, .response:
            return .connectionFailed
        }
    }
}

// MARK: - Self-test suite (saved hosts)

enum I2PSavedHostsSelfTest {
    static func runAll() -> [I2PSelfTestResult] {
        var results: [I2PSelfTestResult] = []
        func run(_ name: String, _ body: () throws -> String) {
            do {
                let detail = try body()
                results.append(I2PSelfTestResult(name: name, passed: true, detail: detail))
            } catch {
                results.append(I2PSelfTestResult(name: name, passed: false,
                                                 detail: String(describing: error)))
            }
        }

        run("saved hosts · saves a .i2p name and a b33 address, and persists") {
            let (defaults, key) = makeDefaults("save")
            let store = I2PSavedHostsStore(defaults: defaults, storageKey: key)
            let savedAt = Date(timeIntervalSince1970: 1_700_000_000)
            // A typed URL with scheme, path and port saves as the bare host.
            guard store.save("  HTTPS://I2PWiki.i2p:8080/wiki/Main_Page ",
                             at: savedAt) else {
                throw I2PWireError.invalidFormat
            }
            guard let first = store.entries.first,
                  first.host == "i2pwiki.i2p",
                  first.kind == .i2pName,
                  first.savedAt == savedAt,
                  first.lastVisitedAt == nil,
                  first.lastResult == nil,
                  store.entries.count == 1 else {
                throw I2PWireError.invalidFormat
            }
            // A b33 address saves in the browser's canonical host form.
            let address = try b33Address()
            guard store.save("b33:\(address.uppercased())", at: savedAt) else {
                throw I2PWireError.invalidFormat
            }
            guard store.entries.count == 2,
                  let b33 = store.entries.first,
                  b33.host == "\(address).b33.i2p",
                  b33.kind == .b33,
                  b33.kind.label == "b33 address" else {
                throw I2PWireError.invalidFormat
            }
            guard store.entries[1].kind == .i2pName else { throw I2PWireError.invalidFormat }
            // A duplicate, a clear-net name and an empty field add nothing.
            guard store.save("i2pwiki.i2p") == false,
                  store.save("example.com") == false,
                  store.save("   ") == false,
                  store.contains("i2pwiki.i2p"),
                  !store.contains("example.com"),
                  store.entries.count == 2 else {
                throw I2PWireError.invalidFormat
            }
            // The bookmarks survive a relaunch.
            let reopened = I2PSavedHostsStore(defaults: defaults, storageKey: key)
            guard reopened.entries == store.entries else { throw I2PWireError.invalidFormat }
            defaults.removePersistentDomain(forName: suiteName("save"))
            return "typed URL normalized to its host; b33 saved in canonical form; duplicate, clear-net and empty input refused; list persisted"
        }

        run("saved hosts · fetch results, visits, filtering and removal") {
            let (defaults, key) = makeDefaults("fetch")
            let store = I2PSavedHostsStore(defaults: defaults, storageKey: key)
            guard store.save("i2pwiki.i2p"),
                  store.save("tracker.i2p"),
                  store.save("forum.i2p") else {
                throw I2PWireError.invalidFormat
            }
            let visited = Date(timeIntervalSince1970: 1_700_100_000)
            // A successful fetch and both failure kinds land on the saved row.
            guard store.recordFetch("i2pwiki.i2p/wiki", result: .ok, at: visited),
                  store.recordFetch("tracker.i2p", result: .resolveFailed, at: visited),
                  store.recordFetch("forum.i2p", result: .connectionFailed, at: visited) else {
                throw I2PWireError.invalidFormat
            }
            guard let wiki = store.entries.first(where: { $0.host == "i2pwiki.i2p" }),
                  wiki.lastResult == .ok,
                  wiki.lastVisitedAt == visited,
                  store.entries.first(where: { $0.host == "tracker.i2p" })?.lastResult == .resolveFailed,
                  store.entries.first(where: { $0.host == "forum.i2p" })?.lastResult == .connectionFailed else {
                throw I2PWireError.invalidFormat
            }
            guard I2PSavedHostFetchResult.ok.label == "ok",
                  I2PSavedHostFetchResult.resolveFailed.label == "resolve failed",
                  I2PSavedHostFetchResult.connectionFailed.label == "connection failed",
                  I2PSavedHostFetchResult.ok.isFailure == false,
                  I2PSavedHostFetchResult.resolveFailed.isFailure else {
                throw I2PWireError.invalidFormat
            }
            // A host that is not saved never records a visit.
            guard store.recordFetch("stranger.i2p", result: .ok) == false,
                  store.entries.count == 3 else {
                throw I2PWireError.invalidFormat
            }
            // The filter narrows by host text; an empty filter shows all.
            guard store.filtered("tracker").map(\.host) == ["tracker.i2p"],
                  store.filtered("  ").count == 3,
                  store.filtered("nothing-matches").isEmpty else {
                throw I2PWireError.invalidFormat
            }
            // The readings persist, and swipe-to-delete removes the row.
            let reopened = I2PSavedHostsStore(defaults: defaults, storageKey: key)
            guard reopened.entries.first(where: { $0.host == "i2pwiki.i2p" })?.lastResult == .ok else {
                throw I2PWireError.invalidFormat
            }
            reopened.remove("tracker.i2p")
            guard reopened.entries.count == 2,
                  !reopened.contains("tracker.i2p") else {
                throw I2PWireError.invalidFormat
            }
            let afterRemoval = I2PSavedHostsStore(defaults: defaults, storageKey: key)
            guard afterRemoval.entries.count == 2 else { throw I2PWireError.invalidFormat }
            // A failed fetch classifies by the stage that broke.
            guard I2PEepsiteFailure(stage: .address, message: "").savedHostResult == .resolveFailed,
                  I2PEepsiteFailure(stage: .lookup, message: "").savedHostResult == .resolveFailed,
                  I2PEepsiteFailure(stage: .blinding, message: "").savedHostResult == .resolveFailed,
                  I2PEepsiteFailure(stage: .leases, message: "").savedHostResult == .resolveFailed,
                  I2PEepsiteFailure(stage: .tunnels, message: "").savedHostResult == .connectionFailed,
                  I2PEepsiteFailure(stage: .connect, message: "").savedHostResult == .connectionFailed,
                  I2PEepsiteFailure(stage: .request, message: "").savedHostResult == .connectionFailed,
                  I2PEepsiteFailure(stage: .response, message: "").savedHostResult == .connectionFailed else {
                throw I2PWireError.invalidFormat
            }
            defaults.removePersistentDomain(forName: suiteName("fetch"))
            return "ok, resolve-failed and connection-failed readings recorded and persisted; unsaved host ignored; filter and delete; every stage classified"
        }

        run("saved hosts · address bar suggestions and completion") {
            let (defaults, key) = makeDefaults("suggest")
            let store = I2PSavedHostsStore(defaults: defaults, storageKey: key)
            let base = Date(timeIntervalSince1970: 1_700_000_000)
            guard store.save("i2pwiki.i2p", at: base),
                  store.save("i2pforum.i2p", at: base.addingTimeInterval(10)),
                  store.save("planet.i2p", at: base.addingTimeInterval(20)) else {
                throw I2PWireError.invalidFormat
            }
            // An empty (or blank) bar lists nothing and completes nothing.
            guard store.suggestions(for: "").isEmpty,
                  store.suggestions(for: "   ").isEmpty,
                  store.completion(for: "") == nil,
                  store.completion(for: "  ") == nil else {
                throw I2PWireError.invalidFormat
            }
            // Only bookmarks whose name contains the text, whatever the case.
            guard store.suggestions(for: "I2P").map(\.host).sorted() == ["i2pforum.i2p", "i2pwiki.i2p"],
                  store.suggestions(for: "wiki").map(\.host) == ["i2pwiki.i2p"],
                  store.suggestions(for: "nothing-matches").isEmpty else {
                throw I2PWireError.invalidFormat
            }
            // Most recently visited first; a never-visited host follows them.
            guard store.recordFetch("i2pwiki.i2p", result: .ok,
                                    at: base.addingTimeInterval(100)),
                  store.recordFetch("i2pforum.i2p", result: .resolveFailed,
                                    at: base.addingTimeInterval(200)) else {
                throw I2PWireError.invalidFormat
            }
            let suggested = store.suggestions(for: "i")
            guard suggested.map(\.host) == ["i2pforum.i2p", "i2pwiki.i2p"],
                  suggested.first?.lastResult == .resolveFailed,
                  suggested[1].lastResult == .ok,
                  store.suggestions(for: "i2pwiki").map(\.host) == ["i2pwiki.i2p"],
                  // Only the name is matched: the ".i2p" every saved host ends
                  // in does not make a query of "i2p" match all of them.
                  !store.suggestions(for: "i2p").map(\.host).contains("planet.i2p"),
                  // A saved host never visited sorts after the visited ones.
                  store.suggestions(for: "p").map(\.host)
                    == ["i2pforum.i2p", "i2pwiki.i2p", "planet.i2p"],
                  store.suggestions(for: "p").last?.lastResult == nil else {
                throw I2PWireError.invalidFormat
            }
            // Never more than six rows, and the limit is the caller's to narrow.
            for index in 0..<8 {
                guard store.save("i2pnode\(index).i2p",
                                 at: base.addingTimeInterval(Double(index))) else {
                    throw I2PWireError.invalidFormat
                }
            }
            guard store.suggestions(for: "i2p").count == 6,
                  store.suggestions(for: "i2p", limit: 3).count == 3,
                  store.suggestions(for: "i2p", limit: 0).isEmpty,
                  store.suggestions(for: "i2p").first?.host == "i2pforum.i2p" else {
                throw I2PWireError.invalidFormat
            }
            // The bar completes only once the typed text is the whole label (or
            // past a dot) of exactly one saved host, and never to the host it
            // already holds — a half-typed word is left alone.
            guard store.completion(for: "planet") == "planet.i2p",
                  store.completion(for: " PLANET ") == "planet.i2p",
                  store.completion(for: "planet.i") == "planet.i2p",
                  store.completion(for: "i2pwiki") == "i2pwiki.i2p",
                  store.completion(for: "i2pnode5") == "i2pnode5.i2p",
                  store.completion(for: "i2pnode5.") == "i2pnode5.i2p",
                  store.completion(for: "plane") == nil,
                  store.completion(for: "planet.i2p") == nil,
                  store.completion(for: "i2pnode0.i2p") == nil,
                  store.completion(for: "i2p") == nil,
                  store.completion(for: "i2pnode") == nil,
                  store.completion(for: "wiki") == nil,
                  store.completion(for: "nothing") == nil else {
                throw I2PWireError.invalidFormat
            }
            // Suggestions stay read-only: they never rename or reorder the list.
            guard store.entries.count == 11,
                  store.entries.first?.host == "i2pnode7.i2p" else {
                throw I2PWireError.invalidFormat
            }
            defaults.removePersistentDomain(forName: suiteName("suggest"))
            return "empty bar lists nothing; contains-match regardless of case; most recently visited first with never-visited last; capped at six; completion only once one host's label is typed"
        }

        return results
    }

    // MARK: Helpers

    private static func suiteName(_ label: String) -> String {
        "i2p.savedHosts.selfTest.\(label)"
    }

    private static func makeDefaults(_ label: String) -> (UserDefaults, String) {
        let suite = suiteName(label)
        let defaults = UserDefaults(suiteName: suite) ?? .standard
        defaults.removePersistentDomain(forName: suite)
        return (defaults, "saved-\(label)")
    }

    private static func b33Address() throws -> String {
        let x25519 = I2PCrypto.generateX25519KeyPair()
        return try I2PB33Blinding.blind(destinationSeed: I2PCrypto.generateEd25519Seed(),
                                        encryptionPublicKey: x25519.publicKey).b33Address
    }
}
