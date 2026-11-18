//
//  I2PBrowserHistory.swift
//  The browser's history: every host the eepsite browser opened, the time of
//  the visit and how that fetch ended. Persisted across launches in user
//  defaults and kept apart from the saved hosts, so clearing the history never
//  touches a bookmark.
//

import Foundation
import Combine

// MARK: - Entry

/// One visit: the host the browser opened, when the fetch ended and how.
struct I2PBrowserHistoryEntry: Codable, Identifiable, Equatable {
    /// Stable per visit, so two visits of one host stay two rows.
    let id: UUID
    /// The host in the browser's own canonical form — "wiki.i2p", a b32 host or
    /// "<b33>.b33.i2p" — the same form a bookmark stores.
    let host: String
    let kind: I2PSavedHostKind
    /// When the fetch for this visit ended.
    let visitedAt: Date
    /// How that fetch ended.
    let result: I2PSavedHostFetchResult

    init(id: UUID = UUID(),
         host: String,
         kind: I2PSavedHostKind,
         visitedAt: Date,
         result: I2PSavedHostFetchResult) {
        self.id = id
        self.host = host
        self.kind = kind
        self.visitedAt = visitedAt
        self.result = result
    }

    /// The visit line the row shows: "today at 14:02", "yesterday at 09:14",
    /// "Mar 4 at 11:03". The time follows the device's own clock settings.
    func visitText(now: Date = Date(), calendar: Calendar = .current) -> String {
        let time = visitedAt.formatted(date: .omitted, time: .shortened)
        if calendar.isDate(visitedAt, inSameDayAs: now) { return "today at \(time)" }
        if let yesterday = calendar.date(byAdding: .day, value: -1, to: now),
           calendar.isDate(visitedAt, inSameDayAs: yesterday) {
            return "yesterday at \(time)"
        }
        let day = visitedAt.formatted(.dateTime.month(.abbreviated).day())
        return "\(day) at \(time)"
    }
}

// MARK: - History store

/// The browser's visits, newest first.
///
/// Every completed fetch records one row, whether or not the host is saved, so
/// the list reads as a history rather than a bookmark set: the same host opened
/// twice is two rows. A fetch that never finished (cancelled by a newer
/// navigation) records nothing. Every mutation is driven from the main thread,
/// so the published state stays consistent with the views that observe it.
final class I2PBrowserHistoryStore: ObservableObject {
    static let shared = I2PBrowserHistoryStore()
    static let defaultsKey = "i2p.browserHistory"
    /// How many visits are kept: past this the oldest drop off, so the list —
    /// and the user defaults behind it — stay bounded.
    static let limit = 200

    @Published private(set) var entries: [I2PBrowserHistoryEntry] = []

    private let defaults: UserDefaults
    private let storageKey: String
    private let maxEntries: Int

    init(defaults: UserDefaults = .standard,
         storageKey: String = I2PBrowserHistoryStore.defaultsKey,
         limit: Int = I2PBrowserHistoryStore.limit) {
        self.defaults = defaults
        self.storageKey = storageKey
        self.maxEntries = max(1, limit)
        self.entries = Self.load(defaults: defaults, key: storageKey)
        if entries.count > maxEntries {
            entries.removeLast(entries.count - maxEntries)
        }
    }

    var isEmpty: Bool { entries.isEmpty }

    // MARK: Recording and removing

    /// Records one finished visit. The host is normalized the way the browser
    /// loads it, so a typed URL with a scheme, port or path lands as its bare
    /// host. A text that is not an eepsite host (a clear-net name, an empty
    /// field) records nothing.
    @discardableResult
    func record(_ raw: String,
                result: I2PSavedHostFetchResult,
                at date: Date = Date()) -> Bool {
        guard let candidate = I2PSavedHostsStore.host(in: raw) else { return false }
        let entry = I2PBrowserHistoryEntry(host: candidate.host,
                                           kind: candidate.kind,
                                           visitedAt: date,
                                           result: result)
        // The list is newest first: land the row ahead of the first older visit,
        // so an out-of-order completion cannot put an old visit on top.
        let index = entries.firstIndex { $0.visitedAt < date } ?? entries.count
        entries.insert(entry, at: index)
        if entries.count > maxEntries {
            entries.removeLast(entries.count - maxEntries)
        }
        persist()
        return true
    }

    /// Drops one visit (swipe to delete).
    func remove(_ id: UUID) {
        let before = entries.count
        entries.removeAll { $0.id == id }
        guard entries.count != before else { return }
        persist()
    }

    /// Empties the history. Saved hosts live in their own store, so bookmarks
    /// and their recorded visits are left exactly as they were.
    func clear() {
        guard !entries.isEmpty else { return }
        entries = []
        persist()
    }

    /// The visits matching the filter field; everything when it is empty.
    func filtered(_ query: String) -> [I2PBrowserHistoryEntry] {
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !trimmed.isEmpty else { return entries }
        return entries.filter { $0.host.lowercased().contains(trimmed) }
    }

    // MARK: Persistence

    private func persist() {
        guard let data = try? JSONEncoder().encode(entries) else { return }
        defaults.set(data, forKey: storageKey)
    }

    private static func load(defaults: UserDefaults, key: String) -> [I2PBrowserHistoryEntry] {
        guard let data = defaults.data(forKey: key),
              let decoded = try? JSONDecoder().decode([I2PBrowserHistoryEntry].self, from: data) else {
            return []
        }
        return decoded
    }
}

// MARK: - Self-test suite (browser history)

enum I2PBrowserHistorySelfTest {
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

        run("browser history · records every visit, newest first, and persists") {
            let (defaults, key) = makeDefaults("record")
            let store = I2PBrowserHistoryStore(defaults: defaults, storageKey: key)
            let base = Date(timeIntervalSince1970: 1_700_000_000)
            let b33 = try b33Address()
            // Three visits, of a .i2p name, a b33 address and a host that
            // failed to connect — every one its own row.
            guard store.record("i2pwiki.i2p", result: .ok, at: base),
                  store.record("b33:\(b33.uppercased())", result: .resolveFailed,
                               at: base.addingTimeInterval(60)),
                  store.record("tracker.i2p", result: .connectionFailed,
                               at: base.addingTimeInterval(120)) else {
                throw I2PWireError.invalidFormat
            }
            guard store.entries.count == 3,
                  store.entries[0].host == "tracker.i2p",
                  store.entries[0].result == .connectionFailed,
                  store.entries[0].visitedAt == base.addingTimeInterval(120),
                  store.entries[1].host == "\(b33).b33.i2p",
                  store.entries[1].kind == .b33,
                  store.entries[1].result == .resolveFailed,
                  store.entries[2].host == "i2pwiki.i2p",
                  store.entries[2].kind == .i2pName,
                  store.entries[2].result == .ok,
                  Set(store.entries.map(\.id)).count == 3 else {
                throw I2PWireError.invalidFormat
            }
            guard I2PSavedHostFetchResult.ok.label == "ok",
                  I2PSavedHostFetchResult.resolveFailed.label == "resolve failed",
                  I2PSavedHostFetchResult.connectionFailed.label == "connection failed" else {
                throw I2PWireError.invalidFormat
            }
            // A typed URL records its bare host, and a repeat visit is a second
            // row — history is not a set of bookmarks.
            guard store.record("HTTPS://I2PWiki.i2p:8080/wiki/Main_Page",
                               result: .ok,
                               at: base.addingTimeInterval(180)) else {
                throw I2PWireError.invalidFormat
            }
            guard store.entries.count == 4,
                  store.entries[0].host == "i2pwiki.i2p",
                  store.entries[0].result == .ok,
                  store.entries[0].visitedAt == base.addingTimeInterval(180) else {
                throw I2PWireError.invalidFormat
            }
            // A clear-net name and an empty field are no visits at all.
            guard store.record("example.com", result: .ok) == false,
                  store.record("   ", result: .ok) == false,
                  store.entries.count == 4 else {
                throw I2PWireError.invalidFormat
            }
            // The whole history survives a relaunch.
            let reopened = I2PBrowserHistoryStore(defaults: defaults, storageKey: key)
            guard reopened.entries == store.entries else { throw I2PWireError.invalidFormat }
            defaults.removePersistentDomain(forName: suiteName("record"))
            return "ok, resolve-failed and connection-failed visits recorded newest first; typed URL normalized; repeat visit kept as its own row; clear-net and empty input refused; persisted"
        }

        run("browser history · newest first whatever the order, capped, cleared") {
            let (defaults, key) = makeDefaults("clear")
            let store = I2PBrowserHistoryStore(defaults: defaults, storageKey: key, limit: 3)
            let base = Date(timeIntervalSince1970: 1_700_000_000)
            // Visits land in time order even when they are recorded out of it.
            guard store.record("a.i2p", result: .ok, at: base.addingTimeInterval(30)),
                  store.record("b.i2p", result: .ok, at: base),
                  store.record("c.i2p", result: .ok, at: base.addingTimeInterval(60)) else {
                throw I2PWireError.invalidFormat
            }
            guard store.entries.map(\.host) == ["c.i2p", "a.i2p", "b.i2p"] else {
                throw I2PWireError.invalidFormat
            }
            // Past the cap the oldest visit drops off, and the cap persists.
            guard store.record("d.i2p", result: .ok, at: base.addingTimeInterval(90)) else {
                throw I2PWireError.invalidFormat
            }
            guard store.entries.map(\.host) == ["d.i2p", "c.i2p", "a.i2p"] else {
                throw I2PWireError.invalidFormat
            }
            // The filter narrows by host text; an empty filter shows everything.
            guard store.filtered("c.i2p").map(\.host) == ["c.i2p"],
                  store.filtered("  i2P  ").count == 3,
                  store.filtered("nothing-matches").isEmpty else {
                throw I2PWireError.invalidFormat
            }
            // Swipe-to-delete drops that one visit and nothing else.
            guard let victim = store.entries.first(where: { $0.host == "c.i2p" }) else {
                throw I2PWireError.invalidFormat
            }
            store.remove(victim.id)
            guard store.entries.map(\.host) == ["d.i2p", "a.i2p"],
                  I2PBrowserHistoryStore(defaults: defaults, storageKey: key)
                    .entries.map(\.host) == ["d.i2p", "a.i2p"] else {
                throw I2PWireError.invalidFormat
            }
            // Clearing the history leaves the saved hosts exactly as they were.
            let (savedDefaults, savedKey) = makeDefaults("saved")
            let saved = I2PSavedHostsStore(defaults: savedDefaults, storageKey: savedKey)
            guard saved.save("a.i2p"), saved.save("d.i2p") else {
                throw I2PWireError.invalidFormat
            }
            store.clear()
            guard store.entries.isEmpty,
                  I2PBrowserHistoryStore(defaults: defaults, storageKey: key).entries.isEmpty,
                  saved.entries.map(\.host).sorted() == ["a.i2p", "d.i2p"],
                  saved.contains("a.i2p"), saved.contains("d.i2p"),
                  saved.entries.count == 2 else {
                throw I2PWireError.invalidFormat
            }
            defaults.removePersistentDomain(forName: suiteName("clear"))
            savedDefaults.removePersistentDomain(forName: suiteName("saved"))
            return "out-of-order visits land newest first; capped at three; filter matches regardless of case; one delete removes one visit; clear empties history only, bookmarks untouched"
        }

        run("browser history · the visit line names today, yesterday or the date") {
            let calendar = Calendar(identifier: .gregorian)
            let now = Date(timeIntervalSince1970: 1_700_000_000)
            let entry = I2PBrowserHistoryEntry(host: "a.i2p", kind: .i2pName,
                                               visitedAt: now, result: .ok)
            let time = now.formatted(date: .omitted, time: .shortened)
            guard entry.visitText(now: now, calendar: calendar) == "today at \(time)" else {
                throw I2PWireError.invalidFormat
            }
            guard let yesterdayMoment = calendar.date(byAdding: .day, value: -1, to: now) else {
                throw I2PWireError.invalidFormat
            }
            let yesterday = I2PBrowserHistoryEntry(host: "a.i2p", kind: .i2pName,
                                                   visitedAt: yesterdayMoment,
                                                   result: .resolveFailed)
            let yesterdayText = yesterday.visitText(now: now, calendar: calendar)
            guard yesterdayText.hasPrefix("yesterday at "),
                  yesterday.visitText(now: now, calendar: calendar).hasSuffix(
                    yesterdayMoment.formatted(date: .omitted, time: .shortened)),
                  yesterday.result.label == "resolve failed" else {
                throw I2PWireError.invalidFormat
            }
            guard let olderMoment = calendar.date(byAdding: .day, value: -5, to: now) else {
                throw I2PWireError.invalidFormat
            }
            let older = I2PBrowserHistoryEntry(host: "a.i2p", kind: .i2pName,
                                               visitedAt: olderMoment,
                                               result: .connectionFailed)
            let olderText = older.visitText(now: now, calendar: calendar)
            guard olderText.contains(" at "),
                  !olderText.hasPrefix("today"),
                  !olderText.hasPrefix("yesterday"),
                  olderText.hasSuffix(olderMoment.formatted(date: .omitted, time: .shortened)) else {
                throw I2PWireError.invalidFormat
            }
            return "today / yesterday / dated visit lines, each carrying the visit's own time"
        }

        return results
    }

    // MARK: Helpers

    private static func suiteName(_ label: String) -> String {
        "i2p.browserHistory.selfTest.\(label)"
    }

    private static func makeDefaults(_ label: String) -> (UserDefaults, String) {
        let suite = suiteName(label)
        let defaults = UserDefaults(suiteName: suite) ?? .standard
        defaults.removePersistentDomain(forName: suite)
        return (defaults, "history-\(label)")
    }

    private static func b33Address() throws -> String {
        let x25519 = I2PCrypto.generateX25519KeyPair()
        return try I2PB33Blinding.blind(destinationSeed: I2PCrypto.generateEd25519Seed(),
                                        encryptionPublicKey: x25519.publicKey).b33Address
    }
}
