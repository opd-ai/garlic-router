//
//  I2PIRCSnoozes.swift
//  A conversation put to sleep for a stretch of time: the chat header's bell
//  offers the same three durations the highlights pause does — 15 minutes, 1
//  hour, until tomorrow — plus one that lasts until the bell is turned back on.
//
//  A snooze is a mute with a clock: while it runs the conversation adds no
//  unread badge, no mention count and no keyword count, its chip shows a slashed
//  bell with the time left ('#i2p · 42m'), and the silence lifts by itself when
//  the time runs out, exactly as a mute's silence ends when it is cleared. It is
//  kept per server and per conversation, so a channel snoozed on one network is
//  still loud on another.
//

import Foundation
import Combine

// MARK: - Duration

/// How long a conversation is snoozed for, as the bell's menu offers it: the
/// highlights pause's three durations, and one that lasts until the user turns
/// the bell back on.
enum I2PIRCSnoozeDuration: String, CaseIterable, Identifiable {
    /// A short snooze: the rest of a build, a call, a meeting.
    case quarterHour
    /// The middle choice: the next hour.
    case hour
    /// Until the next day starts, whatever the hour is now.
    case tomorrow
    /// The plain mute's silence, kept as the fourth choice: it never ends on its
    /// own, only when the bell is turned back on.
    case untilTurnedOn

    var id: String { rawValue }

    /// What the bell's menu reads.
    var label: String {
        switch self {
        case .quarterHour: return I2PIRCKeywordPauseDuration.quarterHour.label
        case .hour: return I2PIRCKeywordPauseDuration.hour.label
        case .tomorrow: return I2PIRCKeywordPauseDuration.tomorrow.label
        case .untilTurnedOn: return "Until I turn it back on"
        }
    }

    /// What the item tells VoiceOver it does.
    var actionLabel: String {
        switch self {
        case .quarterHour: return "Snooze this conversation for 15 minutes"
        case .hour: return "Snooze this conversation for 1 hour"
        case .tomorrow: return "Snooze this conversation until tomorrow"
        case .untilTurnedOn: return "Snooze this conversation until I turn it back on"
        }
    }

    /// The glyph the item wears in the menu.
    var icon: String {
        switch self {
        case .quarterHour: return "timer"
        case .hour: return "clock"
        case .tomorrow: return "moon"
        case .untilTurnedOn: return "bell.slash"
        }
    }

    /// When a snooze chosen at `now` lifts; nil for the one that lasts until the
    /// user turns it back on. The timed choices end exactly where the highlights
    /// pause's do, so the two features read the same way.
    func end(from now: Date = Date(), calendar: Calendar = .current) -> Date? {
        switch self {
        case .quarterHour:
            return I2PIRCKeywordPauseDuration.quarterHour.end(from: now, calendar: calendar)
        case .hour:
            return I2PIRCKeywordPauseDuration.hour.end(from: now, calendar: calendar)
        case .tomorrow:
            return I2PIRCKeywordPauseDuration.tomorrow.end(from: now, calendar: calendar)
        case .untilTurnedOn:
            return nil
        }
    }
}

// MARK: - Record

/// One snoozed conversation of one server. An entry with no end date is the
/// indefinite snooze — the plain mute — which only the bell's "turn it back on"
/// ends.
struct I2PIRCSnoozeEntry: Codable, Equatable {
    var key: String
    var endsAt: Date?
}

// MARK: - Rule

enum I2PIRCSnoozeRule {
    /// Whether a snooze that ends at `endsAt` is running at `now`. No end date is
    /// the indefinite one, which runs until it is cleared.
    static func isLive(_ endsAt: Date?, at now: Date = Date()) -> Bool {
        guard let endsAt else { return true }
        return endsAt > now
    }

    /// What is left of a timed snooze in the chip's shorthand: "42m", "1h",
    /// "1h 5m". Rounded up, so a snooze with a few seconds to run never reads as
    /// no time at all.
    static func shortRemaining(until endsAt: Date, from now: Date = Date()) -> String {
        let minutes = max(1, Int((endsAt.timeIntervalSince(now) / 60).rounded(.up)))
        guard minutes >= 60 else { return "\(minutes)m" }
        let hours = minutes / 60
        let rest = minutes % 60
        guard rest > 0 else { return "\(hours)h" }
        return "\(hours)h \(rest)m"
    }

    /// What the bell reads out: the snooze and the time left in it, or that the
    /// conversation is not snoozed.
    static func summary(for entry: I2PIRCSnoozeEntry?, at now: Date = Date()) -> String {
        guard let entry, isLive(entry.endsAt, at: now) else { return "Not snoozed" }
        guard let endsAt = entry.endsAt else {
            return "Snoozed until you turn it back on"
        }
        return "Snoozed for \(I2PIRCKeywordPause.remaining(until: endsAt, from: now))"
    }
}

// MARK: - Store

/// The snoozed conversations, keyed by the id of the server entry they belong
/// to, persisted in user defaults like the mutes, the server book and the saved
/// transcripts. They never leave the device.
final class I2PIRCSnoozeBook: ObservableObject {
    static let shared = I2PIRCSnoozeBook()
    static let defaultsKey = "i2p.irc.snoozes"

    /// Bumped when a snooze is set, cleared or lifts by itself, so whatever shows
    /// a conversation's silence re-reads the record.
    @Published private(set) var revision = 0

    /// Bumped while a timed snooze runs, so the time left on a chip follows the
    /// clock without anything else changing.
    @Published private(set) var minuteTick = 0

    private let defaults: UserDefaults
    private let storageKey: String
    /// Server id (as a UUID string) → the conversations it has snoozed.
    private var records: [String: [I2PIRCSnoozeEntry]]
    /// The countdown that lifts timed snoozes by itself and keeps the time left
    /// ticking while one runs.
    private var expiryTask: Task<Void, Never>? = nil
    /// Serialises the record. The expiry clock runs on the main actor while
    /// SwiftUI and the self-test suites call in from their own threads, and a
    /// dictionary read on one thread while another mutates it is undefined
    /// behaviour — ThreadSanitizer reported exactly that access race on
    /// 2026-11-18. Recursive because every entry point re-enters its own
    /// readers (`entries` → `liveEntries`, `snooze` → `scheduleExpiry`).
    private let stateLock = NSRecursiveLock()

    init(defaults: UserDefaults = .standard,
         storageKey: String = I2PIRCSnoozeBook.defaultsKey) {
        self.defaults = defaults
        self.storageKey = storageKey
        self.records = Self.load(defaults: defaults, key: storageKey)
        // A snooze that ran out while the app was closed is over the next time
        // the book is read.
        prune()
        scheduleExpiry()
    }

    // MARK: Reading

    /// The snoozed conversations of one server, as they stand at `now`.
    func entries(for serverID: UUID, at now: Date = Date()) -> [I2PIRCSnoozeEntry] {
        stateLock.lock()
        defer { stateLock.unlock() }
        return liveEntries(for: serverID.uuidString, at: now)
    }

    /// The conversation keys a server has snoozed right now.
    func snoozedKeys(for serverID: UUID, at now: Date = Date()) -> Set<String> {
        Set(entries(for: serverID, at: now).map(\.key))
    }

    /// Whether one conversation of a server is snoozed. The name is matched the
    /// way IRC matches a conversation, so "#i2p" and "#I2P" are the same one.
    func isSnoozed(_ conversationID: String,
                   on serverID: UUID,
                   at now: Date = Date()) -> Bool {
        entry(conversationID, on: serverID, at: now) != nil
    }

    /// The record of one conversation's snooze, while it is running.
    func entry(_ conversationID: String,
               on serverID: UUID,
               at now: Date = Date()) -> I2PIRCSnoozeEntry? {
        let key = I2PIRCName.key(conversationID)
        guard !key.isEmpty else { return nil }
        stateLock.lock()
        defer { stateLock.unlock() }
        return liveEntries(for: serverID.uuidString, at: now).first { $0.key == key }
    }

    // MARK: Writing

    /// Snoozes one conversation for the chosen time. Returns whether the record
    /// changed: the same snooze set twice at the same second writes nothing.
    @discardableResult
    func snooze(_ conversationID: String,
                for duration: I2PIRCSnoozeDuration,
                on serverID: UUID,
                at now: Date = Date()) -> Bool {
        let key = I2PIRCName.key(conversationID)
        guard !key.isEmpty else { return false }
        stateLock.lock()
        defer { stateLock.unlock() }
        let serverKey = serverID.uuidString
        var entries = liveEntries(for: serverKey, at: now)
        let entry = I2PIRCSnoozeEntry(key: key, endsAt: duration.end(from: now))
        if let index = entries.firstIndex(where: { $0.key == key }) {
            guard entries[index] != entry else { return false }
            entries[index] = entry
        } else {
            entries.append(entry)
        }
        entries.sort { $0.key < $1.key }
        records[serverKey] = entries
        persist()
        bumpRevision()
        scheduleExpiry()
        return true
    }

    /// Ends one conversation's snooze early — what the bell's "turn it back on"
    /// does. Returns whether a running snooze was cleared.
    @discardableResult
    func clearSnooze(_ conversationID: String,
                     on serverID: UUID,
                     at now: Date = Date()) -> Bool {
        let key = I2PIRCName.key(conversationID)
        guard !key.isEmpty else { return false }
        stateLock.lock()
        defer { stateLock.unlock() }
        let serverKey = serverID.uuidString
        let entries = liveEntries(for: serverKey, at: now)
        guard entries.contains(where: { $0.key == key }) else { return false }
        let kept = entries.filter { $0.key != key }
        if kept.isEmpty {
            records.removeValue(forKey: serverKey)
        } else {
            records[serverKey] = kept
        }
        persist()
        bumpRevision()
        scheduleExpiry()
        return true
    }

    // MARK: Storage

    private func liveEntries(for serverKey: String, at now: Date) -> [I2PIRCSnoozeEntry] {
        (records[serverKey] ?? []).filter { I2PIRCSnoozeRule.isLive($0.endsAt, at: now) }
    }

    /// Drops every snooze whose time has run out. A silent tidy-up: whoever has
    /// something to tell bumps the revision itself.
    private func prune(at now: Date = Date()) {
        stateLock.lock()
        defer { stateLock.unlock() }
        var changed = false
        for (serverKey, entries) in records {
            let live = entries.filter { I2PIRCSnoozeRule.isLive($0.endsAt, at: now) }
            guard live.count != entries.count else { continue }
            changed = true
            if live.isEmpty {
                records.removeValue(forKey: serverKey)
            } else {
                records[serverKey] = live
            }
        }
        if changed { persist() }
    }

    /// The earliest end of a timed snooze still to come, which is when the clock
    /// next has something to do.
    private func nearestEndsAt(at now: Date = Date()) -> Date? {
        stateLock.lock()
        defer { stateLock.unlock() }
        return records.values.flatMap { $0 }.compactMap(\.endsAt).filter { $0 > now }.min()
    }

    /// The revision is read by SwiftUI and written by both the callers and the
    /// expiry clock, so its writes go through the same lock as the record.
    private func bumpRevision() {
        stateLock.lock()
        revision &+= 1
        stateLock.unlock()
    }

    private func bumpMinuteTick() {
        stateLock.lock()
        minuteTick &+= 1
        stateLock.unlock()
    }

    /// Runs the clock: a tick every twenty seconds so a chip's time left follows
    /// it, a prune and a revision bump when a snooze's time is up, and nothing at
    /// all once no timed snooze is left.
    private func scheduleExpiry() {
        expiryTask?.cancel()
        expiryTask = nil
        guard nearestEndsAt() != nil else { return }
        expiryTask = Task { @MainActor [weak self] in
            while !Task.isCancelled {
                guard let book = self, let nearest = book.nearestEndsAt() else { return }
                let step = min(20, max(1, nearest.timeIntervalSinceNow))
                try? await Task.sleep(for: .seconds(step))
                guard !Task.isCancelled else { return }
                if Date() >= nearest {
                    book.prune()
                    book.bumpRevision()
                } else {
                    book.bumpMinuteTick()
                }
            }
        }
    }

    private func persist() {
        guard !records.isEmpty else {
            defaults.removeObject(forKey: storageKey)
            return
        }
        guard let data = try? JSONEncoder().encode(records) else { return }
        defaults.set(data, forKey: storageKey)
    }

    private static func load(defaults: UserDefaults,
                             key: String) -> [String: [I2PIRCSnoozeEntry]] {
        guard let data = defaults.data(forKey: key),
              let decoded = try? JSONDecoder().decode([String: [I2PIRCSnoozeEntry]].self,
                                                      from: data) else {
            return [:]
        }
        return decoded
    }
}

// MARK: - Self-test suite (IRC snoozes)

enum I2PIRCSnoozeSelfTest {
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

        run("irc · a snooze offers the pause's durations, plus one with no end") {
            var calendar = Calendar(identifier: .gregorian)
            calendar.timeZone = TimeZone(secondsFromGMT: 0) ?? .current
            let noon = calendar.date(from: DateComponents(year: 2024, month: 5, day: 17,
                                                          hour: 12, minute: 30)) ?? Date()
            let tomorrow = calendar.date(from: DateComponents(year: 2024, month: 5, day: 18))
                ?? noon

            // The four choices the bell offers, in the order its menu shows them.
            guard I2PIRCSnoozeDuration.allCases.map(\.label)
                    == ["15 minutes", "1 hour", "Until tomorrow", "Until I turn it back on"],
                  I2PIRCSnoozeDuration.quarterHour.end(from: noon, calendar: calendar)
                    == noon.addingTimeInterval(15 * 60),
                  I2PIRCSnoozeDuration.hour.end(from: noon, calendar: calendar)
                    == noon.addingTimeInterval(60 * 60),
                  I2PIRCSnoozeDuration.tomorrow.end(from: noon, calendar: calendar)
                    == tomorrow,
                  // The last one has no end at all: it lasts until it is cleared.
                  I2PIRCSnoozeDuration.untilTurnedOn.end(from: noon, calendar: calendar) == nil else {
                throw I2PWireError.invalidFormat
            }

            // The time left the chip wears, and the line the bell reads out.
            guard I2PIRCSnoozeRule.shortRemaining(until: noon.addingTimeInterval(42 * 60),
                                                  from: noon) == "42m",
                  I2PIRCSnoozeRule.shortRemaining(until: noon.addingTimeInterval(60 * 60),
                                                  from: noon) == "1h",
                  I2PIRCSnoozeRule.shortRemaining(until: noon.addingTimeInterval(65 * 60),
                                                  from: noon) == "1h 5m",
                  I2PIRCSnoozeRule.shortRemaining(until: noon.addingTimeInterval(120 * 60),
                                                  from: noon) == "2h",
                  // A second or two left still reads as a minute, never as none.
                  I2PIRCSnoozeRule.shortRemaining(until: noon.addingTimeInterval(20),
                                                  from: noon) == "1m",
                  I2PIRCSnoozeRule.summary(for: nil, at: noon) == "Not snoozed",
                  I2PIRCSnoozeRule.summary(for: I2PIRCSnoozeEntry(
                                            key: "#i2p",
                                            endsAt: noon.addingTimeInterval(42 * 60)),
                                           at: noon) == "Snoozed for 42 minutes",
                  I2PIRCSnoozeRule.summary(for: I2PIRCSnoozeEntry(key: "#i2p", endsAt: nil),
                                           at: noon) == "Snoozed until you turn it back on",
                  !I2PIRCSnoozeRule.isLive(noon, at: noon),
                  I2PIRCSnoozeRule.isLive(nil, at: noon) else {
                throw I2PWireError.invalidFormat
            }
            return "the bell offers 15 minutes, 1 hour, until tomorrow and until it is turned back on; the chip's shorthand and the read-out name the time left in each"
        }

        run("irc · a snooze is kept per server and lifts when its time is up") {
            let suite = "i2p.irc.snoozes.selfTest"
            let defaults = UserDefaults(suiteName: suite) ?? .standard
            defaults.removePersistentDomain(forName: suite)
            let first = UUID()
            let second = UUID()
            let now = Date()

            let book = I2PIRCSnoozeBook(defaults: defaults, storageKey: "snoozes")
            guard book.snoozedKeys(for: first).isEmpty,
                  !book.isSnoozed("#i2p", on: first) else {
                throw I2PWireError.invalidFormat
            }

            guard book.snooze("#i2p", for: .hour, on: first, at: now) else {
                throw I2PWireError.invalidFormat
            }
            // Setting the same snooze again writes nothing.
            guard !book.snooze("#i2p", for: .hour, on: first, at: now) else {
                throw I2PWireError.invalidFormat
            }
            // The same channel on another server is a different conversation,
            // and so is another conversation of the same server.
            guard book.isSnoozed("#I2P", on: first, at: now),
                  !book.isSnoozed("#i2p", on: second, at: now),
                  !book.isSnoozed("#help", on: first, at: now) else {
                throw I2PWireError.invalidFormat
            }
            // The fourth choice has no end, so it is the plain mute's silence.
            book.snooze("alice", for: .untilTurnedOn, on: first, at: now)

            // A relaunch reads both back, and the timed one names its end.
            let reopened = I2PIRCSnoozeBook(defaults: defaults, storageKey: "snoozes")
            guard reopened.snoozedKeys(for: first, at: now) == ["#i2p", "alice"],
                  reopened.entry("#i2p", on: first, at: now)?.endsAt
                    == now.addingTimeInterval(60 * 60),
                  reopened.entry("alice", on: first, at: now)?.endsAt == nil,
                  reopened.snoozedKeys(for: second, at: now).isEmpty else {
                throw I2PWireError.invalidFormat
            }

            // The timed snooze lifts by itself; the indefinite one does not.
            let later = now.addingTimeInterval(61 * 60)
            guard !reopened.isSnoozed("#i2p", on: first, at: later),
                  reopened.isSnoozed("alice", on: first, at: later),
                  // Fifteen seconds in, the hour is still running.
                  reopened.isSnoozed("#i2p", on: first, at: now.addingTimeInterval(15)) else {
                throw I2PWireError.invalidFormat
            }

            // One that ran out while the app was closed is over the next time the
            // book is read, and leaves nothing behind.
            let expiring = I2PIRCSnoozeBook(defaults: defaults, storageKey: "expiring")
            expiring.snooze("#help", for: .hour, on: first,
                            at: now.addingTimeInterval(-2 * 60 * 60))
            let reopenedExpiring = I2PIRCSnoozeBook(defaults: defaults, storageKey: "expiring")
            guard reopenedExpiring.snoozedKeys(for: first).isEmpty,
                  defaults.data(forKey: "expiring") == nil else {
                throw I2PWireError.invalidFormat
            }

            // The bell turns one back on early, and the clear sticks.
            reopened.clearSnooze("alice", on: first, at: now)
            let third = I2PIRCSnoozeBook(defaults: defaults, storageKey: "snoozes")
            guard !third.isSnoozed("alice", on: first, at: now),
                  third.isSnoozed("#i2p", on: first, at: now),
                  !third.isSnoozed("alice", on: first, at: now.addingTimeInterval(3600)) else {
                throw I2PWireError.invalidFormat
            }

            defaults.removePersistentDomain(forName: suite)
            return "a snooze belongs to one conversation of one server and survives a relaunch; a timed one lifts by itself, the indefinite one waits to be turned back on, and a clear early sticks"
        }

        run("irc · a snoozed conversation adds no badge but keeps its marked lines") {
            var state = I2PIRCChatState(serverName: "irc.example.i2p", nick: "tester")
            state.setKeywords(["release"])
            try applyAll(&state, [
                ":irc.example.i2p 001 tester :Welcome to the network",
                ":tester!t@client JOIN #i2p",
                ":alice!a@host JOIN #i2p",
                ":alice!a@host PRIVMSG #i2p :tester, the release is up",
                ":alice!a@host PRIVMSG tester :tester, a private word"
            ])
            let channel = try unwrap(state.conversation("#i2p"))
            guard channel.unread == 1, channel.mentionCount == 1, channel.keywordCount == 1,
                  state.conversation("alice")?.unread == 1 else {
                throw I2PWireError.invalidFormat
            }

            // The snooze silences the conversation the way a mute does: no badge,
            // no mention count, no keyword count, and the marks still painted.
            state.setMutedConversations(["#i2p"])
            let snoozed = try unwrap(state.conversation("#i2p"))
            guard snoozed.unread == 0, snoozed.mentionCount == 0, snoozed.keywordCount == 0,
                  state.isMuted("#I2P"),
                  snoozed.messages.contains(where: { $0.mentionsUs }),
                  snoozed.messages.contains(where: { !$0.keywordHits.isEmpty }),
                  state.conversation("alice")?.unread == 1 else {
                throw I2PWireError.invalidFormat
            }

            // Lines arriving while it is snoozed carry their marks but count on
            // nothing — here or in the total.
            try applyAll(&state, [
                ":bob!b@host PRIVMSG #i2p :tester, did the release build pass?",
                ":tester!t@client PRIVMSG #i2p :it did"
            ])
            guard state.conversation("#i2p")?.unread == 0,
                  state.conversation("#i2p")?.mentionCount == 0,
                  state.conversation("#i2p")?.keywordCount == 0,
                  state.totalUnread == 1 else {
                throw I2PWireError.invalidFormat
            }

            // The time running out lifts the silence exactly as clearing a mute
            // does: the next line to arrive counts again.
            state.setMutedConversations([])
            try applyAll(&state, [
                ":bob!b@host PRIVMSG #i2p :tester, the release notes are up"
            ])
            let ringing = try unwrap(state.conversation("#i2p"))
            guard ringing.unread == 1, ringing.mentionCount == 1, ringing.keywordCount == 1 else {
                throw I2PWireError.invalidFormat
            }
            return "a snoozed conversation's badges are silent while its marks stay on the lines, and the silence lifting lets the next line count again"
        }

        return results
    }

    private static func applyAll(_ state: inout I2PIRCChatState, _ lines: [String]) throws {
        for raw in lines {
            guard let line = I2PIRCLine.parse(raw) else { throw I2PWireError.invalidFormat }
            state.apply(line)
        }
    }

    private static func unwrap<T>(_ value: T?) throws -> T {
        guard let value else { throw I2PWireError.invalidFormat }
        return value
    }
}
