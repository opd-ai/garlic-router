//
//  I2PIRCIgnores.swift
//  The nicks the user ignores on a server: one record per server, persisted in
//  user defaults like the server book, the saved transcripts and the mutes.
//
//  Ignoring someone never stops what they say from arriving and never touches
//  the saved transcript: the line is stored and still counts as unread, and the
//  transcript folds that person's lines into one quiet row that opens on tap.
//  The rules are pure, so the self-test suite covers them without a router.
//

import Foundation
import Combine

// MARK: - Store

/// The ignored nicks, keyed by the id of the server entry they belong to and
/// persisted in user defaults. They never leave the device.
final class I2PIRCIgnoreBook: ObservableObject {
    static let shared = I2PIRCIgnoreBook()
    static let defaultsKey = "i2p.irc.ignores"

    /// Bumped when an ignore is set or cleared, so the member list and the
    /// transcript re-read the record.
    @Published private(set) var revision = 0

    private let defaults: UserDefaults
    private let storageKey: String
    /// Server id (as a UUID string) → the nick keys it ignores.
    private var records: [String: [String]]

    init(defaults: UserDefaults = .standard,
         storageKey: String = I2PIRCIgnoreBook.defaultsKey) {
        self.defaults = defaults
        self.storageKey = storageKey
        self.records = Self.load(defaults: defaults, key: storageKey)
    }

    // MARK: Reading

    /// The nick keys a server ignores.
    func nicks(for serverID: UUID) -> Set<String> {
        Set(records[serverID.uuidString] ?? [])
    }

    /// Whether one nick is ignored on a server. The name is matched the way IRC
    /// matches a nick, so "Bob", "bob" and "@bob" are the same one.
    func isIgnored(_ nick: String, on serverID: UUID) -> Bool {
        nicks(for: serverID).contains(Self.normalized(nick))
    }

    // MARK: Writing

    /// Switches one nick's ignore. Returns whether the record changed: an
    /// ignore set twice, or cleared where there was none, writes nothing.
    @discardableResult
    func setIgnored(_ ignored: Bool, _ nick: String, on serverID: UUID) -> Bool {
        let key = Self.normalized(nick)
        guard !key.isEmpty else { return false }
        let serverKey = serverID.uuidString
        let before = Set(records[serverKey] ?? [])
        var keys = before
        if ignored {
            keys.insert(key)
        } else {
            keys.remove(key)
        }
        guard keys != before else { return false }
        if keys.isEmpty {
            records.removeValue(forKey: serverKey)
        } else {
            records[serverKey] = keys.sorted()
        }
        persist()
        revision &+= 1
        return true
    }

    // MARK: Storage

    /// The form a nick is stored in: no status prefixes, lowercased.
    static func normalized(_ nick: String) -> String {
        I2PIRCName.key(I2PIRCName.stripNickPrefixes(
            nick.trimmingCharacters(in: .whitespacesAndNewlines)))
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
                             key: String) -> [String: [String]] {
        guard let data = defaults.data(forKey: key),
              let decoded = try? JSONDecoder().decode([String: [String]].self,
                                                      from: data) else {
            return [:]
        }
        return decoded
    }
}

// MARK: - Rules

enum I2PIRCIgnoreRule {
    /// Whether a nick may be ignored at all: it has to be somebody, and our own
    /// nick can never be ignored.
    static func canIgnore(_ nick: String, ourNick: String) -> Bool {
        let key = I2PIRCIgnoreBook.normalized(nick)
        guard !key.isEmpty else { return false }
        return key != I2PIRCIgnoreBook.normalized(ourNick)
    }

    /// Whether a line's nick is one the conversation folds away.
    static func ignores(_ nick: String, in ignored: Set<String>) -> Bool {
        let key = I2PIRCIgnoreBook.normalized(nick)
        return !key.isEmpty && ignored.contains(key)
    }

    /// The quiet row's sentence: "3 lines from bob ignored", "1 line from bob
    /// ignored".
    static func summary(count: Int, nick: String) -> String {
        let name = nick.isEmpty ? "someone" : nick
        return count == 1
            ? "1 line from \(name) ignored"
            : "\(count) lines from \(name) ignored"
    }
}

// MARK: - A folded nick

/// The lines one ignored nick said in a conversation, folded into a single quiet
/// row: what it counts, whose it is, and the lines it holds so a tap can open
/// them.
struct I2PIRCIgnoredGroup: Identifiable, Equatable {
    let nick: String
    let messages: [I2PIRCMessage]

    var count: Int { messages.count }
    var date: Date { messages.first?.date ?? Date(timeIntervalSince1970: 0) }

    var id: String {
        "ignored-\(I2PIRCName.key(nick))-\(messages.first?.id.uuidString ?? "none")"
    }

    var summary: String { I2PIRCIgnoreRule.summary(count: count, nick: nick) }
}

// MARK: - The fold

/// Turns the lines on screen into the transcript's rows: every line of a nick
/// the server ignores folds into one quiet group, drawn where that person first
/// spoke, and everything else stays exactly where it was. The days keep their
/// separators over whichever row opens them.
enum I2PIRCIgnoreFold {
    /// One thing the transcript draws: a line, or a folded run of ignored lines.
    enum Item: Equatable {
        case message(I2PIRCMessage)
        case ignored(I2PIRCIgnoredGroup)

        var date: Date {
            switch self {
            case .message(let message): return message.date
            case .ignored(let group): return group.date
            }
        }
    }

    /// Folds one ignored nick's lines into a single group, drawn where that
    /// nick's first line stood: the conversation shows "3 lines from bob
    /// ignored" once, however the three lines were spread out. A line this
    /// client sent is never folded, and a line from somebody else is left
    /// exactly where it was.
    static func items(messages: [I2PIRCMessage],
                      ignored: Set<String>) -> [Item] {
        guard !ignored.isEmpty else { return messages.map { .message($0) } }

        // Every ignored nick's lines, in the order they were said, and where the
        // first of them sat in the conversation.
        var groups: [String: [I2PIRCMessage]] = [:]
        var firstIndex: [String: Int] = [:]
        for (index, message) in messages.enumerated() {
            guard let nick = message.nick,
                  !message.isLocal,
                  I2PIRCIgnoreRule.ignores(nick, in: ignored) else { continue }
            let key = I2PIRCName.key(nick)
            if groups[key] == nil { firstIndex[key] = index }
            groups[key, default: []].append(message)
        }

        var items: [Item] = []
        items.reserveCapacity(messages.count)
        for (index, message) in messages.enumerated() {
            if let nick = message.nick,
               !message.isLocal,
               I2PIRCIgnoreRule.ignores(nick, in: ignored) {
                let key = I2PIRCName.key(nick)
                // The quiet row stands where the nick first spoke; every later
                // line of theirs joins it instead of drawing its own.
                if firstIndex[key] == index, let lines = groups[key], let first = lines.first {
                    items.append(.ignored(I2PIRCIgnoredGroup(nick: first.nick ?? key,
                                                             messages: lines)))
                }
                continue
            }
            items.append(.message(message))
        }
        return items
    }

    /// The transcript rows: the folded items with a day's separator over the
    /// first row of each day, so an ignored run never swallows a day's label.
    static func rows(messages: [I2PIRCMessage],
                     ignored: Set<String>,
                     now: Date = Date(),
                     calendar: Calendar = Calendar.current,
                     locale: Locale = Locale.current) -> [I2PIRCTranscriptRow] {
        var rows: [I2PIRCTranscriptRow] = []
        rows.reserveCapacity(messages.count + 2)
        var currentDay: Date?
        for item in items(messages: messages, ignored: ignored) {
            let day = I2PIRCDayGrouping.dayStart(for: item.date, calendar: calendar)
            if day != currentDay {
                currentDay = day
                rows.append(.day(I2PIRCDaySeparator(
                    dayStart: day,
                    label: I2PIRCDayGrouping.label(for: item.date, now: now,
                                                   calendar: calendar, locale: locale)
                )))
            }
            switch item {
            case .message(let message): rows.append(.message(message))
            case .ignored(let group): rows.append(.ignored(group))
            }
        }
        return rows
    }
}

// MARK: - Self-test suite (IRC ignored nicks)

enum I2PIRCIgnoreSelfTest {
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

        run("irc · the ignored nicks are kept per server across launches") {
            let suite = "i2p.irc.ignores.selfTest"
            let defaults = UserDefaults(suiteName: suite) ?? .standard
            defaults.removePersistentDomain(forName: suite)
            let first = UUID()
            let second = UUID()

            let book = I2PIRCIgnoreBook(defaults: defaults, storageKey: "ignores")
            guard book.nicks(for: first).isEmpty,
                  !book.isIgnored("bob", on: first) else {
                throw I2PWireError.invalidFormat
            }

            guard book.setIgnored(true, "bob", on: first) else {
                throw I2PWireError.invalidFormat
            }
            // The same person ignored again writes nothing — whatever casing or
            // status prefix the member list hands over.
            guard !book.setIgnored(true, "Bob", on: first),
                  !book.setIgnored(true, "@BOB", on: first) else {
                throw I2PWireError.invalidFormat
            }
            book.setIgnored(true, "@marisol", on: first)
            guard book.nicks(for: first) == ["bob", "marisol"],
                  // The same nick on another server is another record.
                  !book.isIgnored("bob", on: second) else {
                throw I2PWireError.invalidFormat
            }

            // A relaunch reads the same records back.
            let reopened = I2PIRCIgnoreBook(defaults: defaults, storageKey: "ignores")
            guard reopened.isIgnored("BOB", on: first),
                  reopened.isIgnored("marisol", on: first),
                  !reopened.isIgnored("bob", on: second) else {
                throw I2PWireError.invalidFormat
            }

            // Letting one person speak again leaves the other one quiet, and the
            // clear sticks across a relaunch too.
            reopened.setIgnored(false, "bob", on: first)
            guard !reopened.isIgnored("bob", on: first),
                  reopened.isIgnored("marisol", on: first) else {
                throw I2PWireError.invalidFormat
            }
            let third = I2PIRCIgnoreBook(defaults: defaults, storageKey: "ignores")
            guard !third.isIgnored("bob", on: first),
                  third.isIgnored("marisol", on: first) else {
                throw I2PWireError.invalidFormat
            }
            defaults.removePersistentDomain(forName: suite)
            return "an ignore belongs to one server and survives a relaunch; ignoring twice writes nothing and letting someone speak again sticks"
        }

        run("irc · an ignored nick's lines still arrive, still count and fold into one quiet row") {
            var state = I2PIRCChatState(serverName: "irc.example.i2p", nick: "tester")
            try applyAll(&state, [
                ":irc.example.i2p 001 tester :Welcome to the network",
                ":tester!t@client JOIN #i2p",
                ":bob!b@host JOIN #i2p",
                ":alice!a@host JOIN #i2p",
                ":bob!b@host PRIVMSG #i2p :one",
                ":bob!b@host PRIVMSG #i2p :two",
                ":alice!a@host PRIVMSG #i2p :hey",
                ":bob!b@host PRIVMSG #i2p :three"
            ])
            let channel = try unwrap(state.conversation("#i2p"))
            // Nothing about the ignored lines is suppressed: the lines are all
            // in the conversation and each one still counts as unread. The
            // joins the transcript records as stage notes are lines too, but
            // they are not chat and do not count as unread.
            guard channel.messages.count == 7, channel.unread == 4 else {
                throw I2PWireError.invalidFormat
            }

            let ignored = Set(["bob"])
            let items = I2PIRCIgnoreFold.items(messages: channel.messages, ignored: ignored)
            // The three join notes keep their place; bob's three lines — the two
            // in a row and the one after alice's — draw as one quiet row where
            // he first spoke.
            guard items.count == 5,
                  case .ignored(let group) = items[3],
                  case .message(let aliceLine) = items[4],
                  group.count == 3,
                  group.summary == "3 lines from bob ignored",
                  group.messages.map(\.text) == ["one", "two", "three"],
                  aliceLine.nick == "alice", aliceLine.text == "hey" else {
                throw I2PWireError.invalidFormat
            }
            // The fold only changes what is drawn: the conversation keeps every
            // line — the chat lines in the order they arrived — so the saved
            // history is untouched.
            guard channel.messages.suffix(4).map(\.text) == ["one", "two", "hey", "three"] else {
                throw I2PWireError.invalidFormat
            }

            // With nobody ignored, every line stands on its own.
            let unfolded = I2PIRCIgnoreFold.items(messages: channel.messages, ignored: [])
            guard unfolded.count == 7,
                  unfolded.allSatisfy({
                      if case .message = $0 { return true }
                      return false
                  }) else {
                throw I2PWireError.invalidFormat
            }

            // The rows carry the day's separator over the folded row, and the
            // group keeps its own id so a tap can open it.
            let rows = I2PIRCIgnoreFold.rows(messages: channel.messages, ignored: ignored)
            guard rows.count == 6,
                  case .day = rows[0],
                  case .ignored = rows[4],
                  case .message = rows[5],
                  Set(rows.map(\.id)).count == rows.count else {
                throw I2PWireError.invalidFormat
            }
            return "ignored lines arrive, count as unread and stay in the transcript; one nick's lines draw as one quiet row wherever they sat, and nothing is deleted"
        }

        run("irc · our own nick can never be ignored and a query folds the same way") {
            guard I2PIRCIgnoreRule.canIgnore("bob", ourNick: "tester"),
                  I2PIRCIgnoreRule.canIgnore("@Bob", ourNick: "tester"),
                  // Our own nick, whatever its casing or status prefix.
                  !I2PIRCIgnoreRule.canIgnore("Tester", ourNick: "tester"),
                  !I2PIRCIgnoreRule.canIgnore("@tEster", ourNick: "tester"),
                  !I2PIRCIgnoreRule.canIgnore("   ", ourNick: "tester") else {
                throw I2PWireError.invalidFormat
            }
            // A query folds the run of that person's lines exactly as a channel
            // does, and our own echo stays where it is.
            var state = I2PIRCChatState(serverName: "s", nick: "tester")
            try applyAll(&state, [
                ":irc.example.i2p 001 tester :Welcome",
                ":bob!b@host PRIVMSG tester :psst",
                ":bob!b@host PRIVMSG tester :one more"
            ])
            state.noteOutgoing("a word back", to: "bob")
            let query = try unwrap(state.conversation("bob"))
            let items = I2PIRCIgnoreFold.items(messages: query.messages,
                                               ignored: Set(["bob"]))
            guard items.count == 2,
                  case .ignored(let group) = items[0],
                  group.count == 2,
                  group.summary == "2 lines from bob ignored",
                  case .message(let echo) = items[1],
                  echo.isLocal else {
                throw I2PWireError.invalidFormat
            }
            return "our own nick is refused whatever its casing; a query folds the ignored run and leaves our own echo as it is"
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
