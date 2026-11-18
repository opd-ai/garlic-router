//
//  I2PIRCHistory.swift
//  The IRC client's saved transcripts: one record per server holding its
//  conversations (the server buffer, the channels and the queries) with the
//  nick, the time and the kind of every line, written to device storage as
//  lines arrive and restored the next time that server connects.
//
//  At most 200 lines are kept per conversation. A server's record is cleared
//  from its row in the server list, and a cleared server starts empty the next
//  time it connects.
//

import Foundation
import Combine

// MARK: - Persisted line

/// One saved line: everything the chat view needs to draw it again.
struct I2PIRCHistoryLine: Codable, Equatable {
    let date: Date
    let nick: String?
    let text: String
    let kind: I2PIRCMessage.Kind
    let isLocal: Bool

    init(_ message: I2PIRCMessage) {
        self.date = message.date
        self.nick = message.nick
        self.text = message.text
        self.kind = message.kind
        self.isLocal = message.isLocal
    }

    /// The line as the live chat state holds it, with a fresh identity so a
    /// restored transcript and a live one never share a row id.
    func message() -> I2PIRCMessage {
        I2PIRCMessage(date: date, nick: nick, text: text, kind: kind, isLocal: isLocal)
    }
}

// MARK: - Persisted conversation

/// One saved conversation: its name, what kind it is and its lines, oldest
/// first.
struct I2PIRCHistoryConversation: Codable, Equatable {
    let name: String
    let kind: I2PIRCConversation.Kind
    var messages: [I2PIRCHistoryLine]

    init(name: String, kind: I2PIRCConversation.Kind, messages: [I2PIRCHistoryLine]) {
        self.name = name
        self.kind = kind
        self.messages = messages
    }
}

// MARK: - Store

/// The saved transcripts, keyed by the id of the server entry they belong to,
/// persisted in user defaults like the server book.
final class I2PIRCHistoryStore: ObservableObject {
    static let shared = I2PIRCHistoryStore()
    static let defaultsKey = "i2p.irc.history"

    /// The most lines kept per conversation, oldest dropped first.
    static let lineLimit = 200

    /// Bumped when a server's record appears or disappears, so a list showing
    /// per-server history state re-renders. Ordinary lines do not bump it.
    @Published private(set) var revision = 0

    private let defaults: UserDefaults
    private let storageKey: String
    /// Server id (as a UUID string) → its conversations, oldest line first.
    private var records: [String: [I2PIRCHistoryConversation]]

    init(defaults: UserDefaults = .standard,
         storageKey: String = I2PIRCHistoryStore.defaultsKey) {
        self.defaults = defaults
        self.storageKey = storageKey
        self.records = Self.load(defaults: defaults, key: storageKey)
    }

    // MARK: Reading

    /// A server's saved conversations, or an empty list when it has none.
    func conversations(for serverID: UUID) -> [I2PIRCHistoryConversation] {
        records[serverID.uuidString] ?? []
    }

    /// How many lines are saved for a server across its conversations.
    func lineCount(for serverID: UUID) -> Int {
        conversations(for: serverID).reduce(0) { $0 + $1.messages.count }
    }

    func hasHistory(for serverID: UUID) -> Bool {
        lineCount(for: serverID) > 0
    }

    // MARK: Writing

    /// Saves the state's conversations, keeping the newest `lineLimit` lines of
    /// each. Called as lines arrive, so a kill of the app costs at most the line
    /// being written.
    func record(_ state: I2PIRCChatState, for serverID: UUID) {
        let stored: [I2PIRCHistoryConversation] = state.conversations.compactMap { conversation in
            let lines = conversation.messages.suffix(Self.lineLimit).map { I2PIRCHistoryLine($0) }
            guard !lines.isEmpty else { return nil }
            return I2PIRCHistoryConversation(name: conversation.name,
                                             kind: conversation.kind,
                                             messages: Array(lines))
        }
        let key = serverID.uuidString
        let previous = records[key]
        guard !stored.isEmpty else {
            // A freshly created state has no lines in it yet, and a transcript
            // only ever grows: an empty one never erases what is saved.
            return
        }
        // Opening a conversation only changes its unread badge, and that is not
        // saved: an unchanged transcript is never rewritten.
        guard previous != stored else { return }
        records[key] = stored
        persist()
        if (previous ?? []).isEmpty {
            revision &+= 1
        }
    }

    /// Puts a server's saved transcript back into a freshly created state, so
    /// the chat picks up where it left off.
    func restore(into state: inout I2PIRCChatState, for serverID: UUID) {
        let stored = conversations(for: serverID)
        guard !stored.isEmpty else { return }
        state.restore(stored)
    }

    /// Drops a server's saved transcript. A live connection keeps what is on
    /// screen; the next connect starts empty.
    func clear(_ serverID: UUID) {
        guard records.removeValue(forKey: serverID.uuidString) != nil else { return }
        persist()
        revision &+= 1
    }

    // MARK: Storage

    private func persist() {
        guard !records.isEmpty else {
            defaults.removeObject(forKey: storageKey)
            return
        }
        guard let data = try? JSONEncoder().encode(records) else { return }
        defaults.set(data, forKey: storageKey)
    }

    private static func load(defaults: UserDefaults,
                             key: String) -> [String: [I2PIRCHistoryConversation]] {
        guard let data = defaults.data(forKey: key),
              let decoded = try? JSONDecoder().decode([String: [I2PIRCHistoryConversation]].self,
                                                      from: data) else {
            return [:]
        }
        return decoded
    }
}

// MARK: - Self-test suite (IRC history)

enum I2PIRCHistorySelfTest {
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

        run("irc · history saves a transcript and restores it on the next connect") {
            let suite = "i2p.irc.history.selfTest"
            let defaults = UserDefaults(suiteName: suite) ?? .standard
            defaults.removePersistentDomain(forName: suite)
            let serverID = UUID()

            var state = I2PIRCChatState(serverName: "irc.postman.i2p", nick: "tester")
            try applyAll(&state, [
                ":irc.postman.i2p 001 tester :Welcome to the network",
                ":tester!t@client JOIN #i2p",
                ":alice!a@host JOIN #i2p",
                ":alice!a@host PRIVMSG #i2p :hello there",
                ":alice!a@host PRIVMSG tester :psst, private"
            ])
            state.noteOutgoing("hi alice", to: "#i2p")

            let store = I2PIRCHistoryStore(defaults: defaults, storageKey: "history")
            store.record(state, for: serverID)
            guard store.hasHistory(for: serverID),
                  store.conversations(for: serverID).count == 3 else {
                throw I2PWireError.invalidFormat
            }

            // A relaunch reads the same record back and restores it.
            let reopened = I2PIRCHistoryStore(defaults: defaults, storageKey: "history")
            var fresh = I2PIRCChatState(serverName: "irc.postman.i2p", nick: "tester")
            reopened.restore(into: &fresh, for: serverID)

            let channel = try unwrap(fresh.conversation("#i2p"))
            let query = try unwrap(fresh.conversation("alice"))
            guard channel.kind == .channel, query.kind == .query,
                  // A restored channel is not joined until the server says so.
                  !channel.joined,
                  channel.unread == 0,
                  channel.messages.contains(where: {
                      $0.nick == "alice" && $0.text == "hello there"
                          && $0.kind == .message && !$0.isLocal
                  }),
                  channel.messages.contains(where: { $0.isLocal && $0.text == "hi alice" }),
                  query.messages.last?.text == "psst, private",
                  // The server buffer's own connect line is what proves the
                  // buffer was saved and restored; the 001 sentence itself is
                  // summarised into that line rather than duplicated.
                  fresh.conversation(I2PIRCChatState.serverBufferName)?.messages.contains(where: {
                      $0.kind == .system && $0.text.contains("Connected to irc.postman.i2p")
                  }) == true else {
                throw I2PWireError.invalidFormat
            }
            // Timestamps survive the round trip.
            guard let restored = channel.messages.first(where: { $0.text == "hello there" }),
                  abs(restored.date.timeIntervalSinceNow) < 60 else {
                throw I2PWireError.invalidFormat
            }
            defaults.removePersistentDomain(forName: suite)
            return "server buffer, channel and query restored with nicks, times, kinds and local echoes; the channel waits to be re-joined"
        }

        run("irc · history keeps only the newest 200 lines per conversation") {
            let suite = "i2p.irc.history.selfTest.limit"
            let defaults = UserDefaults(suiteName: suite) ?? .standard
            defaults.removePersistentDomain(forName: suite)
            let serverID = UUID()

            var state = I2PIRCChatState(serverName: "irc.example.i2p", nick: "tester")
            state.openConversation("#big")
            for index in 0..<250 {
                state.noteOutgoing("line \(index)", to: "#big")
            }
            let store = I2PIRCHistoryStore(defaults: defaults, storageKey: "history")
            store.record(state, for: serverID)

            let saved = try unwrap(store.conversations(for: serverID).first { $0.name == "#big" })
            guard saved.messages.count == I2PIRCHistoryStore.lineLimit,
                  saved.messages.first?.text == "line 50",
                  saved.messages.last?.text == "line 249" else {
                throw I2PWireError.invalidFormat
            }
            defaults.removePersistentDomain(forName: suite)
            return "250 lines saved as the newest \(I2PIRCHistoryStore.lineLimit), oldest dropped first"
        }

        run("irc · clearing a server's history starts it empty on the next connect") {
            let suite = "i2p.irc.history.selfTest.clear"
            let defaults = UserDefaults(suiteName: suite) ?? .standard
            defaults.removePersistentDomain(forName: suite)
            let first = UUID()
            let second = UUID()

            var state = I2PIRCChatState(serverName: "irc.example.i2p", nick: "tester")
            state.noteOutgoing("only in the first", to: "#i2p")
            state.noteOutgoing("only in the second", to: "#help")
            let store = I2PIRCHistoryStore(defaults: defaults, storageKey: "history")
            store.record(state, for: first)
            store.record(state, for: second)

            store.clear(first)
            guard !store.hasHistory(for: first),
                  store.conversations(for: first).isEmpty,
                  // Another server's transcript is untouched.
                  store.hasHistory(for: second) else {
                throw I2PWireError.invalidFormat
            }
            // The clear sticks across a relaunch, and restoring leaves the
            // server buffer empty.
            let reopened = I2PIRCHistoryStore(defaults: defaults, storageKey: "history")
            guard !reopened.hasHistory(for: first) else { throw I2PWireError.invalidFormat }
            var fresh = I2PIRCChatState(serverName: "irc.example.i2p", nick: "tester")
            reopened.restore(into: &fresh, for: first)
            guard fresh.conversations.count == 1,
                  fresh.conversations[0].kind == .server,
                  fresh.conversations[0].messages.isEmpty else {
                throw I2PWireError.invalidFormat
            }
            defaults.removePersistentDomain(forName: suite)
            return "a cleared server's record is gone for good; another server keeps its own and the cleared one starts empty"
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
