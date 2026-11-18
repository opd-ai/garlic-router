//
//  I2PIRCMutes.swift
//  The conversations the user has silenced: one record per server holding the
//  keys of the conversations that add no badge, persisted in user defaults like
//  the server book and the saved transcripts.
//
//  A mute is per server and per conversation: #i2p silenced on one network is
//  still loud on another. The keys are conversation keys, so a channel muted
//  before it is joined is silent the moment it appears.
//

import Foundation
import Combine

// MARK: - Store

/// The muted conversations, keyed by the id of the server entry they belong to,
/// persisted in user defaults. They never leave the device.
final class I2PIRCMuteBook: ObservableObject {
    static let shared = I2PIRCMuteBook()
    static let defaultsKey = "i2p.irc.mutes"

    /// Bumped when a mute is set or cleared, so whatever shows a conversation's
    /// silence re-reads the record.
    @Published private(set) var revision = 0

    private let defaults: UserDefaults
    private let storageKey: String
    /// Server id (as a UUID string) → the conversation keys it has muted.
    private var records: [String: [String]]

    init(defaults: UserDefaults = .standard,
         storageKey: String = I2PIRCMuteBook.defaultsKey) {
        self.defaults = defaults
        self.storageKey = storageKey
        self.records = Self.load(defaults: defaults, key: storageKey)
    }

    // MARK: Reading

    /// The conversation keys a server has muted.
    func conversations(for serverID: UUID) -> Set<String> {
        Set(records[serverID.uuidString] ?? [])
    }

    /// Whether one conversation of a server is muted. The name is matched the
    /// way IRC matches a conversation, so "#i2p" and "#I2P" are the same one.
    func isMuted(_ conversationID: String, on serverID: UUID) -> Bool {
        conversations(for: serverID).contains(I2PIRCName.key(conversationID))
    }

    // MARK: Writing

    /// Switches one conversation's mute. Returns whether the record changed: a
    /// mute set twice, or cleared where there was none, writes nothing.
    @discardableResult
    func setMuted(_ muted: Bool, for conversationID: String, on serverID: UUID) -> Bool {
        let key = I2PIRCName.key(conversationID)
        guard !key.isEmpty else { return false }
        let serverKey = serverID.uuidString
        let before = Set(records[serverKey] ?? [])
        var keys = before
        if muted {
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

// MARK: - Self-test suite (IRC mutes)

enum I2PIRCMuteSelfTest {
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

        run("irc · a mute is kept per server and per conversation across launches") {
            let suite = "i2p.irc.mutes.selfTest"
            let defaults = UserDefaults(suiteName: suite) ?? .standard
            defaults.removePersistentDomain(forName: suite)
            let first = UUID()
            let second = UUID()

            let book = I2PIRCMuteBook(defaults: defaults, storageKey: "mutes")
            guard book.conversations(for: first).isEmpty,
                  !book.isMuted("#i2p", on: first) else {
                throw I2PWireError.invalidFormat
            }

            guard book.setMuted(true, for: "#i2p", on: first) else {
                throw I2PWireError.invalidFormat
            }
            // Setting the same mute again writes nothing.
            guard !book.setMuted(true, for: "#I2P", on: first) else {
                throw I2PWireError.invalidFormat
            }
            // The same channel on another server is a different conversation,
            // and so is another conversation of the same server.
            guard book.isMuted("#I2P", on: first),
                  !book.isMuted("#i2p", on: second),
                  !book.isMuted("#help", on: first) else {
                throw I2PWireError.invalidFormat
            }
            book.setMuted(true, for: "alice", on: first)
            guard book.conversations(for: first) == ["#i2p", "alice"] else {
                throw I2PWireError.invalidFormat
            }

            // A relaunch reads the same records back.
            let reopened = I2PIRCMuteBook(defaults: defaults, storageKey: "mutes")
            guard reopened.isMuted("#i2p", on: first),
                  reopened.isMuted("alice", on: first),
                  !reopened.isMuted("#i2p", on: second) else {
                throw I2PWireError.invalidFormat
            }

            // Unmuting one conversation leaves the other one silent, and the
            // clear sticks across a relaunch too.
            reopened.setMuted(false, for: "#i2p", on: first)
            guard !reopened.isMuted("#i2p", on: first),
                  reopened.isMuted("alice", on: first) else {
                throw I2PWireError.invalidFormat
            }
            let third = I2PIRCMuteBook(defaults: defaults, storageKey: "mutes")
            guard !third.isMuted("#i2p", on: first),
                  third.isMuted("alice", on: first) else {
                throw I2PWireError.invalidFormat
            }
            defaults.removePersistentDomain(forName: suite)
            return "a mute belongs to one conversation of one server and survives a relaunch; unmuting one leaves the others silent"
        }

        run("irc · a muted conversation adds no badge but keeps its marked lines") {
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
            guard channel.unread == 1, channel.mentionCount == 1,
                  channel.keywordCount == 1,
                  state.conversation("alice")?.unread == 1 else {
                throw I2PWireError.invalidFormat
            }

            // Muting takes the badges off the conversation at once, and the
            // marks stay painted on the lines that earned them.
            state.setMutedConversations(["#i2p"])
            let muted = try unwrap(state.conversation("#i2p"))
            guard muted.unread == 0, muted.mentionCount == 0, muted.keywordCount == 0,
                  state.isMuted("#I2P"),
                  muted.messages.contains(where: { $0.mentionsUs }),
                  muted.messages.contains(where: { !$0.keywordHits.isEmpty }),
                  // Another conversation keeps its own badge.
                  state.conversation("alice")?.unread == 1 else {
                throw I2PWireError.invalidFormat
            }

            // Lines arriving while it is muted still carry their marks, but add
            // no unread, mention or keyword count — here or in the total.
            try applyAll(&state, [
                ":bob!b@host PRIVMSG #i2p :tester, did the release build pass?",
                ":tester!t@client PRIVMSG #i2p :it did"
            ])
            let quiet = try unwrap(state.conversation("#i2p"))
            guard quiet.unread == 0, quiet.mentionCount == 0, quiet.keywordCount == 0,
                  quiet.messages.filter({ $0.mentionsUs }).count == 2,
                  quiet.messages.filter({ !$0.keywordHits.isEmpty }).count == 2,
                  state.totalUnread == 1 else {
                throw I2PWireError.invalidFormat
            }

            // Unmuting does not count the lines said while it was silent; the
            // next line to arrive does.
            state.setMutedConversations([])
            guard !state.isMuted("#i2p"),
                  state.conversation("#i2p")?.unread == 0,
                  state.conversation("#i2p")?.mentionCount == 0,
                  state.conversation("#i2p")?.keywordCount == 0 else {
                throw I2PWireError.invalidFormat
            }
            try applyAll(&state, [
                ":bob!b@host PRIVMSG #i2p :tester, the release notes are up"
            ])
            let ringing = try unwrap(state.conversation("#i2p"))
            guard ringing.unread == 1, ringing.mentionCount == 1,
                  ringing.keywordCount == 1 else {
                throw I2PWireError.invalidFormat
            }
            return "muting clears a conversation's badges and silences the ones its next lines would add; its mention and keyword marks stay on the lines, and unmuting lets the next line count again"
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
