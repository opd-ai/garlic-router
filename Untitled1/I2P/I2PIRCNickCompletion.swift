//
//  I2PIRCNickCompletion.swift
//  The nick completion rule for the IRC composer: which word of the draft is a
//  nick being typed, which nicks of the open channel's roster match it — ours
//  first, then the ones most recently seen speaking — and how a tapped nick
//  replaces that word.
//
//  The rule is pure text and roster work, so the matching, the order and the
//  replacement are verified by the self-test suite without a connection.
//

import Foundation

// MARK: - Suggestion

/// One nick the strip offers, with what the row marks about it.
struct I2PIRCNickSuggestion: Identifiable, Equatable {
    let nick: String
    let role: I2PIRCMemberRole
    /// True for our own nick, which always sorts first.
    let isUs: Bool

    var id: String { I2PIRCName.key(nick) }

    /// The status symbol the row draws, or nil for an ordinary participant.
    var badgeSymbol: String? { role.badgeSymbol }
}

// MARK: - Completion rule

enum I2PIRCNickCompletion {
    /// How many rows the strip shows at most.
    static let suggestionLimit = 5

    /// The word at the start of the draft that is a nick being typed, or nil
    /// when there is nothing to complete: an empty draft, a draft that starts
    /// with a space (so the first word is finished) or one whose first word
    /// already ends with the colon the completion appends.
    static func typingPrefix(in draft: String) -> String? {
        guard let range = wordRange(in: draft) else { return nil }
        return String(draft[range])
    }

    /// The roster nicks the draft starts with, in the order the strip shows
    /// them: our own nick first, then the nicks most recently seen speaking in
    /// the conversation, and the rest by name. `messages` is the transcript on
    /// screen; "recently active" is read from it, so a nick that has not been
    /// seen keeps sorting after the ones that have.
    static func suggestions(draft: String,
                            members: [String],
                            roles: [String: I2PIRCMemberRole],
                            ourNick: String,
                            messages: [I2PIRCMessage],
                            limit: Int = suggestionLimit) -> [I2PIRCNickSuggestion] {
        guard limit > 0, let prefix = typingPrefix(in: draft) else { return [] }
        let needle = I2PIRCName.key(prefix)
        guard !needle.isEmpty else { return [] }

        let activity = activityRank(in: messages)
        let ourKey = I2PIRCName.key(ourNick)
        var seen = Set<String>()
        var matches: [I2PIRCNickSuggestion] = []
        for member in members {
            let nick = I2PIRCName.stripNickPrefixes(member)
            let key = I2PIRCName.key(nick)
            guard !key.isEmpty, seen.insert(key).inserted, key.hasPrefix(needle) else {
                continue
            }
            matches.append(I2PIRCNickSuggestion(nick: nick,
                                                role: roles[key] ?? .participant,
                                                isUs: key == ourKey))
        }

        matches.sort { lhs, rhs in
            if lhs.isUs != rhs.isUs { return lhs.isUs }
            let left = activity[lhs.id] ?? -1
            let right = activity[rhs.id] ?? -1
            if left != right { return left > right }
            return lhs.nick.lowercased() < rhs.nick.lowercased()
        }
        return Array(matches.prefix(limit))
    }

    /// Where each nick was last seen speaking, keyed by `I2PIRCName.key(nick)`
    /// and ranked by its position in the transcript, so a later line ranks
    /// higher. Nicks that never spoke have no entry.
    static func activityRank(in messages: [I2PIRCMessage]) -> [String: Int] {
        var latest: [String: Int] = [:]
        for (index, message) in messages.enumerated() {
            guard let nick = message.nick, !nick.isEmpty else { continue }
            latest[I2PIRCName.key(nick)] = index
        }
        return latest
    }

    /// The draft with the word being typed replaced by `nick` and the `": "`
    /// that follows a nickname, keeping whatever was typed after the word. A
    /// draft with no word to complete comes back untouched.
    static func applying(_ nick: String, to draft: String) -> String {
        guard !nick.isEmpty, let range = wordRange(in: draft) else { return draft }
        let rest = draft[range.upperBound...].drop { isWhitespace($0) }
        let completed = "\(nick): "
        return rest.isEmpty ? completed : completed + rest
    }

    // MARK: Helpers

    private static func wordRange(in draft: String) -> Range<String.Index>? {
        guard let first = draft.first, !isWhitespace(first) else { return nil }
        let end = draft.firstIndex(where: isWhitespace) ?? draft.endIndex
        let word = draft[draft.startIndex..<end]
        guard !word.isEmpty, !word.hasSuffix(":") else { return nil }
        return draft.startIndex..<end
    }

    private static func isWhitespace(_ character: Character) -> Bool {
        character == " " || character == "\t" || character == "\n" || character == "\r"
    }
}

// MARK: - Self-test suite (IRC nick completion)

enum I2PIRCNickCompletionSelfTest {
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

        run("irc · the word being typed is the draft's first word") {
            guard I2PIRCNickCompletion.typingPrefix(in: "al") == "al",
                  I2PIRCNickCompletion.typingPrefix(in: "alice") == "alice",
                  I2PIRCNickCompletion.typingPrefix(in: "ALI") == "ALI",
                  I2PIRCNickCompletion.typingPrefix(in: "al what about this") == "al",
                  I2PIRCNickCompletion.typingPrefix(in: "al\ttabbed") == "al" else {
                throw I2PWireError.invalidFormat
            }
            // Nothing to complete: no draft, a leading space, and a word that
            // already carries the colon of a finished nick.
            for draft in ["", "   ", " al", "alice: ", "alice: hi there"] {
                guard I2PIRCNickCompletion.typingPrefix(in: draft) == nil else {
                    throw I2PWireError.invalidFormat
                }
            }
            return "the first word is the nick being typed, and an empty draft, a leading space or a finished nick ends it"
        }

        run("irc · the strip puts our nick first and the most recently active next") {
            var state = I2PIRCChatState(serverName: "irc.example.i2p", nick: "tester")
            try applyAll(&state, [
                ":irc.example.i2p 001 tester :Welcome",
                ":tester!t@client JOIN #i2p",
                ":irc.example.i2p 353 tester = #i2p :@orbital +velvet tester alice alma albert tina",
                ":irc.example.i2p 366 tester #i2p :End of /NAMES list",
                ":albert!a@h PRIVMSG #i2p :first",
                ":alma!a@h PRIVMSG #i2p :second",
                ":tina!t@h PRIVMSG #i2p :hello tester"
            ])
            let channel = try unwrap(state.conversation("#i2p"))
            func suggestions(_ draft: String) -> [I2PIRCNickSuggestion] {
                I2PIRCNickCompletion.suggestions(draft: draft,
                                                 members: channel.members,
                                                 roles: channel.memberRoles,
                                                 ourNick: "tester",
                                                 messages: channel.messages)
            }
            // Ours first, even though tina spoke last; the casing of the
            // typed prefix does not matter.
            let t = suggestions("T")
            guard t.map(\.nick) == ["tester", "tina"],
                  t.first?.isUs == true, t.last?.isUs == false else {
                throw I2PWireError.invalidFormat
            }
            // Of the rest, the last to speak comes first and a nick never heard
            // from sorts after those two, by name.
            guard suggestions("al").map(\.nick) == ["alma", "albert", "alice"] else {
                throw I2PWireError.invalidFormat
            }
            // Operators and voiced nicks carry the status the row marks.
            guard suggestions("o").map(\.nick) == ["orbital"],
                  suggestions("o").first?.role == .op,
                  suggestions("v").first?.role == .voiced,
                  suggestions("al").allSatisfy({ $0.role == .participant }) else {
                throw I2PWireError.invalidFormat
            }
            // No prefix, no strip; a prefix nobody holds suggests nothing.
            guard suggestions("").isEmpty,
                  suggestions("   ").isEmpty,
                  suggestions("zzz").isEmpty,
                  suggestions("alice: hi").isEmpty else {
                throw I2PWireError.invalidFormat
            }
            return "our nick comes first, then the nicks most recently seen speaking, status marking held, with an empty or finished draft suggesting nothing"
        }

        run("irc · the strip shows five nicks at most") {
            let members = ["alice", "alma", "albert", "amber", "amy", "anna", "arthur"]
            let suggestions = I2PIRCNickCompletion.suggestions(draft: "a",
                                                               members: members,
                                                               roles: [:],
                                                               ourNick: "tester",
                                                               messages: [])
            guard suggestions.count == I2PIRCNickCompletion.suggestionLimit,
                  suggestions.map(\.nick) == ["albert", "alice", "alma", "amber", "amy"] else {
                throw I2PWireError.invalidFormat
            }
            // A smaller roster comes back whole, and a status prefix on a
            // roster entry is not part of the nick.
            let narrow = I2PIRCNickCompletion.suggestions(draft: "ve",
                                                          members: ["@velvet"],
                                                          roles: ["velvet": .op],
                                                          ourNick: "tester",
                                                          messages: [])
            guard narrow.map(\.nick) == ["velvet"], narrow.first?.role == .op else {
                throw I2PWireError.invalidFormat
            }
            return "a wide roster is cut to five rows; without activity the order is by name, and status prefixes never reach the row"
        }

        run("irc · completing a nick replaces the word and appends the colon") {
            guard I2PIRCNickCompletion.applying("albert", to: "al") == "albert: ",
                  I2PIRCNickCompletion.applying("albert", to: "al hey there") == "albert: hey there",
                  I2PIRCNickCompletion.applying("albert", to: "al\twhat") == "albert: what",
                  I2PIRCNickCompletion.applying("albert", to: "albert hello") == "albert: hello" else {
                throw I2PWireError.invalidFormat
            }
            // No word to complete leaves the draft alone: a leading space, a
            // finished nick and an empty suggestion.
            guard I2PIRCNickCompletion.applying("albert", to: "  al") == "  al",
                  I2PIRCNickCompletion.applying("albert", to: "albert: hi") == "albert: hi",
                  I2PIRCNickCompletion.applying("albert", to: "") == "",
                  I2PIRCNickCompletion.applying("", to: "al") == "al" else {
                throw I2PWireError.invalidFormat
            }
            return "a tap or Tab swaps the typed word for the nick and its colon, keeping the rest of the draft, and never touches a draft with no word at its start"
        }

        run("irc · a conversation with no roster suggests nothing") {
            var state = I2PIRCChatState(serverName: "irc.example.i2p", nick: "tester")
            try applyAll(&state, [
                ":irc.example.i2p 001 tester :Welcome",
                ":bob!b@host PRIVMSG tester :a private word"
            ])
            let server = try unwrap(state.conversation(I2PIRCChatState.serverBufferName))
            let query = try unwrap(state.conversation("bob"))
            for conversation in [server, query] {
                let suggestions = I2PIRCNickCompletion.suggestions(
                    draft: "b",
                    members: conversation.members,
                    roles: conversation.memberRoles,
                    ourNick: "tester",
                    messages: conversation.messages)
                guard suggestions.isEmpty else { throw I2PWireError.invalidFormat }
            }
            return "the server buffer and a private query hold no roster, so the strip stays away from both"
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
