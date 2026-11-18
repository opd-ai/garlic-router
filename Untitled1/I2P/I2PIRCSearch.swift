//
//  I2PIRCSearch.swift
//  The search rule for the IRC chat: which lines of the open conversation a
//  typed query matches — the nick that spoke or the line's text, in any case —
//  and how the field's count reads.
//
//  The rule is pure text work over the lines already loaded, so the matching and
//  the count are verified by the self-test suite without a connection.
//

import Foundation

// MARK: - Search rule

enum I2PIRCSearch {
    /// The query with its surrounding whitespace gone: what the matching uses,
    /// so a field holding only spaces filters nothing.
    static func normalized(_ query: String) -> String {
        query.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Whether one line matches: the query appears, in any case, in the nick
    /// that spoke or in the line's own text.
    static func matches(_ message: I2PIRCMessage, query: String) -> Bool {
        let needle = normalized(query)
        guard !needle.isEmpty else { return false }
        if let nick = message.nick,
           nick.range(of: needle, options: .caseInsensitive) != nil {
            return true
        }
        return message.text.range(of: needle, options: .caseInsensitive) != nil
    }

    /// The lines of a conversation the query matches, oldest first. An empty
    /// query matches nothing to drop, so the whole transcript comes back.
    static func results(in messages: [I2PIRCMessage], query: String) -> [I2PIRCMessage] {
        guard !normalized(query).isEmpty else { return messages }
        return messages.filter { matches($0, query: query) }
    }

    /// The count under the field: "7 matches", "1 match" and what an empty
    /// search reads.
    static func summary(count: Int) -> String {
        switch count {
        case 0: return "No matches"
        case 1: return "1 match"
        default: return "\(count) matches"
        }
    }
}

// MARK: - Self-test suite (IRC search)

enum I2PIRCSearchSelfTest {
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

        run("irc · search matches a nick or a line's text in any case") {
            let messages = [
                line(nick: "alice", text: "the tunnel is up"),
                line(nick: "Bob", text: "Tunnel build failed"),
                line(nick: "carol", text: "nothing to see here"),
                line(nick: nil, text: "dave left the channel", kind: .system),
                line(nick: "Dave", text: "bye", kind: .action)
            ]
            // The same word in two lines, whatever the casing of either side.
            guard I2PIRCSearch.results(in: messages, query: "TUNNEL").count == 2,
                  I2PIRCSearch.results(in: messages, query: "tunnel").count == 2,
                  // The nick alone is enough: neither line's text holds "alic".
                  I2PIRCSearch.results(in: messages, query: "ALIC").count == 1,
                  I2PIRCSearch.results(in: messages, query: "dave").count == 2,
                  // A line that matches nothing is left out.
                  I2PIRCSearch.results(in: messages, query: "zzz").isEmpty,
                  // An empty field, and one holding only spaces, filter nothing.
                  I2PIRCSearch.results(in: messages, query: "").count == messages.count,
                  I2PIRCSearch.results(in: messages, query: "  \n ").count == messages.count else {
                throw I2PWireError.invalidFormat
            }
            // Matching is on the loaded lines only, and a system line with no
            // nick is searched by its text.
            guard I2PIRCSearch.matches(messages[3], query: "left the"),
                  !I2PIRCSearch.matches(messages[3], query: "alice") else {
                throw I2PWireError.invalidFormat
            }
            return "the query meets nicks and text case-insensitively; an empty query keeps the whole transcript"
        }

        run("irc · search reports its count in words") {
            guard I2PIRCSearch.summary(count: 7) == "7 matches",
                  I2PIRCSearch.summary(count: 1) == "1 match",
                  I2PIRCSearch.summary(count: 0) == "No matches" else {
                throw I2PWireError.invalidFormat
            }
            return "7 matches, 1 match and No matches read as the field's count line"
        }

        run("irc · search filters only the conversation on screen") {
            var state = I2PIRCChatState(serverName: "irc.example.i2p", nick: "tester")
            try applyAll(&state, [
                ":irc.example.i2p 001 tester :Welcome",
                ":tester!t@client JOIN #i2p",
                ":alice!a@host JOIN #i2p",
                ":alice!a@host PRIVMSG #i2p :tunnel one is up",
                ":bob!b@host PRIVMSG #i2p :tunnel two is up",
                ":bob!b@host PRIVMSG tester :a private tunnel word"
            ])
            let channel = try unwrap(state.conversation("#i2p"))
            let query = try unwrap(state.conversation("bob"))
            guard I2PIRCSearch.results(in: channel.messages, query: "tunnel").count == 2,
                  I2PIRCSearch.results(in: query.messages, query: "tunnel").count == 1 else {
                throw I2PWireError.invalidFormat
            }
            return "each conversation is searched on its own lines, so a private tunnel never answers for the channel"
        }

        return results
    }

    private static func line(nick: String?,
                             text: String,
                             kind: I2PIRCMessage.Kind = .message) -> I2PIRCMessage {
        I2PIRCMessage(date: Date(), nick: nick, text: text, kind: kind, isLocal: false)
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
