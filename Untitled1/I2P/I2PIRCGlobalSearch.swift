//
//  I2PIRCGlobalSearch.swift
//  One search over every conversation of the connected server: the rule the
//  Search all sheet runs, grouping the matching lines under the conversation
//  they came from and counting them for the field's read-out.
//
//  The rule reads the transcripts themselves, so a transcript restored from
//  saved history is searched exactly as the live one is. It is pure text work,
//  and the self-test suite verifies it without a connection.
//

import Foundation

// MARK: - Match

/// One line of any conversation that the search field matches.
struct I2PIRCGlobalMatch: Identifiable, Equatable {
    /// The conversation the line came from, as the chat keys it.
    let conversationID: String
    /// That conversation's name, as the chat shows it ("#i2p", a query's nick).
    let conversationName: String
    let conversationKind: I2PIRCConversation.Kind
    /// The line itself, which is what a tap in the sheet hands the chat to
    /// scroll to.
    let messageID: UUID
    let nick: String?
    let text: String
    let kind: I2PIRCMessage.Kind
    let date: Date
    /// True for a line this client sent, so the row says "You".
    let isLocal: Bool

    /// A row's identity: the same line is one row however often the sheet opens.
    var id: String { "\(conversationID)|\(messageID.uuidString)" }

    /// The conversation as a row names it. The server buffer has no name of its
    /// own, so it is spelled out rather than shown as "#server".
    var conversationLabel: String {
        conversationKind == .server ? "Server buffer" : conversationName
    }
}

// MARK: - Group

/// The matching lines of one conversation, newest first — one card of the
/// Search all list.
struct I2PIRCGlobalMatchGroup: Identifiable {
    let conversationID: String
    let conversationName: String
    let conversationKind: I2PIRCConversation.Kind
    /// The conversation's matching lines, newest first.
    let matches: [I2PIRCGlobalMatch]

    var id: String { conversationID }
    var count: Int { matches.count }

    /// What the card's header reads: the conversation, with the server buffer
    /// spelled out.
    var label: String {
        conversationKind == .server ? "Server buffer" : conversationName
    }

    /// The newest line of the group, which is what a tap on the header opens.
    var newest: I2PIRCGlobalMatch? { matches.first }
}

// MARK: - Rule

enum I2PIRCGlobalSearch {
    /// The query with its surrounding whitespace gone: what the matching uses,
    /// so a field holding only spaces searches nothing.
    static func normalized(_ query: String) -> String {
        query.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Whether one line matches: the query appears, in any case, in the nick
    /// that spoke or in the line's own text — the rule the chat's own search
    /// field uses, applied to every conversation at once.
    static func matches(_ message: I2PIRCMessage, query: String) -> Bool {
        let needle = normalized(query)
        guard !needle.isEmpty else { return false }
        if let nick = message.nick,
           nick.range(of: needle, options: .caseInsensitive) != nil {
            return true
        }
        return message.text.range(of: needle, options: .caseInsensitive) != nil
    }

    /// The matching lines of these conversations, grouped by conversation: each
    /// group's lines newest first, and the group whose newest line is the most
    /// recent first. An empty (or blank) query groups nothing, which is what
    /// leaves the sheet showing its explanation instead of a list.
    static func groups(in conversations: [I2PIRCConversation],
                       query: String) -> [I2PIRCGlobalMatchGroup] {
        guard !normalized(query).isEmpty else { return [] }

        // The order a line was read in, so two lines of the same second keep the
        // order their transcripts hold them and the list never shuffles.
        var found: [(order: Int, position: Int, group: I2PIRCGlobalMatchGroup)] = []
        var order = 0
        for (position, conversation) in conversations.enumerated() {
            var lines: [(order: Int, match: I2PIRCGlobalMatch)] = []
            for message in conversation.messages {
                defer { order += 1 }
                guard matches(message, query: query) else { continue }
                lines.append((order, I2PIRCGlobalMatch(conversationID: conversation.id,
                                                       conversationName: conversation.name,
                                                       conversationKind: conversation.kind,
                                                       messageID: message.id,
                                                       nick: message.nick,
                                                       text: message.text,
                                                       kind: message.kind,
                                                       date: message.date,
                                                       isLocal: message.isLocal)))
            }
            guard let first = lines.first else { continue }
            let newestFirst = lines.sorted { lhs, rhs in
                if lhs.match.date != rhs.match.date { return lhs.match.date > rhs.match.date }
                return lhs.order < rhs.order
            }.map(\.match)
            found.append((first.order,
                          position,
                          I2PIRCGlobalMatchGroup(conversationID: conversation.id,
                                                 conversationName: conversation.name,
                                                 conversationKind: conversation.kind,
                                                 matches: newestFirst)))
        }

        return found.sorted { lhs, rhs in
            let left = lhs.group.newest?.date ?? .distantPast
            let right = rhs.group.newest?.date ?? .distantPast
            if left != right { return left > right }
            return lhs.position < rhs.position
        }.map(\.group)
    }

    /// How many lines the groups hold together — the number beside the field.
    static func totalCount(of groups: [I2PIRCGlobalMatchGroup]) -> Int {
        groups.reduce(0) { $0 + $1.count }
    }

    /// The ranges the query covers in a line, in reading order, matched
    /// case-insensitively and never overlapping — what a row tints so the match
    /// shows inside the line.
    static func matchedRanges(in text: String, query: String) -> [Range<String.Index>] {
        let needle = normalized(query)
        guard !needle.isEmpty, !text.isEmpty else { return [] }
        var ranges: [Range<String.Index>] = []
        var searchStart = text.startIndex
        while searchStart < text.endIndex,
              let range = text.range(of: needle,
                                     options: [.caseInsensitive],
                                     range: searchStart..<text.endIndex) {
            if range.lowerBound < range.upperBound { ranges.append(range) }
            guard range.upperBound > searchStart else { break }
            searchStart = range.upperBound
        }
        return ranges
    }
}

// MARK: - Self-test suite (IRC search across every conversation)

enum I2PIRCGlobalSearchSelfTest {
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

        run("irc · the global search reads every conversation of the server") {
            var state = I2PIRCChatState(serverName: "irc.example.i2p", nick: "tester")
            let now = Date()
            try applyAll(&state, [
                ":irc.example.i2p 001 tester :Welcome to the network",
                ":tester!t@c JOIN #i2p",
                ":alice!a@h JOIN #i2p",
                ":bob!b@h JOIN #i2p",
                ":alice!a@h PRIVMSG #i2p :the release is out",
                ":bob!b@h PRIVMSG #i2p :release notes are on the wiki",
                ":alice!a@h PRIVMSG tester :a private Release word",
                ":alice!a@h PRIVMSG #i2p :nothing about that here"
            ], at: now)

            // The same word in the channel and in the query, whatever the case.
            let groups = I2PIRCGlobalSearch.groups(in: state.orderedConversations,
                                                   query: "RELEASE")
            guard groups.count == 2,
                  I2PIRCGlobalSearch.totalCount(of: groups) == 3 else {
                throw I2PWireError.invalidFormat
            }
            // The query's line is the newest of all, so its group leads.
            guard groups[0].conversationName == "alice",
                  groups[0].conversationKind == .query,
                  groups[0].count == 1,
                  groups[0].matches.first?.nick == "alice",
                  groups[0].matches.first?.text == "a private Release word",
                  groups[1].conversationName == "#i2p",
                  groups[1].label == "#i2p" else {
                throw I2PWireError.invalidFormat
            }
            // Inside a group the lines are newest first too.
            guard groups[1].matches.map(\.text) == ["release notes are on the wiki",
                                                    "the release is out"],
                  groups[1].newest?.text == "release notes are on the wiki" else {
                throw I2PWireError.invalidFormat
            }
            // A line that holds nothing is left out.
            guard !groups.contains(where: { group in
                group.matches.contains(where: { $0.text.hasPrefix("nothing about") })
            }) else {
                throw I2PWireError.invalidFormat
            }

            // The server buffer is searched like any other conversation, and is
            // spelled out because it has no name of its own.
            let buffer = I2PIRCGlobalSearch.groups(in: state.orderedConversations,
                                                   query: "CONNECTED TO")
            guard buffer.count == 1,
                  buffer[0].conversationKind == .server,
                  buffer[0].label == "Server buffer" else {
                throw I2PWireError.invalidFormat
            }

            // An empty field, and one holding only spaces, searches nothing.
            guard I2PIRCGlobalSearch.groups(in: state.orderedConversations, query: "").isEmpty,
                  I2PIRCGlobalSearch.groups(in: state.orderedConversations,
                                            query: "  \n ").isEmpty,
                  I2PIRCSearch.summary(count: I2PIRCGlobalSearch.totalCount(of: groups))
                    == "3 matches" else {
                throw I2PWireError.invalidFormat
            }
            return "channels, queries and the server buffer are all searched case-insensitively, grouped with the newest line first"
        }

        run("irc · the global search reads the transcript restored from saved history") {
            let suite = "i2p.irc.globalSearch.selfTest"
            let defaults = UserDefaults(suiteName: suite) ?? .standard
            defaults.removePersistentDomain(forName: suite)
            let serverID = UUID()

            var live = I2PIRCChatState(serverName: "irc.example.i2p", nick: "tester")
            try applyAll(&live, [
                ":tester!t@c JOIN #i2p",
                ":alice!a@h JOIN #i2p",
                ":alice!a@h PRIVMSG #i2p :the release is out",
                ":bob!b@h PRIVMSG tester :release notes"
            ])
            let history = I2PIRCHistoryStore(defaults: defaults, storageKey: "history")
            history.record(live, for: serverID)

            var restored = I2PIRCChatState(serverName: "irc.example.i2p", nick: "tester")
            history.restore(into: &restored, for: serverID)
            let groups = I2PIRCGlobalSearch.groups(in: restored.orderedConversations,
                                                   query: "release")
            guard groups.count == 2,
                  I2PIRCGlobalSearch.totalCount(of: groups) == 2,
                  groups.contains(where: { $0.conversationName == "#i2p" && $0.count == 1 }),
                  groups.contains(where: { $0.conversationName == "bob" && $0.count == 1 }) else {
                throw I2PWireError.invalidFormat
            }
            defaults.removePersistentDomain(forName: suite)
            return "a transcript restored from saved history answers the search exactly as the live one does"
        }

        run("irc · the global search marks the matched words inside the line") {
            let text = "Release candidates: a release is a release"
            let ranges = I2PIRCGlobalSearch.matchedRanges(in: text, query: "RELEASE")
            guard ranges.count == 3 else { throw I2PWireError.invalidFormat }
            guard ranges.map({ text[$0].lowercased() }) == ["release", "release", "release"],
                  ranges.map({ text.distance(from: text.startIndex, to: $0.lowerBound) }) == [0, 22, 35] else {
                throw I2PWireError.invalidFormat
            }
            // An empty field marks nothing, and a line without the word has no mark.
            guard I2PIRCGlobalSearch.matchedRanges(in: text, query: " ").isEmpty,
                  I2PIRCGlobalSearch.matchedRanges(in: text, query: "zzz").isEmpty,
                  I2PIRCGlobalSearch.matchedRanges(in: "", query: "release").isEmpty else {
                throw I2PWireError.invalidFormat
            }
            return "every occurrence of the query is found case-insensitively, in reading order and without overlaps"
        }

        run("irc · a global search row opens its conversation at that line") {
            var state = I2PIRCChatState(serverName: "s", nick: "tester")
            try applyAll(&state, [
                ":tester!t@c JOIN #i2p",
                ":alice!a@h JOIN #i2p",
                ":alice!a@h PRIVMSG #i2p :the release is out",
                ":bob!b@h PRIVMSG tester :release notes",
                ":tester!t@c JOIN #quiet",
                ":carol!c@h JOIN #quiet",
                ":carol!c@h PRIVMSG #quiet :release in here too"
            ])
            let groups = I2PIRCGlobalSearch.groups(in: state.orderedConversations,
                                                   query: "release")
            guard groups.count == 3 else { throw I2PWireError.invalidFormat }
            let all = groups.flatMap(\.matches)
            // Every row points at a real conversation and a real line in it,
            // which is what the tap hands the chat to scroll to.
            for match in all {
                guard let conversation = state.conversation(match.conversationID),
                      conversation.messages.contains(where: { $0.id == match.messageID }) else {
                    throw I2PWireError.invalidFormat
                }
            }
            guard Set(all.map(\.id)).count == all.count,
                  Set(groups.map(\.id)).count == groups.count else {
                throw I2PWireError.invalidFormat
            }
            return "each row names its conversation and the line inside it, and no two rows share an identity"
        }

        return results
    }

    private static func applyAll(_ state: inout I2PIRCChatState, _ lines: [String]) throws {
        for raw in lines {
            guard let line = I2PIRCLine.parse(raw) else { throw I2PWireError.invalidFormat }
            state.apply(line)
        }
    }

    private static func applyAll(_ state: inout I2PIRCChatState,
                                 _ lines: [String],
                                 at date: Date) throws {
        for (index, raw) in lines.enumerated() {
            guard let line = I2PIRCLine.parse(raw) else { throw I2PWireError.invalidFormat }
            state.apply(line, at: date.addingTimeInterval(TimeInterval(index)))
        }
    }
}
