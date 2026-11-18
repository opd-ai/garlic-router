//
//  I2PIRCHighlightMatches.swift
//  Every line of the conversations the app holds that contains one of the
//  user's words: the list the Highlighted lines sheet shows, newest first, with
//  the word that matched beside the conversation, the nick and the time.
//
//  The list is read from the transcripts themselves — not from the keyword
//  marks, which reading a conversation clears — so a conversation the user has
//  already read still has its lines in here, and so does the transcript
//  restored from saved history. The rule is pure text work, so it is verified by
//  the self-test suite without a connection.
//

import Foundation

// MARK: - Match

/// One line of a conversation that holds one of the user's words.
struct I2PIRCHighlightMatch: Identifiable, Equatable {
    /// The conversation the line came from, as the chat keys it.
    let conversationID: String
    /// That conversation's name, as the chat shows it ("#i2p", a query's nick).
    let conversationName: String
    let conversationKind: I2PIRCConversation.Kind
    /// The line itself, which is what a tap in the sheet scrolls to.
    let messageID: UUID
    /// The word that matched, as the Highlights list spells it. A line that
    /// holds two words shows the first one in the list's order.
    let word: String
    let nick: String?
    let text: String
    let kind: I2PIRCMessage.Kind
    let date: Date

    /// A row's identity: the same line is one row however often the sheet opens.
    var id: String { "\(conversationID)|\(messageID.uuidString)" }

    /// The conversation as a row names it. The server buffer has no name of its
    /// own, so it is spelled out rather than shown as "#server".
    var conversationLabel: String {
        conversationKind == .server ? "Server buffer" : conversationName
    }
}

// MARK: - Rule

enum I2PIRCHighlightMatches {
    /// Every line of these conversations that holds one of `words`, newest
    /// first. The words are the Highlights list's switched-on entries, in the
    /// list's order, and the rule that decides whether a line holds one is the
    /// same whole-word rule the transcript marks with: our own echoes, stage
    /// notes and errors never match.
    static func matches(in conversations: [I2PIRCConversation],
                        words: [String]) -> [I2PIRCHighlightMatch] {
        let enabled = words.filter {
            !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        }
        guard !enabled.isEmpty else { return [] }

        var found: [(order: Int, match: I2PIRCHighlightMatch)] = []
        var order = 0
        for conversation in conversations {
            for message in conversation.messages {
                defer { order += 1 }
                let hits = I2PIRCKeywordRule.hits(in: message.text,
                                                  kind: message.kind,
                                                  isLocal: message.isLocal,
                                                  keywords: enabled)
                guard let word = hits.first else { continue }
                found.append((order, I2PIRCHighlightMatch(conversationID: conversation.id,
                                                          conversationName: conversation.name,
                                                          conversationKind: conversation.kind,
                                                          messageID: message.id,
                                                          word: word,
                                                          nick: message.nick,
                                                          text: message.text,
                                                          kind: message.kind,
                                                          date: message.date)))
            }
        }

        // Newest first, and two lines of the same second in the order the
        // transcripts hold them, so the list never shuffles between openings.
        return found.sorted { lhs, rhs in
            if lhs.match.date != rhs.match.date { return lhs.match.date > rhs.match.date }
            return lhs.order < rhs.order
        }.map(\.match)
    }

    /// The rows the filter field leaves: a case-insensitive match of what was
    /// typed against the line, the word that matched, the nick and the
    /// conversation. An empty (or blank) field leaves the list whole.
    static func filtered(_ matches: [I2PIRCHighlightMatch],
                         query: String) -> [I2PIRCHighlightMatch] {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !needle.isEmpty else { return matches }
        return matches.filter { match in
            match.text.lowercased().contains(needle)
                || match.word.lowercased().contains(needle)
                || (match.nick ?? "").lowercased().contains(needle)
                || match.conversationName.lowercased().contains(needle)
        }
    }

    /// How many lines the list holds, in a sentence — the read-out the
    /// Highlights sheet's "View matches" row carries.
    static func summary(count: Int) -> String {
        switch count {
        case 0: return "No line holds one of your words yet"
        case 1: return "1 line holds one of your words"
        default: return "\(count) lines hold one of your words"
        }
    }

    /// The filter's read-out under the field: "12 matches", "1 match", and an
    /// empty count when the list is empty.
    static func filterSummary(count: Int) -> String {
        switch count {
        case 0: return "No matches"
        case 1: return "1 match"
        default: return "\(count) matches"
        }
    }
}

// MARK: - Self-test suite (IRC highlighted lines)

enum I2PIRCHighlightMatchesSelfTest {
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

        run("irc · the highlighted lines list holds every matched line, newest first") {
            var state = I2PIRCChatState(serverName: "irc.example.i2p", nick: "tester")
            let now = Date()
            try applyAll(&state, [
                ":tester!t@c JOIN #i2p",
                ":alice!a@h JOIN #i2p",
                ":alice!a@h PRIVMSG #i2p :the release is out",
                ":bob!b@h PRIVMSG #i2p :released already, sorry",
                ":carol!c@h PRIVMSG #i2p :i2pd release notes are up",
                ":bob!b@h PRIVMSG tester :a private release word"
            ], at: now)
            let matches = I2PIRCHighlightMatches.matches(in: state.orderedConversations,
                                                         words: ["release", "i2pd"])
            guard matches.count == 3 else { throw I2PWireError.invalidFormat }
            // Newest first: the query's line was said last.
            guard matches[0].conversationName == "bob",
                  matches[0].nick == "bob",
                  matches[0].word == "release",
                  matches[0].text == "a private release word",
                  matches[1].nick == "carol",
                  // A line holding two words shows the first of the list's order.
                  matches[1].word == "release",
                  matches[2].conversationName == "#i2p",
                  matches[2].nick == "alice",
                  matches[2].word == "release" else {
                throw I2PWireError.invalidFormat
            }
            // "released" is not a whole word, so it never reaches the list.
            guard !matches.contains(where: { $0.text.contains("released") }) else {
                throw I2PWireError.invalidFormat
            }
            // The channel's matched lines are newest first among themselves too.
            let channel = matches.filter { $0.conversationName == "#i2p" }
            guard channel.map(\.text) == ["i2pd release notes are up",
                                          "the release is out"] else {
                throw I2PWireError.invalidFormat
            }
            guard I2PIRCHighlightMatches.summary(count: matches.count)
                    == "3 lines hold one of your words",
                  I2PIRCHighlightMatches.summary(count: 1) == "1 line holds one of your words",
                  I2PIRCHighlightMatches.summary(count: 0) == "No line holds one of your words yet" else {
                throw I2PWireError.invalidFormat
            }
            return "every matched line across channels and queries is in the list, newest first, with the word that matched, the conversation, the nick and the time"
        }

        run("irc · the highlighted lines list leaves out echoes, notes and paused words") {
            var state = I2PIRCChatState(serverName: "s", nick: "tester")
            try applyAll(&state, [
                ":tester!t@c JOIN #i2p",
                ":alice!a@h JOIN #i2p",
                ":alice!a@h PRIVMSG #i2p :the release is out",
                ":bob!b@h PRIVMSG #i2p :\u{01}ACTION is testing i2pd\u{01}",
                ":irc.example.i2p NOTICE #i2p :release policy changed"
            ])
            state.noteOutgoing("release party at mine", to: "#i2p")
            state.noteSystem("release: a note from the client", in: "#i2p")
            let matches = I2PIRCHighlightMatches.matches(in: state.orderedConversations,
                                                         words: ["release", "i2pd"])
            // The message, the action and the server's notice are in; our echo
            // and the client's note are not.
            guard matches.count == 3,
                  !matches.contains(where: { $0.text.contains("party at mine") }),
                  !matches.contains(where: { $0.text.contains("a note from the client") }),
                  matches.contains(where: { $0.kind == .action && $0.word == "i2pd" }),
                  matches.contains(where: { $0.kind == .notice }) else {
                throw I2PWireError.invalidFormat
            }
            // A word switched off takes its lines out of the list at once.
            let onlyRelease = I2PIRCHighlightMatches.matches(in: state.orderedConversations,
                                                             words: ["release"])
            guard onlyRelease.count == 2,
                  !onlyRelease.contains(where: { $0.word == "i2pd" }) else {
                throw I2PWireError.invalidFormat
            }
            // With no switched-on word the list is empty.
            guard I2PIRCHighlightMatches.matches(in: state.orderedConversations,
                                                 words: []).isEmpty else {
                throw I2PWireError.invalidFormat
            }
            return "messages, actions and notices holding a word are listed; echoes, client notes and paused words are not"
        }

        run("irc · the highlighted lines list survives reading and a relaunch") {
            let suite = "i2p.irc.highlights.selfTest"
            let defaults = UserDefaults(suiteName: suite) ?? .standard
            defaults.removePersistentDomain(forName: suite)
            let serverID = UUID()

            var live = I2PIRCChatState(serverName: "irc.example.i2p", nick: "tester")
            live.setKeywords(["release"])
            try applyAll(&live, [
                ":tester!t@c JOIN #i2p",
                ":alice!a@h JOIN #i2p",
                ":alice!a@h PRIVMSG #i2p :the release is out"
            ])
            // Reading the conversation takes the edges away but not the line.
            live.markKeywordsRead("#i2p")
            guard live.conversation("#i2p")?.messages.first(where: {
                      $0.text == "the release is out"
                  })?.keywordHits.isEmpty == true else {
                throw I2PWireError.invalidFormat
            }
            guard I2PIRCHighlightMatches.matches(in: live.orderedConversations,
                                                 words: ["release"]).count == 1 else {
                throw I2PWireError.invalidFormat
            }

            // Saved and restored, the line is still in the list.
            let history = I2PIRCHistoryStore(defaults: defaults, storageKey: "history")
            history.record(live, for: serverID)
            var restored = I2PIRCChatState(serverName: "irc.example.i2p", nick: "tester")
            restored.setKeywords(["release"])
            history.restore(into: &restored, for: serverID)
            let matches = I2PIRCHighlightMatches.matches(in: restored.orderedConversations,
                                                         words: ["release"])
            guard matches.count == 1,
                  matches[0].text == "the release is out",
                  matches[0].nick == "alice",
                  matches[0].conversationName == "#i2p",
                  matches[0].word == "release" else {
                throw I2PWireError.invalidFormat
            }
            defaults.removePersistentDomain(forName: suite)
            return "a line whose edges reading removed is still listed, and so is the transcript restored from saved history"
        }

        run("irc · the highlighted lines filter narrows the list as it is typed") {
            var state = I2PIRCChatState(serverName: "s", nick: "tester")
            let now = Date()
            try applyAll(&state, [
                ":tester!t@c JOIN #i2p",
                ":tester!t@c JOIN #notbob",
                ":alice!a@h JOIN #i2p",
                ":carol!c@h JOIN #notbob",
                ":alice!a@h PRIVMSG #i2p :the release is out",
                ":carol!c@h PRIVMSG #notbob :release notes are on the wiki",
                ":alice!a@h PRIVMSG tester :release word to you"
            ], at: now)
            let all = I2PIRCHighlightMatches.matches(in: state.orderedConversations,
                                                     words: ["release"])
            guard all.count == 3 else { throw I2PWireError.invalidFormat }

            guard I2PIRCHighlightMatches.filtered(all, query: "").count == 3,
                  I2PIRCHighlightMatches.filtered(all, query: "   ").count == 3,
                  I2PIRCHighlightMatches.filtered(all, query: "WIKI").count == 1,
                  I2PIRCHighlightMatches.filtered(all, query: "#notbob").count == 1,
                  I2PIRCHighlightMatches.filtered(all, query: "carol").count == 1,
                  I2PIRCHighlightMatches.filtered(all, query: "release").count == 3,
                  I2PIRCHighlightMatches.filtered(all, query: "nothing here").isEmpty else {
                throw I2PWireError.invalidFormat
            }
            // The filter narrows without reordering, and the read-out names it.
            let narrowed = I2PIRCHighlightMatches.filtered(all, query: "release word")
            guard narrowed.map(\.text) == ["release word to you"],
                  I2PIRCHighlightMatches.filterSummary(count: 3) == "3 matches",
                  I2PIRCHighlightMatches.filterSummary(count: 1) == "1 match",
                  I2PIRCHighlightMatches.filterSummary(count: 0) == "No matches" else {
                throw I2PWireError.invalidFormat
            }
            return "the filter narrows by line, word, nick and conversation, case-insensitively, and leaves the order alone"
        }

        run("irc · a highlighted line is opened in its conversation at that line") {
            var state = I2PIRCChatState(serverName: "s", nick: "tester")
            try applyAll(&state, [
                ":tester!t@c JOIN #i2p",
                ":alice!a@h JOIN #i2p",
                ":alice!a@h PRIVMSG #i2p :the release is out",
                ":bob!b@h PRIVMSG tester :release notes"
            ])
            let matches = I2PIRCHighlightMatches.matches(in: state.orderedConversations,
                                                         words: ["release"])
            guard let queryMatch = matches.first(where: { $0.conversationName == "bob" }) else {
                throw I2PWireError.invalidFormat
            }
            // The row points at a real conversation and a real line in it, which
            // is what the tap hands the chat to scroll to.
            let conversation = try unwrap(state.conversation(queryMatch.conversationID))
            guard conversation.name == "bob",
                  conversation.messages.contains(where: { $0.id == queryMatch.messageID }) else {
                throw I2PWireError.invalidFormat
            }
            // Two rows of two conversations never share an identity.
            let ids = Set(matches.map(\.id))
            guard ids.count == matches.count else { throw I2PWireError.invalidFormat }
            return "each row names its conversation and the line inside it, so a tap can open the chat there"
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

    private static func unwrap<T>(_ value: T?) throws -> T {
        guard let value else { throw I2PWireError.invalidFormat }
        return value
    }
}
