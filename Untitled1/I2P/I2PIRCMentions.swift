//
//  I2PIRCMentions.swift
//  The mention rule for the IRC chat: which lines name us — our nick matched
//  case-insensitively as a whole word — and how the chat's Next mention control
//  steps through the marked lines of the conversation on screen.
//
//  The rule is pure text work, so the matching and the stepping are verified by
//  the self-test suite without a connection.
//

import Foundation

// MARK: - Mention rule

enum I2PIRCMention {
    /// The characters IRC lets a nick hold. A nick sitting inside a longer word
    /// built from these is part of that word, not a mention of us.
    static func isNickCharacter(_ character: Character) -> Bool {
        if character.isLetter || character.isNumber { return true }
        return "[]\\`_^{}|-".contains(character)
    }

    /// Whether a line of chat names `nick`: case-insensitive, as a whole word.
    /// "tester" is named by "hey tester:" and "TESTER, look", never by
    /// "testers", "tester_" or "atesters".
    static func names(_ text: String, nick: String) -> Bool {
        let needle = Array(nick.lowercased())
        guard !needle.isEmpty else { return false }
        let haystack = Array(text.lowercased())
        guard haystack.count >= needle.count else { return false }

        var index = 0
        while index <= haystack.count - needle.count {
            if haystack[index..<(index + needle.count)].elementsEqual(needle) {
                let before = index > 0 ? haystack[index - 1] : nil
                let afterIndex = index + needle.count
                let after = afterIndex < haystack.count ? haystack[afterIndex] : nil
                if !(before.map(isNickCharacter) ?? false),
                   !(after.map(isNickCharacter) ?? false) {
                    return true
                }
            }
            index += 1
        }
        return false
    }

    /// The kinds of line that can name us: what someone said to us, did or
    /// noticed at us. Stage notes, errors and our own lines never do.
    static func counts(kind: I2PIRCMessage.Kind) -> Bool {
        switch kind {
        case .message, .action, .notice: return true
        case .system, .error: return false
        }
    }

    // MARK: Stepping

    /// The position the Next mention control moves to, counted from one, given
    /// where it stands now and how many lines name us. The first press takes
    /// the first line, and the press after the last wraps to the first again.
    static func nextPosition(after position: Int, count: Int) -> Int {
        guard count > 0 else { return 0 }
        guard position >= 1, position <= count else { return 1 }
        return position % count + 1
    }

    /// The control's read-out: the step it is on and how many there are
    /// ("2 of 5"), and an empty count when nothing names us.
    static func counter(position: Int, count: Int) -> String {
        guard count > 0 else { return "0 of 0" }
        let step = min(max(position, 1), count)
        return "\(step) of \(count)"
    }
}

// MARK: - Self-test suite (IRC mentions)

enum I2PIRCMentionSelfTest {
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

        run("irc · a mention is our nick as a whole word, in any case") {
            guard I2PIRCMention.names("hey tester: look", nick: "tester"),
                  I2PIRCMention.names("TESTER please", nick: "tester"),
                  I2PIRCMention.names("tester, are you there?", nick: "tester"),
                  I2PIRCMention.names("(tester) ping", nick: "tester"),
                  I2PIRCMention.names("tester's idea", nick: "tester"),
                  I2PIRCMention.names("ping Tester!", nick: "tester"),
                  // The other direction folds too: our nick upper, the line lower.
                  I2PIRCMention.names("hello tester", nick: "TESTER") else {
                throw I2PWireError.invalidFormat
            }
            // A longer word that merely starts or ends with our nick is not us.
            for line in ["testers are welcome", "a tester_ here", "atesters", "tester2",
                         "mister testerx", "no mention here"] {
                guard !I2PIRCMention.names(line, nick: "tester") else {
                    throw I2PWireError.invalidFormat
                }
            }
            // An empty nick can name nothing.
            guard !I2PIRCMention.names("anything at all", nick: "") else {
                throw I2PWireError.invalidFormat
            }
            return "whole-word, case-insensitive matching names us after punctuation and rejects longer words built from nick characters"
        }

        run("irc · the chat marks and counts the lines that name us per conversation") {
            var state = I2PIRCChatState(serverName: "irc.example.i2p", nick: "tester")
            try applyAll(&state, [
                ":irc.example.i2p 001 tester :Welcome to the network",
                ":tester!t@client JOIN #i2p",
                ":alice!a@host JOIN #i2p",
                ":alice!a@host PRIVMSG #i2p :hey tester: look at this",
                ":bob!b@host PRIVMSG #i2p :testers are welcome too",
                ":bob!b@host PRIVMSG #i2p :\u{01}ACTION waves at TESTER\u{01}",
                ":alice!a@host PRIVMSG tester :tester, a private word"
            ])
            let channel = try unwrap(state.conversation("#i2p"))
            guard channel.mentionCount == 2,
                  channel.messages.filter({ $0.mentionsUs }).count == 2,
                  channel.messages.last?.mentionsUs == true,
                  state.conversation("alice")?.mentionCount == 1 else {
                throw I2PWireError.invalidFormat
            }
            // Our own echo never marks, and a stage note never does.
            state.noteOutgoing("hello tester", to: "#i2p")
            state.noteSystem("tester: a note from the client", in: "#i2p")
            guard state.conversation("#i2p")?.mentionCount == 2 else {
                throw I2PWireError.invalidFormat
            }
            // Reading a conversation clears its marks; another keeps its own.
            state.markMentionsRead("#i2p")
            guard state.conversation("#i2p")?.mentionCount == 0,
                  state.conversation("#i2p")?.messages.contains(where: { $0.mentionsUs }) == false,
                  state.conversation("alice")?.mentionCount == 1 else {
                throw I2PWireError.invalidFormat
            }
            // Clearing the transcript takes the marks with it.
            state.clearHistory()
            guard state.conversation("alice")?.mentionCount == 0 else {
                throw I2PWireError.invalidFormat
            }
            return "messages, actions and notices that name us are marked and counted per conversation; local echoes, stage notes and a cleared transcript are not"
        }

        run("irc · the count follows the transcript when old lines drop off") {
            var state = I2PIRCChatState(serverName: "s", nick: "tester")
            try applyAll(&state, [
                ":tester!t@client JOIN #big",
                ":alice!a@host JOIN #big"
            ])
            // Fill the buffer past its limit, naming us on every line.
            for index in 0..<(I2PIRCChatState.messageLimit + 3) {
                try applyAll(&state, [":alice!a@host PRIVMSG #big :tester line \(index)"])
            }
            let channel = try unwrap(state.conversation("#big"))
            let marked = channel.messages.filter({ $0.mentionsUs }).count
            guard marked == channel.mentionCount,
                  channel.messages.count == I2PIRCChatState.messageLimit else {
                throw I2PWireError.invalidFormat
            }
            return "the mention count stays equal to the marked lines left in the capped buffer"
        }

        run("irc · the next mention control reports 2 of 5 and wraps") {
            var position = 0
            var trail: [Int] = []
            for _ in 0..<6 {
                position = I2PIRCMention.nextPosition(after: position, count: 5)
                trail.append(position)
            }
            guard trail == [1, 2, 3, 4, 5, 1],
                  I2PIRCMention.counter(position: 2, count: 5) == "2 of 5",
                  I2PIRCMention.counter(position: 1, count: 1) == "1 of 1",
                  // Nothing names us: no step, and the control reads empty.
                  I2PIRCMention.counter(position: 0, count: 0) == "0 of 0",
                  I2PIRCMention.nextPosition(after: 0, count: 0) == 0,
                  // A count that shrank under a stale position starts over.
                  I2PIRCMention.nextPosition(after: 7, count: 3) == 1 else {
                throw I2PWireError.invalidFormat
            }
            return "stepping runs 1, 2, 3, 4, 5 and back to 1, the read-out names the step and the total, and an empty count steps nowhere"
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
