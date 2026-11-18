//
//  I2PIRCKeywords.swift
//  The words the user wants to be told about: the Highlights list opened from
//  the IRC toolbar, the whole-word rule that decides whether a line holds one of
//  them, and the store that keeps them across launches.
//
//  The list is device-wide — the same words mark every server, channel and query
//  — and the rule is pure text work, so the whole behaviour is verified by the
//  self-test suite without a connection.
//

import Foundation
import Combine

// MARK: - Keyword

/// One word the user keeps, with the switch that pauses it. A paused word stays
/// in the list and keeps matching nothing until it is switched back on.
struct I2PIRCKeyword: Identifiable, Codable, Equatable {
    var id: UUID
    /// The word as the list shows it; matching folds the case.
    var word: String
    var isEnabled: Bool
    var addedAt: Date

    init(id: UUID = UUID(),
         word: String,
         isEnabled: Bool = true,
         addedAt: Date = Date()) {
        self.id = id
        self.word = word
        self.isEnabled = isEnabled
        self.addedAt = addedAt
    }

    /// The word folded for comparison and de-duplication.
    var key: String { word.lowercased() }
}

// MARK: - Keyword rule

/// The answer to "does this line hold one of my words?": case-insensitive, as a
/// whole word, and only on the lines a person said — the same lines a mention
/// can come from.
enum I2PIRCKeywordRule {
    /// A character that makes a keyword part of a longer word. Unlike a nick, a
    /// word is bounded by letters, digits and the underscore alone, so "release"
    /// is a word of "pre-release" and of "(release)" but never of "released".
    static func isWordCharacter(_ character: Character) -> Bool {
        if character.isLetter || character.isNumber { return true }
        return character == "_"
    }

    /// Whether `text` holds `keyword` as a whole word, in any case. An empty
    /// keyword matches nothing.
    static func matches(_ text: String, keyword: String) -> Bool {
        !ranges(of: keyword, in: text).isEmpty
    }

    /// Where `text` holds `keyword` as a whole word, in any case and in
    /// reading order — the occurrences `matches` answers for, and the ones a
    /// marked line tints so the word it was marked for shows inside it.
    static func ranges(of keyword: String, in text: String) -> [Range<String.Index>] {
        let needle = Array(keyword.lowercased())
        guard !needle.isEmpty else { return [] }

        let characters = Array(text)
        guard characters.count >= needle.count else { return [] }

        // Each character folds on its own, so an offset in the folded line is
        // the same offset in the line itself. A fold that would make two
        // characters of one leaves that character as it stands.
        let folded = characters.map { character -> Character in
            let lowered = character.lowercased()
            return lowered.count == 1 ? Character(lowered) : character
        }

        // Where each character starts, plus the end of the line, so a match at
        // an offset becomes the range the text itself holds.
        var bounds = Array(text.indices)
        bounds.append(text.endIndex)

        var found: [Range<String.Index>] = []
        var index = 0
        while index <= folded.count - needle.count {
            if folded[index..<(index + needle.count)].elementsEqual(needle) {
                let before = index > 0 ? folded[index - 1] : nil
                let afterIndex = index + needle.count
                let after = afterIndex < folded.count ? folded[afterIndex] : nil
                if !(before.map(isWordCharacter) ?? false),
                   !(after.map(isWordCharacter) ?? false) {
                    found.append(bounds[index]..<bounds[afterIndex])
                }
            }
            index += 1
        }
        return found
    }

    /// The keywords a line holds, in the list's order. Our own echoes, stage
    /// notes and errors are never marked — the lines a keyword is for are the
    /// ones somebody else said, did or noticed, exactly as for a mention.
    static func hits(in text: String,
                     kind: I2PIRCMessage.Kind,
                     isLocal: Bool,
                     keywords: [String]) -> [String] {
        guard !isLocal, I2PIRCMention.counts(kind: kind) else { return [] }
        return keywords.filter { matches(text, keyword: $0) }
    }

    /// The lines of a conversation that hold one of the user's words, oldest
    /// first — the lines the chat header's Highlight control steps through. A
    /// line that both names us and holds a word is in this list and in the
    /// mention control's too.
    static func markedIDs(in messages: [I2PIRCMessage]) -> [UUID] {
        messages.filter { !$0.keywordHits.isEmpty }.map(\.id)
    }

    /// How many lines of the conversations arrived on `day` and hold `word` the
    /// way a keyword does — the read-out under each row of the Highlights list.
    /// It counts the transcript the app holds, restored history included.
    static func matchCount(of word: String,
                           in conversations: [I2PIRCConversation],
                           on day: Date = Date(),
                           calendar: Calendar = .current) -> Int {
        conversations.reduce(0) { total, conversation in
            total + conversation.messages.filter { message in
                !message.isLocal
                    && I2PIRCMention.counts(kind: message.kind)
                    && calendar.isDate(message.date, inSameDayAs: day)
                    && matches(message.text, keyword: word)
            }.count
        }
    }
}

// MARK: - Store

/// The saved keywords, in the order they were added, persisted in user defaults
/// like the server book. They never leave the device.
///
/// The book also keeps the master switch's pause: a moment until which every
/// word is off, the list itself untouched.
final class I2PIRCKeywordBook: ObservableObject {
    static let shared = I2PIRCKeywordBook()
    static let defaultsKey = "i2p.irc.keywords"

    @Published private(set) var entries: [I2PIRCKeyword] = []

    /// When the master switch's pause ends; nil while highlighting is on.
    @Published private(set) var pauseEndsAt: Date?

    /// The duration the last pause was set for, so switching highlighting off
    /// again re-uses it.
    @Published private(set) var lastPauseDuration: I2PIRCKeywordPauseDuration = .hour

    private let defaults: UserDefaults
    private let storageKey: String
    /// Where the pause and the duration it was set for are kept.
    private let endsAtKey: String
    private let durationKey: String
    /// The countdown that puts the switch back on by itself.
    private var pauseTask: Task<Void, Never>?

    init(defaults: UserDefaults = .standard,
         storageKey: String = I2PIRCKeywordBook.defaultsKey) {
        self.defaults = defaults
        self.storageKey = storageKey
        self.endsAtKey = storageKey + ".pause.endsAt"
        self.durationKey = storageKey + ".pause.duration"
        self.entries = Self.load(defaults: defaults, key: storageKey)

        let storedEnd = defaults.object(forKey: endsAtKey) as? Date
        self.lastPauseDuration = defaults.string(forKey: durationKey)
            .flatMap(I2PIRCKeywordPauseDuration.init(rawValue:)) ?? .hour
        if let storedEnd, storedEnd > Date() {
            self.pauseEndsAt = storedEnd
            schedulePauseExpiry(until: storedEnd)
        } else {
            self.pauseEndsAt = nil
            // A pause that ran out while the app was closed is over.
            if storedEnd != nil {
                defaults.removeObject(forKey: endsAtKey)
            }
        }
    }

    /// The words that mark a line: the switched-on entries, in the list's order.
    /// Nothing while the master switch's pause is running — the list keeps every
    /// word, and every word keeps its own switch.
    var enabledWords: [String] {
        guard !isPaused else { return [] }
        return entries.filter(\.isEnabled).map(\.word)
    }

    var isEmpty: Bool { entries.isEmpty }

    func contains(_ word: String) -> Bool {
        let key = word.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !key.isEmpty else { return false }
        return entries.contains { $0.key == key }
    }

    /// Adds a word. A word already on the list — in any case — is refused, and
    /// so is one that is only whitespace. Returns whether the list changed.
    @discardableResult
    func add(_ raw: String, at date: Date = Date()) -> Bool {
        let word = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !word.isEmpty, !contains(word) else { return false }
        entries.append(I2PIRCKeyword(word: word, addedAt: date))
        persist()
        return true
    }

    /// Switches a word on or off, which is what its row's switch does.
    func setEnabled(_ enabled: Bool, for id: UUID) {
        guard let index = entries.firstIndex(where: { $0.id == id }),
              entries[index].isEnabled != enabled else { return }
        entries[index].isEnabled = enabled
        persist()
    }

    func remove(_ id: UUID) {
        let before = entries.count
        entries.removeAll { $0.id == id }
        guard entries.count != before else { return }
        persist()
    }

    // MARK: Pause

    /// Whether the master switch is off right now: every keyword paused for a
    /// time, the list itself untouched.
    var isPaused: Bool {
        I2PIRCKeywordPause.isPaused(until: pauseEndsAt)
    }

    /// The line under the master switch: a pause with the time it has left, or
    /// that highlighting is on.
    var pauseSummary: String {
        I2PIRCKeywordPause.summary(until: pauseEndsAt)
    }

    /// Switches every keyword off until the chosen moment. The list is not
    /// touched — a pause is a time, not an edit — and the words keep their own
    /// switches for when it is over.
    func pause(for duration: I2PIRCKeywordPauseDuration, at now: Date = Date()) {
        lastPauseDuration = duration
        pauseEndsAt = duration.end(from: now)
        persistPause()
        schedulePauseExpiry(until: pauseEndsAt ?? now)
    }

    /// Switches highlighting back on now, without waiting the pause out.
    func resume() {
        pauseTask?.cancel()
        pauseTask = nil
        guard pauseEndsAt != nil else { return }
        pauseEndsAt = nil
        persistPause()
    }

    /// The countdown that puts the switch back on by itself when the time runs
    /// out, so the words mark lines again without the sheet being opened.
    private func schedulePauseExpiry(until endsAt: Date) {
        pauseTask?.cancel()
        pauseTask = nil
        let interval = endsAt.timeIntervalSinceNow
        guard interval > 0 else {
            notePauseElapsed()
            return
        }
        pauseTask = Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(interval))
            guard !Task.isCancelled else { return }
            self?.notePauseElapsed()
        }
    }

    /// A pause that has run out is over: the stored switch comes back on and
    /// everything that marks a line reads the words again.
    private func notePauseElapsed() {
        pauseTask = nil
        guard let endsAt = pauseEndsAt, endsAt <= Date() else { return }
        pauseEndsAt = nil
        persistPause()
    }

    /// Writes the pause and the duration it was set for, so a relaunch reads the
    /// switch back exactly as it was left.
    private func persistPause() {
        if let pauseEndsAt {
            defaults.set(pauseEndsAt, forKey: endsAtKey)
        } else {
            defaults.removeObject(forKey: endsAtKey)
        }
        defaults.set(lastPauseDuration.rawValue, forKey: durationKey)
    }

    // MARK: Persistence

    private func persist() {
        guard !entries.isEmpty else {
            defaults.removeObject(forKey: storageKey)
            return
        }
        guard let data = try? JSONEncoder().encode(entries) else { return }
        defaults.set(data, forKey: storageKey)
    }

    private static func load(defaults: UserDefaults, key: String) -> [I2PIRCKeyword] {
        guard let data = defaults.data(forKey: key),
              let decoded = try? JSONDecoder().decode([I2PIRCKeyword].self, from: data) else {
            return []
        }
        return decoded
    }
}

// MARK: - Self-test suite (IRC keywords)

enum I2PIRCKeywordSelfTest {
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

        run("irc · a keyword marks a line as a whole word, in any case") {
            for line in ["the release is out", "RELEASE!", "(release)", "pre-release notes",
                         "does it release?"] {
                guard I2PIRCKeywordRule.matches(line, keyword: "release") else {
                    throw I2PWireError.invalidFormat
                }
            }
            for line in ["released already", "prereleases", "releases_", "release2", "no news"] {
                guard !I2PIRCKeywordRule.matches(line, keyword: "release") else {
                    throw I2PWireError.invalidFormat
                }
            }
            // The other direction folds too, and a word with digits or dots is
            // bounded the same way.
            guard I2PIRCKeywordRule.matches("hello i2pd:", keyword: "I2PD"),
                  I2PIRCKeywordRule.matches("v2.5 is out", keyword: "v2.5"),
                  // An empty keyword can mark nothing.
                  !I2PIRCKeywordRule.matches("anything at all", keyword: "") else {
                throw I2PWireError.invalidFormat
            }
            return "keywords match case-insensitively as whole words, bounded by letters, digits and underscores only"
        }

        run("irc · lines that hold a keyword are marked and counted per conversation") {
            var state = I2PIRCChatState(serverName: "irc.example.i2p", nick: "tester")
            state.setKeywords(["release", "i2pd"])
            try applyAll(&state, [
                ":tester!t@client JOIN #i2p",
                ":alice!a@host JOIN #i2p",
                ":alice!a@host PRIVMSG #i2p :the release is out",
                ":bob!b@host PRIVMSG #i2p :released already, sorry",
                ":bob!b@host PRIVMSG #i2p :\u{01}ACTION is testing i2pd\u{01}",
                ":alice!a@host PRIVMSG tester :release notes are up"
            ])
            let channel = try unwrap(state.conversation("#i2p"))
            guard channel.keywordCount == 2,
                  channel.messages.first(where: { $0.text == "the release is out" })?.keywordHits
                  == ["release"],
                  channel.messages.first(where: { $0.text.contains("released already") })?
                      .keywordHits.isEmpty == true,
                  channel.messages.first(where: { $0.kind == .action })?.keywordHits == ["i2pd"],
                  state.conversation("alice")?.keywordCount == 1 else {
                throw I2PWireError.invalidFormat
            }
            // Our own echo and a stage note never wear an edge or count.
            state.noteOutgoing("release party at mine", to: "#i2p")
            state.noteSystem("release: a note from the client", in: "#i2p")
            guard state.conversation("#i2p")?.keywordCount == 2,
                  state.conversation("#i2p")?.messages.last?.keywordHits.isEmpty == true else {
                throw I2PWireError.invalidFormat
            }
            // Pausing a word takes its edges and its count away, and the other
            // word's lines keep theirs.
            state.setKeywords(["i2pd"])
            guard state.conversation("#i2p")?.keywordCount == 1,
                  state.conversation("#i2p")?.messages.first(where: {
                      $0.text == "the release is out"
                  })?.keywordHits.isEmpty == true,
                  state.conversation("alice")?.keywordCount == 0 else {
                throw I2PWireError.invalidFormat
            }
            // Reading a conversation clears its marks; another keeps its own.
            state.setKeywords(["release", "i2pd"])
            state.markKeywordsRead("#i2p")
            guard state.conversation("#i2p")?.keywordCount == 0,
                  state.conversation("#i2p")?.messages.contains(where: {
                      !$0.keywordHits.isEmpty
                  }) == false,
                  state.conversation("alice")?.keywordCount == 1 else {
                throw I2PWireError.invalidFormat
            }
            // Clearing the transcript takes the remaining marks with it.
            state.clearHistory()
            guard state.conversation("alice")?.keywordCount == 0 else {
                throw I2PWireError.invalidFormat
            }
            return "messages, actions and notices holding a word are marked and counted; echoes and notes are not; pausing, reading and clearing drop the marks"
        }

        run("irc · the count follows the transcript when old lines drop off") {
            var state = I2PIRCChatState(serverName: "s", nick: "tester")
            state.setKeywords(["release"])
            try applyAll(&state, [":tester!t@c JOIN #big", ":alice!a@h JOIN #big"])
            for index in 0..<(I2PIRCChatState.messageLimit + 3) {
                try applyAll(&state, [":alice!a@h PRIVMSG #big :release \(index)"])
            }
            let channel = try unwrap(state.conversation("#big"))
            let marked = channel.messages.filter { !$0.keywordHits.isEmpty }.count
            guard marked == channel.keywordCount,
                  channel.messages.count == I2PIRCChatState.messageLimit else {
                throw I2PWireError.invalidFormat
            }
            return "the keyword count stays equal to the marked lines left in the capped buffer"
        }

        run("irc · the highlight control steps the lines that hold a word") {
            var state = I2PIRCChatState(serverName: "s", nick: "tester")
            state.setKeywords(["release", "i2pd"])
            try applyAll(&state, [
                ":tester!t@c JOIN #i2p",
                ":tester!t@c JOIN #quiet",
                ":alice!a@h JOIN #i2p",
                ":alice!a@h JOIN #quiet",
                ":alice!a@h PRIVMSG #i2p :the release is out",
                ":bob!b@h PRIVMSG #i2p :nothing to see here",
                ":bob!b@h PRIVMSG #i2p :tester, i2pd is up",
                ":alice!a@h PRIVMSG #i2p :release notes are up",
                ":carol!c@h PRIVMSG #i2p :released, sorry",
                ":bob!b@h PRIVMSG #quiet :nothing to see here either"
            ])
            let channel = try unwrap(state.conversation("#i2p"))
            let ids = I2PIRCKeywordRule.markedIDs(in: channel.messages)
            let mentioning = channel.messages.filter { $0.mentionsUs }.map(\.id)
            // The line that both names us and holds a word is stepped by both
            // controls: three keyword lines, one of them a mention.
            guard ids.count == 3, mentioning == [ids[1]] else {
                throw I2PWireError.invalidFormat
            }

            // Stepping runs through the three and wraps to the first again,
            // reporting the step it is on.
            var position = 0
            var trail: [Int] = []
            for _ in 0..<4 {
                position = I2PIRCMention.nextPosition(after: position, count: ids.count)
                trail.append(position)
            }
            guard trail == [1, 2, 3, 1],
                  I2PIRCMention.counter(position: 2, count: ids.count) == "2 of 3" else {
                throw I2PWireError.invalidFormat
            }

            // A conversation with no keyword line steps nowhere, which is what
            // leaves the control dimmed.
            guard I2PIRCKeywordRule.markedIDs(
                in: try unwrap(state.conversation("#quiet")).messages
            ).isEmpty else {
                throw I2PWireError.invalidFormat
            }

            // Switching every word off takes the lines away with the marks.
            state.setKeywords([])
            guard I2PIRCKeywordRule.markedIDs(
                in: try unwrap(state.conversation("#i2p")).messages
            ).isEmpty else {
                throw I2PWireError.invalidFormat
            }
            return "the Highlight control steps the marked lines in order and wraps, counts a line that both names us and holds a word in both lists, and steps nowhere with no keyword line"
        }

        run("irc · keywords persist across launches and mark a restored transcript") {
            let suite = "i2p.irc.keywords.selfTest"
            let defaults = UserDefaults(suiteName: suite) ?? .standard
            defaults.removePersistentDomain(forName: suite)
            let serverID = UUID()

            let book = I2PIRCKeywordBook(defaults: defaults, storageKey: "keywords")
            guard book.add("Release"), book.add("i2pd"),
                  // A word already on the list is refused, in any case, and so
                  // is one that is only spaces.
                  !book.add("  release "), !book.add("   "),
                  book.entries.map(\.word) == ["Release", "i2pd"],
                  book.enabledWords == ["Release", "i2pd"] else {
                throw I2PWireError.invalidFormat
            }
            book.setEnabled(false, for: book.entries[0].id)

            // A relaunch reads the same list back, pause included.
            let reopened = I2PIRCKeywordBook(defaults: defaults, storageKey: "keywords")
            guard reopened.entries.count == 2,
                  reopened.enabledWords == ["i2pd"],
                  reopened.entries.first?.isEnabled == false else {
                throw I2PWireError.invalidFormat
            }

            // A transcript saved earlier picks its edges up on the next connect,
            // without lighting up the chip for lines read in that session.
            var live = I2PIRCChatState(serverName: "irc.example.i2p", nick: "tester")
            try applyAll(&live, [
                ":tester!t@c JOIN #i2p",
                ":alice!a@h JOIN #i2p",
                ":alice!a@h PRIVMSG #i2p :the release is out"
            ])
            let history = I2PIRCHistoryStore(defaults: defaults, storageKey: "history")
            history.record(live, for: serverID)

            var restored = I2PIRCChatState(serverName: "irc.example.i2p", nick: "tester")
            restored.setKeywords(reopened.enabledWords)
            history.restore(into: &restored, for: serverID)
            let channel = try unwrap(restored.conversation("#i2p"))
            guard channel.messages.first(where: { $0.text == "the release is out" })?
                      .keywordHits.isEmpty == true,
                  channel.keywordCount == 0 else {
                throw I2PWireError.invalidFormat
            }

            // With a word switched on, the restored line wears its edge.
            restored.setKeywords(["release", "i2pd"])
            guard restored.conversation("#i2p")?.messages.first(where: {
                      $0.text == "the release is out"
                  })?.keywordHits == ["release"] else {
                throw I2PWireError.invalidFormat
            }
            // Removing a word persists too.
            reopened.remove(reopened.entries[0].id)
            guard I2PIRCKeywordBook(defaults: defaults, storageKey: "keywords").entries
                    .map(\.word) == ["i2pd"] else {
                throw I2PWireError.invalidFormat
            }
            defaults.removePersistentDomain(forName: suite)
            return "the list, its order and its paused words survive a relaunch; a restored transcript wears the edges of the words switched on and never counts"
        }

        run("irc · the highlights read-out counts today's matched lines") {
            var state = I2PIRCChatState(serverName: "s", nick: "tester")
            let now = Date()
            let yesterday = now.addingTimeInterval(-26 * 60 * 60)
            apply(&state, ":tester!t@c JOIN #i2p", at: now)
            apply(&state, ":alice!a@h JOIN #i2p", at: now)
            apply(&state, ":alice!a@h PRIVMSG #i2p :the release is out", at: now)
            apply(&state, ":bob!b@h PRIVMSG #i2p :released, sorry", at: now)
            apply(&state, ":bob!b@h PRIVMSG #i2p :release candidate two", at: yesterday)
            apply(&state, ":carol!c@h PRIVMSG tester :the release notes", at: now)

            let conversations = state.orderedConversations
            guard I2PIRCKeywordRule.matchCount(of: "release", in: conversations, on: now) == 2,
                  I2PIRCKeywordRule.matchCount(of: "release", in: conversations, on: yesterday) == 1,
                  // A word nobody used reads zero, and so does an empty one.
                  I2PIRCKeywordRule.matchCount(of: "i2pd", in: conversations, on: now) == 0,
                  I2PIRCKeywordRule.matchCount(of: "", in: conversations, on: now) == 0 else {
                throw I2PWireError.invalidFormat
            }
            return "the row's read-out counts today's whole-word matches across every channel and query, the yesterday's line on its own day"
        }

        return results
    }

    private static func applyAll(_ state: inout I2PIRCChatState, _ lines: [String]) throws {
        for raw in lines {
            guard let line = I2PIRCLine.parse(raw) else { throw I2PWireError.invalidFormat }
            state.apply(line)
        }
    }

    private static func apply(_ state: inout I2PIRCChatState, _ raw: String, at date: Date) {
        guard let line = I2PIRCLine.parse(raw) else { return }
        state.apply(line, at: date)
    }

    private static func unwrap<T>(_ value: T?) throws -> T {
        guard let value else { throw I2PWireError.invalidFormat }
        return value
    }
}
