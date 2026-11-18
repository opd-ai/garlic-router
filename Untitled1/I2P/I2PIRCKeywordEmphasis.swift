//
//  I2PIRCKeywordEmphasis.swift
//  The word inside a marked line: which of the user's words a line was marked
//  for, and how the transcript and the Highlighted lines sheet show it — the
//  matched word itself tinted and emboldened in the cool blue the edge wears.
//
//  The rule is the whole-word rule the mark itself uses, less the places a word
//  only appears inside a link or inside a nick, so the emphasis never points at
//  something the user was not told about. It is pure text work, and the
//  self-test suite verifies it without a connection.
//

import SwiftUI

// MARK: - Span

/// One occurrence of a user's word inside a line: the characters to tint and
/// the entry of the Highlights list it matched.
struct I2PIRCKeywordEmphasisSpan: Equatable {
    let range: Range<String.Index>
    /// The word as the Highlights list spells it.
    let word: String
}

// MARK: - Rule

enum I2PIRCKeywordEmphasis {
    /// The tint a matched word wears: the cool blue the keyword edge is drawn
    /// in, a shade cooler than a mention's violet so the two marks never read
    /// as the same thing.
    static let tint = Color(red: 0.45, green: 0.71, blue: 1.00)

    /// The words a line is marked for, as the list spells them: trimmed,
    /// blanks dropped and a repeat of a word already here dropped too. The
    /// order is the list's, so a line holding two words shows both.
    static func normalized(_ words: [String]) -> [String] {
        var seen: Set<String> = []
        var result: [String] = []
        for word in words {
            let trimmed = word.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty, seen.insert(trimmed.lowercased()).inserted else { continue }
            result.append(trimmed)
        }
        return result
    }

    /// The places inside `text` that hold one of `words` and are to be
    /// emphasised: every whole-word occurrence of every word, in reading
    /// order, less the ones that sit inside a link or inside a nick.
    static func spans(in text: String,
                      words: [String]) -> [I2PIRCKeywordEmphasisSpan] {
        let entries = normalized(words)
        guard !text.isEmpty, !entries.isEmpty else { return [] }

        let protected = protectedSpans(in: text)

        var found: [I2PIRCKeywordEmphasisSpan] = []
        for word in entries {
            for range in I2PIRCKeywordRule.ranges(of: word, in: text) {
                guard !protected.contains(where: { $0.overlaps(range) }),
                      !found.contains(where: { $0.range.overlaps(range) }) else { continue }
                found.append(I2PIRCKeywordEmphasisSpan(range: range, word: word))
            }
        }
        return found.sorted { $0.range.lowerBound < $1.range.lowerBound }
    }

    /// The stretches of a line the emphasis leaves alone: a link, which is a web
    /// or I2P address and carries its own colour, and a nick, written the two
    /// ways chat writes one — with an "@" in front, or as the addressee of the
    /// line with a colon after it. A name is not a word the user was told
    /// about, so nothing inside it is emphasised.
    static func protectedSpans(in text: String) -> [Range<String.Index>] {
        var spans: [Range<String.Index>] = []
        var index = text.startIndex
        while let token = nextToken(in: text, from: index) {
            let value = String(text[token])
            if isLink(value) || isNick(value) { spans.append(token) }
            index = token.upperBound
        }
        return spans
    }

    /// The word after `start`, with the whitespace in front of it skipped.
    private static func nextToken(in text: String,
                                  from start: String.Index) -> Range<String.Index>? {
        var begin = start
        while begin < text.endIndex, text[begin].isWhitespace {
            begin = text.index(after: begin)
        }
        guard begin < text.endIndex else { return nil }
        var end = begin
        while end < text.endIndex, !text[end].isWhitespace {
            end = text.index(after: end)
        }
        return begin..<end
    }

    /// Whether a token is a link: it carries a scheme, or it is written as a web
    /// address without one.
    private static func isLink(_ token: String) -> Bool {
        token.contains("://") || token.lowercased().hasPrefix("www.")
    }

    /// Whether a token is a nick as chat writes one: "@alice", or "alice:" at
    /// the head of a line. An ordinary hyphenated word is a word, not a nick.
    private static func isNick(_ token: String) -> Bool {
        if token.hasPrefix("@") {
            let stem = token.dropFirst()
            return !stem.isEmpty && stem.allSatisfy(I2PIRCMention.isNickCharacter)
        }
        guard token.hasSuffix(":") else { return false }
        let stem = token.dropLast()
        return !stem.isEmpty && stem.allSatisfy(I2PIRCMention.isNickCharacter)
    }

    /// The line with every span tinted in the edge's cool blue and emboldened,
    /// so the word a marked line was marked for shows inside it. A line no word
    /// marks comes back exactly as it went in.
    static func attributed(_ text: String,
                           words: [String],
                           tint: Color,
                           boldFont: Font) -> AttributedString {
        var attributed = AttributedString(text)
        for span in spans(in: text, words: words) {
            guard let lower = AttributedString.Index(span.range.lowerBound, within: attributed),
                  let upper = AttributedString.Index(span.range.upperBound, within: attributed) else {
                continue
            }
            attributed[lower..<upper].foregroundColor = tint
            attributed[lower..<upper].font = boldFont
        }
        return attributed
    }
}

// MARK: - Self-test suite (IRC keyword emphasis)

enum I2PIRCKeywordEmphasisSelfTest {
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

        run("irc · a marked line emphasises every word it holds") {
            let text = "RELEASE both, i2pd and release again"
            let spans = I2PIRCKeywordEmphasis.spans(in: text, words: ["release", "i2pd"])
            guard spans.map({ String(text[$0.range]) }) == ["RELEASE", "i2pd", "release"],
                  spans.map(\.word) == ["release", "i2pd", "release"] else {
                throw I2PWireError.invalidFormat
            }
            // A word is emphasised once, however often the list spells it, and
            // a blank or a repeat leaves nothing behind.
            guard I2PIRCKeywordEmphasis.spans(in: text,
                                              words: ["release", "RELEASE", " release "]).count == 2,
                  I2PIRCKeywordEmphasis.normalized(["release", " RELEASE ", "", " i2pd"])
                    == ["release", "i2pd"] else {
                throw I2PWireError.invalidFormat
            }
            return "every switched-on word a line holds is emphasised, in reading order, with repeats and blanks dropped"
        }

        run("irc · the emphasis follows the whole-word rule the mark uses") {
            func emphasised(_ text: String, _ word: String) -> [String] {
                I2PIRCKeywordEmphasis.spans(in: text, words: [word])
                    .map { String(text[$0.range]) }
            }
            guard emphasised("released already", "release").isEmpty,
                  emphasised("prerelease notes", "release").isEmpty,
                  emphasised("release_notes", "release").isEmpty,
                  emphasised("release2", "release").isEmpty,
                  emphasised("a pre-release build", "release") == ["release"],
                  emphasised("(release)", "release") == ["release"],
                  emphasised("Release, now", "release") == ["Release"],
                  emphasised("v2.5 is out", "v2.5") == ["v2.5"] else {
                throw I2PWireError.invalidFormat
            }
            // The emphasis and the mark never disagree about a plain line.
            let corpus = ["the release is out", "released already", "a pre-release build",
                          "(release) now", "release2", "RELEASE!", "no words here",
                          "v2.5 is out"]
            for text in corpus {
                for word in ["release", "i2pd"] {
                    let emphasisedAny = !I2PIRCKeywordEmphasis.spans(in: text, words: [word]).isEmpty
                    guard emphasisedAny == I2PIRCKeywordRule.matches(text, keyword: word) else {
                        throw I2PWireError.invalidFormat
                    }
                }
            }
            return "an emphasis appears exactly where the whole-word rule marks a line, and nowhere else"
        }

        run("irc · a word inside a link or a nick is left as it is") {
            func emphasised(_ text: String) -> [String] {
                I2PIRCKeywordEmphasis.spans(in: text, words: ["release"])
                    .map { String(text[$0.range]) }
            }
            // A link carries its own colour and weight. The line is still
            // marked — the whole-word rule says it holds "release" — but the
            // address itself is left alone.
            guard emphasised("see https://stats.i2p/release for more").isEmpty,
                  I2PIRCKeywordRule.matches("see https://stats.i2p/release for more",
                                            keyword: "release"),
                  emphasised("read www.stats.i2p/release today").isEmpty,
                  // A nick is a name: "release-bot:" addresses somebody, so
                  // only the sentence after it keeps its emphasis.
                  emphasised("release-bot: the release is out") == ["release"],
                  emphasised("@release ping").isEmpty,
                  emphasised("release: look here").isEmpty,
                  // An ordinary hyphenated word is not a nick.
                  emphasised("a pre-release build") == ["release"] else {
                throw I2PWireError.invalidFormat
            }
            return "a word sitting inside a link or inside a nick is left as it is, while the line itself stays marked"
        }

        run("irc · the emphasis tints and emboldens the matched word in the line") {
            let tint = I2PIRCKeywordEmphasis.tint
            let bold = Font.callout.weight(.bold)
            let line = "the release is out"

            let marked = I2PIRCKeywordEmphasis.attributed(line,
                                                          words: ["release"],
                                                          tint: tint,
                                                          boldFont: bold)
            guard String(marked.characters) == line else { throw I2PWireError.invalidFormat }
            var tinted: [String] = []
            var bolded: [String] = []
            for run in marked.runs {
                let piece = String(marked[run.range].characters)
                if marked[run.range].foregroundColor == tint { tinted.append(piece) }
                if marked[run.range].font == bold { bolded.append(piece) }
            }
            guard tinted == ["release"], bolded == ["release"] else {
                throw I2PWireError.invalidFormat
            }

            // A line no word marks is handed back exactly as it arrived.
            let plain = I2PIRCKeywordEmphasis.attributed(line,
                                                         words: [],
                                                         tint: tint,
                                                         boldFont: bold)
            guard plain.runs.allSatisfy({ plain[$0.range].foregroundColor == nil }) else {
                throw I2PWireError.invalidFormat
            }
            return "the matched characters alone wear the edge's blue and a bolder weight, and an unmarked line is untouched"
        }

        run("irc · only a line that holds a switched-on word is touched") {
            let suite = "i2p.irc.keywordEmphasis.selfTest"
            let defaults = UserDefaults(suiteName: suite) ?? .standard
            defaults.removePersistentDomain(forName: suite)

            var state = I2PIRCChatState(serverName: "irc.example.i2p", nick: "tester")
            let book = I2PIRCKeywordBook(defaults: defaults, storageKey: "keywords")
            guard book.add("release"), book.add("i2pd") else {
                throw I2PWireError.invalidFormat
            }
            state.setKeywords(book.enabledWords)
            for raw in [":tester!t@c JOIN #i2p",
                        ":alice!a@h JOIN #i2p",
                        ":alice!a@h PRIVMSG #i2p :the release is out",
                        ":bob!b@h PRIVMSG #i2p :nothing here"] {
                guard let line = I2PIRCLine.parse(raw) else { throw I2PWireError.invalidFormat }
                state.apply(line)
            }
            let channel = try unwrap(state.conversation("#i2p"))
            let markedLine = try unwrap(channel.messages.first(where: { $0.text == "the release is out" }))
            let quietLine = try unwrap(channel.messages.first(where: { $0.text == "nothing here" }))
            guard !I2PIRCKeywordEmphasis.spans(in: markedLine.text,
                                               words: markedLine.keywordHits).isEmpty,
                  I2PIRCKeywordEmphasis.spans(in: quietLine.text,
                                              words: quietLine.keywordHits).isEmpty else {
                throw I2PWireError.invalidFormat
            }

            // Reading the conversation takes the marks away, and the emphasis
            // goes with them.
            state.markKeywordsRead("#i2p")
            let readLine = try unwrap(state.conversation("#i2p")?.messages.first(where: {
                $0.text == "the release is out"
            }))
            guard readLine.keywordHits.isEmpty,
                  I2PIRCKeywordEmphasis.spans(in: readLine.text,
                                              words: readLine.keywordHits).isEmpty else {
                throw I2PWireError.invalidFormat
            }

            // A paused highlight marks nothing: the list comes back empty, so
            // no line is touched however long the pause runs.
            book.pause(for: .quarterHour)
            guard book.enabledWords.isEmpty,
                  I2PIRCKeywordEmphasis.spans(in: markedLine.text,
                                              words: book.enabledWords).isEmpty else {
                throw I2PWireError.invalidFormat
            }
            book.resume()
            defaults.removePersistentDomain(forName: suite)
            return "a line holding a switched-on word is touched, an unmarked line is not, and reading it or pausing the highlight marks nothing"
        }

        return results
    }

    private static func unwrap<T>(_ value: T?) throws -> T {
        guard let value else { throw I2PWireError.invalidFormat }
        return value
    }
}
