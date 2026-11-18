//
//  I2PEepsiteFind.swift
//  Find in page for the eepsite browser: the query, every place it appears in
//  the rendered reader blocks, and the tints the reader draws over them. One
//  state serves a live page and a kept copy alike — both are reader blocks.
//

import Foundation
import SwiftUI

// MARK: - Match

/// One match: the rendered block it sits in and the character range it covers
/// in that block's plain text.
struct I2PEepsiteFindMatch: Equatable {
    /// Index of the block inside the page's reader blocks.
    let block: Int
    /// The match's first character, counted from the block's start.
    let start: Int
    /// How many characters the match covers.
    let length: Int

    var end: Int { start + length }
}

/// A request to bring a block on screen. The token changes with every request,
/// so stepping to a block that is already the current one scrolls again.
struct I2PEepsiteFindScroll: Equatable {
    let token: Int
    let block: Int
}

// MARK: - Search state

/// The find bar's state: what is being looked for, every place it was found,
/// and which of them is being stepped to.
struct I2PEepsiteFind: Equatable {
    /// Matches kept per search, so a query that hits everything stays bounded.
    static let matchLimit = 1_000

    /// The query as it was searched: trimmed, empty when nothing is searched.
    private(set) var query = ""
    private(set) var matches: [I2PEepsiteFindMatch] = []
    /// Position in `matches`; -1 when the search found nothing.
    private(set) var current = -1

    var isSearching: Bool { !query.isEmpty }
    var isEmpty: Bool { matches.isEmpty }
    var count: Int { matches.count }

    var currentMatch: I2PEepsiteFindMatch? {
        matches.indices.contains(current) ? matches[current] : nil
    }

    /// The bar's report — "3 of 12 matches" — and its two empty forms.
    var summary: String {
        guard isSearching else { return "Find in page" }
        guard !matches.isEmpty else { return "No matches" }
        if matches.count == 1 { return "1 match" }
        return "\(current + 1) of \(matches.count) matches"
    }

    /// Searches the blocks for a new query, starting again at the first match.
    /// A query with nothing in it but spaces clears the search.
    mutating func search(_ text: String, in blocks: [I2PReadBlock]) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            clear()
            return
        }
        query = trimmed
        matches = Self.matches(of: trimmed, in: blocks)
        current = matches.isEmpty ? -1 : 0
    }

    /// Empties the search and its highlights with it.
    mutating func clear() {
        query = ""
        matches = []
        current = -1
    }

    /// Steps to the next match, wrapping around at the end of the page.
    mutating func next() {
        guard !matches.isEmpty else { return }
        current = (current + 1) % matches.count
    }

    /// Steps to the previous match, wrapping around at the start of the page.
    mutating func previous() {
        guard !matches.isEmpty else { return }
        current = (current - 1 + matches.count) % matches.count
    }

    // MARK: Matching

    /// Every match of the query inside the blocks, in reading order.
    static func matches(of query: String, in blocks: [I2PReadBlock]) -> [I2PEepsiteFindMatch] {
        guard !query.isEmpty else { return [] }
        var found: [I2PEepsiteFindMatch] = []
        for (index, block) in blocks.enumerated() {
            for (start, length) in spans(of: query, in: block.plainText) {
                found.append(I2PEepsiteFindMatch(block: index, start: start, length: length))
                if found.count >= matchLimit { return found }
            }
        }
        return found
    }

    /// The character spans at which the query appears in the text — matched
    /// case-insensitively, and never overlapping each other.
    static func spans(of query: String, in text: String) -> [(start: Int, length: Int)] {
        guard !query.isEmpty, !text.isEmpty else { return [] }
        var spans: [(start: Int, length: Int)] = []
        var searchStart = text.startIndex
        while searchStart < text.endIndex,
              let range = text.range(of: query,
                                     options: [.caseInsensitive],
                                     range: searchStart..<text.endIndex) {
            let start = text.distance(from: text.startIndex, to: range.lowerBound)
            let length = text.distance(from: range.lowerBound, to: range.upperBound)
            if length > 0 { spans.append((start, length)) }
            guard range.upperBound > searchStart else { break }
            searchStart = range.upperBound
        }
        return spans
    }

    /// The character offsets alone, the form the self-test compares against.
    static func offsets(of query: String, in text: String) -> [Int] {
        spans(of: query, in: text).map(\.start)
    }
}

// MARK: - Highlighting

/// The tints drawn over the matches of a reader block.
enum I2PEepsiteFindHighlight {
    /// Every match, and the one being stepped to, over the browser's violet.
    static let matchTint = Color(red: 0.47, green: 0.44, blue: 0.97).opacity(0.26)
    static let currentTint = Color(red: 0.47, green: 0.44, blue: 0.97).opacity(0.62)

    /// The block's own attributed text with every match tinted, so links and
    /// the reader's typography stay exactly as they were.
    static func highlight(_ block: I2PReadBlock,
                          matches: [I2PEepsiteFindMatch],
                          current: I2PEepsiteFindMatch?) -> AttributedString {
        guard !matches.isEmpty else { return block.text }
        var text = block.text
        for match in matches {
            // Each range is taken from the string as it stands, so no index
            // outlives the attribute change the previous match made.
            guard let range = characterRange(of: match, in: text) else { continue }
            text[range].backgroundColor = match == current ? currentTint : matchTint
        }
        return text
    }

    private static func characterRange(of match: I2PEepsiteFindMatch,
                                       in text: AttributedString) -> Range<AttributedString.Index>? {
        guard match.start >= 0, match.length > 0 else { return nil }
        let characters = text.characters
        guard let start = characters.index(characters.startIndex,
                                           offsetBy: match.start,
                                           limitedBy: characters.endIndex),
              let end = characters.index(start,
                                         offsetBy: match.length,
                                         limitedBy: characters.endIndex) else {
            return nil
        }
        return start..<end
    }
}

// MARK: - Self-test suite (find in page)

enum I2PEepsiteFindSelfTest {
    static func runAll() -> [I2PSelfTestResult] {
        var results: [I2PSelfTestResult] = []
        func run(_ name: String, _ body: () throws -> String) {
            do {
                let detail = try body()
                results.append(I2PSelfTestResult(name: name, passed: true, detail: detail))
            } catch {
                results.append(I2PSelfTestResult(name: name, passed: false,
                                                 detail: String(describing: error)))
            }
        }

        run("find in page · matches case-insensitively across blocks and steps through them") {
            let blocks = [
                block(.title, "I2P Wiki"),
                block(.paragraph, "Read about I2P and the i2p network."),
                block(.code, "i2p"),
                I2PReadBlock(kind: .rule, text: AttributedString(), plainText: ""),
                block(.paragraph, "Nothing here")
            ]

            // An empty bar searches for nothing and reports the placeholder.
            var find = I2PEepsiteFind()
            guard !find.isSearching, find.count == 0, find.currentMatch == nil,
                  find.summary == "Find in page" else {
                throw I2PWireError.invalidFormat
            }

            // A query finds every occurrence — the lower-case ones too — in
            // reading order, and starts on the first.
            find.search("i2p", in: blocks)
            guard find.isSearching, find.query == "i2p", find.count == 4,
                  find.matches == [
                    I2PEepsiteFindMatch(block: 0, start: 0, length: 3),
                    I2PEepsiteFindMatch(block: 1, start: 11, length: 3),
                    I2PEepsiteFindMatch(block: 1, start: 23, length: 3),
                    I2PEepsiteFindMatch(block: 2, start: 0, length: 3)
                  ],
                  find.currentMatch == I2PEepsiteFindMatch(block: 0, start: 0, length: 3),
                  find.summary == "1 of 4 matches" else {
                throw I2PWireError.invalidFormat
            }

            // Next walks the matches and wraps past the last one.
            find.next()
            guard find.summary == "2 of 4 matches",
                  find.currentMatch == I2PEepsiteFindMatch(block: 1, start: 11, length: 3) else {
                throw I2PWireError.invalidFormat
            }
            find.next()
            find.next()
            guard find.summary == "4 of 4 matches",
                  find.currentMatch == I2PEepsiteFindMatch(block: 2, start: 0, length: 3) else {
                throw I2PWireError.invalidFormat
            }
            find.next()
            guard find.summary == "1 of 4 matches",
                  find.currentMatch == I2PEepsiteFindMatch(block: 0, start: 0, length: 3) else {
                throw I2PWireError.invalidFormat
            }
            // Previous wraps the other way.
            find.previous()
            guard find.summary == "4 of 4 matches" else { throw I2PWireError.invalidFormat }

            // The query is searched as typed but trimmed, and case does not
            // change what it finds.
            find.search("  I2P  ", in: blocks)
            guard find.query == "I2P", find.count == 4,
                  find.summary == "1 of 4 matches" else {
                throw I2PWireError.invalidFormat
            }

            // Nothing found still reports, and stepping does nothing.
            find.search("zzz", in: blocks)
            guard find.isSearching, find.isEmpty, find.currentMatch == nil,
                  find.summary == "No matches" else {
                throw I2PWireError.invalidFormat
            }
            find.next()
            find.previous()
            guard find.currentMatch == nil, find.summary == "No matches" else {
                throw I2PWireError.invalidFormat
            }

            // A single hit reads as itself.
            find.search("wiki", in: blocks)
            guard find.count == 1,
                  find.currentMatch == I2PEepsiteFindMatch(block: 0, start: 4, length: 4),
                  find.summary == "1 match" else {
                throw I2PWireError.invalidFormat
            }

            // An empty (or blank) bar clears the highlights.
            find.search("   ", in: blocks)
            guard !find.isSearching, find.query == "", find.count == 0,
                  find.currentMatch == nil, find.summary == "Find in page" else {
                throw I2PWireError.invalidFormat
            }
            find.search("", in: blocks)
            guard find.count == 0, find.query == "" else { throw I2PWireError.invalidFormat }

            // Matches never overlap, and a hit-heavy query stays bounded.
            guard I2PEepsiteFind.offsets(of: "aa", in: "aaaa") == [0, 2],
                  I2PEepsiteFind.offsets(of: "AA", in: "aaaa") == [0, 2],
                  I2PEepsiteFind.offsets(of: "a", in: "aaaa") == [0, 1, 2, 3],
                  I2PEepsiteFind.offsets(of: "", in: "aaaa").isEmpty,
                  I2PEepsiteFind.offsets(of: "b", in: "aaaa").isEmpty else {
                throw I2PWireError.invalidFormat
            }
            let flood = String(repeating: "a", count: I2PEepsiteFind.matchLimit + 6)
            guard I2PEepsiteFind.matches(of: "a", in: [block(.paragraph, flood)]).count
                    == I2PEepsiteFind.matchLimit else {
                throw I2PWireError.invalidFormat
            }
            return "4 matches found case-insensitively in reading order; next and previous wrap; summary read '1 of 4 matches'; blank bar cleared the search; no hits read 'No matches'; one hit read '1 match'; matches never overlap and are capped"
        }

        run("find in page · every match is tinted and the current one stands out") {
            var paragraph = AttributedString("Read ")
            var linked = AttributedString("i2p")
            if let url = URL(string: "http://i2pwiki.i2p/") {
                linked.link = url
            }
            paragraph.append(linked)
            paragraph.append(AttributedString(" about i2p."))
            let block = I2PReadBlock(kind: .paragraph,
                                     text: paragraph,
                                     plainText: "Read i2p about i2p.")

            var find = I2PEepsiteFind()
            find.search("I2P", in: [block])
            guard find.count == 2,
                  find.matches[0] == I2PEepsiteFindMatch(block: 0, start: 5, length: 3),
                  find.matches[1] == I2PEepsiteFindMatch(block: 0, start: 15, length: 3) else {
                throw I2PWireError.invalidFormat
            }
            // Step to the second match, so the two tints are told apart.
            find.next()
            guard find.currentMatch == find.matches[1] else { throw I2PWireError.invalidFormat }

            let highlighted = I2PEepsiteFindHighlight.highlight(block,
                                                                matches: find.matches,
                                                                current: find.currentMatch)
            var tintedText: [String] = []
            var tintedColors: [Color] = []
            var linkText: String?
            var linkURL: String?
            for run in highlighted.runs {
                let text = highlighted[run.range].characters
                    .reduce(into: String()) { $0.append($1) }
                if let tint = highlighted[run.range].backgroundColor {
                    tintedText.append(text)
                    tintedColors.append(tint)
                }
                if let link = run.link {
                    linkText = text
                    linkURL = link.absoluteString
                }
            }
            guard tintedText == ["i2p", "i2p"],
                  tintedColors == [I2PEepsiteFindHighlight.matchTint,
                                   I2PEepsiteFindHighlight.currentTint],
                  I2PEepsiteFindHighlight.matchTint != I2PEepsiteFindHighlight.currentTint,
                  linkText == "i2p",
                  linkURL == "http://i2pwiki.i2p/" else {
                throw I2PWireError.invalidFormat
            }

            // No matches means the block exactly as the reader had it.
            let plain = I2PEepsiteFindHighlight.highlight(block, matches: [], current: nil)
            let plainText = plain.characters.reduce(into: String()) { $0.append($1) }
            guard plainText == block.plainText,
                  plain.runs.allSatisfy({ plain[$0.range].backgroundColor == nil }) else {
                throw I2PWireError.invalidFormat
            }

            // A stray match outside the block's text is skipped, not a crash.
            let stray = I2PEepsiteFindHighlight.highlight(
                block,
                matches: [I2PEepsiteFindMatch(block: 0, start: 90, length: 3)],
                current: nil)
            let strayText = stray.characters.reduce(into: String()) { $0.append($1) }
            guard strayText == block.plainText,
                  stray.runs.allSatisfy({ stray[$0.range].backgroundColor == nil }) else {
                throw I2PWireError.invalidFormat
            }

            // The current match's tint is the one the reader draws brightest.
            let currentOnly = I2PEepsiteFindHighlight.highlight(block,
                                                                matches: [find.matches[1]],
                                                                current: find.matches[1])
            var currentTints: [Color] = []
            for run in currentOnly.runs {
                if let tint = currentOnly[run.range].backgroundColor {
                    currentTints.append(tint)
                }
            }
            guard currentTints == [I2PEepsiteFindHighlight.currentTint] else {
                throw I2PWireError.invalidFormat
            }
            return "both matches tinted in place, the stepped-to one brighter; the link kept its address through highlighting; no matches and an out-of-range match left the block untouched"
        }

        return results
    }

    // MARK: Helpers

    private static func block(_ kind: I2PReadBlock.Kind, _ text: String) -> I2PReadBlock {
        I2PReadBlock(kind: kind, text: AttributedString(text), plainText: text)
    }
}
