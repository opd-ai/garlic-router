//
//  I2PHTMLReader.swift
//  A lightweight HTML → reader transformer for the eepsite browser: markup is
//  stripped into native typographic blocks (titles, headings, paragraphs,
//  bullets, quotes, code, rules) with inline links kept tappable, so a fetched
//  page renders with the app's own typography instead of a web view.
//

import Foundation
import SwiftUI

/// One typographic block of a fetched page.
struct I2PReadBlock: Identifiable {
    enum Kind: Equatable {
        case title
        case heading(Int)
        case paragraph
        case bullet
        case quote
        case code
        case rule
    }

    let id = UUID()
    let kind: Kind
    let text: AttributedString
    let plainText: String
}

/// The block being assembled from the HTML token stream.
private struct I2PPendingBlock {
    var kind: I2PReadBlock.Kind = .paragraph
    var runs: [(text: String, href: String?)] = []

    var plain: String { runs.map { $0.text }.joined() }
    var isEmpty: Bool { runs.allSatisfy { $0.text.trimmingCharacters(in: .whitespaces).isEmpty } }

    /// Appends text, collapsing whitespace outside `<pre>` and never letting a
    /// space open a block.
    mutating func append(_ text: String, href: String?, collapseWhitespace: Bool) {
        var value = text
        if collapseWhitespace {
            value = value.replacingOccurrences(of: "\\s+", with: " ",
                                               options: .regularExpression)
        }
        guard !value.isEmpty else { return }
        if collapseWhitespace, !runs.isEmpty,
           runs[runs.count - 1].text.hasSuffix(" "), value.hasPrefix(" ") {
            value.removeFirst()
        }
        guard !value.isEmpty else { return }
        runs.append((value, href))
    }

    mutating func appendBreak() {
        append("\n", href: nil, collapseWhitespace: false)
    }

    mutating func trimEdges() {
        guard !runs.isEmpty else { return }
        runs[0].text = String(runs[0].text.drop(while: { $0 == " " }))
        if let last = runs.indices.last {
            runs[last].text = String(runs[last].text.reversed().drop(while: { $0 == " " }).reversed())
        }
        runs.removeAll { $0.text.isEmpty }
    }

    func makeBlock(baseHost: String?) -> I2PReadBlock? {
        var pending = self
        pending.trimEdges()
        guard !pending.runs.isEmpty else { return nil }
        var attributed = AttributedString()
        for run in pending.runs {
            var piece = AttributedString(run.text)
            if let href = run.href,
               let url = I2PHTMLReader.linkURL(href, baseHost: baseHost) {
                piece.link = url
            }
            attributed.append(piece)
        }
        return I2PReadBlock(kind: pending.kind, text: attributed, plainText: pending.plain)
    }
}

/// A deliberately small HTML reader: enough structure to present an eepsite
/// page natively, without pretending to be a full renderer.
enum I2PHTMLReader {
    /// Blocks kept per page (bounds memory on huge documents).
    private static let blockLimit = 2_000

    private static let skipNames: Set<String> = [
        "script", "style", "noscript", "template", "svg", "head", "canvas", "iframe"
    ]

    private static let voidNames: Set<String> = [
        "br", "hr", "img", "meta", "link", "input", "source", "track", "wbr",
        "area", "base", "col", "embed", "param"
    ]

    static func parse(_ html: String, baseHost: String?) -> (title: String?, blocks: [I2PReadBlock]) {
        let cleaned = stripComments(html)
        let title = extractTitle(cleaned)
        var blocks: [I2PReadBlock] = []
        var pending = I2PPendingBlock()
        var inPre = false
        var linkHref: String?
        var skipDepth = 0

        func flush() {
            if blocks.count < blockLimit, let block = pending.makeBlock(baseHost: baseHost) {
                blocks.append(block)
            }
            pending = I2PPendingBlock()
        }

        for token in tokenize(cleaned) {
            guard token.isTag else {
                guard skipDepth == 0 else { continue }
                pending.append(decodeEntities(token.text),
                               href: linkHref,
                               collapseWhitespace: !inPre)
                continue
            }
            guard let tag = parseTag(token.text) else { continue }

            // Comments, doctypes and stray markup carry no text.
            if skipDepth > 0 {
                if !tag.isClosing {
                    if skipNames.contains(tag.name), !voidNames.contains(tag.name) {
                        skipDepth += 1
                    }
                } else if skipNames.contains(tag.name) {
                    skipDepth = max(0, skipDepth - 1)
                }
                continue
            }
            if skipNames.contains(tag.name), !tag.isClosing {
                if !voidNames.contains(tag.name) { skipDepth += 1 }
                continue
            }

            if tag.isClosing {
                switch tag.name {
                case "a":
                    linkHref = nil
                case "pre":
                    flush()
                    inPre = false
                case "p", "div", "section", "article", "header", "footer", "main",
                     "aside", "table", "tr", "ul", "ol", "blockquote",
                     "h1", "h2", "h3", "h4", "h5", "h6", "li", "figure", "figcaption":
                    flush()
                default:
                    break
                }
                continue
            }

            switch tag.name {
            case "h1", "h2", "h3", "h4", "h5", "h6":
                flush()
                let level = Int(String(tag.name.last ?? "2")) ?? 2
                pending.kind = level <= 1 ? .title : .heading(level)
            case "p", "div", "section", "article", "header", "footer", "main",
                 "aside", "table", "tr", "figure", "figcaption":
                flush()
                pending.kind = inPre ? .code : .paragraph
            case "ul", "ol":
                flush()
            case "li":
                flush()
                pending.kind = .bullet
            case "blockquote":
                flush()
                pending.kind = .quote
            case "pre":
                flush()
                inPre = true
                pending.kind = .code
            case "br":
                if inPre {
                    pending.appendBreak()
                } else {
                    pending.append(" ", href: nil, collapseWhitespace: true)
                }
            case "hr":
                flush()
                if blocks.count < blockLimit {
                    blocks.append(I2PReadBlock(kind: .rule,
                                               text: AttributedString(),
                                               plainText: ""))
                }
            case "a":
                linkHref = tag.attributes["href"]
            case "td", "th":
                if !pending.isEmpty {
                    pending.append(" · ", href: nil, collapseWhitespace: false)
                }
            case "img":
                if let alt = tag.attributes["alt"], !alt.isEmpty {
                    pending.append("[\(decodeEntities(alt))]", href: nil, collapseWhitespace: true)
                }
            default:
                break
            }
        }
        flush()
        return (title, blocks)
    }

    /// Turns a possibly relative href into an absolute `.i2p` URL the browser
    /// can load. Anchors, mail and script links are not navigable.
    static func linkURL(_ href: String, baseHost: String?) -> URL? {
        let trimmed = decodeEntities(href).trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              !trimmed.hasPrefix("#"),
              !trimmed.lowercased().hasPrefix("mailto:"),
              !trimmed.lowercased().hasPrefix("javascript:") else { return nil }
        let lowered = trimmed.lowercased()
        if lowered.hasPrefix("http://") || lowered.hasPrefix("https://") {
            return URL(string: trimmed)
        }
        guard let baseHost, !baseHost.isEmpty else { return nil }
        if trimmed.hasPrefix("/") {
            return URL(string: "http://\(baseHost)\(trimmed)")
        }
        return URL(string: "http://\(baseHost)/\(trimmed)")
    }

    // MARK: - Tokenizing

    private static func tokenize(_ html: String) -> [(isTag: Bool, text: String)] {
        var tokens: [(isTag: Bool, text: String)] = []
        var index = html.startIndex
        while index < html.endIndex {
            if html[index] == "<" {
                guard let end = html[index...].firstIndex(of: ">") else { break }
                tokens.append((true, String(html[index...end])))
                index = html.index(after: end)
            } else if let next = html[index...].firstIndex(of: "<") {
                tokens.append((false, String(html[index..<next])))
                index = next
            } else {
                tokens.append((false, String(html[index...])))
                break
            }
        }
        return tokens
    }

    private static func parseTag(_ raw: String) -> (name: String, isClosing: Bool,
                                                    attributes: [String: String])? {
        var body = raw.dropFirst() // drop "<"
        guard !body.isEmpty else { return nil }
        var isClosing = false
        if body.first == "/" {
            isClosing = true
            body = body.dropFirst()
        }
        while let first = body.first, first == " " || first == "\n" || first == "\t" || first == "\r" {
            body = body.dropFirst()
        }
        if body.last == "/" { body = body.dropLast() }

        var nameEnd = body.endIndex
        var index = body.startIndex
        while index < body.endIndex {
            let character = body[index]
            if character == " " || character == "\t" || character == "\n"
                || character == "\r" || character == "/" {
                nameEnd = index
                break
            }
            index = body.index(after: index)
        }
        let name = String(body[body.startIndex..<nameEnd]).lowercased()
        guard let first = name.first, first.isLetter else { return nil }

        var attributes: [String: String] = [:]
        var cursor = nameEnd
        while cursor < body.endIndex {
            while cursor < body.endIndex, isSeparator(body[cursor]) {
                cursor = body.index(after: cursor)
            }
            guard cursor < body.endIndex else { break }
            var attributeEnd = cursor
            while attributeEnd < body.endIndex,
                  !isSeparator(body[attributeEnd]),
                  body[attributeEnd] != "=" {
                attributeEnd = body.index(after: attributeEnd)
            }
            let attributeName = String(body[cursor..<attributeEnd]).lowercased()
            cursor = attributeEnd
            if attributeName.isEmpty {
                if cursor < body.endIndex { cursor = body.index(after: cursor) }
                continue
            }
            while cursor < body.endIndex, body[cursor] == " " {
                cursor = body.index(after: cursor)
            }
            guard cursor < body.endIndex, body[cursor] == "=" else {
                attributes[attributeName] = ""
                continue
            }
            cursor = body.index(after: cursor)
            while cursor < body.endIndex, body[cursor] == " " {
                cursor = body.index(after: cursor)
            }
            guard cursor < body.endIndex else {
                attributes[attributeName] = ""
                break
            }
            if body[cursor] == "\"" || body[cursor] == "'" {
                let quote = body[cursor]
                cursor = body.index(after: cursor)
                let start = cursor
                while cursor < body.endIndex, body[cursor] != quote {
                    cursor = body.index(after: cursor)
                }
                attributes[attributeName] = String(body[start..<cursor])
                if cursor < body.endIndex { cursor = body.index(after: cursor) }
            } else {
                let start = cursor
                while cursor < body.endIndex, !isSeparator(body[cursor]) {
                    cursor = body.index(after: cursor)
                }
                attributes[attributeName] = String(body[start..<cursor])
            }
        }
        return (name, isClosing, attributes)
    }

    private static func isSeparator(_ character: Character) -> Bool {
        character == " " || character == "\t" || character == "\n" || character == "\r"
    }

    // MARK: - Document helpers

    private static func stripComments(_ html: String) -> String {
        guard html.contains("<!--") else { return html }
        return html.replacingOccurrences(of: "<!--[\\s\\S]*?-->", with: "",
                                         options: .regularExpression)
    }

    private static func extractTitle(_ html: String) -> String? {
        guard let open = html.range(of: "<title", options: .caseInsensitive),
              let bodyStart = html[open.upperBound...].firstIndex(of: ">"),
              let close = html.range(of: "</title", options: .caseInsensitive,
                                     range: html.index(after: bodyStart)..<html.endIndex) else {
            return nil
        }
        let text = String(html[html.index(after: bodyStart)..<close.lowerBound])
        let decoded = decodeEntities(text).trimmingCharacters(in: .whitespacesAndNewlines)
        return decoded.isEmpty ? nil : decoded
    }

    // MARK: - Entities

    static func decodeEntities(_ text: String) -> String {
        guard text.contains("&") else { return text }
        var out = ""
        var index = text.startIndex
        while index < text.endIndex {
            let character = text[index]
            if character == "&",
               let semicolon = text[index...].firstIndex(of: ";"),
               text.distance(from: index, to: semicolon) <= 12 {
                let name = String(text[text.index(after: index)..<semicolon])
                if let decoded = entity(name) {
                    out += decoded
                    index = text.index(after: semicolon)
                    continue
                }
            }
            out.append(character)
            index = text.index(after: index)
        }
        return out
    }

    private static func entity(_ name: String) -> String? {
        switch name.lowercased() {
        case "amp": return "&"
        case "lt": return "<"
        case "gt": return ">"
        case "quot": return "\""
        case "apos": return "'"
        case "nbsp": return " "
        case "ndash": return "–"
        case "mdash": return "—"
        case "hellip": return "…"
        case "lsquo": return "‘"
        case "rsquo": return "’"
        case "ldquo": return "“"
        case "rdquo": return "”"
        case "laquo": return "«"
        case "raquo": return "»"
        case "copy": return "©"
        case "middot": return "·"
        case "bull": return "•"
        case "times": return "×"
        case "deg": return "°"
        default:
            guard name.hasPrefix("#") else { return nil }
            let body = String(name.dropFirst())
            let value: UInt32?
            if body.lowercased().hasPrefix("x") {
                value = UInt32(body.dropFirst(), radix: 16)
            } else {
                value = UInt32(body)
            }
            guard let value, let scalar = Unicode.Scalar(value) else { return nil }
            return String(Character(scalar))
        }
    }
}
