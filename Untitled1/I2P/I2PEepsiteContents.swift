//
//  I2PEepsiteContents.swift
//  The eepsite browser's contents sheet: the headings of the page on screen in
//  document order, sub-headings nested under the parent they belong to, and the
//  jump that scrolls one of them into view. One outline serves a live page and a
//  kept copy alike — both are reader blocks.
//

import Foundation
import SwiftUI

// MARK: - Entry

/// One line of the outline: a heading block of the page and where it sits.
struct I2PEepsiteContentsEntry: Identifiable, Equatable {
    /// Index of the heading's block in the page's reader blocks — what the
    /// reader scrolls to when the line is tapped.
    let block: Int
    /// The heading's own text, trimmed.
    let title: String
    /// 1 for a top-level heading, 2 for a sub-heading under it, 3 for anything
    /// deeper. The sheet indents each step.
    let depth: Int
    /// The heading's number among the top-level headings; nil for a sub-heading,
    /// which belongs to the numbered heading above it.
    let number: Int?

    var id: Int { block }
    var isSubHeading: Bool { depth > 1 }
}

/// A request to bring a heading's block on screen. The token changes with every
/// jump, so tapping the same heading twice scrolls again.
struct I2PEepsiteContentsJump: Equatable {
    let token: Int
    let block: Int
}

// MARK: - Outline

/// A page's headings, ready for the contents sheet.
struct I2PEepsiteContents: Equatable {
    /// Headings kept per outline, so a pathological page stays bounded.
    static let entryLimit = 200
    /// How deep the sheet indents: the deepest step is the last one drawn.
    static let maxDepth = 3

    private(set) var entries: [I2PEepsiteContentsEntry] = []

    var isEmpty: Bool { entries.isEmpty }
    var count: Int { entries.count }

    /// The contents control and its sheet exist from two headings on: a page
    /// with none, or with one, has nothing to jump between. The page's own
    /// title (`<h1>`, drawn as the reader's title block) is not a heading here —
    /// it heads the page rather than dividing it.
    var isAvailable: Bool { entries.count >= 2 }

    /// The sheet's count line: "6 headings", "1 heading", "No headings".
    var countText: String {
        switch entries.count {
        case 0: return "No headings"
        case 1: return "1 heading"
        default: return "\(entries.count) headings"
        }
    }

    /// Reads a page's reader blocks into an outline. Headings keep their
    /// document order; the shallowest heading level on the page is the
    /// top-level one, so every deeper level nests under it — a wiki page whose
    /// sections are `<h2>` with `<h3>` subsections outlines the sections as
    /// numbers and the subsections indented beneath them. Headings holding no
    /// text (an image alone, say) have nothing to list and are skipped.
    static func outline(_ blocks: [I2PReadBlock]) -> I2PEepsiteContents {
        var headings: [(block: Int, level: Int, title: String)] = []
        for (index, block) in blocks.enumerated() {
            guard case .heading(let level) = block.kind else { continue }
            let title = block.plainText.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !title.isEmpty else { continue }
            headings.append((index, level, title))
            if headings.count >= entryLimit { break }
        }
        guard let top = headings.map(\.level).min() else { return I2PEepsiteContents() }

        var outline = I2PEepsiteContents()
        var number = 0
        for heading in headings {
            let depth = min(max(heading.level - top + 1, 1), maxDepth)
            if depth == 1 { number += 1 }
            outline.entries.append(
                I2PEepsiteContentsEntry(block: heading.block,
                                        title: heading.title,
                                        depth: depth,
                                        number: depth == 1 ? number : nil))
        }
        return outline
    }
}

// MARK: - Sheet

/// The contents sheet: the page's address, how many headings it holds, the
/// outline itself, and a Close control. Tapping a line hands the heading back
/// to the browser, which scrolls to it and closes the sheet.
struct I2PEepsiteContentsSheet: View {
    let address: String
    let contents: I2PEepsiteContents
    let onSelect: (I2PEepsiteContentsEntry) -> Void
    let onClose: () -> Void

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                header
                outlineCard
            }
            .padding(.horizontal, 16)
            .padding(.top, 20)
            .padding(.bottom, 24)
        }
        .background(background.ignoresSafeArea())
        .preferredColorScheme(.dark)
    }

    // MARK: Header

    private var header: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline, spacing: 12) {
                Text("Contents")
                    .font(.title.bold())
                    .foregroundStyle(.primary)
                Spacer(minLength: 8)
                Button(action: onClose) {
                    Text("Close")
                        .font(.headline)
                        .foregroundStyle(accent)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Close contents")
            }
            if !address.isEmpty {
                Text(address)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Text(contents.countText)
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    // MARK: Outline

    private var outlineCard: some View {
        VStack(spacing: 0) {
            ForEach(contents.entries) { entry in
                row(entry)
                if entry.id != contents.entries.last?.id {
                    Rectangle()
                        .fill(Color.white.opacity(0.07))
                        .frame(height: 1)
                        .padding(.leading, entry.isSubHeading ? 54 : 34)
                }
            }
            Rectangle()
                .fill(Color.white.opacity(0.07))
                .frame(height: 1)
            Text("Headings from the page on screen. Tapping one scrolls to it.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 16)
                .padding(.vertical, 14)
        }
        .background(Color.white.opacity(0.05), in: RoundedRectangle(cornerRadius: 22))
        .overlay(
            RoundedRectangle(cornerRadius: 22)
                .strokeBorder(Color.white.opacity(0.10), lineWidth: 1)
        )
    }

    private func row(_ entry: I2PEepsiteContentsEntry) -> some View {
        let titleFont: Font = entry.isSubHeading ? .subheadline.weight(.semibold) : .headline
        return Button {
            onSelect(entry)
        } label: {
            HStack(spacing: 12) {
                marker(entry)
                Text(entry.title)
                    .font(titleFont)
                    .foregroundStyle(entry.isSubHeading ? Color.primary.opacity(0.92) : Color.primary)
                    .multilineTextAlignment(.leading)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 8)
                Image(systemName: "chevron.right")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.tertiary)
            }
            .padding(.horizontal, 16)
            .padding(.leading, CGFloat(entry.depth - 1) * 20)
            .padding(.vertical, 14)
            .frame(minHeight: 44)
            .frame(maxWidth: .infinity, alignment: .leading)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(entry.isSubHeading
                            ? "Sub-heading, \(entry.title)"
                            : "Heading \(entry.number ?? 0), \(entry.title)")
        .accessibilityHint("Scrolls this heading into view")
    }

    /// A top-level heading's number, or the violet bar that stands for a
    /// sub-heading in its parent's place.
    @ViewBuilder
    private func marker(_ entry: I2PEepsiteContentsEntry) -> some View {
        if let number = entry.number {
            Text("\(number)")
                .font(.system(.body, design: .rounded).weight(.semibold))
                .foregroundStyle(.secondary)
                .frame(width: 22, alignment: .leading)
        } else {
            RoundedRectangle(cornerRadius: 2)
                .fill(accent)
                .frame(width: 4, height: 26)
                .frame(width: 22, alignment: .leading)
        }
    }
}

// MARK: - Self-test suite (page contents)

enum I2PEepsiteContentsSelfTest {
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

        run("page contents · headings list in document order with sub-headings nested under their parents") {
            let blocks: [I2PReadBlock] = [
                block(.title, "Main Page"),
                block(.paragraph, "Welcome to the wiki."),
                block(.heading(2), "Introduction"),
                block(.paragraph, "Text about the network."),
                block(.heading(2), "Network database"),
                block(.heading(3), "Floodfill routers"),
                block(.heading(3), "Lease sets"),
                block(.heading(4), "Tunnel pools"),
                block(.heading(2), "Troubleshooting")
            ]

            let contents = I2PEepsiteContents.outline(blocks)
            // Six headings: the page's own title is not one of them, and the
            // paragraphs around them are not either.
            guard contents.count == 6,
                  contents.isAvailable,
                  contents.countText == "6 headings" else {
                throw I2PWireError.invalidFormat
            }
            guard contents.entries.map(\.title)
                    == ["Introduction", "Network database", "Floodfill routers",
                        "Lease sets", "Tunnel pools", "Troubleshooting"] else {
                throw I2PWireError.invalidFormat
            }
            // The blocks are the indices the reader scrolls to, and every line
            // points at its own heading block, in document order.
            guard contents.entries.map(\.block) == [2, 4, 5, 6, 7, 8],
                  contents.entries.map(\.id) == [2, 4, 5, 6, 7, 8],
                  Set(contents.entries.map(\.id)).count == contents.count else {
                throw I2PWireError.invalidFormat
            }
            // The shallowest level numbers 1, 2, 3; the deeper ones carry no
            // number and indent one step per level, capped at the deepest step.
            guard contents.entries.map(\.number) == [1, 2, nil, nil, nil, 3],
                  contents.entries.map(\.depth) == [1, 1, 2, 2, 3, 1],
                  contents.entries.map(\.isSubHeading)
                    == [false, false, true, true, true, false] else {
                throw I2PWireError.invalidFormat
            }
            return "6 headings in document order; the h1 title and the paragraphs left out; top-level headings numbered 1-3 and the h3/h4 sub-headings unnumbered at increasing depth; each line names its own block index"
        }

        run("page contents · fewer than two headings leaves the outline unavailable, and odd pages still read") {
            // Nothing on the page: no outline, and the control stays disabled.
            let empty = I2PEepsiteContents.outline([])
            guard empty.isEmpty, empty.count == 0, !empty.isAvailable,
                  empty.countText == "No headings" else {
                throw I2PWireError.invalidFormat
            }
            // Body text alone holds no headings.
            let prose = I2PEepsiteContents.outline([
                block(.title, "Main Page"),
                block(.paragraph, "Just words."),
                I2PReadBlock(kind: .rule, text: AttributedString(), plainText: "")
            ])
            guard prose.isEmpty, !prose.isAvailable else { throw I2PWireError.invalidFormat }
            // One heading is not a set to jump between.
            let single = I2PEepsiteContents.outline([block(.heading(2), "Introduction")])
            guard single.count == 1, !single.isAvailable,
                  single.countText == "1 heading",
                  single.entries[0].number == 1,
                  single.entries[0].depth == 1 else {
                throw I2PWireError.invalidFormat
            }
            // Two headings enable the control.
            let pair = I2PEepsiteContents.outline([
                block(.heading(2), "One"),
                block(.heading(2), "Two")
            ])
            guard pair.isAvailable, pair.countText == "2 headings",
                  pair.entries.map(\.number) == [1, 2] else {
                throw I2PWireError.invalidFormat
            }

            // A heading holding only whitespace has nothing to list.
            guard I2PEepsiteContents.outline([
                block(.heading(2), "   "),
                block(.heading(3), ""),
                block(.heading(2), "\n\t")
            ]).isEmpty else {
                throw I2PWireError.invalidFormat
            }

            // Titles are trimmed, so a padded heading reads cleanly.
            let padded = I2PEepsiteContents.outline([
                block(.heading(2), "  Introduction \n"),
                block(.heading(2), "Troubleshooting")
            ])
            guard padded.entries.map(\.title) == ["Introduction", "Troubleshooting"] else {
                throw I2PWireError.invalidFormat
            }

            // A page whose headings are all one level numbers them all: the
            // shallowest level on the page is the top-level one.
            let flat = I2PEepsiteContents.outline([
                block(.heading(3), "Alpha"),
                block(.heading(3), "Beta")
            ])
            guard flat.entries.map(\.number) == [1, 2],
                  flat.entries.map(\.depth) == [1, 1] else {
                throw I2PWireError.invalidFormat
            }

            // A sub-heading that arrives before its parent indents without a
            // number, and the parent still takes the first number.
            let stray = I2PEepsiteContents.outline([
                block(.heading(3), "Early child"),
                block(.heading(2), "Parent"),
                block(.heading(6), "Deepest")
            ])
            guard stray.entries.map(\.title) == ["Early child", "Parent", "Deepest"],
                  stray.entries.map(\.number) == [nil, 1, nil],
                  stray.entries.map(\.depth) == [2, 1, 3] else {
                throw I2PWireError.invalidFormat
            }

            // A heading-heavy page is capped, so the sheet stays bounded.
            let flood = (0..<(I2PEepsiteContents.entryLimit + 25)).map {
                block(.heading(2), "Heading \($0)")
            }
            let capped = I2PEepsiteContents.outline(flood)
            guard capped.count == I2PEepsiteContents.entryLimit,
                  capped.entries.last?.title
                    == "Heading \(I2PEepsiteContents.entryLimit - 1)" else {
                throw I2PWireError.invalidFormat
            }
            return "no headings reads 'No headings' and stays unavailable; one reads '1 heading' and stays unavailable; two enable the control; blank headings are skipped, titles trimmed, an all-one-level page numbered flat, a child before its parent left unnumbered, and a heading-heavy page capped"
        }

        return results
    }

    // MARK: Helpers

    private static func block(_ kind: I2PReadBlock.Kind, _ text: String) -> I2PReadBlock {
        I2PReadBlock(kind: kind, text: AttributedString(text), plainText: text)
    }
}
