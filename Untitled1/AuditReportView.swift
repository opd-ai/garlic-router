//
//  AuditReportView.swift
//  Untitled1
//
//  Reader for the bundled end-to-end audit report (AUDIT-2026-11-17.md).
//  Opened from the Alignment tab, next to the truth table it assesses.
//
//  The report is a long Markdown document, so it is rendered block by block
//  (headings, paragraphs, bullets, tables, fenced code) rather than as one
//  AttributedString — SwiftUI's Markdown support drops table layout entirely,
//  and every deliverable in the report is either a table or a command block.
//

import SwiftUI

// MARK: - Report metadata

/// Facts about the bundled report the Alignment tab shows before the document
/// itself is opened. Kept here so the card and the reader cannot disagree.
enum I2PAuditReport {
    static let resourceName = "AUDIT-2026-11-17"
    static let title = "Defensive end-to-end audit"
    static let date = "2026-11-17"
    static let highSeverity = 1
    static let mediumSeverity = 6
    static let lowSeverity = 3

    /// The one sentence the report asks a reader to carry away.
    static let headline = """
        Wire-format interoperability with Java I2P and i2pd remains unverified — \
        no authorised test environment was supplied, so the report makes no \
        interoperability claim.
        """

    /// Loads the bundled Markdown. Returns nil when the resource is missing,
    /// which the reader surfaces instead of pretending the report is empty.
    static func markdown() -> String? {
        for url in candidateURLs() {
            if let text = try? String(contentsOf: url, encoding: .utf8) {
                return text
            }
        }
        return nil
    }

    private static func candidateURLs() -> [URL] {
        var urls: [URL] = []
        if let root = Bundle.main.url(forResource: resourceName, withExtension: "md") {
            urls.append(root)
        }
        if let nested = Bundle.main.url(forResource: resourceName, withExtension: "md",
                                        subdirectory: "Resources") {
            urls.append(nested)
        }
        return urls
    }
}

// MARK: - Block model

enum I2PAuditBlock {
    case heading(level: Int, text: String)
    case paragraph(String)
    case bullet(text: String, depth: Int)
    case numbered(marker: String, text: String)
    case code([String])
    case table(header: [String]?, rows: [[String]])
    case rule
}

// MARK: - Markdown parsing

enum I2PAuditMarkdown {
    static func blocks(from markdown: String) -> [I2PAuditBlock] {
        var blocks: [I2PAuditBlock] = []
        let lines = markdown.components(separatedBy: "\n")
        var index = 0
        var paragraph: [String] = []

        func flushParagraph() {
            guard !paragraph.isEmpty else { return }
            blocks.append(.paragraph(paragraph.joined(separator: " ")))
            paragraph.removeAll()
        }

        while index < lines.count {
            let raw = lines[index]
            let line = raw.trimmingCharacters(in: .whitespaces)

            // Fenced code — consume verbatim, so '#' and '|' inside stay literal.
            if line.hasPrefix("```") {
                flushParagraph()
                index += 1
                var code: [String] = []
                while index < lines.count,
                      !lines[index].trimmingCharacters(in: .whitespaces).hasPrefix("```") {
                    code.append(lines[index])
                    index += 1
                }
                if index < lines.count { index += 1 }
                blocks.append(.code(code))
                continue
            }

            if line.isEmpty {
                flushParagraph()
                index += 1
                continue
            }

            if line == "---" || line == "***" {
                flushParagraph()
                blocks.append(.rule)
                index += 1
                continue
            }

            if line.hasPrefix("#") {
                flushParagraph()
                let level = line.prefix(while: { $0 == "#" }).count
                let text = line.drop(while: { $0 == "#" })
                    .trimmingCharacters(in: .whitespaces)
                blocks.append(.heading(level: min(max(level, 1), 4), text: text))
                index += 1
                continue
            }

            if line.hasPrefix("|") {
                flushParagraph()
                var rows: [[String]] = []
                var header: [String]?
                var sawSeparator = false
                while index < lines.count,
                      lines[index].trimmingCharacters(in: .whitespaces).hasPrefix("|") {
                    let rowText = lines[index].trimmingCharacters(in: .whitespaces)
                    if isTableSeparator(rowText) {
                        // The separator directly after the first row promotes
                        // that row to the table's header.
                        if !sawSeparator, rows.count == 1 {
                            header = rows.removeLast()
                        }
                        sawSeparator = true
                        index += 1
                        continue
                    }
                    rows.append(tableCells(rowText))
                    index += 1
                }
                if !rows.isEmpty {
                    blocks.append(.table(header: header, rows: rows))
                }
                continue
            }

            if let bullet = bulletText(line) {
                flushParagraph()
                let depth = max(0, (raw.prefix(while: { $0 == " " }).count) / 2)
                blocks.append(.bullet(text: bullet, depth: depth))
                index += 1
                continue
            }

            if let numbered = numberedText(line) {
                flushParagraph()
                blocks.append(.numbered(marker: numbered.marker, text: numbered.text))
                index += 1
                continue
            }

            paragraph.append(line)
            index += 1
        }

        flushParagraph()
        return blocks
    }

    private static func bulletText(_ line: String) -> String? {
        if line.hasPrefix("- ") { return String(line.dropFirst(2)) }
        if line.hasPrefix("* ") { return String(line.dropFirst(2)) }
        return nil
    }

    private static func numberedText(_ line: String) -> (marker: String, text: String)? {
        guard let dot = line.firstIndex(of: ".") else { return nil }
        let digits = line[line.startIndex..<dot]
        guard !digits.isEmpty, digits.count <= 3, digits.allSatisfy(\.isNumber) else { return nil }
        let after = line.index(after: dot)
        guard after < line.endIndex, line[after] == " " else { return nil }
        return (String(line[line.startIndex...dot]),
                String(line[line.index(after: after)...]))
    }

    private static func isTableSeparator(_ line: String) -> Bool {
        line.contains("-") && line.allSatisfy { "-:| ".contains($0) }
    }

    private static func tableCells(_ line: String) -> [String] {
        var body = line
        if body.hasPrefix("|") { body.removeFirst() }
        if body.hasSuffix("|") { body.removeLast() }
        return body.components(separatedBy: "|")
            .map { $0.trimmingCharacters(in: .whitespaces) }
    }
}

// MARK: - Reader

struct AuditReportView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var blocks: [I2PAuditBlock] = []
    @State private var didLoad = false

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)

    var body: some View {
        NavigationStack {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 14) {
                    headerCard
                    if blocks.isEmpty {
                        emptyState
                    } else {
                        ForEach(Array(blocks.enumerated()), id: \.offset) { _, block in
                            blockView(block)
                        }
                    }
                }
                .padding(.horizontal, 16)
                .padding(.top, 8)
                .padding(.bottom, 32)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .background(background.ignoresSafeArea())
            .navigationTitle("Audit report")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                        .tint(accent)
                }
            }
            .onAppear(perform: loadIfNeeded)
        }
        .preferredColorScheme(.dark)
    }

    private func loadIfNeeded() {
        guard !didLoad else { return }
        didLoad = true
        if let markdown = I2PAuditReport.markdown() {
            blocks = I2PAuditMarkdown.blocks(from: markdown)
        }
    }

    // MARK: Header

    private var headerCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(I2PAuditReport.title)
                .font(.title3.weight(.semibold))
            Text("garlic-router · \(I2PAuditReport.date)")
                .font(.caption)
                .foregroundStyle(.secondary)

            HStack(spacing: 8) {
                severityChip("high", count: I2PAuditReport.highSeverity, color: .red)
                severityChip("medium", count: I2PAuditReport.mediumSeverity, color: .orange)
                severityChip("low", count: I2PAuditReport.lowSeverity, color: .gray)
            }

            Text(I2PAuditReport.headline)
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    private func severityChip(_ label: String, count: Int, color: Color) -> some View {
        VStack(spacing: 2) {
            Text("\(count)")
                .font(.subheadline.weight(.bold))
                .foregroundStyle(color)
            Text(label)
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 8)
        .background(Color.white.opacity(0.05), in: RoundedRectangle(cornerRadius: 10))
    }

    private var emptyState: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Report not bundled", systemImage: "doc.questionmark")
                .font(.subheadline.weight(.semibold))
            Text("\(I2PAuditReport.resourceName).md is missing from this build. "
                 + "The document lives in the app folder; a rebuild that copies it "
                 + "into the bundle is needed to read it here.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    // MARK: Blocks

    @ViewBuilder
    private func blockView(_ block: I2PAuditBlock) -> some View {
        switch block {
        case .heading(let level, let text):
            Text(inline(text))
                .font(headingFont(level))
                .foregroundStyle(level <= 2 ? Color.primary : accent)
                .padding(.top, level <= 2 ? 10 : 4)
                .fixedSize(horizontal: false, vertical: true)

        case .paragraph(let text):
            Text(inline(text))
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

        case .bullet(let text, let depth):
            HStack(alignment: .top, spacing: 8) {
                Text("•")
                    .font(.footnote.weight(.bold))
                    .foregroundStyle(accent)
                Text(inline(text))
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(.leading, CGFloat(depth) * 14)

        case .numbered(let marker, let text):
            HStack(alignment: .top, spacing: 8) {
                Text(marker)
                    .font(.system(.footnote, design: .monospaced).weight(.semibold))
                    .foregroundStyle(accent)
                Text(inline(text))
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

        case .code(let lines):
            ScrollView(.horizontal, showsIndicators: false) {
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(Array(lines.enumerated()), id: \.offset) { _, line in
                        Text(line.isEmpty ? " " : line)
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundStyle(Color.white.opacity(0.75))
                    }
                }
                .padding(10)
            }
            .background(Color.black.opacity(0.35), in: RoundedRectangle(cornerRadius: 10))

        case .table(let header, let rows):
            VStack(alignment: .leading, spacing: 6) {
                if let header {
                    Text(header.joined(separator: " · ").uppercased())
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(.tertiary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                ForEach(Array(rows.enumerated()), id: \.offset) { _, row in
                    tableRow(row)
                }
            }

        case .rule:
            Rectangle()
                .fill(Color.white.opacity(0.12))
                .frame(height: 1)
                .padding(.vertical, 4)
        }
    }

    /// One table row. The first cell is the row's subject; the rest are its
    /// detail, so they step down in emphasis instead of competing for width.
    private func tableRow(_ cells: [String]) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            ForEach(Array(cells.enumerated()), id: \.offset) { index, cell in
                if !cell.isEmpty {
                    Text(inline(cell))
                        .font(index == 0 ? .footnote.weight(.semibold) : .caption2)
                        .foregroundStyle(index == 0 ? Color.primary : Color.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
        .background(Color.white.opacity(0.04), in: RoundedRectangle(cornerRadius: 10))
    }

    private func headingFont(_ level: Int) -> Font {
        switch level {
        case 1: return .title2.weight(.bold)
        case 2: return .headline
        case 3: return .subheadline.weight(.semibold)
        default: return .footnote.weight(.semibold)
        }
    }

    /// Inline Markdown (**bold**, `code`) for a single block's text.
    private func inline(_ text: String) -> AttributedString {
        (try? AttributedString(
            markdown: text,
            options: .init(interpretedSyntax: .inlineOnlyPreservingWhitespace)
        )) ?? AttributedString(text)
    }
}

#Preview {
    AuditReportView()
        .preferredColorScheme(.dark)
}
