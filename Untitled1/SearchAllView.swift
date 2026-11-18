//
//  SearchAllView.swift
//  The Search all screen the chat's toolbar opens: one field that searches every
//  conversation of the connected server at once, a count under it, and the
//  matching lines grouped under the conversation they came from, newest first.
//  A tap hands the line back to the chat, which opens its conversation and
//  brings the line into view.
//

import SwiftUI

struct SearchAllView: View {
    @ObservedObject var model: I2PIRCChatModel
    /// What a tap on a row does: the chat opens the conversation the line came
    /// from and scrolls the line itself into view.
    var onOpen: (I2PIRCGlobalMatch) -> Void = { _ in }

    @Environment(\.dismiss) private var dismiss
    @State private var query = ""
    @FocusState private var fieldFocused: Bool

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)
    /// The tint every nick in the list wears, the same violet the transcript
    /// paints the people talking.
    private let nickViolet = Color(red: 0.68, green: 0.45, blue: 1.00)
    /// The tint a matched word wears inside a line, a shade cooler than the
    /// nick's violet so the match reads as the match and not as another voice.
    private let matchTint = Color(red: 0.45, green: 0.71, blue: 1.00)

    /// Every conversation's matching lines, grouped with the most recent group
    /// first. Empty while the field holds nothing.
    private var groups: [I2PIRCGlobalMatchGroup] {
        I2PIRCGlobalSearch.groups(in: model.state.orderedConversations, query: query)
    }

    private var totalMatches: Int {
        I2PIRCGlobalSearch.totalCount(of: groups)
    }

    private var isSearching: Bool {
        !I2PIRCGlobalSearch.normalized(query).isEmpty
    }

    private var serverName: String {
        model.state.serverName.isEmpty ? "the connected server" : model.state.serverName
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            searchField
            ScrollView {
                if !isSearching {
                    explanationCard
                } else if groups.isEmpty {
                    noMatchesCard
                } else {
                    LazyVStack(spacing: 12) {
                        ForEach(groups) { group in
                            groupCard(group)
                        }
                    }
                    .padding(.horizontal, 16)
                    .padding(.top, 2)
                    .padding(.bottom, 24)
                }
            }
            .scrollDismissesKeyboard(.interactively)
        }
        .background(background.ignoresSafeArea())
        .preferredColorScheme(.dark)
        .task {
            // A short beat, so the sheet is in place before the field takes
            // focus and the keyboard rises with it.
            try? await Task.sleep(for: .milliseconds(320))
            fieldFocused = true
        }
    }

    // MARK: - Header

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .firstTextBaseline, spacing: 12) {
                Text("Search all")
                    .font(.system(size: 32, weight: .bold))
                    .foregroundStyle(.primary)
                Spacer(minLength: 8)
                Button {
                    fieldFocused = false
                    dismiss()
                } label: {
                    Text("Done")
                        .font(.callout.weight(.semibold))
                        .foregroundStyle(accent)
                        .padding(.horizontal, 16)
                        .padding(.vertical, 7)
                        .background(accent.opacity(0.18), in: Capsule())
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Done")
            }
            Text("Every conversation of \(serverName).")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .lineLimit(2)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.horizontal, 20)
        .padding(.top, 20)
        .padding(.bottom, 14)
    }

    // MARK: - Field

    private var searchField: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 10) {
                Image(systemName: "magnifyingglass")
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(.secondary)
                TextField("Search every conversation", text: $query)
                    .font(.callout)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled(true)
                    .submitLabel(.search)
                    .focused($fieldFocused)
                if !query.isEmpty {
                    Button {
                        query = ""
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .font(.system(size: 16))
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("Clear the search")
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 14)
            .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
            .overlay(
                RoundedRectangle(cornerRadius: 18)
                    .strokeBorder(Color.white.opacity(0.07), lineWidth: 1)
            )

            if isSearching {
                Text(I2PIRCSearch.summary(count: totalMatches))
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(totalMatches == 0 ? Color.secondary : accent)
                    .padding(.leading, 4)
                    .accessibilityLabel(I2PIRCSearch.summary(count: totalMatches))
            }
        }
        .padding(.horizontal, 16)
        .padding(.bottom, 12)
    }

    // MARK: - List

    private func groupCard(_ group: I2PIRCGlobalMatchGroup) -> some View {
        VStack(spacing: 0) {
            Button {
                open(group.newest)
            } label: {
                HStack(spacing: 6) {
                    Text(group.label)
                        .font(.callout.weight(.semibold))
                        .foregroundStyle(.primary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Text("· \(group.count)")
                        .font(.callout.weight(.semibold))
                        .foregroundStyle(accent)
                    Spacer(minLength: 6)
                    Image(systemName: "chevron.right")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundStyle(.tertiary)
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .disabled(group.newest == nil)
            .accessibilityLabel("\(group.label), \(group.count) match\(group.count == 1 ? "" : "es")")
            .accessibilityHint("Opens the newest matching line")

            ForEach(group.matches) { match in
                VStack(spacing: 0) {
                    Rectangle()
                        .fill(Color.white.opacity(0.07))
                        .frame(height: 1)
                    Button {
                        open(match)
                    } label: {
                        row(match)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(accessibilityLabel(match))
                    .accessibilityHint("Opens \(match.conversationLabel) at this line")
                }
            }
        }
        .background(Color.white.opacity(0.045), in: RoundedRectangle(cornerRadius: 18))
        .overlay(
            RoundedRectangle(cornerRadius: 18)
                .strokeBorder(Color.white.opacity(0.06), lineWidth: 1)
        )
    }

    private func row(_ match: I2PIRCGlobalMatch) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                Text(nickText(match))
                    .font(.footnote.weight(.semibold))
                    .lineLimit(1)
                Spacer(minLength: 4)
                Text(match.date.formatted(date: .omitted, time: .shortened))
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
            Text(lineText(match))
                .font(.callout)
                .multilineTextAlignment(.leading)
                .lineLimit(4)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .contentShape(Rectangle())
    }

    /// What the row's top line says: the nick that spoke, "You" for a line this
    /// client sent, and a word for the lines that carry no nick.
    private func nickLabel(_ match: I2PIRCGlobalMatch) -> String {
        if match.isLocal { return "You" }
        if let nick = match.nick, !nick.isEmpty { return nick }
        switch match.kind {
        case .notice: return "notice"
        case .system, .error: return "server"
        case .message, .action: return "—"
        }
    }

    /// The nick in the conversation's violet, with the query tinted inside it
    /// when the nick itself is what matched.
    private func nickText(_ match: I2PIRCGlobalMatch) -> AttributedString {
        let label = nickLabel(match)
        var text = AttributedString(label)
        text.foregroundColor = match.isLocal ? accent : nickViolet
        for range in I2PIRCGlobalSearch.matchedRanges(in: label, query: query) {
            guard let lower = AttributedString.Index(range.lowerBound, within: text),
                  let upper = AttributedString.Index(range.upperBound, within: text) else { continue }
            text[lower..<upper].foregroundColor = matchTint
            text[lower..<upper].font = Font.footnote.weight(.bold)
        }
        return text
    }

    /// The line itself with every match of the query tinted and emboldened, so
    /// the word the search found shows inside the line.
    private func lineText(_ match: I2PIRCGlobalMatch) -> AttributedString {
        var text = AttributedString(match.text)
        for range in I2PIRCGlobalSearch.matchedRanges(in: match.text, query: query) {
            guard let lower = AttributedString.Index(range.lowerBound, within: text),
                  let upper = AttributedString.Index(range.upperBound, within: text) else { continue }
            text[lower..<upper].foregroundColor = matchTint
            text[lower..<upper].font = Font.callout.weight(.semibold)
        }
        return text
    }

    private func accessibilityLabel(_ match: I2PIRCGlobalMatch) -> String {
        let time = match.date.formatted(date: .omitted, time: .shortened)
        return "\(nickLabel(match)), \(time): \(match.text)"
    }

    /// Closes the sheet and then opens the line, so the chat behind it is back on
    /// screen when it jumps there.
    private func open(_ match: I2PIRCGlobalMatch?) {
        guard let match else { return }
        fieldFocused = false
        dismiss()
        Task { @MainActor in
            try? await Task.sleep(for: .milliseconds(280))
            onOpen(match)
        }
    }

    // MARK: - Empty states

    /// What an empty field shows instead of a list.
    private var explanationCard: some View {
        VStack(spacing: 10) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 26, weight: .light))
                .foregroundStyle(accent)
                .frame(width: 84, height: 84)
                .background(accent.opacity(0.14), in: Circle())

            Text("Search the whole server")
                .font(.headline)

            Text("Type a word and every line of \(serverName) is looked through at once — the server buffer, the channels and the queries, saved history included. Matching ignores case.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity)
        .padding(.horizontal, 32)
        .padding(.top, 36)
    }

    /// What the list shows when the search found nothing.
    private var noMatchesCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("No matches")
                .font(.footnote.weight(.semibold))
                .foregroundStyle(accent)
            Text("Nothing here matches “\(I2PIRCGlobalSearch.normalized(query))”. The search looks through the lines of every conversation, saved history included.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(14)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 16))
        .padding(.horizontal, 16)
        .padding(.top, 4)
    }
}
