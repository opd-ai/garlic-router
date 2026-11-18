//
//  HighlightedLinesView.swift
//  The Highlighted lines sheet: every line of the conversations the app holds
//  that contains one of the user's words, newest first. A filter field narrows
//  the list as the user types, and a tap hands the line back to the chat, which
//  opens its conversation and scrolls to it.
//

import SwiftUI

struct HighlightedLinesView: View {
    @ObservedObject var model: I2PIRCChatModel
    @ObservedObject var book: I2PIRCKeywordBook
    /// What a tap on a row does: the chat opens the conversation the line came
    /// from and brings the line itself into view.
    var onOpen: (I2PIRCHighlightMatch) -> Void = { _ in }

    @Environment(\.dismiss) private var dismiss
    @State private var filter = ""
    @FocusState private var filterFocused: Bool

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)

    /// Every matched line of the conversations on screen — restored history
    /// included — newest first.
    private var matches: [I2PIRCHighlightMatch] {
        I2PIRCHighlightMatches.matches(in: model.state.orderedConversations,
                                       words: book.enabledWords)
    }

    private var visibleMatches: [I2PIRCHighlightMatch] {
        I2PIRCHighlightMatches.filtered(matches, query: filter)
    }

    private var isFiltering: Bool {
        !filter.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            filterField
            ScrollView {
                if matches.isEmpty {
                    emptyState
                } else if visibleMatches.isEmpty {
                    noFilterMatchesCard
                } else {
                    matchesCard
                }
            }
            .scrollDismissesKeyboard(.interactively)
        }
        .background(background.ignoresSafeArea())
        .preferredColorScheme(.dark)
    }

    // MARK: - Header

    private var header: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Highlighted lines")
                    .font(.system(size: 30, weight: .bold))
                    .foregroundStyle(.primary)
                Text("Every line that holds one of your words, newest first.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            Button {
                filterFocused = false
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
        .padding(.horizontal, 20)
        .padding(.top, 20)
        .padding(.bottom, 14)
    }

    // MARK: - Filter

    private var filterField: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass")
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(.secondary)
                TextField("Filter matches", text: $filter)
                    .font(.callout)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled(true)
                    .submitLabel(.done)
                    .focused($filterFocused)
                if !filter.isEmpty {
                    Button {
                        filter = ""
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .font(.system(size: 14))
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("Clear the filter")
                }
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 12)
            .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 16))
            .overlay(
                RoundedRectangle(cornerRadius: 16)
                    .strokeBorder(Color.white.opacity(0.06), lineWidth: 1)
            )

            if isFiltering {
                Text(I2PIRCHighlightMatches.filterSummary(count: visibleMatches.count))
                    .font(.caption2)
                    .foregroundStyle(visibleMatches.isEmpty ? Color.secondary : accent)
                    .padding(.leading, 2)
            }
        }
        .padding(.horizontal, 20)
        .padding(.bottom, 12)
    }

    // MARK: - List

    private var matchesCard: some View {
        let rows = visibleMatches
        return VStack(spacing: 0) {
            ForEach(Array(rows.enumerated()), id: \.element.id) { index, match in
                VStack(spacing: 0) {
                    if index > 0 {
                        Rectangle()
                            .fill(Color.white.opacity(0.07))
                            .frame(height: 1)
                            .padding(.leading, 78)
                    }
                    Button {
                        filterFocused = false
                        onOpen(match)
                    } label: {
                        row(match)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(accessibilityLabel(match))
                    .accessibilityHint("Opens \(match.conversationLabel) at this line")
                }
            }
        }
        .background(Color.white.opacity(0.04), in: RoundedRectangle(cornerRadius: 20))
        .overlay(
            RoundedRectangle(cornerRadius: 20)
                .strokeBorder(Color.white.opacity(0.06), lineWidth: 1)
        )
        .padding(.horizontal, 16)
        .padding(.bottom, 20)
    }

    private func row(_ match: I2PIRCHighlightMatch) -> some View {
        HStack(spacing: 12) {
            Image(systemName: "highlighter")
                .font(.system(size: 19, weight: .medium))
                .foregroundStyle(accent)
                .frame(width: 52, height: 52)
                .background(accent.opacity(0.18), in: RoundedRectangle(cornerRadius: 14))
                .overlay(
                    RoundedRectangle(cornerRadius: 14)
                        .strokeBorder(accent.opacity(0.28), lineWidth: 1)
                )

            VStack(alignment: .leading, spacing: 6) {
                Text(match.word)
                    .font(.system(size: 12, weight: .semibold, design: .monospaced))
                    .foregroundStyle(accent)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .background(accent.opacity(0.20), in: Capsule())

                Text(markedLine(match))
                    .font(.callout)
                    .multilineTextAlignment(.leading)
                    .lineLimit(4)
                    .fixedSize(horizontal: false, vertical: true)

                Text(metaLine(match))
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            Spacer(minLength: 4)

            Image(systemName: "chevron.right")
                .font(.system(size: 12, weight: .bold))
                .foregroundStyle(.tertiary)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .contentShape(Rectangle())
    }

    /// The line with the words that matched it tinted and emboldened in the
    /// edge's cool blue, so a row shows which words the line holds and a line
    /// holding two shows both. The rule is the whole-word one the row itself
    /// was listed by.
    private func markedLine(_ match: I2PIRCHighlightMatch) -> AttributedString {
        I2PIRCKeywordEmphasis.attributed(match.text,
                                         words: book.enabledWords,
                                         tint: I2PIRCKeywordEmphasis.tint,
                                         boldFont: .callout.weight(.bold))
    }

    /// The line under a row: the conversation it came from, the nick that said
    /// it and the time, in the shape "#i2p · alice · 14:02".
    private func metaLine(_ match: I2PIRCHighlightMatch) -> String {
        var parts = [match.conversationLabel]
        if let nick = match.nick, !nick.isEmpty {
            parts.append(nick)
        }
        parts.append(match.date.formatted(date: .omitted, time: .shortened))
        return parts.joined(separator: " · ")
    }

    private func accessibilityLabel(_ match: I2PIRCHighlightMatch) -> String {
        "\(match.word): \(match.text) — \(metaLine(match))"
    }

    // MARK: - Empty states

    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "highlighter")
                .font(.system(size: 28, weight: .light))
                .foregroundStyle(accent)
                .frame(width: 96, height: 96)
                .background(accent.opacity(0.14), in: Circle())

            Text("Nothing highlighted yet")
                .font(.headline)

            Text(book.isPaused
                 ? "Highlighting is paused — turn it back on in Highlights and the lines show up here again."
                 : "Lines that hold one of your words show up here as they arrive.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity)
        .padding(.horizontal, 32)
        .padding(.top, 30)
    }

    /// What the list shows when the filter leaves nothing of it.
    private var noFilterMatchesCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("No matches")
                .font(.footnote.weight(.semibold))
                .foregroundStyle(accent)
            Text("No line holds “\(filter.trimmingCharacters(in: .whitespacesAndNewlines))”. The filter looks through the lines loaded in every conversation.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(14)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 16))
        .padding(.horizontal, 16)
    }
}
