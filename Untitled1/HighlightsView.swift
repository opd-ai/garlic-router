//
//  HighlightsView.swift
//  The Highlights sheet the IRC toolbar opens: the words the user wants to be
//  told about. A word added here marks every line that holds it, in every
//  channel and query; its switch pauses it and a swipe removes it.
//

import SwiftUI

struct HighlightsView: View {
    @ObservedObject var model: I2PIRCChatModel
    @ObservedObject var book: I2PIRCKeywordBook
    /// What a tap on a row of the Highlighted lines sheet does: the chat opens
    /// the conversation the line came from and brings the line into view.
    var onOpenMatch: (I2PIRCHighlightMatch) -> Void = { _ in }

    @Environment(\.dismiss) private var dismiss
    @State private var draft = ""
    @State private var addProblem: String?
    @State private var showMatches = false
    @FocusState private var addFocused: Bool

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)
    /// The tint the pause wears, so a switched-off highlighting never reads as
    /// one more violet control.
    private let warnOrange = Color(red: 0.98, green: 0.62, blue: 0.24)

    private var trimmedDraft: String {
        draft.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    var body: some View {
        NavigationStack {
            List {
                masterSection
                matchesSection
                introSection
                keywordsSection
                footnoteSection
            }
            .listStyle(.insetGrouped)
            .scrollContentBackground(.hidden)
            .scrollDismissesKeyboard(.interactively)
            .background(background.ignoresSafeArea())
            .navigationTitle("Highlights")
            .navigationBarTitleDisplayMode(.large)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
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
            }
            .sheet(isPresented: $showMatches) {
                HighlightedLinesView(model: model, book: book) { match in
                    // The list closes itself first, so the chat behind it is
                    // back on screen when it jumps to the line.
                    showMatches = false
                    Task { @MainActor in
                        try? await Task.sleep(for: .milliseconds(280))
                        onOpenMatch(match)
                        dismiss()
                    }
                }
            }
        }
        .preferredColorScheme(.dark)
    }

    // MARK: - Master switch

    /// Whether the master switch is off: every word paused for a time, the list
    /// exactly as it was left.
    private var isPaused: Bool { book.isPaused }

    /// The line under the switch: the pause with the time it has left, or that
    /// highlighting is on.
    private var pauseSummary: String { book.pauseSummary }

    private var masterBinding: Binding<Bool> {
        Binding(get: { !book.isPaused },
                set: { highlighted in
                    addFocused = false
                    if highlighted {
                        book.resume()
                    } else {
                        // Switching it off re-uses the duration chosen last time.
                        book.pause(for: book.lastPauseDuration)
                    }
                })
    }

    private func isSelectedDuration(_ duration: I2PIRCKeywordPauseDuration) -> Bool {
        isPaused && book.lastPauseDuration == duration
    }

    /// The switch at the top of the sheet: one toggle for every keyword, and the
    /// row of durations a pause can be set for. A tap on a duration pauses for
    /// it at once, whatever the toggle says now.
    private var masterSection: some View {
        Section {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 12) {
                    Image(systemName: isPaused ? "pause.circle.fill" : "highlighter")
                        .font(.system(size: 16, weight: .medium))
                        .foregroundStyle(isPaused ? warnOrange : accent)
                        .frame(width: 40, height: 40)
                        .background((isPaused ? warnOrange : accent).opacity(0.16),
                                    in: RoundedRectangle(cornerRadius: 11))

                    VStack(alignment: .leading, spacing: 3) {
                        Text("Highlighting")
                            .font(.callout.weight(.semibold))
                            .foregroundStyle(.primary)
                        Text(pauseSummary)
                            .font(.caption2)
                            .foregroundStyle(isPaused ? warnOrange : Color.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }

                    Spacer(minLength: 6)

                    Toggle("", isOn: masterBinding)
                        .labelsHidden()
                        .tint(accent)
                        .accessibilityLabel("Highlighting")
                        .accessibilityValue(pauseSummary)
                }

                durationRow
            }
            .padding(.vertical, 3)
        }
        .listRowBackground(Color.white.opacity(0.05))
    }

    private var durationRow: some View {
        HStack(spacing: 8) {
            ForEach(I2PIRCKeywordPauseDuration.allCases) { duration in
                Button {
                    addFocused = false
                    book.pause(for: duration)
                } label: {
                    Text(duration.label)
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(isSelectedDuration(duration) ? accent : Color.secondary)
                        .lineLimit(1)
                        .minimumScaleFactor(0.8)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 8)
                        .frame(maxWidth: .infinity)
                        .background(isSelectedDuration(duration)
                                    ? accent.opacity(0.20)
                                    : Color.white.opacity(0.05),
                                    in: Capsule())
                }
                .buttonStyle(.plain)
                .accessibilityLabel(duration.actionLabel)
                .accessibilityValue(isSelectedDuration(duration) ? "Selected" : "")
            }
        }
    }

    // MARK: - Every matched line

    /// The count the "View matches" row reads out: every line of the
    /// conversations the app holds that holds one of the switched-on words.
    private var matchCount: Int {
        I2PIRCHighlightMatches.matches(in: model.state.orderedConversations,
                                       words: book.enabledWords).count
    }

    /// What the row says about the list: a pause marks nothing, so it says so
    /// rather than reading as an empty list of words.
    private var matchSummary: String {
        isPaused
            ? "Nothing is marked while highlighting is paused"
            : I2PIRCHighlightMatches.summary(count: matchCount)
    }

    private var matchesSection: some View {
        Section {
            Button {
                addFocused = false
                showMatches = true
            } label: {
                HStack(spacing: 12) {
                    Image(systemName: "highlighter")
                        .font(.system(size: 16, weight: .medium))
                        .foregroundStyle(accent)
                        .frame(width: 40, height: 40)
                        .background(accent.opacity(0.16), in: RoundedRectangle(cornerRadius: 11))

                    VStack(alignment: .leading, spacing: 3) {
                        Text("View matches")
                            .font(.callout.weight(.semibold))
                            .foregroundStyle(.primary)
                        Text(matchSummary)
                            .font(.caption2)
                            .foregroundStyle(isPaused ? warnOrange : Color.secondary)
                            .lineLimit(1)
                    }

                    Spacer(minLength: 6)

                    Image(systemName: "chevron.right")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundStyle(.tertiary)
                }
                .padding(.vertical, 3)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .listRowBackground(Color.white.opacity(0.05))
            .accessibilityLabel("View matches")
            .accessibilityValue(matchSummary)
            .accessibilityHint("Every line that holds one of your words, newest first")
        }
    }

    // MARK: - Intro and the add field

    private var introSection: some View {
        Section {
            VStack(alignment: .leading, spacing: 14) {
                Text("Lines that contain these words get a violet edge in every channel and query.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                HStack(spacing: 10) {
                    TextField("Add a keyword", text: $draft)
                        .font(.callout)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled(true)
                        .submitLabel(.done)
                        .focused($addFocused)
                        .onSubmit { add() }
                        .padding(.horizontal, 14)
                        .padding(.vertical, 11)
                        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 14))

                    Button {
                        add()
                    } label: {
                        Text("Add")
                            .font(.subheadline.weight(.semibold))
                            .foregroundStyle(trimmedDraft.isEmpty ? Color.secondary : accent)
                            .padding(.horizontal, 16)
                            .padding(.vertical, 11)
                            .background(trimmedDraft.isEmpty
                                        ? Color.white.opacity(0.05)
                                        : accent.opacity(0.20),
                                        in: Capsule())
                    }
                    .buttonStyle(.plain)
                    .disabled(trimmedDraft.isEmpty)
                    .accessibilityLabel("Add keyword")
                }

                if let addProblem {
                    Text(addProblem)
                        .font(.caption2)
                        .foregroundStyle(Color.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(.vertical, 2)
        }
        .listRowBackground(Color.clear)
        .listRowSeparator(.hidden)
        .listRowInsets(EdgeInsets(top: 6, leading: 16, bottom: 6, trailing: 16))
    }

    private func add() {
        let word = trimmedDraft
        guard !word.isEmpty else { return }
        guard book.add(word) else {
            addProblem = "“\(word)” is already on the list."
            return
        }
        addProblem = nil
        draft = ""
        addFocused = true
    }

    // MARK: - Keywords

    private var keywordsSection: some View {
        Section {
            if book.entries.isEmpty {
                emptyState
                    .listRowBackground(Color.clear)
                    .listRowSeparator(.hidden)
            } else {
                ForEach(book.entries) { keyword in
                    keywordRow(keyword)
                        .listRowBackground(Color.white.opacity(0.05))
                        .swipeActions(edge: .trailing, allowsFullSwipe: true) {
                            Button(role: .destructive) {
                                book.remove(keyword.id)
                            } label: {
                                Label("Delete", systemImage: "trash")
                            }
                        }
                }
            }
        }
    }

    private func keywordRow(_ keyword: I2PIRCKeyword) -> some View {
        HStack(spacing: 12) {
            Image(systemName: "key")
                .font(.system(size: 15, weight: .medium))
                .foregroundStyle(accent)
                .frame(width: 38, height: 38)
                .background(accent.opacity(0.16), in: RoundedRectangle(cornerRadius: 10))

            VStack(alignment: .leading, spacing: 3) {
                Text(keyword.word)
                    .font(.system(.callout, design: .monospaced))
                    .foregroundStyle(keyword.isEnabled ? Color.primary : Color.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Text(matchLine(keyword))
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }

            Spacer(minLength: 6)

            Toggle("", isOn: Binding(get: { keyword.isEnabled },
                                     set: { book.setEnabled($0, for: keyword.id) }))
                .labelsHidden()
                .tint(accent)
                .accessibilityLabel(keyword.word)
                .accessibilityValue(keyword.isEnabled ? "On" : "Paused")
        }
        .padding(.vertical, 3)
    }

    /// The read-out under a word: how many lines of the chat it matches today.
    private func matchLine(_ keyword: I2PIRCKeyword) -> String {
        let count = model.keywordMatchCount(for: keyword.word)
        return "\(count) line\(count == 1 ? "" : "s") matched today"
    }

    private var emptyState: some View {
        VStack(spacing: 10) {
            Image(systemName: "key")
                .font(.system(size: 30, weight: .light))
                .foregroundStyle(accent)
                .frame(width: 88, height: 88)
                .background(accent.opacity(0.14), in: Circle())

            Text("No keywords yet")
                .font(.headline)

            Text("Add a word to have every line that mentions it marked.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 26)
    }

    // MARK: - Footnote

    private var footnoteSection: some View {
        Section {
            Text("Swiped rows are deleted. A pause switches every word off without touching the list. Keywords never leave this device.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: .infinity, alignment: .center)
        }
        .listRowBackground(Color.clear)
        .listRowSeparator(.hidden)
    }
}
