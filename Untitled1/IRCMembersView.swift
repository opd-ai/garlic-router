//
//  IRCMembersView.swift
//  The member list of one channel: the nicks this server ignores at the top —
//  each one a tap from speaking again — then every nick in the channel grouped
//  into operators, voiced and everyone else, our own nick first and marked, with
//  the count in the header and a filter for long rosters. A tap opens a private
//  query with that person and closes the list; a swipe ignores them, folding
//  their lines into one quiet row in every conversation of the server.
//

import SwiftUI

struct IRCMembersView: View {
    @ObservedObject var model: I2PIRCChatModel
    let channelID: String

    @Environment(\.dismiss) private var dismiss
    @State private var filter = ""
    @FocusState private var filterFocused: Bool

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)
    private let avatarTint = Color(red: 0.42, green: 0.36, blue: 0.86)
    private let opTint = Color(red: 0.96, green: 0.60, blue: 0.24)
    private let voicedTint = Color(red: 0.62, green: 0.55, blue: 1.00)
    /// The tint an ignored nick wears, and the swipe that ignores one: a quiet
    /// grey-violet, so it reads as silencing rather than as a warning.
    private let ignoreTint = Color(red: 0.55, green: 0.52, blue: 0.88)

    private var conversation: I2PIRCConversation? {
        model.conversation(channelID)
    }

    private var channelName: String {
        conversation?.name ?? channelID
    }

    private var trimmedFilter: String {
        filter.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private var sections: [I2PIRCMemberSection] {
        conversation?.memberSections(ourNick: model.state.nick, filter: filter) ?? []
    }

    /// The nicks this server ignores, whatever channel they are in — the list is
    /// the server's, not the channel's.
    private var ignoredNicks: [String] {
        model.ignoredNickList
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            filterField
            rosterList
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .background(background.ignoresSafeArea())
        .preferredColorScheme(.dark)
    }

    // MARK: - Header

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .center, spacing: 12) {
                Text("\(channelName) members")
                    .font(.system(size: 30, weight: .bold))
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.6)
                Spacer(minLength: 6)
                Button {
                    filterFocused = false
                    dismiss()
                } label: {
                    Text("Done")
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(accent)
                        .padding(.horizontal, 18)
                        .padding(.vertical, 9)
                        .background(accent.opacity(0.18), in: Capsule())
                        .overlay(Capsule().strokeBorder(accent.opacity(0.35), lineWidth: 1))
                }
                .buttonStyle(.plain)
            }
            Text(peopleLine)
                .font(.footnote)
                .foregroundStyle(.secondary)
            Text("Tap a nick to open a private query; swipe it to ignore that person.")
                .font(.caption)
                .foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.horizontal, 16)
        .padding(.top, 22)
        .padding(.bottom, 12)
    }

    private var peopleLine: String {
        let count = conversation?.members.count ?? 0
        var line = count == 1
            ? "1 person in \(channelName)"
            : "\(count) people in \(channelName)"
        if !ignoredNicks.isEmpty {
            line += ignoredNicks.count == 1
                ? " · 1 nick ignored"
                : " · \(ignoredNicks.count) nicks ignored"
        }
        return line
    }

    // MARK: - Filter

    private var filterField: some View {
        HStack(spacing: 9) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 15, weight: .medium))
                .foregroundStyle(.secondary)
            TextField("Filter nicks", text: $filter)
                .font(.callout)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled(true)
                .submitLabel(.search)
                .focused($filterFocused)
            if !filter.isEmpty {
                Button {
                    filter = ""
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .font(.system(size: 15))
                        .foregroundStyle(.tertiary)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Clear the filter")
            }
        }
        .padding(.horizontal, 15)
        .padding(.vertical, 13)
        .background(Color.white.opacity(0.06),
                    in: RoundedRectangle(cornerRadius: 16, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .strokeBorder(Color.white.opacity(0.07), lineWidth: 1)
        )
        .padding(.horizontal, 16)
        .padding(.bottom, 4)
    }

    // MARK: - Roster

    private var rosterList: some View {
        List {
            if !ignoredNicks.isEmpty {
                Section {
                    ForEach(ignoredNicks, id: \.self) { nick in
                        ignoredRow(nick)
                    }
                } header: {
                    sectionHeader("Ignored on this server")
                }
            }
            ForEach(sections) { section in
                Section {
                    ForEach(section.members) { member in
                        memberRow(member)
                    }
                } header: {
                    sectionHeader(section.title)
                }
            }
            Section {
                if sections.isEmpty {
                    emptyCard
                        .listRowBackground(Color.clear)
                        .listRowSeparator(.hidden)
                        .listRowInsets(EdgeInsets(top: 4, leading: 16,
                                                  bottom: 4, trailing: 16))
                }
                footnote
                    .listRowBackground(Color.clear)
                    .listRowSeparator(.hidden)
                    .listRowInsets(EdgeInsets(top: 12, leading: 16,
                                              bottom: 28, trailing: 16))
            }
        }
        .listStyle(.plain)
        .scrollContentBackground(.hidden)
        .scrollDismissesKeyboard(.interactively)
    }

    private func sectionHeader(_ title: String) -> some View {
        Text(title.uppercased())
            .font(.caption2.weight(.semibold))
            .foregroundStyle(.secondary)
            .kerning(0.7)
            .textCase(nil)
            .padding(.leading, 2)
    }

    // MARK: - Members

    private func memberRow(_ member: I2PIRCMember) -> some View {
        Button {
            openQuery(with: member)
        } label: {
            HStack(spacing: 12) {
                Text(member.initial)
                    .font(.system(size: 17, weight: .bold))
                    .foregroundStyle(Color.white)
                    .frame(width: 40, height: 40)
                    .background(avatarTint, in: Circle())
                if let badge = member.role.badgeSymbol {
                    Image(systemName: badge)
                        .font(.system(size: 11, weight: .bold))
                        .foregroundStyle(tint(for: member.role))
                        .frame(width: 22, height: 22)
                        .background(tint(for: member.role).opacity(0.18),
                                    in: RoundedRectangle(cornerRadius: 6, style: .continuous))
                }
                Text(member.nick)
                    .font(.system(.body, design: .monospaced))
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                if member.isUs {
                    Text("you")
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(accent)
                        .padding(.horizontal, 7)
                        .padding(.vertical, 2)
                        .background(accent.opacity(0.22), in: Capsule())
                }
                Spacer(minLength: 6)
                Image(systemName: "chevron.right")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(.tertiary)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .listRowBackground(Color.white.opacity(0.05))
        .listRowSeparatorTint(Color.white.opacity(0.06))
        .listRowInsets(EdgeInsets(top: 2, leading: 14, bottom: 2, trailing: 14))
        // Our own nick can never be ignored, so its row has nothing to swipe to.
        .swipeActions(edge: .trailing, allowsFullSwipe: true) {
            if model.canIgnore(member.nick) {
                Button {
                    model.ignore(member.nick)
                } label: {
                    Label("Ignore", systemImage: "eye.slash")
                }
                .tint(ignoreTint)
            }
        }
        .accessibilityLabel(accessibilityLabel(member))
        .accessibilityHint(member.isUs ? "That is you" : "Opens a private query; swipe to ignore")
    }

    private func tint(for role: I2PIRCMemberRole) -> Color {
        switch role {
        case .op: return opTint
        case .voiced: return voicedTint
        case .participant: return accent
        }
    }

    private func accessibilityLabel(_ member: I2PIRCMember) -> String {
        var parts = [member.nick]
        if member.role != .participant { parts.append(member.role.title) }
        if member.isUs { parts.append("you") }
        return parts.joined(separator: ", ")
    }

    private func openQuery(with member: I2PIRCMember) {
        filterFocused = false
        if model.openQuery(with: member.nick) {
            dismiss()
        }
    }

    // MARK: - Ignored nicks

    private func ignoredRow(_ nick: String) -> some View {
        HStack(spacing: 12) {
            Image(systemName: "eye.slash.fill")
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(ignoreTint)
                .frame(width: 40, height: 40)
                .background(ignoreTint.opacity(0.18), in: Circle())
            VStack(alignment: .leading, spacing: 2) {
                Text(nick)
                    .font(.system(.body, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Text("Their lines fold into one quiet row")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .lineLimit(1)
            }
            Spacer(minLength: 6)
            Button {
                model.stopIgnoring(nick)
            } label: {
                Text("Let speak again")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(accent)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(accent.opacity(0.16), in: Capsule())
                    .overlay(Capsule().strokeBorder(accent.opacity(0.32), lineWidth: 1))
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Let \(nick) speak again")
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .contentShape(Rectangle())
        .listRowBackground(Color.white.opacity(0.05))
        .listRowSeparatorTint(Color.white.opacity(0.06))
        .listRowInsets(EdgeInsets(top: 2, leading: 14, bottom: 2, trailing: 14))
    }

    // MARK: - Empty and footnote

    private var emptyCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(trimmedFilter.isEmpty
                 ? "No nicks yet"
                 : "No nick matches \(trimmedFilter)")
                .font(.footnote.weight(.semibold))
                .foregroundStyle(accent)
            Text(trimmedFilter.isEmpty
                 ? "The server has not sent this channel's NAMES list yet. It arrives right after the join."
                 : "Clear the filter to see everyone in \(channelName).")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(14)
        .background(Color.white.opacity(0.06),
                    in: RoundedRectangle(cornerRadius: 16, style: .continuous))
    }

    private var footnote: some View {
        Text("Nicks come from the server's NAMES list; they leave when the person does. An ignored nick keeps every line it said — it is folded into one quiet row, never deleted.")
            .font(.caption2)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}
