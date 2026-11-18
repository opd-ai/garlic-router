//
//  IRCChannelsView.swift
//  The channel list of the connected server, shown in a sheet: a filter field,
//  one row per advertised channel with its member count and topic, a Refresh
//  control that asks the server again, and an empty state before anything has
//  come back. A tap joins the channel and closes the sheet.
//

import SwiftUI

struct IRCChannelsView: View {
    @ObservedObject var model: I2PIRCChatModel

    @Environment(\.dismiss) private var dismiss
    @State private var filter = ""
    @FocusState private var filterFocused: Bool

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)
    private let tileTint = Color(red: 0.42, green: 0.36, blue: 0.86)
    private let warnOrange = Color(red: 0.98, green: 0.62, blue: 0.24)

    private var list: I2PIRCChannelList { model.channelList }

    private var rows: [I2PIRCChannelEntry] { list.filtered(filter) }

    private var trimmedFilter: String {
        filter.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Rectangle()
                .fill(Color.white.opacity(0.07))
                .frame(height: 1)
            ScrollView {
                content
            }
            .scrollDismissesKeyboard(.interactively)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .background(background.ignoresSafeArea())
        .preferredColorScheme(.dark)
        .task { model.loadChannelListIfNeeded() }
    }

    // MARK: - Header

    private var header: some View {
        ZStack {
            Text("Channels")
                .font(.system(size: 21, weight: .bold))
                .foregroundStyle(.primary)
            HStack {
                Spacer()
                refreshButton
            }
        }
        .padding(.horizontal, 18)
        .padding(.top, 18)
        .padding(.bottom, 14)
    }

    private var refreshButton: some View {
        Button {
            filterFocused = false
            model.requestChannelList()
        } label: {
            HStack(spacing: 6) {
                if list.isLoading {
                    ProgressView()
                        .controlSize(.mini)
                        .tint(accent)
                }
                Text("Refresh")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(accent)
            }
            .padding(.horizontal, 4)
            .padding(.vertical, 4)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(list.isLoading || !model.phase.isLive)
        .opacity(model.phase.isLive ? 1 : 0.4)
        .accessibilityLabel("Refresh the channel list")
    }

    // MARK: - Content

    private var content: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("From \(model.state.serverName) — tap a channel to join it.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            filterField

            Text(I2PIRCChannelList.countLine(rows.count))
                .font(.caption.weight(.semibold))
                .foregroundStyle(accent)
                .padding(.horizontal, 2)

            if rows.isEmpty {
                emptyCard
            } else {
                VStack(spacing: 10) {
                    ForEach(rows) { entry in
                        channelRow(entry)
                    }
                }
            }

            footnote
        }
        .padding(.horizontal, 16)
        .padding(.top, 14)
        .padding(.bottom, 28)
    }

    private var filterField: some View {
        HStack(spacing: 9) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 15, weight: .medium))
                .foregroundStyle(.secondary)
            TextField("Filter channels", text: $filter)
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
        .padding(.vertical, 12)
        .background(Color.white.opacity(0.06),
                    in: RoundedRectangle(cornerRadius: 16, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .strokeBorder(Color.white.opacity(0.07), lineWidth: 1)
        )
    }

    // MARK: - Rows

    private func channelRow(_ entry: I2PIRCChannelEntry) -> some View {
        Button {
            filterFocused = false
            model.join(entry.name)
            dismiss()
        } label: {
            HStack(alignment: .center, spacing: 14) {
                Text("#")
                    .font(.system(size: 26, weight: .bold))
                    .foregroundStyle(accent)
                    .frame(width: 58, height: 58)
                    .background(tileTint.opacity(0.30),
                                in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                VStack(alignment: .leading, spacing: 3) {
                    Text(entry.name)
                        .font(.system(size: 17, weight: .semibold))
                        .foregroundStyle(.primary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Text(entry.topicLine)
                        .font(.system(size: 14))
                        .foregroundStyle(entry.topic == nil
                                         ? Color.secondary.opacity(0.65)
                                         : Color.secondary)
                        .lineLimit(2)
                        .multilineTextAlignment(.leading)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 6)
                HStack(spacing: 5) {
                    Image(systemName: "person.fill")
                        .font(.system(size: 12, weight: .medium))
                    Text(entry.memberLine)
                        .font(.system(size: 14, weight: .medium))
                        .monospacedDigit()
                }
                .foregroundStyle(.secondary)
                Image(systemName: "chevron.right")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(.tertiary)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.white.opacity(0.055),
                        in: RoundedRectangle(cornerRadius: 18, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 18, style: .continuous)
                    .strokeBorder(Color.white.opacity(0.06), lineWidth: 1)
            )
            .contentShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
        }
        .buttonStyle(.plain)
        .accessibilityLabel(entry.accessibilityLabel)
        .accessibilityHint("Joins the channel")
    }

    // MARK: - Empty state

    private var emptyCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let failure = list.failure {
                Text("The server did not list its channels")
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(warnOrange)
                Text(failure)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Text("Refresh asks again.")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            } else if list.isLoading {
                HStack(spacing: 9) {
                    ProgressView()
                        .controlSize(.mini)
                        .tint(accent)
                    Text("Asking \(model.state.serverName) for its channel list…")
                        .font(.footnote.weight(.semibold))
                        .foregroundStyle(accent)
                }
                Text("The channels arrive a line at a time as the server answers LIST.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else if !trimmedFilter.isEmpty {
                Text("No channel matches \(trimmedFilter)")
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(accent)
                Text("Clear the filter to see the channels \(model.state.serverName) advertises.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                Text("No channels listed")
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(accent)
                Text("The server answered its channel list but advertised no channels. Refresh asks it again.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(14)
        .background(Color.white.opacity(0.06),
                    in: RoundedRectangle(cornerRadius: 16, style: .continuous))
    }

    private var footnote: some View {
        Text("The list only holds channels the server advertises.")
            .font(.caption2)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}
