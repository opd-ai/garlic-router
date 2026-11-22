//
//  OpenTabsView.swift
//  The Tabs sheet: every page the eepsite browser has open in this session, in
//  the order they were opened, with the page on screen marked — a tap switches
//  to a page without fetching it again, each row closes its own page, and the
//  last row empties the address bar for a new load.
//

import SwiftUI

struct OpenTabsView: View {
    @ObservedObject var model: I2PEepsiteBrowserModel

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)
    private let warning = Color.orange

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                header
                pagesCard
                footnote
            }
            .padding(.horizontal, 16)
            .padding(.top, 18)
            .padding(.bottom, 24)
        }
        .background(background.ignoresSafeArea())
        .preferredColorScheme(.dark)
    }

    // MARK: - Header

    private var header: some View {
        HStack(alignment: .top, spacing: 10) {
            VStack(alignment: .leading, spacing: 3) {
                Text("Tabs")
                    .font(.system(size: 34, weight: .bold))
                    .foregroundStyle(.primary)
                Text(model.tabs.summary)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 6)
            Button {
                model.closeTabs()
            } label: {
                Text("Close")
                    .font(.headline)
                    .foregroundStyle(accent)
                    .padding(.vertical, 4)
                    .padding(.leading, 8)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Close the tabs list")
        }
        .padding(.horizontal, 2)
    }

    // MARK: - Pages

    /// The open pages in one card, each row separated by a hairline, with the
    /// row that opens a fresh page at the bottom.
    private var pagesCard: some View {
        VStack(spacing: 0) {
            ForEach(model.tabs.pages) { tab in
                row(tab)
                Rectangle()
                    .fill(Color.white.opacity(0.07))
                    .frame(height: 1)
            }
            newPageRow
        }
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    /// One open page: its icon, host, title and how its last fetch ended, with
    /// the mark that says it is the page on screen and its own close control.
    private func row(_ tab: I2PBrowserTab) -> some View {
        let isCurrent = tab.id == model.tabs.activeID
        return HStack(spacing: 8) {
            Button {
                select(tab)
            } label: {
                HStack(alignment: .center, spacing: 12) {
                    iconTile(tab)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(hostLine(tab))
                            .font(.system(.subheadline, design: .monospaced).weight(.semibold))
                            .foregroundStyle(.primary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        if let title = tab.title, !title.isEmpty {
                            Text(title)
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                                .truncationMode(.tail)
                        }
                        // The page on screen that is still fetching says so in
                        // the badge, so the row does not repeat it.
                        if !(isCurrent && tab.fetch.isReading) {
                            Text(tab.fetch.line())
                                .font(.caption)
                                .foregroundStyle(tint(tab.fetch))
                                .lineLimit(1)
                        }
                    }
                    Spacer(minLength: 2)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel(rowLabel(tab, isCurrent: isCurrent))
            .accessibilityHint(isCurrent ? "Closes the tabs list" : "Shows this page")

            if isCurrent {
                currentBadge(tab)
            }
            Button {
                model.closeTab(tab.id)
            } label: {
                Image(systemName: "xmark")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(.secondary)
                    .frame(width: 30, height: 30)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Close \(hostLine(tab))")
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }

    /// The row that empties the address bar for a new load, in a page of its
    /// own with its own stack.
    private var newPageRow: some View {
        Button {
            model.openNewTab()
        } label: {
            HStack(spacing: 12) {
                Image(systemName: "plus")
                    .font(.system(size: 17, weight: .semibold))
                    .foregroundStyle(accent)
                    .frame(width: 38, height: 38)
                    .background(accent.opacity(0.16), in: RoundedRectangle(cornerRadius: 11))
                Text("Open a new page")
                    .font(.subheadline)
                    .foregroundStyle(accent)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel("Open a new page")
        .accessibilityHint("Empties the address bar for a new load")
    }

    // MARK: - Row pieces

    private func hostLine(_ tab: I2PBrowserTab) -> String {
        let host = tab.displayHost
        return host.isEmpty ? "New page" : host
    }

    private func iconTile(_ tab: I2PBrowserTab) -> some View {
        Image(systemName: tab.isB33Host ? "key.fill" : "globe")
            .font(.system(size: 16, weight: .medium))
            .foregroundStyle(accent)
            .frame(width: 38, height: 38)
            .background(accent.opacity(0.16), in: RoundedRectangle(cornerRadius: 11))
            .accessibilityHidden(true)
    }

    /// The mark on the page on screen: it is being read while its fetch runs,
    /// and shown once the page it holds is the one behind this sheet.
    private func currentBadge(_ tab: I2PBrowserTab) -> some View {
        Text(tab.fetch.isReading ? "Reading" : "Showing")
            .font(.caption.weight(.semibold))
            .foregroundStyle(accent)
            .lineLimit(1)
            .padding(.horizontal, 10)
            .padding(.vertical, 4)
            .background(accent.opacity(0.18), in: Capsule())
            .overlay(
                Capsule()
                    .strokeBorder(accent.opacity(0.30), lineWidth: 1)
            )
            .accessibilityHidden(true)
    }

    private func tint(_ fetch: I2PBrowserTabFetch) -> Color {
        switch fetch {
        case .failed: return warning
        case .notLoaded: return .secondary
        case .reading, .fetched, .kept: return accent
        }
    }

    private func rowLabel(_ tab: I2PBrowserTab, isCurrent: Bool) -> String {
        var parts = [hostLine(tab)]
        if let title = tab.title, !title.isEmpty { parts.append(title) }
        parts.append(tab.fetch.line())
        if isCurrent { parts.append("Showing now") }
        return parts.joined(separator: ", ")
    }

    /// Tapping a row puts that page on screen and closes the sheet. The page
    /// already on screen needs no switch: the tap only closes the list.
    private func select(_ tab: I2PBrowserTab) {
        if tab.id != model.tabs.activeID {
            model.activateTab(tab.id)
        }
        model.closeTabs()
    }

    // MARK: - Footnote

    private var footnote: some View {
        Text("Tabs last for as long as the browser stays open.")
            .font(.footnote)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 2)
    }
}
