//
//  BrowserHistoryView.swift
//  The browser's history screen: every host the eepsite browser opened, newest
//  first, with the time of the visit and how the fetch ended.
//

import SwiftUI

struct BrowserHistoryView: View {
    @ObservedObject private var store: I2PBrowserHistoryStore
    @Environment(\.dismiss) private var dismiss
    @State private var query = ""

    /// Opens a visited host in the browser behind this screen.
    private let onOpen: (String) -> Void

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)
    private let okGreen = Color(red: 0.29, green: 0.87, blue: 0.50)

    init(store: I2PBrowserHistoryStore = .shared,
         onOpen: @escaping (String) -> Void) {
        self._store = ObservedObject(wrappedValue: store)
        self.onOpen = onOpen
    }

    var body: some View {
        VStack(spacing: 12) {
            caption
            filterField
            historyList
        }
        .padding(.top, 4)
        .background(background.ignoresSafeArea())
        .safeAreaInset(edge: .bottom) { clearBar }
        .navigationTitle("History")
        .navigationBarTitleDisplayMode(.large)
        .preferredColorScheme(.dark)
    }

    // MARK: - Header

    private var caption: some View {
        Text("Every host the browser opened, newest first.")
            .font(.footnote)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 16)
    }

    private var filterField: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass")
                .font(.subheadline)
                .foregroundStyle(.secondary)
            TextField("Filter hosts", text: $query)
                .font(.footnote)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .submitLabel(.search)
            if !query.isEmpty {
                Button {
                    query = ""
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Clear filter")
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
        .background(RoundedRectangle(cornerRadius: 14).fill(Color.white.opacity(0.05)))
        .overlay(
            RoundedRectangle(cornerRadius: 14)
                .strokeBorder(Color.white.opacity(0.12), lineWidth: 1)
        )
        .padding(.horizontal, 16)
    }

    // MARK: - Rows

    private var visibleEntries: [I2PBrowserHistoryEntry] {
        store.filtered(query)
    }

    private var historyList: some View {
        List {
            if store.entries.isEmpty {
                emptyState
                    .listRowBackground(Color.clear)
                    .listRowSeparator(.hidden)
                    .listRowInsets(EdgeInsets(top: 2, leading: 16, bottom: 6, trailing: 16))
            } else if visibleEntries.isEmpty {
                noMatchCard
                    .listRowBackground(Color.clear)
                    .listRowSeparator(.hidden)
                    .listRowInsets(EdgeInsets(top: 2, leading: 16, bottom: 8, trailing: 16))
            } else {
                ForEach(visibleEntries) { entry in
                    row(entry)
                        .listRowBackground(Color.clear)
                        .listRowSeparator(.hidden)
                        .listRowInsets(EdgeInsets(top: 5, leading: 16, bottom: 5, trailing: 0))
                        .swipeActions(edge: .trailing, allowsFullSwipe: true) {
                            Button(role: .destructive) {
                                store.remove(entry.id)
                            } label: {
                                Label("Delete", systemImage: "trash")
                            }
                        }
                }
            }

            footnote
                .listRowBackground(Color.clear)
                .listRowSeparator(.hidden)
                .listRowInsets(EdgeInsets(top: 10, leading: 16, bottom: 16, trailing: 16))
        }
        .listStyle(.plain)
        .scrollContentBackground(.hidden)
        .animation(.easeInOut(duration: 0.2), value: store.entries)
    }

    private func row(_ entry: I2PBrowserHistoryEntry) -> some View {
        Button {
            open(entry)
        } label: {
            HStack(spacing: 12) {
                iconTile(entry.kind)
                VStack(alignment: .leading, spacing: 4) {
                    Text(entry.host)
                        .font(.system(.subheadline, design: .monospaced).weight(.medium))
                        .foregroundStyle(.primary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    visitLine(entry)
                        .lineLimit(1)
                }
                Spacer(minLength: 4)
                Image(systemName: "chevron.right")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(.tertiary)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 16))
            .contentShape(RoundedRectangle(cornerRadius: 16))
        }
        .buttonStyle(.plain)
        .padding(.trailing, 16)
        .accessibilityLabel("\(entry.host), \(entry.visitText()), \(entry.result.label)")
    }

    private func iconTile(_ kind: I2PSavedHostKind) -> some View {
        Image(systemName: kind == .b33 ? "key.fill" : "globe")
            .font(.system(size: 18, weight: .medium))
            .foregroundStyle(accent)
            .frame(width: 44, height: 44)
            .background(accent.opacity(0.16), in: RoundedRectangle(cornerRadius: 12))
            .accessibilityHidden(true)
    }

    private func visitLine(_ entry: I2PBrowserHistoryEntry) -> some View {
        HStack(spacing: 0) {
            Text(entry.visitText())
                .foregroundStyle(.secondary)
            Text(" · ")
                .foregroundStyle(.secondary)
            Text(entry.result.label)
                .foregroundStyle(entry.result.isFailure ? Color.orange : okGreen)
        }
        .font(.caption)
    }

    private func open(_ entry: I2PBrowserHistoryEntry) {
        onOpen(entry.host)
        dismiss()
    }

    // MARK: - Empty state

    private var emptyState: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Nothing visited yet", systemImage: "clock")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(accent)
            Text("Every host the browser opens is listed here with the time of the visit and how the fetch ended — ok, resolve failed or connection failed. History stays on this device.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Text("Load an eepsite in the browser and its visit appears here.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    private var noMatchCard: some View {
        Text("No visit matches this filter.")
            .font(.footnote)
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(16)
            .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    private var footnote: some View {
        Text("History stays on this device.")
            .font(.caption2)
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .center)
            .padding(.top, 2)
    }

    // MARK: - Clear bar

    private var clearBar: some View {
        VStack(spacing: 8) {
            Button {
                store.clear()
            } label: {
                Text("Clear history")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(store.entries.isEmpty ? Color.white.opacity(0.45) : Color.white)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 14)
                    .background(store.entries.isEmpty ? accent.opacity(0.32) : accent.opacity(0.80),
                                in: Capsule())
            }
            .buttonStyle(.plain)
            .disabled(store.entries.isEmpty)
            Text("Removing history leaves saved hosts alone.")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, 16)
        .padding(.top, 8)
        .padding(.bottom, 8)
        .background(background.opacity(0.95))
    }
}
