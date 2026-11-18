//
//  SavedHostsView.swift
//  The saved hosts screen: the .i2p names and b33 addresses kept from the
//  browser, with the last visit and how that fetch ended.
//

import SwiftUI

struct SavedHostsView: View {
    @ObservedObject private var store: I2PSavedHostsStore
    @StateObject private var refresh = I2PSavedHostsRefreshModel.live()
    @Environment(\.dismiss) private var dismiss
    @State private var query = ""

    /// The browser's address text at the moment the screen was opened, so the
    /// empty state and the bottom button can offer to save it.
    private let currentAddress: String
    /// Keeps a host the way the browser's bookmark button does, so the page on
    /// screen is remembered as its first visit.
    private let onSave: (String) -> Void
    private let onOpen: (String) -> Void

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)
    private let okGreen = Color(red: 0.29, green: 0.87, blue: 0.50)

    init(currentAddress: String,
         store: I2PSavedHostsStore = .shared,
         onSave: @escaping (String) -> Void,
         onOpen: @escaping (String) -> Void) {
        self.currentAddress = currentAddress
        self._store = ObservedObject(wrappedValue: store)
        self.onSave = onSave
        self.onOpen = onOpen
    }

    var body: some View {
        VStack(spacing: 12) {
            caption
            filterField
            refreshCard
            hostList
        }
        .padding(.top, 4)
        .background(background.ignoresSafeArea())
        .safeAreaInset(edge: .bottom) { saveBar }
        .navigationTitle("Saved hosts")
        .navigationBarTitleDisplayMode(.large)
        .preferredColorScheme(.dark)
        // The pass belongs to this screen: closing it stops the walk where it
        // stands and keeps the readings the rows already got.
        .onDisappear { refresh.stop() }
    }

    // MARK: - Header

    private var caption: some View {
        Text("Hosts you kept from the browser. Tap one to open it again.")
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

    // MARK: - Refresh

    /// The Refresh all control, with the pass's progress line above the list.
    /// While it runs the button turns into a stop control.
    @ViewBuilder
    private var refreshCard: some View {
        if !store.entries.isEmpty {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 12) {
                    Image(systemName: "arrow.clockwise.circle")
                        .font(.system(size: 18, weight: .medium))
                        .foregroundStyle(accent)
                        .frame(width: 44, height: 44)
                        .background(accent.opacity(0.16), in: RoundedRectangle(cornerRadius: 12))
                        .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(refreshTitle)
                            .font(.subheadline.weight(.semibold))
                        Text(refreshDetail)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(2)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer(minLength: 4)
                    refreshButton
                }
                if refresh.isRunning {
                    ProgressView(value: refresh.fraction)
                        .progressViewStyle(.linear)
                        .tint(accent)
                        .accessibilityLabel("Refresh progress")
                }
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 12)
            .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
            .padding(.horizontal, 16)
        }
    }

    private var refreshTitle: String {
        switch refresh.phase {
        case .idle: return "Refresh hosts"
        case .running: return "Refreshing hosts"
        case .finished: return "Refreshed hosts"
        case .stopped: return "Refresh stopped"
        }
    }

    /// The progress line itself while a pass runs, its outcome afterwards.
    private var refreshDetail: String {
        if let line = refresh.progressLine { return line }
        return "Re-fetch every host, one at a time — each row records this attempt's result."
    }

    private var refreshButton: some View {
        Button {
            if refresh.isRunning {
                refresh.stop()
            } else {
                refresh.start()
            }
        } label: {
            HStack(spacing: 6) {
                Image(systemName: refresh.isRunning ? "stop.fill" : "arrow.clockwise")
                    .font(.caption2.weight(.bold))
                Text(refresh.isRunning ? "Stop" : "Refresh all")
                    .font(.caption.weight(.semibold))
            }
            .foregroundStyle(refresh.isRunning ? Color.primary : Color.white)
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(refresh.isRunning ? Color.white.opacity(0.12) : accent.opacity(0.80),
                        in: Capsule())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(refresh.isRunning ? "Stop refreshing" : "Refresh all hosts")
    }

    // MARK: - Rows

    private var visibleEntries: [I2PSavedHostEntry] {
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return store.entries }
        return store.entries.filter { $0.host.localizedCaseInsensitiveContains(trimmed) }
    }

    private var hostList: some View {
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
                                store.remove(entry.host)
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

    private func row(_ entry: I2PSavedHostEntry) -> some View {
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
        .accessibilityLabel("\(entry.host), \(entry.kind.label)")
    }

    private func iconTile(_ kind: I2PSavedHostKind) -> some View {
        Image(systemName: kind == .b33 ? "key.fill" : "globe")
            .font(.system(size: 18, weight: .medium))
            .foregroundStyle(accent)
            .frame(width: 44, height: 44)
            .background(accent.opacity(0.16), in: RoundedRectangle(cornerRadius: 12))
            .accessibilityHidden(true)
    }

    private func visitLine(_ entry: I2PSavedHostEntry) -> some View {
        HStack(spacing: 0) {
            Text(visitText(entry))
                .foregroundStyle(.secondary)
            if let result = entry.lastResult {
                Text(" · ")
                    .foregroundStyle(.secondary)
                Text(result.label)
                    .foregroundStyle(result.isFailure ? Color.orange : okGreen)
            }
        }
        .font(.caption)
    }

    /// "last visited 2 hours ago", or when the host was saved and that it has
    /// not been visited since.
    private func visitText(_ entry: I2PSavedHostEntry) -> String {
        if let lastVisited = entry.lastVisitedAt {
            return "last visited \(lastVisited.formatted(.relative(presentation: .named)))"
        }
        let saved = entry.savedAt.formatted(.relative(presentation: .named))
        return "saved \(saved) · not visited yet"
    }

    private func open(_ entry: I2PSavedHostEntry) {
        onOpen(entry.host)
        dismiss()
    }

    // MARK: - Empty state

    private var emptyState: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("No saved hosts yet", systemImage: "bookmark")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(accent)
            Text("A saved host is a bookmark to an eepsite you want to find again: its .i2p name or b33 address is kept with the time you saved it, when you last visited it and how that fetch ended. Bookmarks stay on this device.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if let candidate = currentCandidate {
                Button {
                    save()
                } label: {
                    HStack(spacing: 8) {
                        Image(systemName: "bookmark")
                            .font(.caption)
                        Text("Save \(candidate.host)")
                            .font(.footnote.weight(.semibold))
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                    .foregroundStyle(accent)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 10)
                    .background(accent.opacity(0.14), in: Capsule())
                }
                .buttonStyle(.plain)
                .disabled(store.contains(candidate.host))
            } else {
                Text("Type a host in the browser's address bar first — whatever is in it can be saved from here.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    private var noMatchCard: some View {
        Text("No saved host matches this filter.")
            .font(.footnote)
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(16)
            .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    private var footnote: some View {
        Text("A failed host keeps the reason of its last attempt: resolution, lease expiry or the stream itself.")
            .font(.caption2)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 2)
    }

    // MARK: - Save bar

    /// The host currently in the browser's address bar, when it is savable.
    private var currentCandidate: (host: String, kind: I2PSavedHostKind)? {
        I2PSavedHostsStore.host(in: currentAddress)
    }

    private var saveEnabled: Bool {
        guard let candidate = currentCandidate else { return false }
        return !store.contains(candidate.host)
    }

    private var saveBar: some View {
        VStack(spacing: 8) {
            Button {
                save()
            } label: {
                Text("Save the host in the address bar")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(saveEnabled ? Color.white : Color.white.opacity(0.45))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 14)
                    .background(saveEnabled ? accent.opacity(0.80) : accent.opacity(0.32),
                                in: Capsule())
            }
            .buttonStyle(.plain)
            .disabled(!saveEnabled)
            Text("Bookmarks stay on this device.")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, 16)
        .padding(.top, 8)
        .padding(.bottom, 8)
        .background(background.opacity(0.95))
    }

    private func save() {
        guard let candidate = currentCandidate, !store.contains(candidate.host) else { return }
        onSave(candidate.host)
    }
}
