//
//  OfflineLibraryView.swift
//  The offline library: every saved host whose last good fetch is still kept on
//  the device, newest copy first, each readable in the browser without a live
//  fetch.
//

import SwiftUI

struct OfflineLibraryView: View {
    @ObservedObject private var store: I2POfflinePageStore
    @ObservedObject private var savedHosts: I2PSavedHostsStore
    @Environment(\.dismiss) private var dismiss
    @State private var searchText = ""

    /// Reads a kept copy in the browser behind this screen.
    private let onOpen: (I2PKeptPage) -> Void

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)

    init(store: I2POfflinePageStore = .shared,
         onOpen: @escaping (I2PKeptPage) -> Void) {
        self._store = ObservedObject(wrappedValue: store)
        self._savedHosts = ObservedObject(wrappedValue: .shared)
        self.onOpen = onOpen
    }

    var body: some View {
        VStack(spacing: 12) {
            caption
            summaryCard
            copyList
        }
        .padding(.top, 4)
        .background(background.ignoresSafeArea())
        .navigationTitle("Offline library")
        .navigationBarTitleDisplayMode(.large)
        .preferredColorScheme(.dark)
    }

    // MARK: - Header

    private var caption: some View {
        Text("Pages you keep from the reader, alongside saved hosts' last good fetches — readable even when the router can't reach them.")
            .font(.footnote)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 16)
    }

    /// How many copies the library holds and what they add up to on the device,
    /// with the button that empties it. It only exists while there is
    /// something kept, so an empty library is just its explanation.
    @ViewBuilder
    private var summaryCard: some View {
        if !store.copies.isEmpty {
            let count = store.copies.count
            let size = I2PKeptPage.sizeText(store.libraryBytes)
            HStack(spacing: 12) {
                Text("\(count)")
                    .font(.system(size: 34, weight: .bold, design: .rounded))
                    .foregroundStyle(accent)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text(count == 1 ? "page kept" : "pages kept")
                        .font(.subheadline.weight(.semibold))
                    Text("\(size) on this device")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 6)
                Button {
                    store.clear()
                } label: {
                    Text("Clear all")
                        .font(.footnote.weight(.semibold))
                        .foregroundStyle(accent)
                        .padding(.vertical, 6)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Clear the offline library")
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 14)
            .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
            .padding(.horizontal, 16)
        }
    }

    // MARK: - Rows

    private var copyList: some View {
        let copies = store.library
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        let results = I2POfflineLibrarySearch.results(in: copies, query: query)
        return List {
            searchField
                .listRowBackground(Color.clear)
                .listRowSeparator(.hidden)
                .listRowInsets(EdgeInsets(top: 4, leading: 16, bottom: 4, trailing: 16))

            if !query.isEmpty {
                searchCount(results.count, query: query)
                    .listRowBackground(Color.clear)
                    .listRowSeparator(.hidden)
                    .listRowInsets(EdgeInsets(top: 2, leading: 16, bottom: 6, trailing: 16))
            }

            if query.isEmpty {
                if copies.isEmpty {
                    emptyState
                        .listRowBackground(Color.clear)
                        .listRowSeparator(.hidden)
                        .listRowInsets(EdgeInsets(top: 2, leading: 16, bottom: 6, trailing: 16))
                } else {
                    ForEach(copies, id: \.host) { kept in
                        row(kept)
                            .listRowBackground(Color.clear)
                            .listRowSeparator(.hidden)
                            .listRowInsets(EdgeInsets(top: 5, leading: 16, bottom: 5, trailing: 0))
                            .swipeActions(edge: .trailing, allowsFullSwipe: true) {
                                Button(role: .destructive) {
                                    store.remove(kept.host)
                                } label: {
                                    Label("Delete", systemImage: "trash")
                                }
                            }
                    }
                }
            } else if results.isEmpty {
                noSearchResults(query)
                    .listRowBackground(Color.clear)
                    .listRowSeparator(.hidden)
                    .listRowInsets(EdgeInsets(top: 2, leading: 16, bottom: 6, trailing: 16))
            } else {
                ForEach(results, id: \.page.host) { result in
                    row(result.page, searchResult: result, query: query)
                        .listRowBackground(Color.clear)
                        .listRowSeparator(.hidden)
                        .listRowInsets(EdgeInsets(top: 5, leading: 16, bottom: 5, trailing: 0))
                        .swipeActions(edge: .trailing, allowsFullSwipe: true) {
                            Button(role: .destructive) {
                                store.remove(result.page.host)
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
        .scrollDismissesKeyboard(.interactively)
        .animation(.easeInOut(duration: 0.2), value: store.copies)
        .animation(.easeInOut(duration: 0.2), value: searchText)
    }

    private var searchField: some View {
        HStack(spacing: 10) {
            Image(systemName: "magnifyingglass")
                .font(.subheadline.weight(.medium))
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            TextField("Search inside kept pages", text: $searchText)
                .font(.subheadline)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .accessibilityHint("Searches text in offline copies only. Nothing is fetched.")
            if !searchText.isEmpty {
                Button {
                    searchText = ""
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundStyle(.tertiary)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Clear search")
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 11)
        .background(Color.white.opacity(0.07), in: RoundedRectangle(cornerRadius: 13))
    }

    private func searchCount(_ count: Int, query: String) -> some View {
        Text("\(count) \(count == 1 ? "page holds" : "pages hold") \"\(query)\"")
            .font(.footnote.weight(.medium))
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
            .accessibilityAddTraits(.isHeader)
    }

    private func noSearchResults(_ query: String) -> some View {
        VStack(spacing: 10) {
            Image(systemName: "text.magnifyingglass")
                .font(.system(size: 38, weight: .light))
                .foregroundStyle(.tertiary)
                .accessibilityHidden(true)
            Text("No matching pages")
                .font(.headline.weight(.semibold))
            Text("Nothing matched \"\(query)\" in your kept pages.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity)
        .padding(18)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    private func row(_ kept: I2PKeptPage,
                     searchResult: I2POfflineLibrarySearchResult? = nil,
                     query: String = "") -> some View {
        Button {
            open(kept)
        } label: {
            HStack(alignment: .top, spacing: 12) {
                iconTile(kept)
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 8) {
                        Text(kept.host)
                            .font(.system(.subheadline, design: .monospaced).weight(.medium))
                            .foregroundStyle(.primary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Spacer(minLength: 6)
                        keptBadge(kept)
                    }
                    Text(kept.address)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Text(metaLine(kept))
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.tail)
                    if let searchResult {
                        Text(matchedBlocksText(searchResult.matchingBlockCount))
                            .font(.caption2.weight(.medium))
                            .foregroundStyle(accent)
                        Text(highlightedSnippet(searchResult.snippet, query: query))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .truncationMode(.tail)
                    }
                }
                Image(systemName: "chevron.right")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(.tertiary)
                    .padding(.top, 6)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 16))
            .contentShape(RoundedRectangle(cornerRadius: 16))
        }
        .buttonStyle(.plain)
        .padding(.trailing, 16)
        .accessibilityLabel(accessibilityLabel(for: kept, searchResult: searchResult))
    }

    private func matchedBlocksText(_ count: Int) -> String {
        count == 1 ? "1 block matched" : "\(count) blocks matched"
    }

    private func highlightedSnippet(_ snippet: String, query: String) -> AttributedString {
        var text = AttributedString(snippet)
        guard !query.isEmpty else { return text }
        var searchStart = snippet.startIndex
        while searchStart < snippet.endIndex,
              let match = snippet.range(of: query,
                                        options: [.caseInsensitive],
                                        range: searchStart..<snippet.endIndex) {
            guard let lower = AttributedString.Index(match.lowerBound, within: text),
                  let upper = AttributedString.Index(match.upperBound, within: text) else { break }
            text[lower..<upper].foregroundColor = accent
            text[lower..<upper].font = .system(.caption, design: .default, weight: .bold)
            guard match.upperBound > searchStart else { break }
            searchStart = match.upperBound
        }
        return text
    }

    private func accessibilityLabel(for kept: I2PKeptPage,
                                    searchResult: I2POfflineLibrarySearchResult?) -> String {
        var label = "\(kept.host), \(kept.address), \(kept.keptText()), \(metaLine(kept))"
        if let searchResult {
            label += ", \(matchedBlocksText(searchResult.matchingBlockCount)), \(searchResult.snippet)"
        }
        return label
    }

    private func iconTile(_ kept: I2PKeptPage) -> some View {
        Image(systemName: hostKind(kept) == .b33 ? "key.fill" : "globe")
            .font(.system(size: 18, weight: .medium))
            .foregroundStyle(accent)
            .frame(width: 44, height: 44)
            .background(accent.opacity(0.16), in: RoundedRectangle(cornerRadius: 12))
            .accessibilityHidden(true)
    }

    /// The saved host's kind when it is bookmarked, or a kind inferred from the
    /// host suffix for an explicitly kept page.
    private func hostKind(_ kept: I2PKeptPage) -> I2PSavedHostKind {
        if let entry = savedHosts.entries.first(where: { $0.host == kept.host }) {
            return entry.kind
        }
        return kept.host.hasSuffix(".b33.i2p") ? .b33 : .i2pName
    }

    /// When the copy was kept, as a capsule beside the host.
    private func keptBadge(_ kept: I2PKeptPage) -> some View {
        Text(kept.keptBadgeText())
            .font(.caption2.weight(.semibold))
            .foregroundStyle(accent)
            .lineLimit(1)
            .padding(.horizontal, 9)
            .padding(.vertical, 4)
            .background(accent.opacity(0.18), in: Capsule())
            .accessibilityHidden(true)
    }

    /// The copy's readings: the lease route it resolved through, its leases, how
    /// many reader blocks it carries and its size.
    private func metaLine(_ kept: I2PKeptPage) -> String {
        let leases = kept.leaseCount == 1 ? "1 lease" : "\(kept.leaseCount) leases"
        let blocks = kept.blocks.count == 1
            ? "1 reader block"
            : "\(kept.blocks.count) reader blocks"
        return "\(kept.route) · \(leases) · \(blocks) · \(kept.sizeText)"
    }

    private func open(_ kept: I2PKeptPage) {
        onOpen(kept)
        dismiss()
    }

    // MARK: - Empty state

    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "doc.text")
                .font(.system(size: 44, weight: .light))
                .foregroundStyle(.tertiary)
                .accessibilityHidden(true)
            Text("No kept pages yet")
                .font(.headline.weight(.semibold))
            Text("Use Keep offline in any page's header to save it here. Saved hosts also keep their last good fetch automatically.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    private var footnote: some View {
        Text("Copies stay on this device. Deleting one, or clearing the library, leaves saved-host bookmarks alone.")
            .font(.caption2)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 2)
    }
}
