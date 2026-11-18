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
        Text("Pages kept from your saved hosts' last good fetch — readable even when the router can't reach them.")
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
        return List {
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

            footnote
                .listRowBackground(Color.clear)
                .listRowSeparator(.hidden)
                .listRowInsets(EdgeInsets(top: 10, leading: 16, bottom: 16, trailing: 16))
        }
        .listStyle(.plain)
        .scrollContentBackground(.hidden)
        .animation(.easeInOut(duration: 0.2), value: store.copies)
    }

    private func row(_ kept: I2PKeptPage) -> some View {
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
        .accessibilityLabel("\(kept.host), \(kept.address), \(kept.keptText()), \(metaLine(kept))")
    }

    private func iconTile(_ kept: I2PKeptPage) -> some View {
        Image(systemName: hostKind(kept) == .b33 ? "key.fill" : "globe")
            .font(.system(size: 18, weight: .medium))
            .foregroundStyle(accent)
            .frame(width: 44, height: 44)
            .background(accent.opacity(0.16), in: RoundedRectangle(cornerRadius: 12))
            .accessibilityHidden(true)
    }

    /// The bookmark's kind for the copy's host: a b33 address or a .i2p name.
    /// Every copy belongs to a saved host, so the bookmark is normally there.
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
            Text("We keep the last good fetch of every saved host so you can read it when the router can't reach it. Save a host in the browser, open it once, and it shows up here.")
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
        Text("Copies stay on this device. Deleting one, or clearing the library, leaves the bookmarks alone.")
            .font(.caption2)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 2)
    }
}
