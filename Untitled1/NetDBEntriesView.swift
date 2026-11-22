//
//  NetDBEntriesView.swift
//  The network database browser, opened from the Router dashboard: every entry
//  the netdb cache holds, freshest first, with a hash search, the RouterInfo /
//  LeaseSet split, and a detail sheet behind each row.
//
//  The screen reads the cache the running router's network database holds — no
//  lookup is issued to show it — so a row is an entry this router already
//  accepted and verified.
//

import SwiftUI

struct NetDBEntriesView: View {
    @Environment(\.dismiss) private var dismiss

    @State private var entries: [I2PNetDBEntrySummary] = []
    @State private var query = ""
    @State private var filter: I2PNetDBEntrySummary.Filter = .all
    @State private var selectedDetail: I2PNetDBEntryDetail?
    /// Set when a tapped row left the cache before its detail was read.
    @State private var openFailure: String?
    @State private var isLoading = true
    @State private var now = Date()

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)
    private let okGreen = Color(red: 0.29, green: 0.87, blue: 0.50)
    private let warnOrange = Color(red: 0.98, green: 0.62, blue: 0.24)

    /// The live refresh cadence while the screen is open: the netdb gains and
    /// prunes entries constantly, and a stale list would claim entries the
    /// cache no longer holds.
    private static let refreshInterval: TimeInterval = 4

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                header
                if let openFailure {
                    Text(openFailure)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                searchField
                filterControl
                content
            }
            .padding(.horizontal, 16)
            .padding(.top, 18)
            .padding(.bottom, 28)
        }
        .background(background.ignoresSafeArea())
        .preferredColorScheme(.dark)
        .sheet(item: $selectedDetail) { detail in
            NetDBEntryDetailSheet(detail: detail)
        }
        .task {
            await load()
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(Self.refreshInterval))
                guard !Task.isCancelled else { return }
                await load()
            }
        }
    }

    // MARK: - Loading

    private func load() async {
        let listing = await I2PRouterAppContext.shared.mainnetNetDB.browseEntries()
        now = Date()
        entries = listing
        isLoading = false
    }

    // MARK: - Header

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Text("Network database")
                    .font(.largeTitle.weight(.bold))
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.7)
                Spacer(minLength: 6)
                Button {
                    dismiss()
                } label: {
                    Text("Done")
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(.white)
                        .padding(.horizontal, 16)
                        .padding(.vertical, 8)
                        .background(accent, in: Capsule())
                }
                .buttonStyle(.plain)
                .accessibilityHint("Closes the network database")
            }

            Text(I2PNetDBEntryText.header(entries, now: now))
                .font(.footnote)
                .foregroundStyle(.secondary)
                .accessibilityLabel(I2PNetDBEntryText.header(entries, now: now))
        }
    }

    // MARK: - Search

    private var searchField: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass")
                .font(.subheadline)
                .foregroundStyle(.secondary)
            TextField("Search hash", text: $query)
                .font(.subheadline)
                .foregroundStyle(.primary)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .submitLabel(.search)
            if !query.isEmpty {
                Button {
                    query = ""
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Clear the search")
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 14))
    }

    // MARK: - Filter

    private var filterControl: some View {
        HStack(spacing: 4) {
            ForEach(I2PNetDBEntrySummary.Filter.allCases) { option in
                let isSelected = filter == option
                Button {
                    withAnimation(.easeOut(duration: 0.16)) {
                        filter = option
                    }
                } label: {
                    Text(option.rawValue)
                        .font(.subheadline.weight(isSelected ? .semibold : .regular))
                        .foregroundStyle(isSelected ? Color.white : Color.secondary)
                        .lineLimit(1)
                        .minimumScaleFactor(0.8)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 9)
                        .background {
                            if isSelected {
                                RoundedRectangle(cornerRadius: 12).fill(accent)
                            }
                        }
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(isSelected ? .isSelected : [])
            }
        }
        .padding(4)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 16))
    }

    // MARK: - List

    @ViewBuilder
    private var content: some View {
        if isLoading && entries.isEmpty {
            HStack(spacing: 10) {
                ProgressView().controlSize(.small).tint(accent)
                Text("Reading the cache…")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(16)
            .background(cardBackground)
        } else if entries.isEmpty {
            emptyCard
        } else if visibleEntries.isEmpty {
            noMatchesCard
        } else {
            LazyVStack(spacing: 10) {
                ForEach(visibleEntries) { summary in
                    row(summary)
                }
            }
        }
    }

    /// The list narrowed by the search field and the segmented control, over
    /// the full hash of each entry.
    private var visibleEntries: [I2PNetDBEntrySummary] {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return entries.filter { summary in
            guard filter.includes(summary.kind) else { return false }
            return needle.isEmpty || summary.id.contains(needle)
        }
    }

    private func row(_ summary: I2PNetDBEntrySummary) -> some View {
        Button {
            open(summary)
        } label: {
            HStack(spacing: 12) {
                Text(summary.kind.badge)
                    .font(.caption.weight(.bold))
                    .foregroundStyle(summary.kind == .routerInfo ? accent : Color.secondary)
                    .frame(width: 44, height: 40)
                    .background(
                        RoundedRectangle(cornerRadius: 10)
                            .strokeBorder((summary.kind == .routerInfo ? accent : Color.white)
                                .opacity(0.45), lineWidth: 1)
                    )
                    .accessibilityHidden(true)

                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 8) {
                        Text(summary.shortHash)
                            .font(.system(.headline, design: .rounded).weight(.semibold))
                            .foregroundStyle(.primary)
                            .lineLimit(1)
                        if summary.isFloodfill {
                            Text("floodfill")
                                .font(.caption2.weight(.semibold))
                                .foregroundStyle(accent)
                                .padding(.horizontal, 8)
                                .padding(.vertical, 3)
                                .background(accent.opacity(0.18), in: Capsule())
                        }
                        Spacer(minLength: 0)
                    }
                    Text(I2PNetDBEntryText.rowDetail(summary, now: now))
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .minimumScaleFactor(0.85)
                }

                Image(systemName: "chevron.right")
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 13)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(cardBackground, in: RoundedRectangle(cornerRadius: 16))
            .contentShape(RoundedRectangle(cornerRadius: 16))
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(accessibilityRow(summary))
        .accessibilityHint("Opens the entry's full hash, timing and payload")
    }

    private func accessibilityRow(_ summary: I2PNetDBEntrySummary) -> String {
        var parts = [summary.typeLabel, summary.shortHash]
        if summary.isFloodfill { parts.append("floodfill") }
        parts.append("published " + I2PNetDBEntryText.age(summary.publishedAt, now: now))
        parts.append(summary.countText)
        return parts.joined(separator: ", ")
    }

    private func open(_ summary: I2PNetDBEntrySummary) {
        Task { @MainActor in
            if let detail = await I2PRouterAppContext.shared.mainnetNetDB
                .browseDetail(keyHex: summary.id) {
                openFailure = nil
                selectedDetail = detail
            } else {
                openFailure = "\(summary.shortHash) left the cache before its detail could be read."
            }
        }
    }

    // MARK: - Empty states

    private var emptyCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Nothing cached yet", systemImage: "cylinder.split.1x2")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(accent)
            Text("Entries arrive once the router has bootstrapped. Verified RouterInfos and LeaseSets then stay in this cache for about an hour.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(cardBackground, in: RoundedRectangle(cornerRadius: 18))
        .accessibilityElement(children: .combine)
    }

    private var noMatchesCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("No entry matches", systemImage: "magnifyingglass")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(.secondary)
            Text(query.isEmpty
                 ? "The cache holds no \(filter == .routerInfos ? "RouterInfo" : "LeaseSet") right now."
                 : "No cached hash contains “\(query)”. The search matches the hex hash only.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if !query.isEmpty || filter != .all {
                Button {
                    withAnimation(.easeOut(duration: 0.16)) {
                        query = ""
                        filter = .all
                    }
                } label: {
                    Text("Show everything")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(accent)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 7)
                        .background(accent.opacity(0.16), in: Capsule())
                }
                .buttonStyle(.plain)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(cardBackground, in: RoundedRectangle(cornerRadius: 18))
    }

    // MARK: - Shared card style

    private var cardBackground: Color {
        Color.white.opacity(0.06)
    }
}

// MARK: - Detail sheet

/// One entry, read from the cache when its row was tapped: the full hash, the
/// publication and expiry it carries, the parsed addresses or leases, and
/// whether the stored signature verifies against the entry's own identity.
struct NetDBEntryDetailSheet: View {
    @Environment(\.dismiss) private var dismiss

    let detail: I2PNetDBEntryDetail

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)
    private let okGreen = Color(red: 0.29, green: 0.87, blue: 0.50)
    private let warnOrange = Color(red: 0.98, green: 0.62, blue: 0.24)

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                header
                identityCard
                timingCard
                if detail.kind == .routerInfo {
                    addressesCard
                    capabilitiesCard
                } else {
                    leasesCard
                }
                Text("Read from the netdb cache. Nothing is fetched to show this sheet.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.top, 2)
            }
            .padding(.horizontal, 16)
            .padding(.top, 18)
            .padding(.bottom, 28)
        }
        .background(background.ignoresSafeArea())
        .preferredColorScheme(.dark)
    }

    // MARK: - Header

    private var header: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(detail.kind.title)
                .font(.largeTitle.weight(.bold))
                .foregroundStyle(.primary)
                .lineLimit(1)
                .minimumScaleFactor(0.7)
            Spacer(minLength: 6)
            Button {
                dismiss()
            } label: {
                Text("Done")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.white)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 8)
                    .background(accent, in: Capsule())
            }
            .buttonStyle(.plain)
            .accessibilityHint("Closes this entry")
        }
    }

    // MARK: - Identity

    private var identityCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                Text(detail.kind.badge)
                    .font(.caption.weight(.bold))
                    .foregroundStyle(accent)
                    .frame(width: 34, height: 30)
                    .background(
                        RoundedRectangle(cornerRadius: 8)
                            .strokeBorder(accent.opacity(0.5), lineWidth: 1)
                    )
                    .accessibilityHidden(true)
                Text(detail.typeLabel)
                    .font(.headline)
                Spacer(minLength: 6)
                if detail.isFloodfill {
                    Text("floodfill")
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(accent)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .background(accent.opacity(0.18), in: Capsule())
                }
            }

            Text(detail.hashHex)
                .font(.system(.caption, design: .monospaced).weight(.medium))
                .lineSpacing(3)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
                .padding(.vertical, 10)
                .padding(.horizontal, 12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(accent.opacity(0.12), in: RoundedRectangle(cornerRadius: 12))
                .accessibilityLabel("Full hash")
                .accessibilityValue(detail.hashHex)

            Text("SHA-256 of the entry's identity — its key in the netdb")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    // MARK: - Timing

    private var timingCard: some View {
        card(title: "Publication") {
            timingRow("Published",
                      value: I2PNetDBEntryText.absolute(detail.publishedAt),
                      note: I2PNetDBEntryText.age(detail.publishedAt))
            Divider().opacity(0.15)
            timingRow("Expires",
                      value: I2PNetDBEntryText.absolute(detail.expiresAt),
                      note: I2PNetDBEntryText.expiry(detail.expiresAt),
                      tone: detail.expiresAt <= Date() ? warnOrange : nil)
            Divider().opacity(0.15)
            HStack(spacing: 8) {
                Text("Signature")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                Spacer(minLength: 8)
                Text(detail.signatureVerified ? "Verified at ingest" : "Does not verify")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(detail.signatureVerified ? okGreen : warnOrange)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 4)
                    .background((detail.signatureVerified ? okGreen : warnOrange).opacity(0.16),
                                in: Capsule())
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Signature: \(detail.signatureVerified ? "verified at ingest" : "does not verify")")

            HStack {
                Text("Payload")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                Spacer(minLength: 8)
                Text(payloadText)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Payload \(payloadText)")
        }
    }

    private var payloadText: String {
        let bytes = detail.payloadBytes
        if bytes >= 1024 { return String(format: "%.1f KB", Double(bytes) / 1024) }
        return "\(bytes) B"
    }

    private func timingRow(_ label: String, value: String, note: String,
                           tone: Color? = nil) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(label)
                .font(.footnote)
                .foregroundStyle(.secondary)
            Spacer(minLength: 8)
            VStack(alignment: .trailing, spacing: 2) {
                Text(value)
                    .font(.system(.footnote, design: .monospaced))
                    .foregroundStyle(.primary)
                Text(note)
                    .font(.caption2)
                    .foregroundStyle(tone ?? Color.secondary)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(label): \(value), \(note)")
    }

    // MARK: - Addresses

    private var addressesCard: some View {
        card(title: "Addresses") {
            if detail.endpoints.isEmpty {
                Text("No address carried yet — an unpublished RouterInfo lists none.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                ForEach(Array(detail.endpoints.enumerated()), id: \.offset) { index, endpoint in
                    if index > 0 { Divider().opacity(0.15) }
                    addressRow(endpoint)
                }
            }
        }
    }

    private func addressRow(_ endpoint: I2PNetDBEntryDetail.Endpoint) -> some View {
        HStack(spacing: 10) {
            Text(endpoint.transport)
                .font(.caption2.weight(.bold))
                .foregroundStyle(accent)
                .padding(.horizontal, 9)
                .padding(.vertical, 4)
                .background(accent.opacity(0.16), in: Capsule())
            VStack(alignment: .leading, spacing: 2) {
                Text(endpoint.endpoint)
                    .font(.system(.footnote, design: .monospaced))
                    .foregroundStyle(.primary)
                Text("cost \(endpoint.cost)"
                     + (endpoint.expiration.map { " · expires \(I2PNetDBEntryText.absolute($0))" } ?? ""))
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(endpoint.transport) at \(endpoint.endpoint), cost \(endpoint.cost)")
    }

    private var capabilitiesCard: some View {
        card(title: "Capabilities") {
            if detail.caps.isEmpty {
                Text("No capabilities advertised.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } else {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        ForEach(Array(detail.caps.enumerated()), id: \.offset) { _, letter in
                            Text(I2PPublishedRouterInfoText.capabilityName(letter))
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(okGreen)
                                .padding(.horizontal, 10)
                                .padding(.vertical, 5)
                                .background(okGreen.opacity(0.14), in: Capsule())
                        }
                    }
                    .padding(.vertical, 1)
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel("Advertised capabilities: \(I2PPublishedRouterInfoText.capabilityList(detail.caps))")
            }
        }
    }

    // MARK: - Leases

    private var leasesCard: some View {
        card(title: "Leases") {
            if let note = detail.leaseNote {
                Text(note)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else if detail.leases.isEmpty {
                Text("No lease carried by this entry.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                ForEach(Array(detail.leases.enumerated()), id: \.offset) { index, lease in
                    if index > 0 { Divider().opacity(0.15) }
                    leaseRow(lease)
                }
            }
        }
    }

    private func leaseRow(_ lease: I2PNetDBEntryDetail.Lease) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(I2PNetDBEntryText.shortHash(lease.gatewayHashHex))
                .font(.system(.footnote, design: .monospaced).weight(.medium))
                .foregroundStyle(.primary)
            Text(String(format: "tunnel 0x%08x", lease.tunnelId))
                .font(.system(.caption2, design: .monospaced))
                .foregroundStyle(.secondary)
            Spacer(minLength: 6)
            Text(I2PNetDBEntryText.expiry(lease.expiration))
                .font(.caption2)
                .foregroundStyle(lease.expiration <= Date() ? warnOrange : Color.secondary)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Lease at gateway \(I2PNetDBEntryText.shortHash(lease.gatewayHashHex)), tunnel \(lease.tunnelId), \(I2PNetDBEntryText.expiry(lease.expiration))")
    }

    // MARK: - Card shell (matches the Router and Peer detail screens)

    private func card(title: String, @ViewBuilder content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title)
                .font(.headline)
                .foregroundStyle(.primary)
                .accessibilityAddTraits(.isHeader)
            content()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }
}
