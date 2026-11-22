//
//  PublishedRouterInfoView.swift
//  The RouterInfo this router currently publishes to the floodfills, opened
//  from the dashboard: the local identity hash in full, when it was published,
//  every published address with its transport and host:port, the advertised
//  capabilities and options, and whether the stored signature verifies against
//  the identity.
//
//  The sheet reads the running router's signed RouterInfo directly. Until the
//  router has bootstrapped and published, it shows the empty state that says so
//  instead of the bootstrap placeholder peers never see.
//

import SwiftUI
import UIKit

struct PublishedRouterInfoView: View {
    @Environment(\.dismiss) private var dismiss

    @State private var routerInfo: I2PRouterInfo?
    @State private var publishedAt: Date?
    @State private var identityHashHex = ""
    @State private var signatureVerified = false
    /// A short confirmation after Copy, cleared on its own.
    @State private var copyNotice: String?
    @State private var copyResetTask: Task<Void, Never>?

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)
    private let okGreen = Color(red: 0.29, green: 0.87, blue: 0.50)
    private let warnOrange = Color(red: 0.98, green: 0.62, blue: 0.24)

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    if let routerInfo, publishedAt != nil {
                        identityCard(routerInfo)
                        addressesCard(routerInfo)
                        capabilitiesCard(routerInfo)
                        optionsCard(routerInfo)
                        copyButton(routerInfo)
                        refreshButton
                        if let copyNotice {
                            Text(copyNotice)
                                .font(.caption2.weight(.medium))
                                .foregroundStyle(accent)
                                .frame(maxWidth: .infinity)
                                .transition(.opacity)
                        }
                    } else {
                        emptyCard
                        refreshButton
                    }
                }
                .padding(.horizontal, 16)
                .padding(.top, 6)
                .padding(.bottom, 24)
            }
            .background(background.ignoresSafeArea())
            .navigationTitle("Published RouterInfo")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") {
                        dismiss()
                    }
                    .font(.subheadline.weight(.semibold))
                }
            }
            .tint(accent)
            .onAppear(perform: load)
        }
        .preferredColorScheme(.dark)
    }

    // MARK: - Loading

    /// Re-reads the signed RouterInfo and the publication time from the running
    /// router. The sheet never builds a RouterInfo of its own: what it shows is
    /// exactly what peers receive.
    private func load() {
        let context = I2PRouterAppContext.shared
        let published = context.lastRouterInfoPublishedAt
        let info = context.mainnetSignedRouterInfo

        publishedAt = published
        identityHashHex = I2PPublishedRouterInfoText.hex(context.mainnetRouterHash)
        signatureVerified = info.verifySignature()
        routerInfo = published != nil ? info : nil
    }

    // MARK: - Identity

    private func identityCard(_ info: I2PRouterInfo) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Our identity")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .textCase(.uppercase)
                .accessibilityAddTraits(.isHeader)

            Text(identityHashHex)
                .font(.system(.body, design: .monospaced))
                .lineSpacing(3)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
                .accessibilityLabel("Router identity hash")
                .accessibilityValue(identityHashHex)

            HStack(spacing: 8) {
                Text(I2PPublishedRouterInfoText.publishedStateLine(publishedAt))
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                Spacer(minLength: 8)
                signatureBadge
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(cardBackground)
    }

    private var signatureBadge: some View {
        Text(signatureVerified ? "Signature verified" : "Signature does not verify")
            .font(.caption2.weight(.semibold))
            .foregroundStyle(signatureVerified ? accent : warnOrange)
            .padding(.horizontal, 10)
            .padding(.vertical, 4)
            .background((signatureVerified ? accent : warnOrange).opacity(0.16), in: Capsule())
            .accessibilityLabel(signatureVerified
                                ? "Signature verified"
                                : "Signature does not verify")
    }

    // MARK: - Addresses

    private func addressesCard(_ info: I2PRouterInfo) -> some View {
        card(title: "Addresses") {
            if info.addresses.isEmpty {
                Text("No address published yet.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                ForEach(Array(info.addresses.enumerated()), id: \.offset) { _, address in
                    addressRow(address)
                }
            }
        }
    }

    private func addressRow(_ address: I2PRouterAddress) -> some View {
        HStack(spacing: 10) {
            Text(address.transportStyle)
                .font(.caption2.weight(.bold))
                .foregroundStyle(accent)
                .padding(.horizontal, 9)
                .padding(.vertical, 4)
                .background(accent.opacity(0.16), in: Capsule())
            Text(I2PPublishedRouterInfoText.endpoint(address))
                .font(.system(.footnote, design: .monospaced))
                .foregroundStyle(.primary)
            Spacer(minLength: 0)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(address.transportStyle) at \(I2PPublishedRouterInfoText.endpoint(address))")
    }

    // MARK: - Capabilities

    private func capabilitiesCard(_ info: I2PRouterInfo) -> some View {
        let caps = info.options["caps"] ?? ""
        return card(title: "Capabilities") {
            if caps.isEmpty {
                Text("No capabilities advertised.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } else {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        ForEach(Array(caps.enumerated()), id: \.offset) { _, letter in
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
                .accessibilityLabel("Advertised capabilities: \(I2PPublishedRouterInfoText.capabilityList(caps))")
            }
        }
    }

    // MARK: - Options

    private func optionsCard(_ info: I2PRouterInfo) -> some View {
        let options = info.options.sorted { $0.key < $1.key }
        return card(title: "Options") {
            if options.isEmpty {
                Text("No options published.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(Array(options.enumerated()), id: \.offset) { index, entry in
                    if index > 0 {
                        Divider().opacity(0.15)
                    }
                    HStack(spacing: 12) {
                        Text(entry.key)
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                        Spacer(minLength: 8)
                        Text(entry.value)
                            .font(.system(.footnote, design: .monospaced))
                            .multilineTextAlignment(.trailing)
                    }
                    .accessibilityElement(children: .combine)
                    .accessibilityLabel("\(entry.key): \(entry.value)")
                }
            }
        }
    }

    // MARK: - Controls

    private func copyButton(_ info: I2PRouterInfo) -> some View {
        Button {
            copy(info)
        } label: {
            Text("Copy RouterInfo")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(.white)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
                .background(accent.opacity(0.85), in: RoundedRectangle(cornerRadius: 16))
        }
        .buttonStyle(.plain)
        .accessibilityHint("Copies the published RouterInfo as base64 to the clipboard")
    }

    private var refreshButton: some View {
        Button(action: load) {
            Text("Refresh")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(.primary)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
                .background(Color.white.opacity(0.08), in: RoundedRectangle(cornerRadius: 16))
        }
        .buttonStyle(.plain)
        .accessibilityHint("Re-reads the RouterInfo the running router publishes")
    }

    private func copy(_ info: I2PRouterInfo) {
        UIPasteboard.general.string = info.serialize().base64EncodedString()
        withAnimation(.easeOut(duration: 0.18)) {
            copyNotice = "RouterInfo copied as base64"
        }
        copyResetTask?.cancel()
        copyResetTask = Task { @MainActor in
            try? await Task.sleep(for: .milliseconds(1800))
            guard !Task.isCancelled else { return }
            withAnimation(.easeOut(duration: 0.2)) {
                copyNotice = nil
            }
        }
    }

    // MARK: - Empty state

    /// Shown until the router has published: the bootstrap placeholder peers
    /// never see is not presented as an advertisement.
    private var emptyCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Nothing published yet", systemImage: "questionmark.circle")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(accent)
            Text("This router publishes its RouterInfo to the floodfills once it has bootstrapped and knows its reachable address. Start the router and come back to see what peers are told.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(cardBackground)
        .accessibilityElement(children: .combine)
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
        .background(cardBackground)
    }

    private var cardBackground: some ShapeStyle {
        Color.white.opacity(0.06)
    }
}

// MARK: - Text

/// The wording the published-RouterInfo card and sheet share, plus the readable
/// names of the RouterInfo capability flags.
enum I2PPublishedRouterInfoText {

    /// "Published 4 minutes ago", or the explanation of why nothing is
    /// published yet. Uses the publication timestamp the router recorded when
    /// it last sent its RouterInfo to the floodfills.
    static func publishedStateLine(_ publishedAt: Date?, now: Date = Date()) -> String {
        guard let publishedAt else {
            return "Not published yet — publishes once the router has bootstrapped"
        }
        return "Published " + relativeFormatter.localizedString(for: publishedAt, relativeTo: now)
    }

    /// The host:port an address advertises, or the honest note that the address
    /// carries neither yet (the spec's unpublished RouterAddress shape).
    static func endpoint(_ address: I2PRouterAddress) -> String {
        let host = (address.options["host"] ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let port = (address.options["port"] ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        if !host.isEmpty, !port.isEmpty { return "\(host):\(port)" }
        if !host.isEmpty { return host }
        return "no host or port published"
    }

    /// The readable name of one RouterInfo capability flag, per the netDb
    /// specification's caps table. An unknown flag reads as itself rather than
    /// being hidden.
    static func capabilityName(_ flag: Character) -> String {
        capabilityNames[flag] ?? String(flag)
    }

    static func capabilityList(_ caps: String) -> String {
        caps.map(capabilityName).joined(separator: ", ")
    }

    static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: Private

    /// Capability flags from the netDb specification's RouterInfo "caps" table.
    private static let capabilityNames: [Character: String] = [
        "D": "medium congestion",
        "E": "high congestion",
        "f": "floodfill",
        "G": "rejecting tunnels",
        "H": "hidden",
        "K": "under 12 KB/s",
        "L": "12–48 KB/s",
        "M": "48–64 KB/s",
        "N": "64–128 KB/s",
        "O": "128–256 KB/s",
        "P": "256–2000 KB/s",
        "R": "reachable",
        "U": "unreachable",
        "X": "over 2000 KB/s",
    ]

    private static let relativeFormatter: RelativeDateTimeFormatter = {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .full
        return formatter
    }()
}
