//
//  PeerDetailView.swift
//  Per-peer inspector opened from the router dashboard's session list:
//  identity hash, transport, session uptime, bytes exchanged in each
//  direction, Kademlia XOR distance, and floodfill / tunnel participation.
//

import SwiftUI

struct PeerDetailView: View {
    @State private var peer: I2PPeerSummary
    @State private var blockReason = ""
    @State private var isBlocked: Bool

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)

    private var engine: I2PRouterStatusEngine {
        I2PRouterAppContext.shared.engine
    }

    init(summary: I2PPeerSummary) {
        _peer = State(initialValue: summary)
        _isBlocked = State(initialValue: I2PPeerBlocklist.shared.isBlocked(identityHex: summary.id))
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                headerCard
                identityCard
                sessionCard
                handshakeCard
                kademliaCard
                participationCard
                blockCard
                Text("Live · from the router status engine")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity)
            }
            .padding(.horizontal, 16)
            .padding(.top, 4)
            .padding(.bottom, 24)
        }
        .background(background.ignoresSafeArea())
        .navigationTitle("Peer")
        .navigationBarTitleDisplayMode(.inline)
        .task {
            // Refresh from the status engine directly (the dashboard consumes
            // the shared snapshot stream; polling here keeps both views live).
            while !Task.isCancelled {
                let snapshot = await engine.snapshot()
                if let fresh = snapshot.peers.first(where: { $0.id == peer.id }) {
                    peer = fresh
                }
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    // MARK: - Header

    private var headerCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Circle().fill(Color.green).frame(width: 8, height: 8)
                Text("Session live")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(Color.green)
                Spacer()
                Text(peer.transport)
                    .font(.caption2.weight(.bold))
                    .foregroundStyle(accent)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .background(accent.opacity(0.14), in: RoundedRectangle(cornerRadius: 7))
            }
            Text("Connected \(uptimeText(Date().timeIntervalSince(peer.establishedAt))) ago")
                .font(.system(.title3, design: .rounded).weight(.bold))
                .foregroundStyle(accent)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    // MARK: - Identity

    private var identityCard: some View {
        card(title: "Peer identity") {
            Text(peer.id)
                .font(.system(.caption, design: .monospaced).weight(.medium))
                .textSelection(.enabled)
                .padding(.vertical, 8)
                .padding(.horizontal, 12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(accent.opacity(0.12), in: RoundedRectangle(cornerRadius: 12))
            Text("SHA-256 of the peer's router identity — its key in the netdb")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
    }

    // MARK: - Session

    private var sessionCard: some View {
        card(title: "Session") {
            HStack(spacing: 16) {
                bytesColumn(label: "Received", value: peer.bytesIn)
                bytesColumn(label: "Sent", value: peer.bytesOut)
            }
            HStack {
                Label("Session uptime", systemImage: "clock")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(.secondary)
                Spacer()
                Text(uptimeText(Date().timeIntervalSince(peer.establishedAt)))
                    .font(.system(.caption, design: .monospaced).weight(.semibold))
                    .foregroundStyle(accent)
            }
        }
    }

    private func bytesColumn(label: String, value: Int) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.caption2.weight(.semibold))
                .foregroundStyle(.secondary)
                .textCase(.uppercase)
            Text(formatBytes(value))
                .font(.system(.title3, design: .rounded).weight(.bold))
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    // MARK: - Handshake backoff

    /// The last failed dial of this peer and when the router will try it again.
    /// The profile lives in memory, so a relaunch starts with no history.
    private var handshakeCard: some View {
        card(title: "Handshake") {
            if let reading = peer.handshakeBackoff {
                HStack(spacing: 8) {
                    Image(systemName: "arrow.triangle.2.circlepath")
                        .font(.caption)
                        .foregroundStyle(accent)
                        .accessibilityHidden(true)
                    Text("Last failure")
                        .font(.footnote.weight(.medium))
                    Spacer()
                    Text("\(uptimeText(Date().timeIntervalSince(reading.failedAt))) ago")
                        .font(.system(.caption, design: .monospaced).weight(.semibold))
                        .foregroundStyle(.secondary)
                }
                Text(reading.reason.label)
                    .font(.footnote)
                    .foregroundStyle(accent)
                    .fixedSize(horizontal: false, vertical: true)
                Text(nextAttemptText(reading))
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                Text("No failed dial recorded for this peer since the router started.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    /// Names when the next dial is due, or says why nothing is scheduled.
    private func nextAttemptText(_ reading: I2PPeerHandshakeBackoffReading) -> String {
        guard let due = reading.nextAttemptAt else {
            return "No retry scheduled — the last handshake succeeded and reset the schedule."
        }
        let remaining = due.timeIntervalSinceNow
        if remaining <= 0 { return "Next attempt is due now." }
        let clock = due.formatted(date: .omitted, time: .shortened)
        return "Next attempt in \(uptimeText(remaining)) (at \(clock))."
    }

    // MARK: - Kademlia keyspace

    private var kademliaCard: some View {
        card(title: "Kademlia keyspace") {
            HStack {
                Text("XOR distance")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(.secondary)
                Spacer()
            }
            Text(shortDistance(peer.xorDistanceHex))
                .font(.system(.footnote, design: .monospaced).weight(.medium))
                .textSelection(.enabled)
                .padding(.vertical, 8)
                .padding(.horizontal, 12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(accent.opacity(0.12), in: RoundedRectangle(cornerRadius: 12))
            HStack {
                Text("Kademlia bucket")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                Spacer()
                Text("\(peer.kademliaBucket) leading zero bits")
                    .font(.system(.caption, design: .monospaced).weight(.semibold))
                    .foregroundStyle(accent)
            }
            Text("Distance is our router hash XOR the peer's — how close this peer sits to us in the netdb keyspace")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
    }

    // MARK: - Participation

    private var participationCard: some View {
        card(title: "Network participation") {
            HStack(spacing: 8) {
                Image(systemName: "point.3.connected.trianglepath.dotted")
                    .font(.caption)
                    .foregroundStyle(peer.isFloodfill ? accent : Color.secondary)
                Text("Floodfill router")
                    .font(.footnote.weight(.medium))
                Spacer()
                Text(peer.isFloodfill ? "Yes" : "No")
                    .font(peer.isFloodfill ? .footnote.weight(.semibold) : .footnote)
                    .foregroundStyle(peer.isFloodfill ? accent : Color.secondary)
            }
            Divider().opacity(0.2)
            HStack(spacing: 8) {
                Image(systemName: "point.topleft.down.curvedto.point.bottomright.up")
                    .font(.caption)
                    .foregroundStyle(peer.tunnelRole != nil ? accent : Color.secondary)
                Text("Tunnel participation")
                    .font(.footnote.weight(.medium))
                Spacer()
                Text(peer.tunnelRole ?? "Not in any of our tunnels")
                    .font(peer.tunnelRole != nil ? .footnote.weight(.semibold) : .footnote)
                    .foregroundStyle(peer.tunnelRole != nil ? accent : Color.secondary)
            }
        }
    }

    // MARK: - Blocklist

    private var blockCard: some View {
        card(title: "Blocklist") {
            if isBlocked {
                Label("Blocked — this peer is never used as a tunnel hop or a netdb lookup target, and its session is closed.",
                      systemImage: "nosign")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Text("Unblock it from the Blocked peers section of the Participation screen.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            } else {
                TextField("Reason (optional)", text: $blockReason)
                    .textFieldStyle(.plain)
                    .font(.footnote)
                    .padding(.vertical, 8)
                    .padding(.horizontal, 12)
                    .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 10))
                Button(action: blockPeer) {
                    Label("Block this peer", systemImage: "nosign")
                        .font(.footnote.weight(.semibold))
                        .foregroundStyle(Color.red)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 9)
                        .background(Color.red.opacity(0.18), in: RoundedRectangle(cornerRadius: 10))
                }
                .buttonStyle(.plain)
                Text("Blocks the identity, not just this connection: hop selection and netdb lookups skip it and the router never dials it again.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func blockPeer() {
        I2PPeerBlocklist.shared.block(identityHex: peer.id, reason: blockReason)
        blockReason = ""
        isBlocked = true
        Task { await I2PRouterAppContext.shared.enforcePeerBlocklist() }
    }

    // MARK: - Helpers

    private func card(title: String, @ViewBuilder content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .textCase(.uppercase)
            content()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    private func formatBytes(_ bytes: Int) -> String {
        let value = Double(bytes)
        if value >= 1_048_576 { return String(format: "%.1f MB", value / 1_048_576) }
        if value >= 1024 { return String(format: "%.1f KB", value / 1024) }
        return "\(bytes) B"
    }

    private func uptimeText(_ seconds: TimeInterval) -> String {
        let total = max(0, Int(seconds))
        if total >= 3600 { return "\(total / 3600)h \((total % 3600) / 60)m \((total % 3600) % 60)s" }
        if total >= 60 { return "\(total / 60)m \(total % 60)s" }
        return "\(total)s"
    }

    private func shortDistance(_ hex: String) -> String {
        guard hex.count > 24 else { return hex }
        return "\(hex.prefix(24))…"
    }
}