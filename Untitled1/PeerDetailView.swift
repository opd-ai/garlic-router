//
//  PeerDetailView.swift
//  Per-peer inspector opened from the router dashboard's session list:
//  identity hash, transport, session uptime, bytes exchanged in each
//  direction, Kademlia XOR distance, and floodfill / tunnel participation.
//

import SwiftUI

struct PeerDetailView: View {
    @State private var peer: I2PPeerSummary

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)

    private var engine: I2PRouterStatusEngine {
        I2PRouterAppContext.shared.engine
    }

    init(summary: I2PPeerSummary) {
        _peer = State(initialValue: summary)
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                headerCard
                identityCard
                sessionCard
                kademliaCard
                participationCard
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