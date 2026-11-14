//
//  RouterDashboardView.swift
//  Live router status dashboard fed by the running router's event stream.
//

import SwiftUI

struct RouterDashboardView: View {
    @State private var snapshot: I2PRouterStatusSnapshot?
    @State private var isStarting = false

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    if let snapshot {
                        headerCard(snapshot)
                        eepsiteBrowserCard
                        participationCard
                        statGrid(snapshot)
                        b33HostsCard
                        peersCard(snapshot)
                        tunnelsCard(snapshot)
                        throughputCard(snapshot)
                        footerText(snapshot)
                    } else if isStarting {
                        ProgressView("Starting router…")
                            .padding(.top, 80)
                    } else {
                        card(title: "Router is stopped") {
                            Text("The router starts only when you ask, keeping app launch light and predictable.")
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                            Button(action: startRouter) {
                                Label("Start router", systemImage: "play.fill")
                                    .font(.subheadline.weight(.semibold))
                                    .frame(maxWidth: .infinity)
                                    .padding(.vertical, 10)
                                    .background(accent.opacity(0.18), in: RoundedRectangle(cornerRadius: 12))
                            }
                            .buttonStyle(.plain)
                            .tint(accent)
                        }
                        eepsiteBrowserCard
                        participationCard
                        b33HostsCard
                    }
                }
                .padding(.horizontal, 16)
                .padding(.top, 4)
                .padding(.bottom, 24)
            }
            .background(background.ignoresSafeArea())
            .navigationTitle("Router")
            .navigationBarTitleDisplayMode(.large)
        }
        .preferredColorScheme(.dark)
    }

    private func startRouter() {
        guard !isStarting else { return }
        isStarting = true
        Task { @MainActor in
            let context = I2PRouterAppContext.shared
            context.start()
            for await update in context.engine.snapshots {
                snapshot = update
                isStarting = false
            }
        }
    }

    // MARK: - Header

    private func headerCard(_ snapshot: I2PRouterStatusSnapshot) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Circle().fill(Color.green).frame(width: 8, height: 8)
                Text("Router live")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(Color.green)
                Spacer()
                Text(uptimeText(snapshot.uptime))
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }

            Text("Router identity")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .textCase(.uppercase)

            Text(formatHash(snapshot.identityHashHex))
                .font(.system(.footnote, design: .monospaced).weight(.medium))
                .lineLimit(1)
                .minimumScaleFactor(0.5)
                .padding(.vertical, 8)
                .padding(.horizontal, 12)
                .frame(maxWidth: .infinity)
                .background(accent.opacity(0.12), in: RoundedRectangle(cornerRadius: 12))

            if snapshot.isLocalFloodfill {
                Label("Floodfill router", systemImage: "point.3.connected.trianglepath.dotted")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(accent)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    // MARK: - Stat grid

    private func statGrid(_ snapshot: I2PRouterStatusSnapshot) -> some View {
        LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 10) {
            statTile("NTCP2 sessions", value: "\(snapshot.ntcp2SessionCount)",
                     icon: "link", caption: "established")
            statTile("Floodfills", value: "\(snapshot.floodfillCount)",
                     icon: "point.3.connected.trianglepath.dotted", caption: "\(snapshot.peerCount) peers known")
            statTile("RouterInfos", value: "\(snapshot.routerInfoCount)",
                     icon: "network", caption: "netdb entries")
            statTile("LeaseSets", value: "\(snapshot.leaseSetCount)",
                     icon: "doc.text", caption: "netdb entries")
        }
    }

    private func statTile(_ title: String, value: String, icon: String, caption: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Label(title, systemImage: icon)
                .font(.caption2.weight(.semibold))
                .foregroundStyle(.secondary)
            Text(value)
                .font(.system(.title2, design: .rounded).weight(.bold))
                .foregroundStyle(accent)
            Text(caption)
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(14)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 16))
    }

    // MARK: - Eepsite browser

    /// The in-app eepsite browser: .i2p pages fetched through this router's
    /// outbound tunnel pool and rendered natively.
    private var eepsiteBrowserCard: some View {
        NavigationLink {
            EepsiteBrowserView()
        } label: {
            HStack(spacing: 12) {
                Image(systemName: "globe")
                    .font(.title3)
                    .foregroundStyle(accent)
                    .frame(width: 32, height: 32)
                    .background(accent.opacity(0.14), in: RoundedRectangle(cornerRadius: 10))
                VStack(alignment: .leading, spacing: 3) {
                    Text("Eepsite Browser")
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(.primary)
                    Text("Browse .i2p pages over this router's tunnels")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .minimumScaleFactor(0.8)
                }
                Spacer(minLength: 6)
                Image(systemName: "chevron.right")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(16)
            .background(accent.opacity(0.10), in: RoundedRectangle(cornerRadius: 18))
            .overlay(
                RoundedRectangle(cornerRadius: 18)
                    .strokeBorder(accent.opacity(0.25), lineWidth: 1)
            )
        }
        .buttonStyle(.plain)
    }

    // MARK: - b33 host book

    /// The b33 host book: the blinded destinations the router knows about,
    /// which ones its credentials unlock, and their last lease resolution.
    private var b33HostsCard: some View {
        NavigationLink {
            B33HostsView()
        } label: {
            HStack(spacing: 10) {
                Image(systemName: "book.closed")
                    .font(.subheadline)
                    .foregroundStyle(accent)
                    .frame(width: 22)
                VStack(alignment: .leading, spacing: 2) {
                    Text("b33 Hosts")
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(.primary)
                    Text("Blinded destinations · credentials, leases and resolution")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .minimumScaleFactor(0.8)
                }
                Spacer(minLength: 6)
                Image(systemName: "chevron.right")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(16)
            .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
        }
        .buttonStyle(.plain)
    }

    // MARK: - Participation controls

    /// The network-participation controls: bandwidth caps, tunnel share and the
    /// floodfill role, each with its live measured value.
    private var participationCard: some View {
        NavigationLink {
            ParticipationView()
        } label: {
            HStack(spacing: 10) {
                Image(systemName: "slider.horizontal.3")
                    .font(.subheadline)
                    .foregroundStyle(accent)
                    .frame(width: 22)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Participation")
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(.primary)
                    Text("Bandwidth caps, tunnel share and floodfill role")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .minimumScaleFactor(0.8)
                }
                Spacer(minLength: 6)
                Image(systemName: "chevron.right")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(16)
            .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
        }
        .buttonStyle(.plain)
    }

    // MARK: - Peers & sessions

    private func peersCard(_ snapshot: I2PRouterStatusSnapshot) -> some View {
        card(title: "Peers & Sessions") {
            if snapshot.peers.isEmpty {
                Label("No peer sessions yet — sessions appear once transports establish",
                      systemImage: "antenna.radiowaves.left.and.right")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(snapshot.peers) { peer in
                    NavigationLink {
                        PeerDetailView(summary: peer)
                    } label: {
                        peerRow(peer)
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }

    private func peerRow(_ peer: I2PPeerSummary) -> some View {
        HStack(spacing: 10) {
            Text(peer.transport)
                .font(.caption2.weight(.bold))
                .foregroundStyle(accent)
                .padding(.horizontal, 7)
                .padding(.vertical, 3)
                .background(accent.opacity(0.14), in: RoundedRectangle(cornerRadius: 7))
            VStack(alignment: .leading, spacing: 2) {
                Text(formatHash(peer.id))
                    .font(.footnote.weight(.medium))
                    .foregroundStyle(.primary)
                Text("\(formatBytes(peer.bytesIn)) in · \(formatBytes(peer.bytesOut)) out")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 2) {
                HStack(spacing: 4) {
                    if peer.isFloodfill {
                        Image(systemName: "point.3.connected.trianglepath.dotted")
                            .font(.caption2)
                            .foregroundStyle(accent)
                    }
                    Text("bucket \(peer.kademliaBucket)")
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
                if let role = peer.tunnelRole {
                    Text(role)
                        .font(.caption2)
                        .foregroundStyle(accent)
                }
            }
            Image(systemName: "chevron.right")
                .font(.caption2.weight(.semibold))
                .foregroundStyle(.secondary)
        }
        .padding(.vertical, 2)
    }

    private func formatBytes(_ bytes: Int) -> String {
        let value = Double(bytes)
        if value >= 1_048_576 { return String(format: "%.1f MB", value / 1_048_576) }
        if value >= 1024 { return String(format: "%.1f KB", value / 1024) }
        return "\(bytes) B"
    }

    // MARK: - Tunnels

    private func tunnelsCard(_ snapshot: I2PRouterStatusSnapshot) -> some View {
        card(title: "Tunnel Pools") {
            ForEach(snapshot.pools, id: \.direction) { pool in
                poolSection(pool)
            }
        }
    }

    @ViewBuilder
    private func poolSection(_ pool: I2PRouterStatusSnapshot.PoolSummary) -> some View {
        HStack(spacing: 8) {
            Text(pool.direction.capitalized)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .textCase(.uppercase)
            Spacer()
            Text("\(pool.tunnels.count) active")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        if pool.tunnels.isEmpty {
            Text("No tunnels yet — builds start once peers are known")
                .font(.caption2)
                .foregroundStyle(.secondary)
        } else {
            ForEach(pool.tunnels) { tunnel in
                tunnelRow(tunnel)
            }
        }
    }

    private func tunnelRow(_ tunnel: I2PRouterStatusSnapshot.TunnelSummary) -> some View {
        let remaining = tunnel.expiresAt.timeIntervalSince(snapshotDate)
        return HStack(spacing: 10) {
            Circle()
                .fill(remaining > 300 ? Color.green : Color.orange)
                .frame(width: 7, height: 7)
            Text("\(tunnel.hopCount) hops")
                .font(.footnote.weight(.medium))
            if let latency = tunnel.buildLatency {
                Text(String(format: "%.1fs build", latency))
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Text("expires in \(countdownText(max(0, remaining)))")
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)
        }
    }

    private var snapshotDate: Date {
        snapshot?.capturedAt ?? Date()
    }

    // MARK: - Throughput

    private func throughputCard(_ snapshot: I2PRouterStatusSnapshot) -> some View {
        card(title: "Message Throughput") {
            HStack(spacing: 16) {
                throughputColumn(label: "In", value: snapshot.messagesIn, rate: snapshot.inRate)
                throughputColumn(label: "Out", value: snapshot.messagesOut, rate: snapshot.outRate)
            }
            sparkline(history: snapshot.inRateHistory)
            Text("Routed I2NP messages per second over the last \(max(1, snapshot.inRateHistory.count))s")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
    }

    private func throughputColumn(label: String, value: Int, rate: Double) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.caption2.weight(.semibold))
                .foregroundStyle(.secondary)
                .textCase(.uppercase)
            Text("\(value)")
                .font(.system(.title3, design: .rounded).weight(.bold))
            Text(String(format: "%.1f msg/s", rate))
                .font(.caption2)
                .foregroundStyle(accent)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func sparkline(history: [Double]) -> some View {
        let maxValue = max(history.max() ?? 1, 1)
        let bars = history.isEmpty ? [Double](repeating: 0, count: 12) : history
        return HStack(alignment: .bottom, spacing: 3) {
            ForEach(bars.indices, id: \.self) { index in
                Capsule()
                    .fill(accent.opacity(0.75))
                    .frame(width: 7, height: max(3, min(44, bars[index] / maxValue * 44)))
            }
        }
        .frame(height: 46, alignment: .bottom)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func footerText(_ snapshot: I2PRouterStatusSnapshot) -> some View {
        Text("Live · updated \(snapshot.capturedAt.formatted(date: .omitted, time: .standard))")
            .font(.caption2)
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity)
    }

    // MARK: - Shared card style

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

    // MARK: - Formatting

    private func formatHash(_ hex: String) -> String {
        guard hex.count > 20 else { return hex }
        return "\(hex.prefix(10))…\(hex.suffix(10))"
    }

    private func uptimeText(_ seconds: TimeInterval) -> String {
        let total = Int(seconds)
        if total >= 3600 { return "up \(total / 3600)h \((total % 3600) / 60)m" }
        return "up \(total / 60)m \(total % 60)s"
    }

    private func countdownText(_ seconds: TimeInterval) -> String {
        let total = Int(seconds)
        return String(format: "%d:%02d", total / 60, total % 60)
    }
}
