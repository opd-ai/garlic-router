//
//  RouterDashboardView.swift
//  Live router status dashboard fed by the running router's event stream.
//
//  The first card answers "is it working?" in plain language and offers the
//  one action that helps; the cards below stay the technical detail they were.
//

import SwiftUI

struct RouterDashboardView: View {
    @State private var snapshot: I2PRouterStatusSnapshot?
    /// True from the moment a start is asked for until the first live reading
    /// arrives, so the screen never flashes "Router is off" while the router
    /// is actually opening connections.
    @State private var isStarting = false
    @State private var isLookingForPeers = false
    /// Set when an explicit "look for peers" round comes back with nothing:
    /// a recovery hint instead of a silent no-op.
    @State private var peerAttemptMessage: String?
    /// One subscription for this view's lifetime: the status stream is a
    /// single-consumer sequence, so it is attached once and never cancelled
    /// (a pushed detail screen does not stop the dashboard's readings).
    @State private var streamTask: Task<Void, Never>?

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)
    private let okGreen = Color(red: 0.29, green: 0.87, blue: 0.50)
    private let warnOrange = Color(red: 0.98, green: 0.62, blue: 0.24)

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    if let snapshot {
                        statusCard(snapshot)
                        eepsiteBrowserCard
                        participationCard
                        statGrid(snapshot)
                        liveInteropCard(snapshot)
                        b33HostsCard
                        peersCard(snapshot)
                        tunnelsCard(snapshot)
                        throughputCard(snapshot)
                        footerText(snapshot)
                    } else if isStarting {
                        startingCard
                            .padding(.top, 40)
                    } else {
                        stoppedCard
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
            .onAppear(perform: attachIfRunning)
        }
        .preferredColorScheme(.dark)
    }

    // MARK: - Starting and subscribing

    /// The router runs for the whole process, not for this tab: a router
    /// started from the first-run screen (or left running while another tab was
    /// open) must read as running here instead of offering to start it again.
    private func attachIfRunning() {
        guard I2PRouterAppContext.shared.lifecycleState == .running else { return }
        isStarting = true
        attachToSnapshots()
    }

    private func attachToSnapshots() {
        guard streamTask == nil else { return }
        let engine = I2PRouterAppContext.shared.engine
        streamTask = Task { @MainActor in
            for await update in engine.snapshots {
                snapshot = update
                isStarting = false
            }
        }
    }

    private func startRouter() {
        guard !isStarting else { return }
        isStarting = true
        Task { @MainActor in
            let context = I2PRouterAppContext.shared
            context.start()
            attachToSnapshots()
        }
    }

    /// The action the "looking for peers" reading offers: one deliberate round
    /// of dialing now instead of waiting for the bootstrap cycle's next pass.
    private func lookForPeers() {
        guard !isLookingForPeers else { return }
        isLookingForPeers = true
        peerAttemptMessage = nil
        Task { @MainActor in
            let established = await I2PRouterAppContext.shared.ensureSessions(atLeast: 3, within: 20)
            isLookingForPeers = false
            peerAttemptMessage = established > 0 ? nil
                : "Still no peer after a fresh attempt. Check that this device has internet access; the router keeps retrying on its own."
        }
    }

    // MARK: - Status

    /// The one honest status line: what the router is doing, in plain words,
    /// with the next useful action when there is one.
    private func statusCard(_ snapshot: I2PRouterStatusSnapshot) -> some View {
        let status = I2PRouterPlainStatus.reading(for: snapshot)
        return VStack(alignment: .leading, spacing: 10) {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Circle()
                        .fill(toneColor(status.tone))
                        .frame(width: 8, height: 8)
                    Text(status.headline)
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(toneColor(status.tone))
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 6)
                }
                Text(status.detail)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel(status.accessibilitySummary)
            .accessibilityAddTraits(.updatesFrequently)

            if status.action == .findPeers {
                Button(action: lookForPeers) {
                    Label(isLookingForPeers ? "Looking for peers…" : "Look for peers now",
                          systemImage: isLookingForPeers ? "hourglass" : "arrow.clockwise")
                        .font(.subheadline.weight(.semibold))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                        .background(accent.opacity(0.18), in: RoundedRectangle(cornerRadius: 12))
                }
                .buttonStyle(.plain)
                .tint(accent)
                .disabled(isLookingForPeers)
                .accessibilityHint("Dials the peers closest to this router again")
            }

            if let note = peerAttemptMessage {
                Text(note)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Divider().opacity(0.2)

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
                .accessibilityLabel("Router identity")
                .accessibilityValue(formatHash(snapshot.identityHashHex))

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

    private func toneColor(_ tone: I2PRouterPlainStatus.Tone) -> Color {
        switch tone {
        case .good: return okGreen
        case .waiting: return warnOrange
        case .off: return Color.secondary
        }
    }

    /// Shown from the tap on Start until the first reading: names what is
    /// happening, how long it normally takes and that nothing is blocked.
    private var startingCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                ProgressView()
                    .controlSize(.small)
                    .tint(accent)
                Text("Starting the router…")
                    .font(.subheadline.weight(.semibold))
            }
            Text("Opening connections and looking for the first peers. That usually takes under a minute.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Text("You can switch tabs — the router keeps working while this app is open.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
        .accessibilityElement(children: .combine)
    }

    /// The stopped state as a small first-run screen of its own: what turning it
    /// on means, the single primary action, and where the limits live.
    private var stoppedCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                Circle()
                    .fill(Color.secondary.opacity(0.6))
                    .frame(width: 8, height: 8)
                Text("Router is off")
                    .font(.subheadline.weight(.semibold))
                Spacer(minLength: 6)
            }

            Text("Nothing is sent or received until you start it. The router runs while this app is open; iOS pauses it when you leave.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Button(action: startRouter) {
                Label("Start router", systemImage: "play.fill")
                    .font(.subheadline.weight(.semibold))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 11)
                    .background(accent.opacity(0.22), in: RoundedRectangle(cornerRadius: 12))
                    .overlay(
                        RoundedRectangle(cornerRadius: 12)
                            .strokeBorder(accent.opacity(0.35), lineWidth: 1)
                    )
            }
            .buttonStyle(.plain)
            .tint(accent)
            .accessibilityHint("Joins the I2P network and starts looking for peers")

            Text("Bandwidth caps, quiet hours and whether the router carries other people's tunnels live in Participation.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    // MARK: - Stat grid

    private func statGrid(_ snapshot: I2PRouterStatusSnapshot) -> some View {
        LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 10) {
            statTile("NTCP2 peers", value: "\(snapshot.ntcp2SessionCount)",
                     icon: "link", caption: "live sessions")
            statTile("SSU2 peers", value: "\(snapshot.ssu2SessionCount)",
                     icon: "antenna.radiowaves.left.and.right", caption: "live sessions")
            statTile("Floodfills", value: "\(snapshot.floodfillCount)",
                     icon: "point.3.connected.trianglepath.dotted", caption: "\(snapshot.peerCount) peers known")
            statTile("RouterInfos", value: "\(snapshot.routerInfoCount)",
                     icon: "network", caption: "network database")
            statTile("LeaseSets", value: "\(snapshot.leaseSetCount)",
                     icon: "doc.text", caption: "network database")
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
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(title): \(value), \(caption)")
    }

    // MARK: - Live interoperability

    /// The transport card's way into the live probe: what the last run of
    /// real handshakes against mainnet peers observed, and how many peers a
    /// failed handshake is holding back from the dial paths right now.
    private func liveInteropCard(_ snapshot: I2PRouterStatusSnapshot) -> some View {
        NavigationLink {
            LiveInteropView()
        } label: {
            HStack(spacing: 10) {
                Image(systemName: "arrow.left.arrow.right")
                    .font(.subheadline)
                    .foregroundStyle(accent)
                    .frame(width: 22)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Live interoperability")
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(.primary)
                    Text("Handshake results from the last live probe")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .minimumScaleFactor(0.8)
                    Text(heldBackLine(snapshot))
                        .font(.caption2)
                        .foregroundStyle(snapshot.handshakeHeldBackCount > 0 ? warnOrange : Color.secondary)
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
        .accessibilityHint("Opens the live handshake probe results")
    }

    /// The transport card's count of peers the dial paths are skipping until
    /// their next attempt is due.
    private func heldBackLine(_ snapshot: I2PRouterStatusSnapshot) -> String {
        let count = snapshot.handshakeHeldBackCount
        guard count > 0 else { return "No peer held back by a failed handshake" }
        return "\(I2PRouterPlainStatus.count(count, "peer")) held back after a failed handshake"
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
        .accessibilityHint("Opens the .i2p browser")
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
        .accessibilityHint("Opens the b33 host book")
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
                    Text("Bandwidth caps, quiet hours and the floodfill role")
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
        .accessibilityHint("Opens the participation controls")
    }

    // MARK: - Peers & sessions

    private func peersCard(_ snapshot: I2PRouterStatusSnapshot) -> some View {
        card(title: "Peers & Sessions") {
            if snapshot.peers.isEmpty {
                Label("No peer connected yet. Peers appear here as soon as a session establishes — the router keeps trying while it runs.",
                      systemImage: "antenna.radiowaves.left.and.right")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                ForEach(snapshot.peers) { peer in
                    NavigationLink {
                        PeerDetailView(summary: peer)
                    } label: {
                        peerRow(peer)
                    }
                    .buttonStyle(.plain)
                    .accessibilityHint("Opens this peer's details")
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
                            .accessibilityLabel("Floodfill")
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
        .accessibilityElement(children: .combine)
    }

    private func formatBytes(_ bytes: Int) -> String {
        let value = Double(bytes)
        if value >= 1_048_576 { return String(format: "%.1f MB", value / 1_048_576) }
        if value >= 1024 { return String(format: "%.1f KB", value / 1024) }
        return "\(bytes) B"
    }

    // MARK: - Tunnels

    private func tunnelsCard(_ snapshot: I2PRouterStatusSnapshot) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            NavigationLink {
                TunnelHealthView()
            } label: {
                HStack(spacing: 6) {
                    Text("Tunnel Pools")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                        .textCase(.uppercase)
                    Spacer(minLength: 6)
                    Text("Health")
                        .font(.caption2.weight(.medium))
                        .foregroundStyle(accent)
                    Image(systemName: "chevron.right")
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(.secondary)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityHint("Opens tunnel health: build success, latency and pool timelines")
            ForEach(snapshot.pools, id: \.direction) { pool in
                poolSection(pool)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
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
            Text("No tunnels yet — builds start once the router has a few peers.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
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
                .fill(remaining > 300 ? okGreen : warnOrange)
                .frame(width: 7, height: 7)
                .accessibilityHidden(true)
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
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(tunnel.hopCount) hops, \(remaining > 300 ? "healthy" : "expiring soon"), expires in \(countdownText(max(0, remaining)))")
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
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(label)bound: \(value) messages, \(String(format: "%.1f", rate)) per second")
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
        .accessibilityHidden(true)
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
                .accessibilityAddTraits(.isHeader)
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

    private func countdownText(_ seconds: TimeInterval) -> String {
        let total = Int(seconds)
        return String(format: "%d:%02d", total / 60, total % 60)
    }
}
