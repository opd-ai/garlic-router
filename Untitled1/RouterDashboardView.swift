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
    /// The sheet showing the RouterInfo this router publishes to the floodfills.
    @State private var showsPublishedRouterInfo = false
    /// The sheet browsing every entry the netdb cache holds.
    @State private var showsNetDBEntries = false
    /// The order the session list is drawn in. Seeded from the run's store so
    /// the choice survives leaving and re-entering the tab, and written back on
    /// every change so it lasts for the life of the app run.
    @State private var sessionSort: I2PSessionSortOrder = I2PSessionSortStore.shared.current

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
                        publishedRouterInfoCard
                        statGrid(snapshot)
                        networkDatabaseCard(snapshot)
                        liveInteropCard(snapshot)
                        b33HostsCard
                        peersCard(snapshot)
                        tunnelsCard(snapshot)
                        routerHealthCard
                        throughputCard(snapshot)
                        lifetimeCard(snapshot)
                        footerText(snapshot)
                    } else if isStarting {
                        startingCard
                            .padding(.top, 40)
                    } else {
                        stoppedCard
                        eepsiteBrowserCard
                        participationCard
                        publishedRouterInfoCard
                        networkDatabaseCard(nil)
                        b33HostsCard
                        routerHealthCard
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
            .sheet(isPresented: $showsPublishedRouterInfo) {
                PublishedRouterInfoView()
            }
            .sheet(isPresented: $showsNetDBEntries) {
                NetDBEntriesView()
            }
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

    // MARK: - Network database

    /// The netdb cache browser: every RouterInfo and LeaseSet this router
    /// holds, by hash. The card names how many there are and how many of them
    /// are floodfills, or — while the router is off — what the screen shows.
    private func networkDatabaseCard(_ snapshot: I2PRouterStatusSnapshot?) -> some View {
        Button {
            showsNetDBEntries = true
        } label: {
            HStack(spacing: 10) {
                Image(systemName: "cylinder.split.1x2")
                    .font(.subheadline)
                    .foregroundStyle(accent)
                    .frame(width: 22)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Network database")
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(.primary)
                    Text("Cached RouterInfos and LeaseSets by hash")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .minimumScaleFactor(0.8)
                    Text(netDBLine(snapshot))
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
        .accessibilityLabel("Network database")
        .accessibilityValue(netDBLine(snapshot))
        .accessibilityHint("Opens every cached RouterInfo and LeaseSet")
    }

    private func netDBLine(_ snapshot: I2PRouterStatusSnapshot?) -> String {
        guard let snapshot else { return "Browse the cached entries" }
        let total = snapshot.routerInfoCount + snapshot.leaseSetCount
        return "\(I2PRouterPlainStatus.count(total, "entry")) · \(I2PRouterPlainStatus.count(snapshot.floodfillCount, "floodfill"))"
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

    // MARK: - Published RouterInfo

    /// The RouterInfo this router advertises to the floodfills. The card names
    /// the publication state; the sheet behind it shows the identity, the
    /// published addresses, the capabilities and options, and whether the
    /// stored signature verifies. Until the router has bootstrapped and
    /// published, the card says so instead of implying an advertisement exists.
    private var publishedRouterInfoCard: some View {
        let publishedAt = I2PRouterAppContext.shared.lastRouterInfoPublishedAt
        let isPublished = publishedAt != nil
        return Button {
            showsPublishedRouterInfo = true
        } label: {
            HStack(spacing: 10) {
                Image(systemName: "person.text.rectangle")
                    .font(.subheadline)
                    .foregroundStyle(accent)
                    .frame(width: 22)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Published RouterInfo")
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(.primary)
                    Text("What this router advertises to the floodfills")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .minimumScaleFactor(0.8)
                    Text(I2PPublishedRouterInfoText.publishedStateLine(publishedAt))
                        .font(.caption2)
                        .foregroundStyle(isPublished ? accent : Color.secondary)
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
        .accessibilityLabel("Published RouterInfo")
        .accessibilityValue(I2PPublishedRouterInfoText.publishedStateLine(publishedAt))
        .accessibilityHint("Opens the RouterInfo this router publishes to the floodfills")
    }

    // MARK: - Peers & sessions

    private func peersCard(_ snapshot: I2PRouterStatusSnapshot) -> some View {
        let pins = I2PPeerPins.shared.pinnedIdentities()
        // The user's own labels, keyed by identity: a labelled row reads by its
        // name with the shortened hash one line below, an unlabelled one is
        // exactly the row it always was.
        let nicknames = I2PPeerNicknames.shared.labels()
        let peers = I2PSessionSorter.sorted(snapshot.peers, by: sessionSort, pinned: pins)
        return VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Text("Peers & Sessions")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .textCase(.uppercase)
                    .accessibilityAddTraits(.isHeader)
                Spacer(minLength: 6)
                sessionSortControl
            }
            Text(I2PPeerPinFormat.orderLine(sessionSort, pinnedCount: pins.count))
                .font(.caption2)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .minimumScaleFactor(0.8)
            if peers.isEmpty {
                Label("No peer connected yet. Peers appear here as soon as a session establishes — the router keeps trying while it runs.",
                      systemImage: "antenna.radiowaves.left.and.right")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                ForEach(peers) { peer in
                    NavigationLink {
                        PeerDetailView(summary: peer)
                    } label: {
                        peerRow(peer,
                                pinned: pins.contains(peer.id.lowercased()),
                                nickname: nicknames[peer.id.lowercased()])
                    }
                    .buttonStyle(.plain)
                    .accessibilityHint("Opens this peer's details")
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    /// The session list's sort control: four orders, the one in effect marked
    /// in the menu. Picking one applies it at once and keeps it for this run.
    private var sessionSortControl: some View {
        Menu {
            ForEach(I2PSessionSortOrder.allCases) { order in
                Button {
                    sessionSort = order
                    I2PSessionSortStore.shared.current = order
                } label: {
                    Label {
                        Text(order.title)
                    } icon: {
                        Image(systemName: order == sessionSort ? "checkmark" : order.systemImage)
                    }
                }
            }
        } label: {
            HStack(spacing: 4) {
                Image(systemName: "arrow.up.arrow.down")
                    .font(.caption2.weight(.semibold))
                Text("Sort")
                    .font(.caption2.weight(.medium))
            }
            .foregroundStyle(accent)
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(accent.opacity(0.14), in: Capsule())
        }
        .accessibilityLabel("Sort sessions")
        .accessibilityValue(sessionSort.title)
        .accessibilityHint("Orders the session list by session start, bytes received, bytes sent or peer hash")
    }

    private func peerRow(_ peer: I2PPeerSummary, pinned: Bool, nickname: String?) -> some View {
        HStack(spacing: 10) {
            Text(peer.transport)
                .font(.caption2.weight(.bold))
                .foregroundStyle(accent)
                .padding(.horizontal, 7)
                .padding(.vertical, 3)
                .background(accent.opacity(0.14), in: RoundedRectangle(cornerRadius: 7))
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(I2PPeerNicknameFormat.displayName(label: nickname, identityHex: peer.id))
                        .font(.footnote.weight(.medium))
                        .foregroundStyle(.primary)
                        .lineLimit(1)
                    if pinned {
                        pinBadge
                    }
                }
                HStack(spacing: 6) {
                    // A labelled peer keeps its shortened hash on the line below
                    // its name, so it is still identifiable at a glance.
                    if let hashLine = I2PPeerNicknameFormat.hashLine(label: nickname,
                                                                     identityHex: peer.id) {
                        Text(hashLine)
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .layoutPriority(1)
                            .accessibilityLabel("Identity \(hashLine)")
                        Text("·")
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                            .accessibilityHidden(true)
                    }
                    Text("\(formatBytes(peer.bytesIn)) in · \(formatBytes(peer.bytesOut)) out")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .minimumScaleFactor(0.8)
                    if let flag = peer.trafficFlag {
                        trafficFlagBadge(flag)
                    }
                }
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

    /// The small pin a peer carries once it is pinned from its inspector: the
    /// row is one of the rows held above the rest of the list, whatever order is
    /// in effect.
    private var pinBadge: some View {
        HStack(spacing: 3) {
            Image(systemName: I2PPeerPinFormat.badgeSystemImage)
                .font(.system(size: 9, weight: .bold))
                .accessibilityHidden(true)
            Text(I2PPeerPinFormat.badgeTitle)
                .font(.caption2.weight(.bold))
        }
        .foregroundStyle(accent)
        .padding(.horizontal, 6)
        .padding(.vertical, 2)
        .background(accent.opacity(0.16), in: RoundedRectangle(cornerRadius: 6))
        .accessibilityLabel("Pinned peer")
    }

    /// A session that has gone quiet or started flooding, named on its row. The
    /// badge is derived from the peer's traffic history on every snapshot, so it
    /// keeps no state of its own and disappears when the traffic is normal again.
    private func trafficFlagBadge(_ flag: I2PPeerTrafficFlag) -> some View {
        HStack(spacing: 3) {
            Image(systemName: I2PPeerTrafficFlagFormat.badgeSystemImage(flag))
                .font(.system(size: 9, weight: .bold))
                .accessibilityHidden(true)
            Text(I2PPeerTrafficFlagFormat.badgeTitle(flag))
                .font(.caption2.weight(.bold))
        }
        .foregroundStyle(warnOrange)
        .padding(.horizontal, 6)
        .padding(.vertical, 2)
        .background(warnOrange.opacity(0.16), in: RoundedRectangle(cornerRadius: 6))
        .accessibilityLabel("\(I2PPeerTrafficFlagFormat.badgeTitle(flag)) peer")
    }

    private func formatBytes(_ bytes: Int) -> String {
        let value = Double(bytes)
        if value >= 1_048_576 { return String(format: "%.1f MB", value / 1_048_576) }
        if value >= 1024 { return String(format: "%.1f KB", value / 1024) }
        return "\(bytes) B"
    }

    // MARK: - Router health

    private var routerHealthCard: some View {
        NavigationLink {
            RouterHealthView()
        } label: {
            HStack(spacing: 10) {
                Image(systemName: "waveform.path.ecg")
                    .font(.subheadline)
                    .foregroundStyle(accent)
                    .frame(width: 22)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Router health")
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(.primary)
                    Text("Local uptime, availability, peer and tunnel trends")
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
        .accessibilityHint("Opens local router health history")
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

    // MARK: - Lifetime totals

    /// What this run of the router has done since it started: cumulative
    /// traffic, sessions, tunnels and I2NP messages, recomputed from the status
    /// engine on every reading. Deliberately quiet — no sparkline, no axis and
    /// no accent — so it stays a summary under the live cards instead of
    /// competing with the transport and throughput readings above it.
    private func lifetimeCard(_ snapshot: I2PRouterStatusSnapshot) -> some View {
        let totals = snapshot.lifetime
        return card(title: "Lifetime totals") {
            LazyVGrid(columns: [GridItem(.flexible(), alignment: .leading),
                                GridItem(.flexible(), alignment: .leading)],
                      spacing: 12) {
                ForEach(totals.figures) { figure in
                    lifetimeFigure(figure)
                }
            }
            Text(I2PRouterLifetimeTotals.caption)
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Lifetime totals")
        .accessibilityValue(totals.accessibilitySummary)
        .accessibilityAddTraits(.updatesFrequently)
    }

    private func lifetimeFigure(_ figure: I2PRouterLifetimeTotals.Figure) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(figure.title)
                .font(.caption2)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .minimumScaleFactor(0.8)
            Text(figure.value)
                .font(.system(.subheadline, design: .monospaced).weight(.medium))
                .foregroundStyle(.primary.opacity(0.88))
                .lineLimit(1)
                .minimumScaleFactor(0.7)
            Text(figure.caption)
                .font(.caption2)
                .foregroundStyle(.tertiary)
                .lineLimit(1)
                .minimumScaleFactor(0.8)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
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
        I2PPeerNicknameFormat.shortHash(hex)
    }

    private func countdownText(_ seconds: TimeInterval) -> String {
        let total = Int(seconds)
        return String(format: "%d:%02d", total / 60, total % 60)
    }
}
