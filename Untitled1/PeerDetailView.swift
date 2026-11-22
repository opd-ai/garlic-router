//
//  PeerDetailView.swift
//  Per-peer inspector opened from the router dashboard's session list:
//  identity hash, transport, session uptime, bytes exchanged in each
//  direction, the session's traffic history, Kademlia XOR distance, and
//  floodfill / tunnel participation.
//

import SwiftUI
import Charts

struct PeerDetailView: View {
    @State private var peer: I2PPeerSummary
    @State private var blockReason = ""
    @State private var isBlocked: Bool
    /// Whether this identity is pinned to the top of the dashboard's session
    /// list. The pin lives in the store keyed by identity, so it outlives the
    /// session and is read back from there on every step.
    @State private var isPinned: Bool
    /// The label the user gave this identity, and the field's draft of it. The
    /// label lives in the store keyed by identity, so it outlives the session
    /// and is what this screen's title reads.
    @State private var nickname: String?
    @State private var nicknameDraft: String
    /// The peer's per-second traffic readings, sampled from the status engine.
    @State private var trafficSamples: [I2PPeerTrafficSample] = []
    @State private var trafficAverage = I2PPeerTrafficAverage.zero
    @State private var trafficCapturedAt = Date()
    @State private var trafficExpanded = false

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)
    /// Received is the app's violet; sent is the cool teal the participation
    /// screen uses for the outbound direction.
    private let receivedTint = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let sentTint = Color(red: 0.36, green: 0.80, blue: 0.85)
    /// The amber the dashboard's session row uses for a quiet or flooding peer,
    /// so the inspector's line reads as the same condition.
    private let flagTint = Color(red: 0.98, green: 0.62, blue: 0.24)

    private var engine: I2PRouterStatusEngine {
        I2PRouterAppContext.shared.engine
    }

    init(summary: I2PPeerSummary) {
        let storedLabel = I2PPeerNicknames.shared.label(identityHex: summary.id)
        _peer = State(initialValue: summary)
        _isBlocked = State(initialValue: I2PPeerBlocklist.shared.isBlocked(identityHex: summary.id))
        _isPinned = State(initialValue: I2PPeerPins.shared.isPinned(identityHex: summary.id))
        _nickname = State(initialValue: storedLabel)
        _nicknameDraft = State(initialValue: storedLabel ?? "")
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                headerCard
                nicknameCard
                identityCard
                sessionCard
                trafficCard
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
        .navigationTitle(I2PPeerNicknameFormat.inspectorTitle(label: nickname))
        .navigationBarTitleDisplayMode(.inline)
        .task {
            // Refresh from the status engine directly (the dashboard consumes
            // the shared snapshot stream; polling here keeps both views live).
            while !Task.isCancelled {
                let snapshot = await engine.snapshot()
                if let fresh = snapshot.peers.first(where: { $0.id == peer.id }) {
                    peer = fresh
                }
                // Reading the counters through the engine's snapshot is what
                // feeds the recorder, so the chart fills while this screen is
                // open and starts fresh each launch.
                trafficSamples = engine.peerTrafficSamples(for: peer.id)
                trafficAverage = engine.peerTrafficAverage(for: peer.id)
                trafficCapturedAt = Date()
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
            VStack(alignment: .leading, spacing: 3) {
                // A labelled peer leads with the user's own name for it, and the
                // shortened hash keeps its place one line below. Without a label
                // nothing here appears, so the card reads as it always has.
                if let nickname {
                    Text(nickname)
                        .font(.system(.title3, design: .rounded).weight(.bold))
                        .foregroundStyle(.primary)
                        .fixedSize(horizontal: false, vertical: true)
                    Text(I2PPeerNicknameFormat.shortHash(peer.id))
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text("Connected \(uptimeText(Date().timeIntervalSince(peer.establishedAt))) ago")
                        .font(.system(nickname == nil ? .title3 : .subheadline,
                                      design: .rounded).weight(.bold))
                        .foregroundStyle(accent)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 6)
                    pinControl
                }
            }
            Text(I2PPeerPinFormat.inspectorLine(pinned: isPinned))
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    // MARK: - Pin

    /// The header's pin control. It names the state the identity is in —
    /// "Pinned" or "Not pinned" — and tapping it flips that state in the store.
    private var pinControl: some View {
        Button(action: togglePin) {
            HStack(spacing: 5) {
                Image(systemName: isPinned
                      ? I2PPeerPinFormat.badgeSystemImage
                      : I2PPeerPinFormat.controlSystemImage)
                    .font(.caption2.weight(.bold))
                    .accessibilityHidden(true)
                Text(I2PPeerPinFormat.controlTitle(pinned: isPinned))
                    .font(.caption.weight(.semibold))
            }
            .foregroundStyle(isPinned ? accent : Color.secondary)
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background((isPinned ? accent : Color.white).opacity(isPinned ? 0.18 : 0.08),
                        in: Capsule())
        }
        .buttonStyle(.plain)
        .accessibilityLabel("Pin peer")
        .accessibilityValue(I2PPeerPinFormat.controlTitle(pinned: isPinned))
        .accessibilityHint(isPinned
                           ? "Double tap to unpin this peer, letting it take its place in the chosen order"
                           : "Double tap to pin this peer above every other row of the session list")
    }

    private func togglePin() {
        let pinned = I2PPeerPins.shared.toggle(identityHex: peer.id)
        withAnimation(.easeInOut(duration: 0.2)) { isPinned = pinned }
    }

    // MARK: - Nickname

    /// The user's own name for this identity. Typing it makes the dashboard's
    /// session list and this screen's title read the label instead of the
    /// shortened hash, with the hash still one line below; the text is trimmed,
    /// capped at 32 characters, and emptying the field clears it. It belongs to
    /// the identity and stays on this device.
    private var nicknameCard: some View {
        card(title: I2PPeerNicknameFormat.cardTitle) {
            HStack(spacing: 8) {
                TextField(I2PPeerNicknameFormat.fieldPlaceholder, text: $nicknameDraft)
                    .textFieldStyle(.plain)
                    .font(.footnote)
                    .submitLabel(.done)
                    .padding(.vertical, 8)
                    .padding(.horizontal, 12)
                    .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 10))
                    .onChange(of: nicknameDraft) { _, newValue in
                        applyNickname(newValue)
                    }
                    .accessibilityLabel("Nickname for this peer")
                    .accessibilityHint("Up to \(I2PPeerNicknameFormat.maxLength) characters. Empty the field to read the peer by its shortened hash again.")
                if nickname != nil {
                    Button(action: clearNickname) {
                        Image(systemName: "xmark.circle.fill")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(I2PPeerNicknameFormat.clearTitle)
                }
            }
            Text(I2PPeerNicknameFormat.counter(nicknameDraft))
                .font(.caption2)
                .foregroundStyle(.secondary)
            Text(I2PPeerNicknameFormat.savedLine(label: nickname, identityHex: peer.id))
                .font(.caption2)
                .foregroundStyle(accent)
                .fixedSize(horizontal: false, vertical: true)
            Text("Kept on this device for this identity only. A nickname never changes what the router sends or how the peer is treated.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    /// Applies the field to the store as it is typed: the draft is capped at the
    /// maximum length first, the store trims it, and a field emptied down to
    /// nothing clears the label so the peer reads by its hash again.
    private func applyNickname(_ raw: String) {
        let capped = I2PPeerNicknameFormat.clamp(raw)
        if capped != raw {
            // Re-enters through the field's onChange carrying the capped text,
            // which is what gets saved.
            nicknameDraft = capped
            return
        }
        let stored = I2PPeerNicknames.shared.setLabel(capped, for: peer.id)
        if stored != nickname { nickname = stored }
    }

    private func clearNickname() {
        withAnimation(.easeInOut(duration: 0.2)) {
            nicknameDraft = ""
            nickname = I2PPeerNicknames.shared.setLabel("", for: peer.id)
        }
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

    // MARK: - Traffic history

    private struct TrafficLinePoint: Identifiable {
        let id: String
        let at: Date
        let kbPerSecond: Double
    }

    /// The session's last 15 minutes as two thin lines, received and sent, drawn
    /// from the per-second counters the status engine samples for this peer.
    /// Tapping the chart expands it into a taller one with per-minute labels.
    private var trafficCard: some View {
        card(title: "Session traffic") {
            if let flag = peer.trafficFlag {
                trafficFlagLine(flag)
            }
            if trafficSamples.count >= 2 {
                trafficChart
                    .frame(height: trafficExpanded ? 160 : 54)
                    .contentShape(Rectangle())
                    .onTapGesture { toggleTrafficChart() }
                    .accessibilityElement(children: .ignore)
                    .accessibilityLabel(trafficAccessibilityLabel)
                    .accessibilityHint(trafficExpanded
                                       ? "Double tap to collapse the chart"
                                       : "Double tap to expand the chart")
                    .accessibilityAddTraits(.isButton)

                HStack(spacing: 12) {
                    legendDot("Received", value: trafficNow.bytesInPerSecond, tint: receivedTint)
                    legendDot("Sent", value: trafficNow.bytesOutPerSecond, tint: sentTint)
                    Spacer(minLength: 6)
                    Image(systemName: trafficExpanded ? "chevron.up" : "chevron.down")
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(.secondary)
                }

                Text("Last minute · received \(I2PPeerTrafficFormat.rate(trafficAverage.bytesInPerSecond)) · sent \(I2PPeerTrafficFormat.rate(trafficAverage.bytesOutPerSecond))")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                Text("Counted every second from the session's byte counters. The history is memory only and starts fresh each launch.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                Text("Collecting the first readings. The chart fills as the status engine samples this session once a second.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            trafficExportControl

            NavigationLink {
                PeerTrafficCompareView(summary: peer)
            } label: {
                HStack(spacing: 6) {
                    Image(systemName: "chart.line.uptrend.xyaxis")
                        .font(.caption2.weight(.semibold))
                    Text("Compare with another peer")
                        .font(.caption.weight(.semibold))
                    Spacer(minLength: 6)
                    Image(systemName: "chevron.right")
                        .font(.caption2.weight(.semibold))
                }
                .foregroundStyle(accent)
                .padding(.vertical, 8)
                .padding(.horizontal, 12)
                .frame(maxWidth: .infinity)
                .background(accent.opacity(0.14), in: RoundedRectangle(cornerRadius: 10))
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Compare with another peer")
            .accessibilityHint("Draws this peer's last 15 minutes beside another live session")
        }
    }

    // MARK: - Traffic export

    /// The CSV the share control hands the system share sheet: the very buckets
    /// the chart is drawing, one row each, named for the peer's shortened hash and
    /// the capture date. Nil while fewer than two buckets are charted, which is
    /// what keeps the control disabled.
    private var trafficExport: I2PPeerTrafficExportFile? {
        guard trafficSamples.count >= 2 else { return nil }
        return I2PPeerTrafficExport.payload(peerID: peer.id, points: trafficBuckets)
    }

    /// The share control for the readings on screen. It names the peer it will
    /// export, and the file carries only the buckets' times and their two rates.
    @ViewBuilder
    private var trafficExportControl: some View {
        let export = trafficExport
        let shortID = I2PPeerTrafficExport.shortHash(peer.id)
        if let export {
            ShareLink(item: export,
                      subject: Text(export.subject),
                      preview: SharePreview(export.fileName,
                                            image: Image(systemName: "tablecells"))) {
                trafficExportLabel(title: "Export traffic as CSV",
                                   detail: "peer \(shortID) · \(export.rowCount) readings",
                                   enabled: true)
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Export traffic readings for \(shortID)")
            .accessibilityHint("Shares \(export.rowCount) plotted readings as the CSV file \(export.fileName)")
            Text("Time, received and sent bytes per second for each plotted bucket, oldest first — no peer address, key or message content.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        } else {
            trafficExportLabel(title: "Export traffic as CSV",
                               detail: "peer \(shortID) · nothing charted yet",
                               enabled: false)
                .accessibilityLabel("Export traffic readings for \(shortID)")
                .accessibilityHint("Nothing is charted yet, so there is nothing to export")
        }
    }

    private func trafficExportLabel(title: String, detail: String, enabled: Bool) -> some View {
        HStack(spacing: 6) {
            Image(systemName: "tablecells")
                .font(.caption2.weight(.semibold))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.caption.weight(.semibold))
                Text(detail)
                    .font(.system(.caption2, design: .monospaced))
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Spacer(minLength: 6)
            Image(systemName: "square.and.arrow.up")
                .font(.caption2.weight(.semibold))
                .accessibilityHidden(true)
        }
        .foregroundStyle(enabled ? accent : Color.secondary)
        .padding(.vertical, 8)
        .padding(.horizontal, 12)
        .frame(maxWidth: .infinity)
        .background((enabled ? accent : Color.white).opacity(enabled ? 0.14 : 0.06),
                    in: RoundedRectangle(cornerRadius: 10))
    }

    /// What the readings say about this session right now: how long it has moved
    /// no bytes, or the received rate it has been sustaining far above its own
    /// median. It is recomputed from the traffic history each second, so it
    /// clears without anything to dismiss.
    private func trafficFlagLine(_ flag: I2PPeerTrafficFlag) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: I2PPeerTrafficFlagFormat.badgeSystemImage(flag))
                .font(.caption)
                .foregroundStyle(flagTint)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(I2PPeerTrafficFlagFormat.badgeTitle(flag))
                    .font(.caption.weight(.bold))
                    .foregroundStyle(flagTint)
                Text(I2PPeerTrafficFlagFormat.inspectorLine(flag))
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(flagTint.opacity(0.14), in: RoundedRectangle(cornerRadius: 12))
        .accessibilityElement(children: .combine)
    }

    private func legendDot(_ title: String, value: Double, tint: Color) -> some View {
        HStack(spacing: 5) {
            Circle()
                .fill(tint)
                .frame(width: 6, height: 6)
                .accessibilityHidden(true)
            Text(title)
                .font(.caption2.weight(.medium))
                .foregroundStyle(.secondary)
            Text(I2PPeerTrafficFormat.rate(value))
                .font(.system(.caption2, design: .monospaced).weight(.semibold))
                .foregroundStyle(tint)
        }
        .accessibilityElement(children: .combine)
    }

    private var trafficChart: some View {
        let buckets = trafficBuckets
        let received = buckets.map {
            TrafficLinePoint(id: "received-\($0.id)", at: $0.at, kbPerSecond: $0.receivedKBPerSecond)
        }
        let sent = buckets.map {
            TrafficLinePoint(id: "sent-\($0.id)", at: $0.at, kbPerSecond: $0.sentKBPerSecond)
        }
        let peak = buckets.reduce(0.0) {
            max($0, max($1.receivedKBPerSecond, $1.sentKBPerSecond))
        }
        let ceiling = max(peak, 1) * 1.15
        let windowEnd = max(trafficCapturedAt, buckets.last?.at ?? trafficCapturedAt)
        let windowStart = windowEnd.addingTimeInterval(-I2PPeerTrafficRecorder.window)
        return Chart {
            ForEach(received) { point in
                LineMark(x: .value("Time", point.at),
                         y: .value("KB/s", point.kbPerSecond),
                         series: .value("Direction", "Received"))
                    .foregroundStyle(receivedTint)
                    .lineStyle(StrokeStyle(lineWidth: trafficExpanded ? 2 : 1.2, lineCap: .round))
                    .interpolationMethod(.monotone)
            }
            ForEach(sent) { point in
                LineMark(x: .value("Time", point.at),
                         y: .value("KB/s", point.kbPerSecond),
                         series: .value("Direction", "Sent"))
                    .foregroundStyle(sentTint)
                    .lineStyle(StrokeStyle(lineWidth: trafficExpanded ? 2 : 1.2, lineCap: .round))
                    .interpolationMethod(.monotone)
            }
        }
        .chartLegend(.hidden)
        .chartXScale(domain: windowStart...windowEnd)
        .chartYScale(domain: 0...ceiling)
        .modifier(PeerTrafficChartAxes(expanded: trafficExpanded))
    }

    /// Hidden axes on the compact sparkline; per-minute time labels and a KB/s
    /// scale once the chart is expanded.
    private struct PeerTrafficChartAxes: ViewModifier {
        let expanded: Bool

        @ViewBuilder
        func body(content: Content) -> some View {
            if expanded {
                content
                    .chartXAxis {
                        AxisMarks(values: .stride(by: .minute, count: 3)) { value in
                            AxisGridLine().foregroundStyle(Color.white.opacity(0.08))
                            AxisValueLabel {
                                if let date = value.as(Date.self) {
                                    Text(date.formatted(date: .omitted, time: .shortened))
                                        .font(.caption2)
                                }
                            }
                        }
                    }
                    .chartYAxis {
                        AxisMarks(position: .leading, values: .automatic(desiredCount: 3)) { value in
                            AxisGridLine().foregroundStyle(Color.white.opacity(0.08))
                            AxisValueLabel {
                                if let kb = value.as(Double.self) {
                                    Text(I2PPeerTrafficFormat.scaleLabel(kb))
                                        .font(.caption2)
                                }
                            }
                        }
                    }
            } else {
                content
                    .chartXAxis(.hidden)
                    .chartYAxis(.hidden)
            }
        }
    }

    private var trafficBuckets: [I2PPeerTrafficPoint] {
        I2PPeerTrafficRecorder.points(from: trafficSamples)
    }

    /// The newest reading, named beside each line's legend entry.
    private var trafficNow: I2PPeerTrafficAverage {
        guard let last = trafficSamples.last else { return .zero }
        return I2PPeerTrafficAverage(bytesInPerSecond: last.bytesInPerSecond,
                                     bytesOutPerSecond: last.bytesOutPerSecond)
    }

    private var trafficAccessibilityLabel: String {
        let received = I2PPeerTrafficFormat.rate(trafficNow.bytesInPerSecond)
        let sent = I2PPeerTrafficFormat.rate(trafficNow.bytesOutPerSecond)
        let averageIn = I2PPeerTrafficFormat.rate(trafficAverage.bytesInPerSecond)
        let averageOut = I2PPeerTrafficFormat.rate(trafficAverage.bytesOutPerSecond)
        return "Session traffic, last 15 minutes. Received \(received), sent \(sent). Last minute, received \(averageIn), sent \(averageOut)."
    }

    private func toggleTrafficChart() {
        withAnimation(.easeInOut(duration: 0.2)) {
            trafficExpanded.toggle()
        }
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