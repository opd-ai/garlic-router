//
//  SAMView.swift
//  The SAMv3.3 tab: listener control, live client sessions, the command
//  reference for SAM clients, and the bridge activity log.
//

import SwiftUI
import Charts

struct SAMView: View {
    @State private var sessions: [I2PSAMSessionSummary] = []
    @State private var stateText = "Stopped"
    @State private var listening = false
    @State private var failure: String?
    @State private var logLines: [String] = []
    /// The cap field of each session row, keyed by session key (nickname).
    @State private var capTexts: [String: String] = [:]
    @State private var capCommitTask: Task<Void, Never>?
    /// Each session's one-minute send-rate history, keyed by session key.
    @State private var sessionRates: [String: [SessionRateMinuteSample]] = [:]
    /// The session keys whose sparkline is expanded into the taller chart.
    @State private var expandedRates: Set<String> = []
    /// The last minute of SAM traffic by client, against the outbound cap.
    @State private var capShare: I2PSAMCapShare = .empty

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)

    private var server: I2PSAMServer {
        I2PRouterAppContext.shared.samServer
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    serverCard
                    capShareCard
                    if !sessions.isEmpty { sessionsCard }
                    apiCard
                    if !logLines.isEmpty { logCard }
                }
                .padding(.horizontal, 16)
                .padding(.top, 4)
                .padding(.bottom, 24)
            }
            .background(background.ignoresSafeArea())
            .navigationTitle("SAM")
            .navigationBarTitleDisplayMode(.large)
        }
        .preferredColorScheme(.dark)
        .task { await liveLoop() }
    }

    private func refresh() {
        switch server.state {
        case .stopped:
            stateText = "Stopped"
            listening = false
            failure = nil
        case .listening(let port):
            stateText = "Listening · 127.0.0.1:\(port)"
            listening = true
            failure = nil
        case .failed(let error):
            stateText = "Failed"
            listening = false
            failure = error
        }
        sessions = server.sessionSummaries()
        loadSessionRates()
        capShare = I2PSAMCapShare.live(sessions: sessions)
        logLines = server.log
        syncCapTexts()
    }

    /// Re-reads each session's one-minute send-rate history. The governor keeps
    /// it in memory only, so a relaunch starts a fresh 15-minute window.
    private func loadSessionRates() {
        var rates: [String: [SessionRateMinuteSample]] = [:]
        for session in sessions {
            rates[session.nickname] = I2PBandwidthGovernor.shared
                .sessionMinuteHistory(session.nickname)
        }
        sessionRates = rates
    }

    /// Keeps the session rows live: a session's measured send rate moves as its
    /// client sends, so the list re-reads the bridge once a second.
    private func liveLoop() async {
        while !Task.isCancelled {
            refresh()
            try? await Task.sleep(for: .seconds(1))
        }
    }

    // MARK: Server card

    private var serverCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                Circle().fill(listening ? Color.green : Color.orange).frame(width: 8, height: 8)
                Text(listening ? "API socket live" : "API socket idle")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(listening ? Color.green : Color.orange)
                Spacer()
                Text("SAMv3.3")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(accent)
            }

            Text("SAM socket")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .textCase(.uppercase)

            Text(stateText)
                .font(.system(.footnote, design: .monospaced).weight(.medium))
                .padding(.vertical, 8)
                .padding(.horizontal, 12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(accent.opacity(0.12), in: RoundedRectangle(cornerRadius: 12))

            if let failure {
                Text(failure)
                    .font(.caption2)
                    .foregroundStyle(.red)
            }

            Text("Sessions \(sessions.count) · tunnels build once peers are known")
                .font(.caption2)
                .foregroundStyle(.secondary)

            Button {
                if listening {
                    server.stop()
                    refresh()
                } else {
                    server.start()
                    Task { @MainActor in
                        for _ in 0..<20 {
                            try? await Task.sleep(for: .milliseconds(100))
                            refresh()
                            if listening || failure != nil { break }
                        }
                    }
                }
            } label: {
                Label(listening ? "Stop SAM socket" : "Start SAM socket",
                      systemImage: listening ? "stop.circle" : "play.circle")
                    .font(.subheadline.weight(.semibold))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .background(accent.opacity(0.18), in: RoundedRectangle(cornerRadius: 12))
            }
            .buttonStyle(.plain)
            .tint(accent)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    // MARK: Outbound cap share

    /// A distinct violet-palette tint per client. The same index drives the
    /// bar segment and the legend dot, so a slice and its row always match.
    private static let clientTints: [Color] = [
        Color(red: 0.64, green: 0.50, blue: 1.00),
        Color(red: 0.40, green: 0.66, blue: 0.99),
        Color(red: 0.78, green: 0.48, blue: 0.97),
        Color(red: 0.52, green: 0.44, blue: 0.92),
        Color(red: 0.90, green: 0.58, blue: 0.98),
        Color(red: 0.58, green: 0.56, blue: 1.00)
    ]

    private func clientTint(_ index: Int) -> Color {
        Self.clientTints[index % Self.clientTints.count]
    }

    /// Who is spending the outbound cap: the last minute of SAM client send
    /// rates stacked against the rest of the router's traffic, with the cap
    /// marked across the bar. Before any client sends, a short empty state
    /// stands in for the bar.
    private var capShareCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 6) {
                Text("Outbound Cap Share")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .textCase(.uppercase)
                Spacer(minLength: 6)
                Text("last minute")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
            if capShare.hasClientTraffic {
                if let headline = capShare.headline {
                    Text(headline)
                        .font(.system(.caption, design: .monospaced).weight(.medium))
                        .foregroundStyle(.primary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                shareBar(capShare)
                shareLegend(capShare)
            } else {
                Text("No SAM client has sent anything in the last minute.")
                    .font(.caption)
                    .foregroundStyle(.primary)
                Text("The bar fills with each client's share of the outbound cap as they send.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    /// The stacked bar: a segment per client in its own violet tint, then the
    /// rest of the router's outbound traffic in grey, with the cap as a line
    /// across the bar.
    private func shareBar(_ share: I2PSAMCapShare) -> some View {
        GeometryReader { proxy in
            let width = proxy.size.width
            ZStack(alignment: .leading) {
                RoundedRectangle(cornerRadius: 4)
                    .fill(Color.white.opacity(0.07))
                HStack(spacing: 1) {
                    ForEach(share.clients.indices, id: \.self) { index in
                        let client = share.clients[index]
                        let segmentWidth = width * CGFloat(share.barFraction(client.bytesPerSecond))
                        if segmentWidth > 0.5 {
                            Rectangle()
                                .fill(clientTint(index))
                                .frame(width: segmentWidth)
                        }
                    }
                    let restWidth = width * CGFloat(share.barFraction(share.otherBytesPerSecond))
                    if restWidth > 0.5 {
                        Rectangle()
                            .fill(Color.white.opacity(0.26))
                            .frame(width: restWidth)
                    }
                    Spacer(minLength: 0)
                }
                .clipShape(RoundedRectangle(cornerRadius: 5))
                if let capFraction = share.capFraction {
                    Rectangle()
                        .fill(Color.white.opacity(0.85))
                        .frame(width: 1.5)
                        .offset(x: min(max(0, width - 2), width * CGFloat(capFraction)))
                }
            }
        }
        .frame(height: 18)
    }

    /// Every client's share of the cap under the bar, then the rest of the
    /// router's own traffic against the same ceiling.
    private func shareLegend(_ share: I2PSAMCapShare) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            ForEach(share.clients.indices, id: \.self) { index in
                let client = share.clients[index]
                HStack(spacing: 7) {
                    RoundedRectangle(cornerRadius: 2)
                        .fill(clientTint(index))
                        .frame(width: 8, height: 8)
                    Text(client.key)
                        .font(.system(.caption2, design: .monospaced).weight(.medium))
                        .foregroundStyle(.primary)
                    Spacer(minLength: 6)
                    Text(share.shareLabel(for: client))
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
            }
            if share.otherBytesPerSecond > 0 {
                HStack(spacing: 7) {
                    RoundedRectangle(cornerRadius: 2)
                        .fill(Color.white.opacity(0.26))
                        .frame(width: 8, height: 8)
                    Text("rest of router")
                        .font(.system(.caption2, design: .monospaced).weight(.medium))
                        .foregroundStyle(.secondary)
                    Spacer(minLength: 6)
                    Text(share.shareLabel(bytesPerSecond: share.otherBytesPerSecond))
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    // MARK: Sessions

    private var sessionsCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Client Sessions")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .textCase(.uppercase)
            ForEach(sessions.indices, id: \.self) { index in
                let session = sessions[index]
                VStack(alignment: .leading, spacing: 6) {
                    // The tap target is the session's reading, not its cap
                    // field: a text field inside a navigation link never gets
                    // focus, so the field stays outside the link.
                    NavigationLink {
                        SAMSessionDetailView(nickname: session.nickname)
                    } label: {
                        VStack(alignment: .leading, spacing: 6) {
                            HStack(spacing: 6) {
                                Text(session.nickname)
                                    .font(.footnote.weight(.semibold))
                                Text(session.style)
                                    .font(.caption2.weight(.semibold))
                                    .foregroundStyle(accent)
                                    .padding(.horizontal, 6)
                                    .padding(.vertical, 2)
                                    .background(accent.opacity(0.14), in: RoundedRectangle(cornerRadius: 6))
                                Spacer(minLength: 6)
                                Text("tx \(session.bytesTx) · rx \(session.bytesRx)")
                                    .font(.system(.caption2, design: .monospaced))
                                    .foregroundStyle(.secondary)
                                Image(systemName: "chevron.right")
                                    .font(.caption2.weight(.semibold))
                                    .foregroundStyle(.tertiary)
                            }
                            Text("dest \(session.destinationHash) · out \(session.tunnelsOut) in \(session.tunnelsIn) · \(session.published ? "lease published" : "no lease yet")")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                            if session.capBytesPerSecond > 0 {
                                capBar(fraction: capFraction(session))
                            }
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    bandwidthRow(session)
                }
                .padding(.vertical, 4)
                if index < sessions.count - 1 {
                    Divider().opacity(0.3)
                }
            }
            Text("A session's cap shapes only that client's stream and datagram sends; empty or 0 is uncapped. Changes apply immediately and persist per session. Tap a sparkline to expand it.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    /// Measured send rate against the session's ceiling, with the cap field
    /// that edits it in place, and the session's 15-minute send-rate sparkline
    /// underneath.
    private func bandwidthRow(_ session: I2PSAMSessionSummary) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Text("send \(I2PSAMBandwidthFormat.rate(session.sendBytesPerSecond))")
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(isAtCap(session) ? Color.orange : Color.secondary)
                if isAtCap(session) {
                    Text("at cap")
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(Color.orange)
                }
                Spacer(minLength: 6)
                Text("cap")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                TextField("0", text: capText(for: session.nickname))
                    .textFieldStyle(.plain)
                    .keyboardType(.numberPad)
                    .multilineTextAlignment(.trailing)
                    .font(.system(.caption, design: .monospaced).weight(.semibold))
                    .foregroundStyle(Color.white)
                    .frame(width: 52)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(Color.white.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
                Text("KB/s")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            rateSparkline(session)
        }
    }

    // MARK: Send-rate sparkline

    private struct SessionRatePoint: Identifiable {
        let id: Int
        let minute: Date
        let kbPerSecond: Double
    }

    /// The session's last 15 minutes as a violet sparkline, with a thin dashed
    /// line at its own cap when it has one. Tapping it expands the chart.
    private func rateSparkline(_ session: I2PSAMSessionSummary) -> some View {
        let expanded = expandedRates.contains(session.nickname)
        return VStack(alignment: .leading, spacing: 4) {
            rateChart(session, expanded: expanded)
                .frame(height: expanded ? 150 : 40)
                .contentShape(Rectangle())
                .onTapGesture { toggleRate(session.nickname) }
            HStack(spacing: 6) {
                Text(expanded ? "last 15 minutes · one-minute averages, KB/s" : "last 15 min")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                Spacer(minLength: 6)
                if expanded {
                    Text("peak \(I2PSAMBandwidthFormat.rate(ratePeak(session.nickname)))")
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
                Image(systemName: expanded ? "chevron.up" : "chevron.down")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(.tertiary)
            }
        }
    }

    private func toggleRate(_ nickname: String) {
        withAnimation(.easeInOut(duration: 0.2)) {
            if expandedRates.contains(nickname) {
                expandedRates.remove(nickname)
            } else {
                expandedRates.insert(nickname)
            }
        }
    }

    private func ratePoints(_ nickname: String) -> [SessionRatePoint] {
        (sessionRates[nickname] ?? []).enumerated().map { index, sample in
            SessionRatePoint(id: index,
                             minute: sample.minute,
                             kbPerSecond: sample.bytesPerSecond / 1024)
        }
    }

    private func ratePeak(_ nickname: String) -> Double {
        (ratePoints(nickname).map(\.kbPerSecond).max() ?? 0) * 1024
    }

    private func rateChart(_ session: I2PSAMSessionSummary, expanded: Bool) -> some View {
        let points = ratePoints(session.nickname)
        let cap = Double(session.capBytesPerSecond) / 1024
        let peak = points.map(\.kbPerSecond).max() ?? 0
        let ceiling = max(max(peak, cap), 1) * 1.15
        let ridingCap = cap > 0 && peak >= cap * 0.95
        return Chart {
            ForEach(points) { point in
                AreaMark(x: .value("Minute", point.minute),
                         y: .value("KB/s", point.kbPerSecond))
                    .foregroundStyle(accent.opacity(expanded ? 0.18 : 0.10))
                    .interpolationMethod(.monotone)
                LineMark(x: .value("Minute", point.minute),
                         y: .value("KB/s", point.kbPerSecond))
                    .foregroundStyle(accent)
                    .lineStyle(StrokeStyle(lineWidth: expanded ? 2 : 1.4, lineCap: .round))
                    .interpolationMethod(.monotone)
            }
            if cap > 0 {
                RuleMark(y: .value("Cap", cap))
                    .foregroundStyle(ridingCap ? Color.orange.opacity(0.9)
                                               : accent.opacity(0.45))
                    .lineStyle(StrokeStyle(lineWidth: 1, dash: [3, 3]))
            }
        }
        .chartYScale(domain: 0...ceiling)
        .modifier(SessionRateChartAxes(expanded: expanded))
    }

    /// Hidden axes on the compact sparkline; per-minute time labels and a KB/s
    /// scale once it is expanded.
    private struct SessionRateChartAxes: ViewModifier {
        let expanded: Bool

        @ViewBuilder
        func body(content: Content) -> some View {
            if expanded {
                content
                    .chartXAxis {
                        AxisMarks(values: .automatic(desiredCount: 5)) { value in
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
                                    Text(SAMView.kbLabel(kb))
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

    /// "512 B", "12 KB" or "1.2 MB" for the expanded chart's scale.
    static func kbLabel(_ kb: Double) -> String {
        if kb >= 1024 { return String(format: "%.1f MB", kb / 1024) }
        if kb >= 1 { return String(format: "%.0f KB", kb) }
        return String(format: "%.0f B", kb * 1024)
    }

    private func capBar(fraction: Double) -> some View {
        GeometryReader { proxy in
            ZStack(alignment: .leading) {
                Capsule()
                    .fill(Color.white.opacity(0.10))
                Capsule()
                    .fill(fraction >= 0.9 ? Color.orange : accent)
                    .frame(width: max(2, proxy.size.width * min(1, max(0, fraction))))
            }
        }
        .frame(height: 4)
    }

    private func capFraction(_ session: I2PSAMSessionSummary) -> Double {
        guard session.capBytesPerSecond > 0 else { return 0 }
        return session.sendBytesPerSecond / Double(session.capBytesPerSecond)
    }

    private func isAtCap(_ session: I2PSAMSessionSummary) -> Bool {
        capFraction(session) >= 0.9
    }

    // MARK: Per-session cap editing

    /// Seeds each session's field from the router the first time the session
    /// appears and drops fields of sessions that closed; a field being edited is
    /// never overwritten.
    private func syncCapTexts() {
        for session in sessions where capTexts[session.nickname] == nil {
            let kb = session.capBytesPerSecond / 1024
            capTexts[session.nickname] = kb == 0 ? "" : String(kb)
        }
        let live = Set(sessions.map(\.nickname))
        capTexts = capTexts.filter { live.contains($0.key) }
        expandedRates = expandedRates.filter { live.contains($0) }
    }

    private func capText(for nickname: String) -> Binding<String> {
        Binding(
            get: { capTexts[nickname] ?? "" },
            set: { text in
                capTexts[nickname] = String(text.filter(\.isNumber).prefix(6))
                scheduleCapCommit(for: nickname)
            }
        )
    }

    private func scheduleCapCommit(for nickname: String) {
        capCommitTask?.cancel()
        capCommitTask = Task { @MainActor in
            try? await Task.sleep(for: .milliseconds(400))
            guard !Task.isCancelled else { return }
            applyCap(for: nickname)
        }
    }

    /// Applies a typed ceiling to the running session and saves it under the
    /// session key, then normalizes the field to what the router accepted.
    private func applyCap(for nickname: String) {
        let typed = Int((capTexts[nickname] ?? "").trimmingCharacters(in: .whitespaces)) ?? 0
        let clamped = I2PSAMSessionCaps.clamp(typed)
        capTexts[nickname] = clamped == 0 ? "" : String(clamped)
        let current = sessions.first { $0.nickname == nickname }?.capBytesPerSecond ?? 0
        guard current != clamped * 1024 else { return }
        server.setSessionCapKBps(clamped, for: nickname)
        sessions = server.sessionSummaries()
        loadSessionRates()
        capShare = I2PSAMCapShare.live(sessions: sessions)
    }

    // MARK: Client protocol reference

    private var apiCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Client Protocol Reference")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .textCase(.uppercase)
            commandRow("HELLO VERSION MIN=3.0 MAX=3.3",
                       caption: "negotiate — replies RESULT=OK VERSION=3.3")
            commandRow("SESSION CREATE STYLE=STREAM ID=s1 DESTINATION=TRANSIENT",
                       caption: "destination + tunnels + LeaseSet; PUB dest returned")
            commandRow("SESSION CREATE STYLE=DATAGRAM ID=d1 DESTINATION=<priv b64> PORT=7658",
                       caption: "imported keys; UDP replies to PORT")
            commandRow("STREAM CONNECT ID=s1 DESTINATION=<dest b64>",
                       caption: "outbound stream; raw bytes follow the OK reply")
            commandRow("STREAM ACCEPT ID=s1",
                       caption: "wait for an inbound stream; OK then raw bytes")
            commandRow("DATAGRAM SEND ID=d1 DESTINATION=<dest b64> SIZE=n",
                       caption: "repliable; the n payload bytes follow the line")
            commandRow("NAMING LOOKUP NAME=me.i2p / .b32.i2p / ME",
                       caption: "DHT LeaseSet + addressbook resolution")
            commandRow("NAMING ADD NAME=site.i2p DESTINATION=<b64>",
                       caption: "destination import into the addressbook")
            commandRow("DEST GENERATE",
                       caption: "PUB + PRIV destination keys (b64)")
            commandRow("SESSION QUIT",
                       caption: "close the session and connection")
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    private func commandRow(_ command: String, caption: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(command)
                .font(.system(.caption2, design: .monospaced).weight(.medium))
                .foregroundStyle(.primary)
                .lineLimit(1)
                .minimumScaleFactor(0.6)
            Text(caption)
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .padding(.vertical, 2)
    }

    // MARK: Activity log

    private var logCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Activity Log")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .textCase(.uppercase)
            ForEach(logLines.suffix(10).indices, id: \.self) { index in
                Text(logLines.suffix(10)[index])
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.head)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }
}