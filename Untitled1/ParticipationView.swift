//
//  ParticipationView.swift
//  Network-participation controls: bandwidth caps, tunnel-share ratio and the
//  floodfill role. Every change applies to the running router immediately and
//  persists across launches; each control shows its live measured value.
//

import SwiftUI
import Charts

struct ParticipationView: View {
    @State private var snapshot: I2PRouterStatusSnapshot?
    @State private var inboundCapKBps = Double(I2PParticipationSettings.shared.inboundCapKBps)
    @State private var outboundCapKBps = Double(I2PParticipationSettings.shared.outboundCapKBps)
    @State private var sharePercent = Double(I2PParticipationSettings.shared.tunnelSharePercent)
    @State private var floodfillEnabled = I2PParticipationSettings.shared.floodfillEnabled
    @State private var quietHoursEnabled = I2PParticipationSettings.shared.quietHoursEnabled
    @State private var quietStartDate = ParticipationView.date(
        forMinutes: I2PParticipationSettings.shared.quietHoursStartMinutes)
    @State private var quietEndDate = ParticipationView.date(
        forMinutes: I2PParticipationSettings.shared.quietHoursEndMinutes)
    @State private var quietCommitTask: Task<Void, Never>?
    @State private var reading = I2PBandwidthGovernor.shared.reading()
    @State private var minuteHistory: [BandwidthMinuteSample] = []
    @State private var expandedBand: BandwidthBand?
    @State private var blockedPeers: [I2PBlockedPeer] = []
    @State private var confirmation: String?
    @State private var republishing = false
    @State private var capCommitTask: Task<Void, Never>?
    @State private var shareCommitTask: Task<Void, Never>?

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)

    private let capRange = Double(I2PParticipationSettings.minCapKBps)...Double(I2PParticipationSettings.maxCapKBps)
    private var capStep: Double { Double(I2PParticipationSettings.capStepKBps) }

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                captionText
                bandwidthHistoryCard
                bandwidthCard
                shareCard
                quietHoursCard
                blockedPeersCard
                floodfillCard
                footnoteText
            }
            .padding(.horizontal, 16)
            .padding(.top, 4)
            .padding(.bottom, 24)
        }
        .background(background.ignoresSafeArea())
        .navigationTitle("Participation")
        .navigationBarTitleDisplayMode(.large)
        .preferredColorScheme(.dark)
        .overlay(alignment: .top) { toast }
        .task { await liveLoop() }
        .onAppear(perform: syncFromSettings)
    }

    // MARK: - Live readings

    private func liveLoop() async {
        while !Task.isCancelled {
            snapshot = await I2PRouterAppContext.shared.engine.snapshot()
            reading = I2PBandwidthGovernor.shared.reading()
            minuteHistory = I2PBandwidthGovernor.shared.minuteHistory()
            // A block made from the peer inspector shows up here within a tick;
            // only reassign on change so an in-flight swipe is not disturbed.
            let latest = I2PPeerBlocklist.shared.all()
            if latest != blockedPeers { blockedPeers = latest }
            try? await Task.sleep(for: .seconds(1))
        }
    }

    private func syncFromSettings() {
        let settings = I2PParticipationSettings.shared
        inboundCapKBps = Double(settings.inboundCapKBps)
        outboundCapKBps = Double(settings.outboundCapKBps)
        sharePercent = Double(settings.tunnelSharePercent)
        floodfillEnabled = settings.floodfillEnabled
        quietHoursEnabled = settings.quietHoursEnabled
        quietStartDate = Self.date(forMinutes: settings.quietHoursStartMinutes)
        quietEndDate = Self.date(forMinutes: settings.quietHoursEndMinutes)
        blockedPeers = I2PPeerBlocklist.shared.all()
    }

    // MARK: - Copy

    private var captionText: some View {
        Text("How this router contributes to the network.")
            .font(.footnote)
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var footnoteText: some View {
        Text("Settings persist across launches; tunnels rebuild with the new caps within one lease cycle.")
            .font(.caption2)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 2)
    }

    // MARK: - Bandwidth

    private var bandwidthCard: some View {
        card(title: "Bandwidth") {
            capRow(title: "Inbound cap",
                   value: $inboundCapKBps,
                   measured: reading.inboundBytesPerSecond)
            Divider().opacity(0.2)
            capRow(title: "Outbound cap",
                   value: $outboundCapKBps,
                   measured: reading.outboundBytesPerSecond)
            Text("measured \(formatRate(reading.inboundBytesPerSecond)) in · \(formatRate(reading.outboundBytesPerSecond)) out over the last minute")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func capRow(title: String, value: Binding<Double>, measured: Double) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(title)
                    .font(.footnote.weight(.medium))
                Spacer()
                Text("\(Int(value.wrappedValue)) KB/s")
                    .font(.system(.footnote, design: .monospaced).weight(.semibold))
                    .foregroundStyle(accent)
            }
            Slider(value: value, in: capRange, step: capStep) {
                Text(title)
            }
            .tint(accent)
            HStack(spacing: 6) {
                Text("measured \(formatRate(measured))")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                if isAtCap(measured, capKBps: value.wrappedValue) {
                    Text("at cap")
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(.orange)
                }
                Spacer()
            }
        }
        .onChange(of: value.wrappedValue) { _, _ in
            scheduleCapCommit()
        }
    }

    private func isAtCap(_ measured: Double, capKBps: Double) -> Bool {
        guard capKBps > 0 else { return false }
        return measured >= capKBps * 1024 * 0.9
    }

    // MARK: - Bandwidth history

    /// The two directions shown as stacked bands.
    private enum BandwidthBand: String, CaseIterable, Identifiable {
        case inbound
        case outbound

        var id: String { rawValue }
        var title: String { self == .inbound ? "Inbound" : "Outbound" }
        var icon: String { self == .inbound ? "arrow.down" : "arrow.up" }
    }

    private struct BandChartPoint: Identifiable {
        let id: Int
        let minute: Date
        let kbPerSecond: Double
    }

    private var bandwidthHistoryCard: some View {
        card(title: "Bandwidth history") {
            Text("Last 60 minutes · one-minute averages, counted as the router offers traffic")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            ForEach(BandwidthBand.allCases) { band in
                if band != BandwidthBand.allCases.first {
                    Divider().opacity(0.2)
                }
                bandSection(band)
            }
            Text("Tap a band to expand it. The dashed line is the cap; a band that touches it is being shaped by the cap.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func bandSection(_ band: BandwidthBand) -> some View {
        let expanded = expandedBand == band
        let tint = bandTint(band)
        return VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Image(systemName: band.icon)
                    .font(.caption2.weight(.bold))
                    .foregroundStyle(tint)
                    .frame(width: 20, height: 20)
                    .background(tint.opacity(0.14), in: RoundedRectangle(cornerRadius: 6))
                Text(band.title)
                    .font(.footnote.weight(.medium))
                Spacer(minLength: 6)
                Text(formatRate(currentRate(band)))
                    .font(.system(.caption, design: .monospaced).weight(.semibold))
                    .foregroundStyle(tint)
                Text(capText(band))
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                Image(systemName: expanded ? "chevron.up" : "chevron.down")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(.secondary)
            }
            bandChart(band, expanded: expanded)
                .frame(height: expanded ? 150 : 46)
            if expanded {
                HStack(spacing: 6) {
                    Text("peak \(formatRate(peakRate(band))) · axes in KB/s")
                    Spacer(minLength: 6)
                    Text("now \(formatRate(currentRate(band)))")
                }
                .font(.caption2)
                .foregroundStyle(.secondary)
            }
        }
        .contentShape(Rectangle())
        .onTapGesture {
            withAnimation(.easeInOut(duration: 0.2)) {
                expandedBand = expanded ? nil : band
            }
        }
    }

    private func bandChart(_ band: BandwidthBand, expanded: Bool) -> some View {
        let points = chartPoints(band)
        let cap = Double(capKBps(band))
        let peak = points.map(\.kbPerSecond).max() ?? 0
        let ceiling = max(max(peak, cap), 1) * 1.15
        let tint = bandTint(band)
        let ridingCap = cap > 0 && peak >= cap * 0.95
        return Chart {
            ForEach(points) { point in
                AreaMark(x: .value("Minute", point.minute),
                         y: .value("KB/s", point.kbPerSecond))
                    .foregroundStyle(LinearGradient(colors: [tint.opacity(0.35), tint.opacity(0.02)],
                                                    startPoint: .top,
                                                    endPoint: .bottom))
                    .interpolationMethod(.catmullRom)
                LineMark(x: .value("Minute", point.minute),
                         y: .value("KB/s", point.kbPerSecond))
                    .foregroundStyle(tint)
                    .lineStyle(StrokeStyle(lineWidth: expanded ? 2 : 1.5, lineCap: .round))
                    .interpolationMethod(.catmullRom)
            }
            if cap > 0 {
                RuleMark(y: .value("Cap", cap))
                    .foregroundStyle(ridingCap ? Color.orange.opacity(0.9)
                                               : Color.secondary.opacity(0.7))
                    .lineStyle(StrokeStyle(lineWidth: 1, dash: [4, 3]))
            }
        }
        .chartYScale(domain: 0...ceiling)
        .modifier(BandChartAxes(expanded: expanded))
    }

    /// Hidden axes while a band is compact; per-minute time labels and a KB/s
    /// scale once it is expanded.
    private struct BandChartAxes: ViewModifier {
        let expanded: Bool

        @ViewBuilder
        func body(content: Content) -> some View {
            if expanded {
                content
                    .chartXAxis {
                        AxisMarks(values: .automatic(desiredCount: 4)) { value in
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
                                    Text(kb >= 1024 ? String(format: "%.1f MB", kb / 1024)
                                                    : String(format: "%.0f KB", kb))
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

    private func chartPoints(_ band: BandwidthBand) -> [BandChartPoint] {
        minuteHistory.enumerated().map { index, sample in
            BandChartPoint(id: index,
                           minute: sample.minute,
                           kbPerSecond: (band == .inbound
                                         ? sample.inboundBytesPerSecond
                                         : sample.outboundBytesPerSecond) / 1024)
        }
    }

    private func bandTint(_ band: BandwidthBand) -> Color {
        band == .inbound ? accent : Color(red: 0.36, green: 0.80, blue: 0.85)
    }

    private func currentRate(_ band: BandwidthBand) -> Double {
        band == .inbound ? reading.inboundBytesPerSecond : reading.outboundBytesPerSecond
    }

    private func capKBps(_ band: BandwidthBand) -> Int {
        band == .inbound ? Int(inboundCapKBps) : Int(outboundCapKBps)
    }

    private func capText(_ band: BandwidthBand) -> String {
        let kb = capKBps(band)
        return kb > 0 ? "cap \(kb) KB/s" : "uncapped"
    }

    private func peakRate(_ band: BandwidthBand) -> Double {
        (chartPoints(band).map(\.kbPerSecond).max() ?? 0) * 1024
    }

    // MARK: - Tunnel share

    private var shareCard: some View {
        card(title: "Tunnel share") {
            HStack {
                Text("Share ratio")
                    .font(.footnote.weight(.medium))
                Spacer()
                Text("\(Int(sharePercent))%")
                    .font(.system(.footnote, design: .monospaced).weight(.semibold))
                    .foregroundStyle(accent)
            }
            Slider(value: $sharePercent, in: 0...100, step: 5) {
                Text("Share ratio")
            }
            .tint(accent)
            .onChange(of: sharePercent) { _, _ in
                scheduleShareCommit()
            }

            Text(transitLine)
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            HStack {
                Text("Measured transit share")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                Spacer()
                Text(String(format: "%.0f%%", (snapshot?.measuredTransitShare ?? 0) * 100))
                    .font(.system(.caption, design: .monospaced).weight(.semibold))
                    .foregroundStyle(accent)
            }

            Text("0% stops accepting transit builds entirely — the router carries only its own traffic.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    /// "14 participating tunnels · 3.1 msg/min transit average".
    private var transitLine: String {
        let participating = snapshot?.participatingTunnelCount ?? 0
        let rate = snapshot?.transitRatePerMinute ?? 0
        return String(format: "%d participating tunnels · %.1f msg/min transit average",
                      participating, rate)
    }

    // MARK: - Quiet hours

    private var quietHoursCard: some View {
        card(title: "Quiet hours") {
            Toggle(isOn: $quietHoursEnabled) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Pause transit tunnels")
                        .font(.footnote.weight(.medium))
                    Text("No new tunnels are carried for other routers during these hours; the ones already carried run to expiry.")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .tint(accent)
            .onChange(of: quietHoursEnabled) { _, _ in scheduleQuietCommit() }

            if quietHoursEnabled {
                Divider().opacity(0.2)
                quietTimeRow("From", date: $quietStartDate)
                quietTimeRow("To", date: $quietEndDate)
                Divider().opacity(0.2)
                HStack(spacing: 6) {
                    Circle()
                        .fill(quietActiveNow ? Color.orange : Color.green)
                        .frame(width: 6, height: 6)
                    Text(quietActiveNow
                         ? "Paused until \(quietEndTimeText)"
                         : "Active · quiet hours \(quietRangeText)")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(quietActiveNow ? Color.orange : Color.secondary)
                    Spacer(minLength: 6)
                }
                Text(quietActiveNow
                     ? "New transit builds are refused with bandwidth-exceeded; tunnels already carried run to expiry."
                     : "The saved \(Int(sharePercent))% share ratio applies outside these hours.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                Text("Off — the saved \(Int(sharePercent))% share ratio applies all day.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func quietTimeRow(_ title: String, date: Binding<Date>) -> some View {
        HStack {
            Text(title)
                .font(.footnote.weight(.medium))
            Spacer()
            DatePicker("", selection: date, displayedComponents: .hourAndMinute)
                .labelsHidden()
                .datePickerStyle(.compact)
                .onChange(of: date.wrappedValue) { _, _ in scheduleQuietCommit() }
        }
    }

    private var quietStartMinutes: Int { Self.minutes(from: quietStartDate) }
    private var quietEndMinutes: Int { Self.minutes(from: quietEndDate) }
    private var quietRangeText: String {
        "\(I2PParticipationSettings.timeLabel(minutes: quietStartMinutes))–\(I2PParticipationSettings.timeLabel(minutes: quietEndMinutes))"
    }
    private var quietEndTimeText: String {
        I2PParticipationSettings.timeLabel(minutes: quietEndMinutes)
    }

    /// Whether the schedule as it is being edited covers the current time, so the
    /// summary reflects a change before the debounced save lands.
    private var quietActiveNow: Bool {
        I2PParticipationSettings.isQuietHours(enabled: quietHoursEnabled,
                                             startMinutes: quietStartMinutes,
                                             endMinutes: quietEndMinutes)
    }

    private func scheduleQuietCommit() {
        quietCommitTask?.cancel()
        quietCommitTask = Task {
            try? await Task.sleep(for: .milliseconds(300))
            guard !Task.isCancelled else { return }
            await commitQuietHours()
        }
    }

    private func commitQuietHours() async {
        let settings = I2PParticipationSettings.shared
        settings.quietHoursEnabled = quietHoursEnabled
        settings.quietHoursStartMinutes = quietStartMinutes
        settings.quietHoursEndMinutes = quietEndMinutes
        await I2PRouterAppContext.shared.applyParticipationSettings()
    }

    private static func date(forMinutes minutes: Int) -> Date {
        let calendar = Calendar.current
        let startOfDay = calendar.startOfDay(for: Date())
        return calendar.date(bySettingHour: minutes / 60, minute: minutes % 60,
                             second: 0, of: startOfDay) ?? startOfDay
    }

    private static func minutes(from date: Date) -> Int {
        let components = Calendar.current.dateComponents([.hour, .minute], from: date)
        return (components.hour ?? 0) * 60 + (components.minute ?? 0)
    }

    // MARK: - Blocked peers

    private var blockedPeersCard: some View {
        card(title: "Blocked peers") {
            if blockedPeers.isEmpty {
                Text("No blocked peers. Block one from its inspector on the Router dashboard.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                Text("\(blockedPeers.count) blocked · never used as a tunnel hop or a netdb lookup target")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                blockedPeerRows
                Text("Swipe a peer to unblock it. Blocking closes its live session on the next maintenance tick.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    /// The rows live in a list so each one carries a real swipe action; the list
    /// is sized to its content and does not scroll, leaving the page to the
    /// surrounding scroll view.
    private var blockedPeerRows: some View {
        List {
            ForEach(blockedPeers) { peer in
                blockedPeerRow(peer)
                    .listRowBackground(Color.clear)
                    .listRowInsets(EdgeInsets(top: 6, leading: 0, bottom: 6, trailing: 0))
                    .listRowSeparator(.hidden)
                    .swipeActions(edge: .trailing, allowsFullSwipe: true) {
                        Button(role: .destructive) {
                            unblock(peer)
                        } label: {
                            Label("Unblock", systemImage: "nosign")
                        }
                    }
            }
        }
        .listStyle(.plain)
        .scrollContentBackground(.hidden)
        .scrollDisabled(true)
        .frame(height: CGFloat(blockedPeers.count) * 62)
    }

    private func blockedPeerRow(_ peer: I2PBlockedPeer) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "nosign")
                .font(.caption.weight(.bold))
                .foregroundStyle(Color.red)
                .frame(width: 22, height: 22)
                .background(Color.red.opacity(0.14), in: RoundedRectangle(cornerRadius: 6))
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(peer.shortIdentity)
                        .font(.system(.caption, design: .monospaced).weight(.semibold))
                    Spacer(minLength: 6)
                    Text(peer.blockedAt.formatted(.relative(presentation: .named)))
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                Text(peer.reason.isEmpty ? "No reason given" : peer.reason)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func unblock(_ peer: I2PBlockedPeer) {
        I2PPeerBlocklist.shared.unblock(identityHex: peer.identityHex)
        blockedPeers = I2PPeerBlocklist.shared.all()
        flash("Unblocked \(peer.shortIdentity)")
    }

    // MARK: - Floodfill

    private var floodfillCard: some View {
        card(title: "Floodfill") {
            Toggle(isOn: $floodfillEnabled) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Act as floodfill")
                        .font(.footnote.weight(.medium))
                    Text("Publishes the floodfill capability and serves netdb lookups — expect more transit traffic")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .tint(accent)
            .disabled(republishing)
            .onChange(of: floodfillEnabled) { _, enabled in
                Task { await applyFloodfill(enabled) }
            }

            if republishing {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.mini).tint(accent)
                    Text("Re-publishing RouterInfo…")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                    Spacer()
                }
            }

            Text(advertisementLine)
                .font(.system(.caption2, design: .monospaced))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var advertisementLine: String {
        let advertised = snapshot?.floodfillAdvertised ?? false
        let capability = advertised ? "capability advertised" : "capability withdrawn"
        guard let published = snapshot?.routerInfoPublishedAt else {
            return "RouterInfo not published yet · \(capability)"
        }
        return "RouterInfo re-published \(published.formatted(.relative(presentation: .named))) · \(capability)"
    }

    private func applyFloodfill(_ enabled: Bool) async {
        republishing = true
        await I2PRouterAppContext.shared.setFloodfillEnabled(enabled)
        republishing = false
        flash(enabled ? "Floodfill capability advertised" : "Floodfill capability withdrawn")
    }

    // MARK: - Commits

    /// Debounces the cap sliders so a drag persists and applies once it settles.
    private func scheduleCapCommit() {
        capCommitTask?.cancel()
        capCommitTask = Task {
            try? await Task.sleep(for: .milliseconds(300))
            guard !Task.isCancelled else { return }
            await commitBandwidth()
        }
    }

    private func commitBandwidth() async {
        I2PParticipationSettings.shared.inboundCapKBps = Int(inboundCapKBps)
        I2PParticipationSettings.shared.outboundCapKBps = Int(outboundCapKBps)
        await I2PRouterAppContext.shared.applyParticipationSettings()
        flash("Bandwidth caps applied")
    }

    private func scheduleShareCommit() {
        shareCommitTask?.cancel()
        shareCommitTask = Task {
            try? await Task.sleep(for: .milliseconds(300))
            guard !Task.isCancelled else { return }
            await commitShare()
        }
    }

    private func commitShare() async {
        I2PParticipationSettings.shared.tunnelSharePercent = Int(sharePercent)
        await I2PRouterAppContext.shared.applyParticipationSettings()
        flash("Tunnel share applied")
    }

    // MARK: - Toast

    @ViewBuilder
    private var toast: some View {
        if let confirmation {
            Text(confirmation)
                .font(.caption.weight(.semibold))
                .foregroundStyle(accent)
                .padding(.horizontal, 14)
                .padding(.vertical, 8)
                .background(.ultraThinMaterial, in: Capsule())
                .overlay(
                    Capsule().strokeBorder(accent.opacity(0.35), lineWidth: 1)
                )
                .padding(.top, 8)
                .transition(.opacity.combined(with: .move(edge: .top)))
        }
    }

    private func flash(_ text: String) {
        withAnimation(.easeOut(duration: 0.2)) {
            confirmation = text
        }
        Task {
            try? await Task.sleep(for: .seconds(2))
            withAnimation(.easeIn(duration: 0.3)) {
                if confirmation == text {
                    confirmation = nil
                }
            }
        }
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

    private func formatRate(_ bytesPerSecond: Double) -> String {
        let kb = bytesPerSecond / 1024
        if kb >= 1024 { return String(format: "%.1f MB/s", kb / 1024) }
        if kb >= 100 { return String(format: "%.0f KB/s", kb) }
        return String(format: "%.1f KB/s", kb)
    }
}
