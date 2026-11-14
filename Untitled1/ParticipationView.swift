//
//  ParticipationView.swift
//  Network-participation controls: bandwidth caps, tunnel-share ratio and the
//  floodfill role. Every change applies to the running router immediately and
//  persists across launches; each control shows its live measured value.
//

import SwiftUI

struct ParticipationView: View {
    @State private var snapshot: I2PRouterStatusSnapshot?
    @State private var inboundCapKBps = Double(I2PParticipationSettings.shared.inboundCapKBps)
    @State private var outboundCapKBps = Double(I2PParticipationSettings.shared.outboundCapKBps)
    @State private var sharePercent = Double(I2PParticipationSettings.shared.tunnelSharePercent)
    @State private var floodfillEnabled = I2PParticipationSettings.shared.floodfillEnabled
    @State private var reading = I2PBandwidthGovernor.shared.reading()
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
                bandwidthCard
                shareCard
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
            try? await Task.sleep(for: .seconds(1))
        }
    }

    private func syncFromSettings() {
        let settings = I2PParticipationSettings.shared
        inboundCapKBps = Double(settings.inboundCapKBps)
        outboundCapKBps = Double(settings.outboundCapKBps)
        sharePercent = Double(settings.tunnelSharePercent)
        floodfillEnabled = settings.floodfillEnabled
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
