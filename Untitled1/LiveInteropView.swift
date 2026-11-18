//
//  LiveInteropView.swift
//  What this router's last live probe observed against real peers: when it ran,
//  the reseed bootstrap it rested on, and one row per dial attempt with the
//  transport used and how the handshake ended.
//
//  Handshakes only. The screen never presents a row as proof that tunnels or
//  messages work — it says so in the summary card.
//

import SwiftUI
import Combine

/// Holds the last probe report for the lifetime of the process. Nothing is
/// written to disk: a relaunch starts with no result, which the screen's empty
/// state explains.
///
/// State changes are applied on the main queue (the store is read by SwiftUI);
/// the probe itself runs off the main actor.
final class I2PLiveInteropStore: ObservableObject {
    static let shared = I2PLiveInteropStore()

    @Published private(set) var report: I2PLiveProbeReport?
    @Published private(set) var isRunning = false
    @Published private(set) var stage: String?

    private let lock = NSLock()
    private var busy = false

    private init() {}

    func run() async {
        lock.lock()
        guard !busy else {
            lock.unlock()
            return
        }
        busy = true
        lock.unlock()
        defer {
            lock.lock()
            busy = false
            lock.unlock()
        }

        setState {
            $0.isRunning = true
            $0.stage = "Starting the probe"
        }
        let fresh = await I2PLiveInteropProbe.run { [weak self] stage in
            self?.setState { $0.stage = stage }
        }
        setState {
            $0.report = fresh
            $0.stage = nil
            $0.isRunning = false
        }
    }

    /// Applies one state change on the main queue, where SwiftUI reads it.
    private func setState(_ change: @escaping (I2PLiveInteropStore) -> Void) {
        if Thread.isMainThread {
            change(self)
        } else {
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                change(self)
            }
        }
    }
}

struct LiveInteropView: View {
    @ObservedObject private var store = I2PLiveInteropStore.shared
    /// Ticks the "last run" line so "4 minutes ago" stays true while the
    /// screen is open.
    @State private var now = Date()

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)
    private let okGreen = Color(red: 0.29, green: 0.87, blue: 0.50)
    private let warnOrange = Color(red: 0.98, green: 0.62, blue: 0.24)

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                if store.isRunning, store.report != nil {
                    // A re-run keeps the previous rows on screen and names what
                    // this run is doing until the fresh ones replace them.
                    progressStrip
                }
                if let report = store.report {
                    summaryCard(report)
                    bootstrapCard(report.bootstrap)
                    peersCard(report.peers)
                    footnote
                } else if store.isRunning {
                    runningCard
                    footnote
                } else {
                    emptyCard
                    footnote
                }
            }
            .padding(.horizontal, 16)
            .padding(.top, 4)
            .padding(.bottom, 24)
        }
        .background(background.ignoresSafeArea())
        .navigationTitle("Live interoperability")
        .navigationBarTitleDisplayMode(.large)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                runButton
            }
        }
        .task {
            while !Task.isCancelled {
                now = Date()
                try? await Task.sleep(for: .seconds(10))
            }
        }
        .preferredColorScheme(.dark)
    }

    // MARK: - Run control

    private var runButton: some View {
        Button {
            Task { await store.run() }
        } label: {
            HStack(spacing: 6) {
                if store.isRunning {
                    ProgressView()
                        .controlSize(.small)
                        .tint(accent)
                } else {
                    Image(systemName: "play.fill")
                        .font(.caption.weight(.bold))
                }
                Text(store.isRunning ? "Running…" : "Run probe")
                    .font(.subheadline.weight(.semibold))
            }
            .foregroundStyle(accent)
            .padding(.horizontal, 12)
            .padding(.vertical, 7)
            .background(accent.opacity(0.22), in: Capsule())
        }
        .buttonStyle(.plain)
        .disabled(store.isRunning)
        .accessibilityLabel(store.isRunning ? "Probe running" : "Run probe")
        .accessibilityHint("Re-runs the live handshake probe and updates the rows")
    }

    // MARK: - Summary

    private func summaryCard(_ report: I2PLiveProbeReport) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Last probe result")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .textCase(.uppercase)

            if report.peers.isEmpty {
                Text("No peers to dial")
                    .font(.system(size: 34, weight: .bold, design: .rounded))
                    .foregroundStyle(accent)
                    .fixedSize(horizontal: false, vertical: true)
                Text("The network database holds no peer with a dialable address yet. Run the probe again once the router has bootstrapped.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text("\(report.establishedCount)")
                        .font(.system(size: 56, weight: .bold, design: .rounded))
                        .foregroundStyle(accent)
                    Text("of \(report.peers.count)")
                        .font(.system(size: 34, weight: .bold, design: .rounded))
                        .foregroundStyle(.primary)
                }
                .accessibilityElement(children: .ignore)
                .accessibilityLabel(report.ratioLine)

                Text(report.peers.count == 1 ? "peer accepted a handshake" : "peers accepted a handshake")
                    .font(.subheadline)
                    .foregroundStyle(.primary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Text("Last run \(relative(report.ranAt))")
                .font(.footnote)
                .foregroundStyle(.secondary)

            Divider().opacity(0.2)

            Text("Handshakes only — no tunnels or messages were attempted.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    private func relative(_ date: Date) -> String {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .full
        return formatter.localizedString(for: date, relativeTo: now)
    }

    // MARK: - Bootstrap

    private func bootstrapCard(_ bootstrap: I2PLiveBootstrapResult) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Bootstrap")
                .font(.subheadline.weight(.semibold))

            bootstrapRow(label: "Reseed source") {
                if let source = bootstrap.source {
                    Text(displayHost(source))
                        .font(.footnote)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .minimumScaleFactor(0.7)
                        .foregroundStyle(.primary)
                } else {
                    Text("No host answered")
                        .font(.footnote.weight(.medium))
                        .foregroundStyle(warnOrange)
                }
            }

            Divider().opacity(0.2)

            bootstrapRow(label: "RouterInfos") {
                Text(bootstrap.didReseed
                     ? bootstrap.routerInfoLine
                     : "\(bootstrap.floodfills) floodfills from the saved network database")
                    .font(.footnote)
                    .multilineTextAlignment(.trailing)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if let failure = bootstrap.failure {
                Text("Reseed unavailable — \(failure)")
                    .font(.caption2)
                    .foregroundStyle(warnOrange)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    private func bootstrapRow<Value: View>(label: String,
                                           @ViewBuilder value: () -> Value) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(label)
                .font(.footnote)
                .foregroundStyle(.secondary)
            Spacer(minLength: 8)
            value()
        }
        .accessibilityElement(children: .combine)
    }

    private func displayHost(_ source: String) -> String {
        // The report carries the base URL the reseed used; show it the way the
        // screen's design does, without the trailing slash or scheme noise.
        source.hasSuffix("/") ? String(source.dropLast()) : source
    }

    // MARK: - Peers dialled

    private func peersCard(_ peers: [I2PLivePeerAttempt]) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("Peers dialled")
                .font(.subheadline.weight(.semibold))
                .padding(.bottom, 6)

            if peers.isEmpty {
                Text("No peer was dialled.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .padding(.vertical, 6)
            } else {
                ForEach(Array(peers.enumerated()), id: \.element.id) { index, peer in
                    if index > 0 {
                        Divider().opacity(0.2)
                    }
                    peerRow(peer)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    private func peerRow(_ peer: I2PLivePeerAttempt) -> some View {
        HStack(spacing: 10) {
            transportBadge(peer.transport)
            VStack(alignment: .leading, spacing: 2) {
                Text(peer.hashLabel)
                    .font(.system(.subheadline, design: .monospaced).weight(.medium))
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
                Text(peer.endpointLabel)
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
            }
            Spacer(minLength: 8)
            statusView(peer)
                .frame(maxWidth: 132, alignment: .trailing)
        }
        .padding(.vertical, 8)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(peer.transport.rawValue), \(peer.hashLabel), \(peer.endpointLabel), \(peer.statusLabel)")
    }

    private func transportBadge(_ transport: I2PLivePeerAttempt.Transport) -> some View {
        Text(transport.rawValue)
            .font(.caption2.weight(.bold))
            .foregroundStyle(transport == .ntcp2 ? accent : warnOrange)
            .frame(width: 58)
            .padding(.vertical, 6)
            .background(
                (transport == .ntcp2 ? accent : warnOrange).opacity(0.18),
                in: RoundedRectangle(cornerRadius: 9)
            )
            .accessibilityHidden(true)
    }

    @ViewBuilder
    private func statusView(_ peer: I2PLivePeerAttempt) -> some View {
        HStack(alignment: .top, spacing: 6) {
            statusGlyph(peer.ending)
                .frame(width: 12, height: 14, alignment: .center)
            Text(peer.statusLabel)
                .font(.footnote)
                .foregroundStyle(statusColor(peer.ending))
                .multilineTextAlignment(.trailing)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    @ViewBuilder
    private func statusGlyph(_ ending: I2PLivePeerAttempt.Ending) -> some View {
        switch ending {
        case .established:
            Circle()
                .fill(okGreen)
                .frame(width: 8, height: 8)
                .padding(.top, 4)
        case .closedAfterSessionRequest, .failed:
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.caption2)
                .foregroundStyle(warnOrange)
        case .connectTimeout, .handshakeTimeout:
            Rectangle()
                .fill(Color.secondary.opacity(0.7))
                .frame(width: 10, height: 2)
                .padding(.top, 6)
        }
    }

    private func statusColor(_ ending: I2PLivePeerAttempt.Ending) -> Color {
        switch ending {
        case .established: return okGreen
        case .closedAfterSessionRequest, .failed: return warnOrange
        case .connectTimeout, .handshakeTimeout: return .secondary
        }
    }

    // MARK: - Running and empty states

    private var progressStrip: some View {
        HStack(spacing: 8) {
            ProgressView()
                .controlSize(.small)
                .tint(accent)
            Text(store.stage ?? "Working…")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(accent.opacity(0.10), in: RoundedRectangle(cornerRadius: 14))
        .accessibilityElement(children: .combine)
    }

    private var runningCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                ProgressView()
                    .controlSize(.small)
                    .tint(accent)
                Text("Probe running")
                    .font(.subheadline.weight(.semibold))
            }
            Text(store.stage ?? "Working…")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Text("One real dial attempt per peer, with a handshake window. No tunnels and no messages are sent.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
        .accessibilityElement(children: .combine)
    }

    private var emptyCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("No probe has run yet")
                .font(.subheadline.weight(.semibold))
            Text("The probe bootstraps from a public reseed server, then dials up to three mainnet peers once each and reports how every handshake ended.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Text("Handshakes only — no tunnels or messages are attempted, and the results are kept in memory until the app quits.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Button {
                Task { await store.run() }
            } label: {
                Label("Run probe", systemImage: "play.fill")
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
            .accessibilityHint("Dials three mainnet peers and reports each handshake")
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    private var footnote: some View {
        Text("A peer's rejection reason is only visible in its own log.")
            .font(.caption2)
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
            .fixedSize(horizontal: false, vertical: true)
    }
}

#Preview {
    NavigationStack {
        LiveInteropView()
    }
}
