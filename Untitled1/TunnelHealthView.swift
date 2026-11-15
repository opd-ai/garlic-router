//
//  TunnelHealthView.swift
//  Tunnel health: build success rate over the last hour, build latency
//  (median and p90), failures broken down by the hop's return code, and a live
//  per-direction pool timeline showing each tunnel's age against its lifetime.
//  Opened from the Router dashboard's tunnel pools; fed by the status engine.
//

import SwiftUI

struct TunnelHealthView: View {
    @State private var snapshot: I2PRouterStatusSnapshot?
    @State private var collapsed: Set<String> = []

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)
    private let warn = Color(red: 0.98, green: 0.62, blue: 0.24)

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                Text("Builds, latencies and the pools behind them")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)

                if let snapshot {
                    successRateCard(snapshot)
                    latencyCard(snapshot)
                    failuresCard(snapshot)
                    poolsCard(snapshot)
                    footer(snapshot)
                } else {
                    waitingCard
                }
            }
            .padding(.horizontal, 16)
            .padding(.top, 4)
            .padding(.bottom, 24)
        }
        .background(background.ignoresSafeArea())
        .navigationTitle("Tunnel health")
        .navigationBarTitleDisplayMode(.large)
        .preferredColorScheme(.dark)
        .task { await liveLoop() }
    }

    // MARK: - Live readings

    private func liveLoop() async {
        while !Task.isCancelled {
            snapshot = await I2PRouterAppContext.shared.engine.snapshot()
            try? await Task.sleep(for: .seconds(1))
        }
    }

    // MARK: - Derived readings

    private struct BuildStats {
        let succeeded: Int
        let failed: Int
        let median: TimeInterval?
        let p90: TimeInterval?
        /// Failure count per hop return code; nil is a build that timed out.
        let failureCounts: [UInt8?: Int]

        var total: Int { succeeded + failed }
        var rate: Double { total == 0 ? 0 : Double(succeeded) / Double(total) }
    }

    private func stats(_ snapshot: I2PRouterStatusSnapshot) -> BuildStats {
        let cutoff = snapshot.capturedAt.addingTimeInterval(-I2PTunnelPool.buildHistoryWindow)
        let attempts = snapshot.tunnelBuilds.filter { $0.startedAt >= cutoff }
        let succeeded = attempts.filter(\.succeeded).count
        let latencies = attempts.compactMap { $0.succeeded ? $0.latency : nil }.sorted()
        var failureCounts: [UInt8?: Int] = [:]
        for record in attempts where !record.succeeded {
            failureCounts[record.returnCode, default: 0] += 1
        }
        return BuildStats(succeeded: succeeded,
                          failed: attempts.count - succeeded,
                          median: percentile(latencies, 0.5),
                          p90: percentile(latencies, 0.9),
                          failureCounts: failureCounts)
    }

    /// Linear-interpolated percentile over an already-sorted series.
    private func percentile(_ sorted: [TimeInterval], _ p: Double) -> TimeInterval? {
        guard let first = sorted.first else { return nil }
        if sorted.count == 1 { return first }
        let position = Double(sorted.count - 1) * p
        let lower = Int(position.rounded(.down))
        let upper = min(sorted.count - 1, lower + 1)
        let weight = position - Double(lower)
        return sorted[lower] * (1 - weight) + sorted[upper] * weight
    }

    // MARK: - Success rate

    private func successRateCard(_ snapshot: I2PRouterStatusSnapshot) -> some View {
        let stats = stats(snapshot)
        return card(title: "Success rate", id: "success") {
            HStack(alignment: .firstTextBaseline, spacing: 1) {
                Text(stats.total == 0 ? "—" : "\(Int((stats.rate * 100).rounded()))")
                    .font(.system(size: 56, weight: .bold, design: .rounded))
                    .foregroundStyle(accent)
                if stats.total > 0 {
                    Text("%")
                        .font(.system(size: 32, weight: .bold, design: .rounded))
                        .foregroundStyle(accent)
                }
            }
            Text(stats.total == 0
                 ? "no build attempts · last hour"
                 : "built \(stats.succeeded) of \(stats.total) attempts · last hour")
                .font(.footnote)
                .foregroundStyle(.secondary)
            splitBar(stats)
            HStack(spacing: 8) {
                Text("\(stats.succeeded) succeeded")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                Spacer(minLength: 4)
                Text("\(stats.failed) failed")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func splitBar(_ stats: BuildStats) -> some View {
        let total = max(stats.total, 1)
        let fraction = CGFloat(stats.succeeded) / CGFloat(total)
        return GeometryReader { proxy in
            ZStack(alignment: .leading) {
                Capsule().fill(warn.opacity(stats.failed > 0 ? 0.9 : 0.18))
                if stats.succeeded > 0 {
                    Capsule()
                        .fill(accent)
                        .frame(width: max(2, proxy.size.width * fraction))
                }
            }
        }
        .frame(height: 9)
        .padding(.vertical, 2)
    }

    // MARK: - Build latency

    private func latencyCard(_ snapshot: I2PRouterStatusSnapshot) -> some View {
        let stats = stats(snapshot)
        return card(title: "Build latency", id: "latency") {
            HStack(alignment: .top, spacing: 0) {
                latencyColumn(label: "median", seconds: stats.median)
                Rectangle()
                    .fill(Color.white.opacity(0.10))
                    .frame(width: 1, height: 62)
                    .padding(.horizontal, 14)
                latencyColumn(label: "p90", seconds: stats.p90)
                Spacer(minLength: 0)
            }
            .padding(.top, 2)
            Text("measured from build send to build reply")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
    }

    private func latencyColumn(label: String, seconds: TimeInterval?) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
            HStack(alignment: .firstTextBaseline, spacing: 3) {
                Text(seconds.map { String(format: "%.1f", $0) } ?? "—")
                    .font(.system(size: 44, weight: .bold, design: .rounded))
                    .foregroundStyle(.primary)
                    .contentTransition(.numericText())
                if seconds != nil {
                    Text("s")
                        .font(.system(size: 20, weight: .semibold, design: .rounded))
                        .foregroundStyle(.secondary)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    // MARK: - Failures

    private struct FailureRow: Identifiable {
        let code: String
        let name: String
        let detail: String
        let count: Int
        let tint: Color
        var id: String { code + name }
    }

    private func failureRows(_ stats: BuildStats) -> [FailureRow] {
        let bandwidth = I2PTunnelBuildReturnCode.bandwidthExceeded.rawValue
        let overload = I2PTunnelBuildReturnCode.overload.rawValue
        let tunnelIDInUse = I2PTunnelBuildReturnCode.tunnelIDInUse.rawValue
        let loop = I2PTunnelBuildReturnCode.loop.rawValue

        var rows: [FailureRow] = [
            FailureRow(code: "\(bandwidth)",
                       name: "Bandwidth exceeded",
                       detail: "Remote hop reported rate limit exceeded.",
                       count: stats.failureCounts[bandwidth] ?? 0,
                       tint: warn),
            FailureRow(code: "\(overload)",
                       name: "Overload",
                       detail: "Remote hop reported they are overloaded.",
                       count: stats.failureCounts[overload] ?? 0,
                       tint: warn),
            FailureRow(code: "\(tunnelIDInUse)",
                       name: "Tunnel ID in use",
                       detail: "Remote hop reported the tunnel ID is already in use.",
                       count: stats.failureCounts[tunnelIDInUse] ?? 0,
                       tint: .secondary),
            FailureRow(code: "\(loop)",
                       name: "Loop",
                       detail: "Reply came back through a hop already on the path.",
                       count: stats.failureCounts[loop] ?? 0,
                       tint: accent),
            FailureRow(code: "—",
                       name: "Timeout",
                       detail: "No response from remote hop within timeout window.",
                       count: stats.failureCounts[nil] ?? 0,
                       tint: warn)
        ]
        // A hop may answer with a code this list does not name; show it rather
        // than folding it into one of the rows above.
        let known: Set<UInt8?> = [bandwidth, overload, tunnelIDInUse, loop, nil]
        for (code, count) in stats.failureCounts.sorted(by: { ($0.key ?? 255) < ($1.key ?? 255) })
        where !known.contains(code) {
            rows.append(FailureRow(code: "\(code ?? 0)",
                                   name: "Rejected (code \(code ?? 0))",
                                   detail: "Remote hop answered with a return code this list does not name.",
                                   count: count,
                                   tint: .secondary))
        }
        return rows
    }

    private func failuresCard(_ snapshot: I2PRouterStatusSnapshot) -> some View {
        let stats = stats(snapshot)
        return card(title: "Failures", id: "failures") {
            ForEach(failureRows(stats)) { row in
                HStack(spacing: 12) {
                    Text(row.code)
                        .font(.system(.caption2, design: .monospaced).weight(.bold))
                        .foregroundStyle(row.tint)
                        .frame(width: 40, height: 26)
                        .background(row.tint.opacity(0.16), in: RoundedRectangle(cornerRadius: 8))
                    VStack(alignment: .leading, spacing: 2) {
                        Text(row.name)
                            .font(.footnote.weight(.semibold))
                            .foregroundStyle(row.count > 0 ? .primary : .secondary)
                        Text(row.detail)
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer(minLength: 6)
                    Text("\(row.count)")
                        .font(.system(.footnote, design: .rounded).weight(.semibold))
                        .foregroundStyle(row.count > 0 ? .primary : .secondary)
                }
                .padding(.vertical, 3)
            }
        }
    }

    // MARK: - Pools

    private func poolsCard(_ snapshot: I2PRouterStatusSnapshot) -> some View {
        card(title: "Pools", id: "pools") {
            if snapshot.pools.isEmpty {
                Text("No pool is attached yet — tunnel builds appear once the router starts.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(snapshot.pools, id: \.direction) { pool in
                    poolSection(pool, now: snapshot.capturedAt)
                }
            }
        }
    }

    private func poolSection(_ pool: I2PRouterStatusSnapshot.PoolSummary, now: Date) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                Text(pool.direction.capitalized)
                    .font(.footnote.weight(.semibold))
                Spacer(minLength: 6)
                Text(poolSummaryText(pool))
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            if pool.tunnels.isEmpty && pool.buildingCount == 0 {
                Text("No tunnels yet — builds start once peers are known.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .padding(.bottom, 2)
            } else {
                ForEach(pool.tunnels) { tunnel in
                    tunnelRow(tunnel, now: now)
                }
                ForEach(Array(0..<pool.buildingCount), id: \.self) { _ in
                    buildingRow
                }
            }
        }
    }

    private func poolSummaryText(_ pool: I2PRouterStatusSnapshot.PoolSummary) -> String {
        var text = "\(pool.tunnels.count) of \(pool.targetCount) active"
        if pool.buildingCount > 0 {
            text += " · \(pool.buildingCount) building"
        }
        return text
    }

    private func tunnelRow(_ tunnel: I2PRouterStatusSnapshot.TunnelSummary, now: Date) -> some View {
        let remaining = max(0, tunnel.expiresAt.timeIntervalSince(now))
        let lifetime = max(1, tunnel.expiresAt.timeIntervalSince(tunnel.createdAt))
        let elapsed = min(1, max(0, 1 - remaining / lifetime))
        let healthy = remaining > lifetime / 3
        let tint = healthy ? Color.green : warn
        return VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 8) {
                Circle()
                    .fill(tint)
                    .frame(width: 8, height: 8)
                Text(gatewayLabel(tunnel.gatewayHashHex))
                    .font(.footnote.weight(.medium))
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
                Spacer(minLength: 6)
                Text("\(tunnel.hopCount) hops")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .frame(width: 52, alignment: .trailing)
                Text("expires in \(countdown(remaining))")
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .frame(width: 104, alignment: .trailing)
            }
            GeometryReader { proxy in
                ZStack(alignment: .leading) {
                    Capsule().fill(Color.white.opacity(0.08))
                    Capsule()
                        .fill(tint.opacity(0.75))
                        .frame(width: max(2, proxy.size.width * elapsed))
                }
            }
            .frame(height: 3)
            .padding(.leading, 16)
        }
        .padding(.vertical, 2)
    }

    private var buildingRow: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(Color.white.opacity(0.25))
                .frame(width: 8, height: 8)
            Text("Building…")
                .font(.footnote)
                .foregroundStyle(.secondary)
            Spacer(minLength: 6)
            Text("—")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .frame(width: 52, alignment: .trailing)
            Text("—")
                .font(.system(.caption2, design: .monospaced))
                .foregroundStyle(.secondary)
                .frame(width: 104, alignment: .trailing)
        }
        .padding(.vertical, 2)
    }

    // MARK: - Footer

    private func footer(_ snapshot: I2PRouterStatusSnapshot) -> some View {
        HStack(spacing: 6) {
            Circle()
                .fill(Color.green)
                .frame(width: 6, height: 6)
            Text("Live · updated \(snapshot.capturedAt.formatted(date: .omitted, time: .standard))")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var waitingCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Waiting for the router")
                .font(.headline)
            Text("Start the router from the Router tab; build attempts, latencies and pool timelines appear here as tunnels are created.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    // MARK: - Card chrome

    private func card<Content: View>(title: String,
                                     id: String,
                                     @ViewBuilder content: () -> Content) -> some View {
        let expanded = !collapsed.contains(id)
        return VStack(alignment: .leading, spacing: 10) {
            Button {
                withAnimation(.easeInOut(duration: 0.18)) {
                    if expanded { collapsed.insert(id) } else { collapsed.remove(id) }
                }
            } label: {
                HStack(spacing: 6) {
                    Text(title)
                        .font(.headline)
                        .foregroundStyle(.primary)
                    Spacer(minLength: 6)
                    Image(systemName: "chevron.right")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                        .rotationEffect(.degrees(expanded ? 90 : 0))
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            if expanded {
                content()
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    // MARK: - Formatting

    private func gatewayLabel(_ hex: String) -> String {
        guard !hex.isEmpty else { return "Tunnel" }
        return "gateway \(hex.prefix(8))…"
    }

    private func countdown(_ seconds: TimeInterval) -> String {
        let total = Int(seconds)
        return String(format: "%d:%02d", total / 60, total % 60)
    }
}
