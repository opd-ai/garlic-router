//
//  RouterHealthView.swift
//  Local router availability and one-minute peer, tunnel and traffic history.
//

import SwiftUI
import Charts

private enum RouterHealthTrend: String, CaseIterable, Identifiable, Equatable {
    case peers
    case tunnels

    var id: String { rawValue }

    var title: String {
        switch self {
        case .peers: return "Peer count"
        case .tunnels: return "Ready tunnels"
        }
    }

    var emptyName: String {
        switch self {
        case .peers: return "peer-count"
        case .tunnels: return "ready-tunnel"
        }
    }

    func value(in sample: I2PRouterHealthSample) -> Int {
        switch self {
        case .peers: return sample.activePeers
        case .tunnels: return sample.readyTunnels
        }
    }
}

struct RouterHealthView: View {
    @State private var window: I2PRouterHealthWindow = .twentyFourHours
    @State private var selectedTrend: RouterHealthTrend = .peers
    @State private var reading = I2PRouterHealthHistory.shared.reading(window: .twentyFourHours)
    @State private var retainedSamples = I2PRouterHealthHistory.shared.allSamples()

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)
    private let healthy = Color(red: 0.29, green: 0.87, blue: 0.50)
    private let warning = Color(red: 0.98, green: 0.62, blue: 0.24)

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                Text("Local history · last \(window.title)")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)

                uptimeCard
                windowPicker
                exportCard

                if reading.hasSamples {
                    availabilityCard
                    trendCard
                    trafficCard
                    interruptionCard
                } else {
                    trendCard
                }

                Text("History stays on this device. Sampling pauses when the app is suspended.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding(.horizontal, 16)
            .padding(.top, 4)
            .padding(.bottom, 24)
        }
        .background(background.ignoresSafeArea())
        .navigationTitle("Router health")
        .navigationBarTitleDisplayMode(.large)
        .preferredColorScheme(.dark)
        .task { await liveLoop() }
        .onChange(of: window) { _, newWindow in
            refreshReading(for: newWindow)
        }
    }

    // MARK: - Readings

    private func liveLoop() async {
        while !Task.isCancelled {
            refreshReading(for: window)
            try? await Task.sleep(for: .seconds(1))
        }
    }

    private func refreshReading(for selectedWindow: I2PRouterHealthWindow) {
        let history = I2PRouterHealthHistory.shared
        reading = history.reading(window: selectedWindow)
        retainedSamples = history.allSamples()
    }

    private var exportCard: some View {
        let export = I2PRouterHealthExport.payload(samples: retainedSamples)
        return Group {
            if let export {
                ShareLink(item: export,
                          subject: Text(export.subject),
                          preview: SharePreview(export.fileName,
                                                image: Image(systemName: "tablecells"))) {
                    exportLabel(sampleCount: export.rowCount, enabled: true)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Export router health history as CSV")
                .accessibilityHint("Shares a file with all \(export.rowCount) retained local samples. Nothing is sent unless you choose a destination.")
            } else {
                Button {} label: {
                    exportLabel(sampleCount: 0, enabled: false)
                }
                .buttonStyle(.plain)
                .disabled(true)
                .accessibilityLabel("Export router health history as CSV")
                .accessibilityHint("There are no retained samples to export")
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(14)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 16))
    }

    private func exportLabel(sampleCount: Int, enabled: Bool) -> some View {
        HStack(spacing: 11) {
            Image(systemName: "doc.text.arrow.up")
                .font(.title3.weight(.semibold))
                .foregroundStyle(enabled ? accent : Color.secondary)
                .frame(width: 34)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text("Export history as CSV")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(enabled ? Color.primary : Color.secondary)
                Text(enabled
                     ? "\(sampleCount) retained samples · saved or shared only when you choose"
                     : "No retained samples yet")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 4)
            if enabled {
                Image(systemName: "chevron.right")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.tertiary)
                    .accessibilityHidden(true)
            }
        }
        .contentShape(Rectangle())
    }

    // MARK: - Uptime

    private var uptimeCard: some View {
        let percent = reading.uptimePercent
        let isHealthy = percent.map { $0 >= 95 } ?? false
        let statusColor = percent == nil ? Color.secondary : (isHealthy ? healthy : warning)
        return VStack(alignment: .leading, spacing: 8) {
            Text("Uptime")
                .font(.headline)
                .foregroundStyle(.primary)
            HStack(alignment: .center, spacing: 8) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(percent.map { String(format: "%.1f%%", $0) } ?? "—")
                        .font(.system(size: 42, weight: .bold, design: .rounded))
                        .foregroundStyle(accent)
                        .contentTransition(.numericText())
                        .accessibilityLabel(percent.map { "\(String(format: "%.1f", $0)) percent uptime" } ?? "Uptime not available yet")
                    Text(reading.onlineSeconds > 0
                         ? "Online \(durationText(reading.onlineSeconds))"
                         : (reading.hasSamples ? "Measuring uptime…" : "Waiting for the first sample"))
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 4)
                HStack(spacing: 7) {
                    Circle()
                        .fill(statusColor)
                        .frame(width: 9, height: 9)
                    Text(percent == nil ? "Collecting" : (isHealthy ? "Healthy" : "Interrupted"))
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(statusColor)
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 9)
                .background(statusColor.opacity(0.13),
                            in: RoundedRectangle(cornerRadius: 11))
                .accessibilityElement(children: .combine)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
        .accessibilityElement(children: .contain)
    }

    private var windowPicker: some View {
        Picker("Trend window", selection: $window) {
            ForEach(I2PRouterHealthWindow.allCases) { option in
                Text(option.title).tag(option)
            }
        }
        .pickerStyle(.segmented)
        .accessibilityHint("Changes the time range shown in router health history")
    }

    // MARK: - Availability trend

    private var availabilityCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Availability")
                .font(.headline)
                .foregroundStyle(.primary)
                .accessibilityAddTraits(.isHeader)

            Chart {
                ForEach(reading.chartPoints) { point in
                    LineMark(x: .value("Time", point.sample.sampledAt),
                             y: .value("Availability", point.value),
                             series: .value("Run", point.segment))
                        .foregroundStyle(accent)
                        .lineStyle(StrokeStyle(lineWidth: 2.5, lineCap: .round))
                        .interpolationMethod(.linear)
                }

                ForEach(visibleInterruptions) { interruption in
                    RuleMark(x: .value("Interruption", interruption.midpoint))
                        .foregroundStyle(warning.opacity(0.75))
                        .lineStyle(interruptionLineStyle(for: interruption))
                        .annotation(position: .bottom, alignment: .center, spacing: 3) {
                            if window != .sevenDays {
                                Text(interruption.cause.title)
                                    .font(.caption2.weight(.medium))
                                    .foregroundStyle(.primary)
                                    .padding(.horizontal, 6)
                                    .padding(.vertical, 3)
                                    .background(.ultraThinMaterial, in: Capsule())
                                    .fixedSize()
                            }
                        }
                }
            }
            .chartXScale(domain: Date().addingTimeInterval(-window.duration)...Date())
            .chartYScale(domain: 0...100)
            .chartXAxis {
                let component: Calendar.Component = window == .sevenDays ? .day : .hour
                let count = window == .sixHours ? 1 : (window == .twentyFourHours ? 6 : 2)
                AxisMarks(values: .stride(by: component, count: count)) { value in
                    AxisGridLine().foregroundStyle(Color.white.opacity(0.08))
                    AxisValueLabel {
                        if let date = value.as(Date.self) {
                            if window == .sevenDays {
                                Text(date.formatted(.dateTime.month(.abbreviated).day()))
                                    .font(.caption2)
                            } else {
                                Text(date.formatted(date: .omitted, time: .shortened))
                                    .font(.caption2)
                            }
                        }
                    }
                }
            }
            .chartYAxis {
                AxisMarks(position: .leading, values: [0, 50, 100]) { value in
                    AxisGridLine().foregroundStyle(Color.white.opacity(0.08))
                    AxisValueLabel {
                        if let percent = value.as(Int.self) {
                            Text("\(percent)%")
                                .font(.caption2)
                        }
                    }
                }
            }
            .frame(height: 205)
            .accessibilityLabel(availabilityAccessibilityLabel)

            if window == .sevenDays, !visibleInterruptions.isEmpty {
                Text("Dashed: app suspended · dotted: sampling gap")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    private var visibleInterruptions: [I2PRouterHealthInterruption] {
        let cutoff = Date().addingTimeInterval(-window.duration)
        return reading.samples.compactMap(\.interruptionBefore)
            .filter { $0.midpoint >= cutoff }
    }

    private func interruptionLineStyle(for interruption: I2PRouterHealthInterruption) -> StrokeStyle {
        guard window == .sevenDays, interruption.cause == .samplingPaused else {
            return StrokeStyle(lineWidth: 1, dash: [4, 4])
        }
        return StrokeStyle(lineWidth: 1, dash: [1, 3])
    }

    private var availabilityAccessibilityLabel: String {
        guard !reading.chartPoints.isEmpty else { return "No availability samples yet" }
        let gaps = visibleInterruptions.count
        return "Availability over the last \(window.title). "
            + "\(reading.uptimePercent.map { String(format: "%.1f percent", $0) } ?? "Uptime not available yet"). "
            + "\(gaps) sampling interruption\(gaps == 1 ? "" : "s")."
    }

    // MARK: - Peer and tunnel trends

    private var trendCard: some View {
        let points = reading.chartPoints
        let latestValue = points.last.map { selectedTrend.value(in: $0.sample) }
        let maximum = points.map { selectedTrend.value(in: $0.sample) }.max() ?? 0
        let trendColor = selectedTrend == .peers
            ? Color(red: 0.32, green: 0.78, blue: 0.94)
            : accent

        return VStack(alignment: .leading, spacing: 10) {
            Text(selectedTrend.title)
                .font(.headline)
                .foregroundStyle(.primary)
                .accessibilityAddTraits(.isHeader)

            Picker("History metric", selection: $selectedTrend) {
                Text("Peers").tag(RouterHealthTrend.peers)
                Text("Ready tunnels").tag(RouterHealthTrend.tunnels)
            }
            .pickerStyle(.segmented)
            .accessibilityHint("Choose which local router history trend to view")

            if let latestValue {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text("\(latestValue)")
                        .font(.system(size: 30, weight: .semibold, design: .rounded))
                        .foregroundStyle(trendColor)
                        .contentTransition(.numericText())
                    Text("at last sample")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                .accessibilityElement(children: .combine)
            }

            if points.isEmpty {
                VStack(alignment: .leading, spacing: 7) {
                    Image(systemName: "chart.xyaxis.line")
                        .font(.title3.weight(.semibold))
                        .foregroundStyle(trendColor)
                        .accessibilityHidden(true)
                    Text("No \(selectedTrend.emptyName) samples in this range")
                        .font(.subheadline.weight(.semibold))
                    Text("Keep the router running with the app open to collect one-minute samples. Sampling pauses while iOS suspends the app.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .frame(maxWidth: .infinity, minHeight: 118, alignment: .leading)
                .padding(12)
                .background(Color.white.opacity(0.035), in: RoundedRectangle(cornerRadius: 12))
                .accessibilityElement(children: .combine)
            } else {
                Chart {
                    ForEach(points) { point in
                        LineMark(x: .value("Time", point.sample.sampledAt),
                                 y: .value(selectedTrend.title, selectedTrend.value(in: point.sample)),
                                 series: .value("Run", point.segment))
                            .foregroundStyle(trendColor)
                            .lineStyle(StrokeStyle(lineWidth: 2.5, lineCap: .round))
                            .interpolationMethod(.linear)
                    }

                    ForEach(visibleInterruptions) { interruption in
                        RuleMark(x: .value("Interruption", interruption.midpoint))
                            .foregroundStyle(warning.opacity(0.75))
                            .lineStyle(interruptionLineStyle(for: interruption))
                    }
                }
                .chartXScale(domain: Date().addingTimeInterval(-window.duration)...Date())
                .chartYScale(domain: 0...max(1, Int(ceil(Double(maximum) * 1.15))))
                .chartXAxis {
                    let component: Calendar.Component = window == .sevenDays ? .day : .hour
                    let count = window == .sixHours ? 1 : (window == .twentyFourHours ? 6 : 2)
                    AxisMarks(values: .stride(by: component, count: count)) { value in
                        AxisGridLine().foregroundStyle(Color.white.opacity(0.08))
                        AxisValueLabel {
                            if let date = value.as(Date.self) {
                                if window == .sevenDays {
                                    Text(date.formatted(.dateTime.month(.abbreviated).day()))
                                        .font(.caption2)
                                } else {
                                    Text(date.formatted(date: .omitted, time: .shortened))
                                        .font(.caption2)
                                }
                            }
                        }
                    }
                }
                .chartYAxis {
                    AxisMarks(position: .leading, values: .automatic(desiredCount: 4)) { value in
                        AxisGridLine().foregroundStyle(Color.white.opacity(0.08))
                        AxisValueLabel {
                            if let count = value.as(Int.self) {
                                Text("\(count)")
                                    .font(.caption2)
                            }
                        }
                    }
                }
                .frame(height: 205)
                .accessibilityLabel(trendAccessibilityLabel)

                if window == .sevenDays, !visibleInterruptions.isEmpty {
                    Text("Dashed: app suspended · dotted: sampling gap")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    private var trendAccessibilityLabel: String {
        let count = reading.chartPoints.count
        let gaps = visibleInterruptions.count
        return "\(selectedTrend.title) over the last \(window.title). "
            + "\(count) samples and \(gaps) sampling interruption\(gaps == 1 ? "" : "s")."
    }

    // MARK: - Traffic summary

    private var trafficCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Traffic")
                .font(.headline)
                .foregroundStyle(.primary)
                .accessibilityAddTraits(.isHeader)
            HStack(alignment: .top, spacing: 0) {
                trafficColumn(value: formatBytes(reading.receivedBytes), label: "received")
                Rectangle()
                    .fill(Color.white.opacity(0.12))
                    .frame(width: 1, height: 48)
                    .padding(.horizontal, 14)
                trafficColumn(value: formatBytes(reading.sentBytes), label: "sent")
                Spacer(minLength: 0)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Traffic over the last \(window.title): \(formatBytes(reading.receivedBytes)) received, \(formatBytes(reading.sentBytes)) sent")
    }

    private func trafficColumn(value: String, label: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(value)
                .font(.system(.title2, design: .rounded).weight(.bold))
                .lineLimit(1)
                .minimumScaleFactor(0.75)
            Text(label)
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    // MARK: - Interruptions

    private var interruptionCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Last interruption")
                .font(.headline)
                .foregroundStyle(.primary)
                .accessibilityAddTraits(.isHeader)
            if let interruption = reading.lastInterruption {
                Text("\(dateText(interruption.startedAt)) · \(durationText(interruption.duration))")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                Text(interruption.cause.title)
                    .font(.caption2)
                    .foregroundStyle(interruption.cause == .appSuspended ? warning : .secondary)
            } else {
                Text("No sampling gaps in this window")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    // MARK: - Formatting

    private func formatBytes(_ bytes: Int) -> String {
        let value = Double(max(0, bytes))
        if value >= 1_048_576 { return String(format: "%.1f MB", value / 1_048_576) }
        if value >= 1024 { return String(format: "%.0f KB", value / 1024) }
        return "\(max(0, bytes)) B"
    }

    private func durationText(_ seconds: TimeInterval) -> String {
        let minutes = max(0, Int(seconds / 60))
        if minutes >= 60 { return "\(minutes / 60)h \(minutes % 60)m" }
        if minutes == 0 { return "less than 1 min" }
        return "\(minutes) min"
    }

    private func dateText(_ date: Date) -> String {
        let day = Calendar.current.isDateInToday(date)
            ? "Today"
            : date.formatted(date: .abbreviated, time: .omitted)
        let time = date.formatted(date: .omitted, time: .shortened)
        return "\(day), \(time)"
    }
}
