//
//  PeerTrafficCompareView.swift
//  Two peers' last 15 minutes on one chart, reached from the peer inspector.
//  The peer being inspected is the violet side, a picked live session is the
//  teal side, and a swap control exchanges them.
//

import SwiftUI
import Charts

struct PeerTrafficCompareView: View {
    /// The left (violet) side's identity — the peer the inspector was opened
    /// on, until a swap makes the picked peer the left one.
    @State private var leftID: String
    /// The right (teal) side, once a peer has been picked.
    @State private var rightID: String?

    @State private var livePeers: [I2PPeerSummary] = []
    /// The last reading held for each identity, kept after a session ends so
    /// the stat columns still name what the session exchanged.
    @State private var summaries: [String: I2PPeerSummary] = [:]
    @State private var samples: [String: [I2PPeerTrafficSample]] = [:]
    @State private var averages: [String: I2PPeerTrafficAverage] = [:]
    @State private var capturedAt = Date()
    @State private var pickerPresented = false

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)
    /// The inspected peer's violet and the comparison peer's teal, the same two
    /// tints the inspector's own traffic chart uses for received and sent.
    private let leftTint = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let rightTint = Color(red: 0.36, green: 0.80, blue: 0.85)

    private var engine: I2PRouterStatusEngine {
        I2PRouterAppContext.shared.engine
    }

    init(summary: I2PPeerSummary) {
        _leftID = State(initialValue: summary.id)
        _summaries = State(initialValue: [summary.id: summary])
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                headerCard

                if let picked = rightID, !isLive(picked) {
                    endedCard(picked)
                }
                if rightID == nil || !isLive(rightID ?? "") {
                    pickPromptCard
                }
                if let picked = rightID, isLive(picked) {
                    chartCard(picked)
                    statsCard(picked)
                }

                Text("Readings come from the router status engine, sampled once a second. Nothing here is stored — the window starts fresh each launch.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: .infinity)
            }
            .padding(.horizontal, 16)
            .padding(.top, 4)
            .padding(.bottom, 24)
        }
        .background(background.ignoresSafeArea())
        .navigationTitle("Compare")
        .navigationBarTitleDisplayMode(.inline)
        .task {
            // Both views poll the engine directly: the dashboard consumes the
            // shared snapshot stream, and reading the counters here is what
            // keeps the two charts filling while the screen is open.
            while !Task.isCancelled {
                let snapshot = await engine.snapshot()
                livePeers = snapshot.peers
                for peer in snapshot.peers {
                    summaries[peer.id] = peer
                }
                var freshSamples: [String: [I2PPeerTrafficSample]] = [:]
                var freshAverages: [String: I2PPeerTrafficAverage] = [:]
                for peerID in [leftID, rightID].compactMap({ $0 }) {
                    freshSamples[peerID] = engine.peerTrafficSamples(for: peerID)
                    freshAverages[peerID] = engine.peerTrafficAverage(for: peerID)
                }
                samples = freshSamples
                averages = freshAverages
                capturedAt = Date()
                try? await Task.sleep(for: .seconds(1))
            }
        }
        .sheet(isPresented: $pickerPresented) {
            PeerComparePickerSheet(peers: pickerChoices, tint: rightTint) { picked in
                rightID = picked
            }
        }
    }

    // MARK: - Header

    private var headerCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Image(systemName: "chart.line.uptrend.xyaxis")
                    .font(.caption)
                    .foregroundStyle(accent)
                    .accessibilityHidden(true)
                Text("Peer traffic comparison")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .textCase(.uppercase)
                    .accessibilityAddTraits(.isHeader)
                Spacer(minLength: 6)
                swapButton
            }
            sideRow(leftID, tint: leftTint)
            if let picked = rightID {
                sideRow(picked, tint: rightTint)
            } else {
                Text("Pick a second live session to draw beside this one.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    private func sideRow(_ peerID: String, tint: Color) -> some View {
        HStack(spacing: 8) {
            Circle()
                .fill(tint)
                .frame(width: 8, height: 8)
                .accessibilityHidden(true)
            Text(I2PPeerTrafficCompare.shortID(peerID))
                .font(.system(.footnote, design: .monospaced).weight(.bold))
                .foregroundStyle(tint)
            if let peer = summaries[peerID] {
                Text(peer.transport)
                    .font(.caption2.weight(.bold))
                    .foregroundStyle(.secondary)
            }
            if !isLive(peerID) {
                Text("Ended")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
        }
        .accessibilityElement(children: .combine)
    }

    /// Exchanges the violet and teal sides: the picked peer becomes the one the
    /// screen was opened on and vice versa, and the picker then offers the other
    /// live sessions for the new left side.
    private var swapButton: some View {
        Button(action: swapSides) {
            HStack(spacing: 4) {
                Image(systemName: "arrow.left.arrow.right")
                    .font(.caption2.weight(.semibold))
                Text("Swap")
                    .font(.caption2.weight(.medium))
            }
            .foregroundStyle(canSwap ? accent : Color.secondary)
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(Color.white.opacity(0.10), in: Capsule())
        }
        .buttonStyle(.plain)
        .disabled(!canSwap)
        .accessibilityLabel("Swap the two sides")
        .accessibilityValue(canSwap ? "Violet and teal" : "Pick a peer first")
        .accessibilityHint("Makes the violet peer the teal one and the teal peer the violet one")
    }

    private var canSwap: Bool { rightID != nil }

    private func swapSides() {
        guard let picked = rightID else { return }
        withAnimation(.easeInOut(duration: 0.2)) {
            rightID = leftID
            leftID = picked
        }
    }

    // MARK: - Picker

    private var pickerChoices: [I2PPeerSummary] {
        I2PPeerTrafficCompare.pickerChoices(inspected: leftID, among: livePeers)
    }

    private func isLive(_ peerID: String) -> Bool {
        I2PPeerTrafficCompare.isLive(peerID, among: livePeers)
    }

    /// Shown until a side is picked, and again once the picked session ends:
    /// the picker is the way back to a comparison.
    private var pickPromptCard: some View {
        card(title: rightID == nil ? "Pick a peer" : "Pick another peer") {
            Text(rightID == nil
                 ? "The peer you inspected is the violet side. Pick another live session and both peers' last 15 minutes are drawn on one chart."
                 : "The teal side has no live session to draw. Pick another live session to compare against the violet side.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if pickerChoices.isEmpty {
                Text("No other session is live right now. Peers appear as the router connects.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                Button { pickerPresented = true } label: {
                    Label(pickerChoices.count == 1 ? "Choose the live session" : "Choose a live session",
                          systemImage: "person.2")
                        .font(.footnote.weight(.semibold))
                        .foregroundStyle(accent)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 9)
                        .background(accent.opacity(0.16), in: RoundedRectangle(cornerRadius: 10))
                }
                .buttonStyle(.plain)
                .accessibilityHint("Lists the other live sessions by identity hash")
            }
        }
    }

    /// The line the screen shows when the picked peer's session is gone.
    private func endedCard(_ peerID: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "bolt.horizontal.circle")
                .font(.caption)
                .foregroundStyle(rightTint)
                .accessibilityHidden(true)
            Text(I2PPeerTrafficCompare.endedMessage(picked: peerID))
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(rightTint.opacity(0.12), in: RoundedRectangle(cornerRadius: 16))
        .accessibilityElement(children: .combine)
    }

    // MARK: - Chart

    private struct CompareLine: Identifiable {
        let id: String
        let at: Date
        let kbPerSecond: Double
    }

    private func points(for peerID: String) -> [I2PPeerTrafficPoint] {
        I2PPeerTrafficRecorder.points(from: samples[peerID] ?? [])
    }

    private func line(_ points: [I2PPeerTrafficPoint], side: String) -> [CompareLine] {
        points.map { point in
            CompareLine(id: "\(side)-\(point.id)",
                        at: point.at,
                        kbPerSecond: point.receivedKBPerSecond + point.sentKBPerSecond)
        }
    }

    private func chartCard(_ picked: String) -> some View {
        let leftPoints = points(for: leftID)
        let pickedPoints = points(for: picked)
        return card(title: "Last 15 minutes") {
            if leftPoints.count >= 2 || pickedPoints.count >= 2 {
                compareChart(leftPoints: leftPoints, pickedPoints: pickedPoints)
                    .frame(height: 180)
                    .accessibilityElement(children: .ignore)
                    .accessibilityLabel(chartAccessibilityLabel(picked))
            } else {
                Text("Collecting the first readings for these sessions. The chart fills as the status engine samples them once a second.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Text("Last minute")
                .font(.caption2.weight(.semibold))
                .foregroundStyle(.secondary)
                .textCase(.uppercase)
            legendRow(leftID, tint: leftTint)
            legendRow(picked, tint: rightTint)

            Text("Each line is one peer's received plus sent bytes per second, both drawn over the same 15-minute window.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    /// The legend entry: the peer's tint, its short hash and the rates it moved
    /// over the last minute.
    private func legendRow(_ peerID: String, tint: Color) -> some View {
        let average = averages[peerID] ?? .zero
        let received = I2PPeerTrafficFormat.rate(average.bytesInPerSecond)
        let sent = I2PPeerTrafficFormat.rate(average.bytesOutPerSecond)
        return HStack(spacing: 6) {
            Circle()
                .fill(tint)
                .frame(width: 7, height: 7)
                .accessibilityHidden(true)
            Text(I2PPeerTrafficCompare.shortID(peerID))
                .font(.system(.caption2, design: .monospaced).weight(.bold))
                .foregroundStyle(tint)
            Spacer(minLength: 6)
            Text("received \(received) · sent \(sent)")
                .font(.system(.caption2, design: .monospaced).weight(.medium))
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .minimumScaleFactor(0.7)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(I2PPeerTrafficCompare.shortID(peerID)), last minute received \(received), sent \(sent)")
    }

    private func compareChart(leftPoints: [I2PPeerTrafficPoint],
                              pickedPoints: [I2PPeerTrafficPoint]) -> some View {
        let leftLine = line(leftPoints, side: "left")
        let pickedLine = line(pickedPoints, side: "picked")
        let peak = max(leftLine.map(\.kbPerSecond).max() ?? 0,
                       pickedLine.map(\.kbPerSecond).max() ?? 0)
        let ceiling = max(peak, 1) * 1.15
        let windowEnd = capturedAt
        let windowStart = windowEnd.addingTimeInterval(-I2PPeerTrafficCompare.window)
        return Chart {
            ForEach(leftLine) { point in
                LineMark(x: .value("Time", point.at),
                         y: .value("KB/s", point.kbPerSecond),
                         series: .value("Peer", "left"))
                    .foregroundStyle(leftTint)
                    .lineStyle(StrokeStyle(lineWidth: 2, lineCap: .round))
                    .interpolationMethod(.monotone)
            }
            ForEach(pickedLine) { point in
                LineMark(x: .value("Time", point.at),
                         y: .value("KB/s", point.kbPerSecond),
                         series: .value("Peer", "picked"))
                    .foregroundStyle(rightTint)
                    .lineStyle(StrokeStyle(lineWidth: 2, lineCap: .round))
                    .interpolationMethod(.monotone)
            }
        }
        .chartLegend(.hidden)
        .chartXScale(domain: windowStart...windowEnd)
        .chartYScale(domain: 0...ceiling)
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
    }

    private func chartAccessibilityLabel(_ picked: String) -> String {
        let left = averages[leftID] ?? .zero
        let other = averages[picked] ?? .zero
        return "Both peers' last 15 minutes. \(I2PPeerTrafficCompare.shortID(leftID)): last minute received \(I2PPeerTrafficFormat.rate(left.bytesInPerSecond)), sent \(I2PPeerTrafficFormat.rate(left.bytesOutPerSecond)). \(I2PPeerTrafficCompare.shortID(picked)): last minute received \(I2PPeerTrafficFormat.rate(other.bytesInPerSecond)), sent \(I2PPeerTrafficFormat.rate(other.bytesOutPerSecond))."
    }

    // MARK: - Stats

    private func statsCard(_ picked: String) -> some View {
        card(title: "Session peaks") {
            HStack(alignment: .top, spacing: 12) {
                statColumn(leftID, tint: leftTint)
                statColumn(picked, tint: rightTint)
            }
        }
    }

    private func statColumn(_ peerID: String, tint: Color) -> some View {
        let peak = I2PPeerTrafficCompare.peak(in: points(for: peerID))
        let summary = summaries[peerID]
        let peakValue = peak.map { I2PPeerTrafficFormat.rate($0.bytesPerSecond) } ?? "—"
        let peakDetail = peak.map { "\($0.direction) peak" } ?? "no reading yet"
        let exchangedValue = summary.map { compareByteText($0.bytesIn + $0.bytesOut) } ?? "—"
        let exchangedDetail = summary.map {
            "\(compareByteText($0.bytesIn)) in · \(compareByteText($0.bytesOut)) out"
        } ?? "no session reading"
        return VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 5) {
                Circle()
                    .fill(tint)
                    .frame(width: 6, height: 6)
                    .accessibilityHidden(true)
                Text(I2PPeerTrafficCompare.shortID(peerID))
                    .font(.system(.caption2, design: .monospaced).weight(.bold))
                    .foregroundStyle(tint)
                Spacer(minLength: 0)
            }
            statValue("Peak rate", value: peakValue, detail: peakDetail)
            statValue("Bytes exchanged", value: exchangedValue, detail: exchangedDetail)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(Color.white.opacity(0.04), in: RoundedRectangle(cornerRadius: 14))
        .accessibilityElement(children: .combine)
    }

    private func statValue(_ label: String, value: String, detail: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(label)
                .font(.caption2.weight(.semibold))
                .foregroundStyle(.secondary)
                .textCase(.uppercase)
            Text(value)
                .font(.system(.title3, design: .rounded).weight(.bold))
                .lineLimit(1)
                .minimumScaleFactor(0.7)
            Text(detail)
                .font(.caption2)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .minimumScaleFactor(0.7)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
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
}

// MARK: - Picker sheet

/// The other live sessions, busiest first: a tap makes that peer the teal side.
private struct PeerComparePickerSheet: View {
    let peers: [I2PPeerSummary]
    let tint: Color
    let onPick: (String) -> Void

    @Environment(\.dismiss) private var dismiss

    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 8) {
                    if peers.isEmpty {
                        Text("No other session is live right now. Peers appear as the router connects.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.top, 8)
                    } else {
                        ForEach(peers) { peer in
                            Button { pick(peer.id) } label: {
                                row(peer)
                            }
                            .buttonStyle(.plain)
                        }
                    }
                }
                .padding(16)
            }
            .background(background.ignoresSafeArea())
            .navigationTitle("Compare with")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                        .foregroundStyle(tint)
                }
            }
        }
        .presentationDetents([.medium, .large])
    }

    private func pick(_ peerID: String) {
        onPick(peerID)
        dismiss()
    }

    private func row(_ peer: I2PPeerSummary) -> some View {
        HStack(spacing: 10) {
            Circle()
                .fill(tint)
                .frame(width: 7, height: 7)
                .accessibilityHidden(true)
            Text(peer.transport)
                .font(.caption2.weight(.bold))
                .foregroundStyle(tint)
                .padding(.horizontal, 7)
                .padding(.vertical, 3)
                .background(tint.opacity(0.14), in: RoundedRectangle(cornerRadius: 7))
            VStack(alignment: .leading, spacing: 2) {
                Text(I2PPeerTrafficCompare.shortID(peer.id))
                    .font(.system(.footnote, design: .monospaced).weight(.medium))
                    .foregroundStyle(.primary)
                Text("\(compareByteText(peer.bytesIn)) in · \(compareByteText(peer.bytesOut)) out")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 6)
            Image(systemName: "chevron.right")
                .font(.caption2.weight(.semibold))
                .foregroundStyle(.secondary)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 14))
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityHint("Makes this peer the teal side")
    }
}

// MARK: - Byte labels

/// "512 B", "12.3 KB" or "1.2 MB" for an exchanged byte total.
private func compareByteText(_ bytes: Int) -> String {
    let value = Double(max(0, bytes))
    if value >= 1_048_576 { return String(format: "%.1f MB", value / 1_048_576) }
    if value >= 1024 { return String(format: "%.1f KB", value / 1024) }
    return "\(max(0, bytes)) B"
}
