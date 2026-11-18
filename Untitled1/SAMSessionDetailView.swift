//
//  SAMSessionDetailView.swift
//  One SAM session's own screen: its destination (hash, copyable base64, b33
//  host when it publishes an encrypted LeaseSet), the tunnel pool per direction
//  with expiry countdowns, stream and datagram traffic, the live send rate
//  against its cap, and the bridge log lines that belong to the session.
//  Opened from a row of the SAM screen's session list.
//

import SwiftUI
import UIKit

struct SAMSessionDetailView: View {
    let nickname: String

    @Environment(\.dismiss) private var dismiss
    @State private var detail: I2PSAMSessionDetail?
    @State private var loaded = false
    @State private var capText = ""
    @State private var capCommitTask: Task<Void, Never>?
    @State private var copiedField: String?
    @State private var copyResetTask: Task<Void, Never>?

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)
    private let warn = Color(red: 0.98, green: 0.62, blue: 0.24)
    private let outboundGreen = Color(red: 0.30, green: 0.85, blue: 0.56)
    private let inboundCyan = Color(red: 0.16, green: 0.83, blue: 0.90)

    private var server: I2PSAMServer {
        I2PRouterAppContext.shared.samServer
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                header
                if let detail {
                    bandwidthCard(detail)
                    destinationCard(detail)
                    tunnelsCard(detail)
                    trafficCard(detail)
                    activityCard(detail)
                    closeCard
                } else {
                    waitingCard
                }
            }
            .padding(.horizontal, 16)
            .padding(.top, 2)
            .padding(.bottom, 24)
        }
        .background(background.ignoresSafeArea())
        .navigationBarTitleDisplayMode(.inline)
        .preferredColorScheme(.dark)
        .task { await liveLoop() }
    }

    // MARK: - Live reading

    private func liveLoop() async {
        while !Task.isCancelled {
            if let fresh = server.sessionDetail(named: nickname) {
                detail = fresh
                if !loaded {
                    loaded = true
                    let kb = fresh.capBytesPerSecond / 1024
                    capText = kb == 0 ? "" : String(kb)
                }
            } else if loaded {
                // The session is gone — closed here, or torn down by its
                // client. The detail screen has nothing left to show.
                dismiss()
                return
            }
            try? await Task.sleep(for: .seconds(1))
        }
    }

    // MARK: - Header

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                Text("Session \(nickname)")
                    .font(.system(size: 30, weight: .bold, design: .rounded))
                if let style = detail?.style {
                    Text(style)
                        .font(.caption.weight(.bold))
                        .foregroundStyle(accent)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .background(accent.opacity(0.18), in: RoundedRectangle(cornerRadius: 7))
                }
                Spacer(minLength: 0)
            }
            Text(subtitle)
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var subtitle: String {
        guard let detail else { return "127.0.0.1" }
        return "127.0.0.1 · created \(age(detail.createdAt))"
    }

    private func age(_ date: Date) -> String {
        let seconds = max(0, Int(Date().timeIntervalSince(date)))
        if seconds < 60 { return "\(seconds)s ago" }
        if seconds < 3600 { return "\(seconds / 60) min ago" }
        return "\(seconds / 3600)h \((seconds % 3600) / 60)m ago"
    }

    // MARK: - Bandwidth

    private func bandwidthCard(_ detail: I2PSAMSessionDetail) -> some View {
        let fraction = capFraction(detail)
        let atCap = isAtCap(detail)
        return card(title: "Bandwidth") {
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Text(rateValue(detail.sendBytesPerSecond))
                    .font(.system(size: 44, weight: .bold, design: .rounded))
                    .foregroundStyle(.primary)
                    .contentTransition(.numericText())
                Text(rateUnit(detail.sendBytesPerSecond))
                    .font(.system(size: 24, weight: .semibold, design: .rounded))
                    .foregroundStyle(.secondary)
                Spacer(minLength: 0)
            }
            Text("send rate, last minute")
                .font(.footnote)
                .foregroundStyle(.secondary)
            gauge(fraction: fraction, atCap: atCap)
            HStack(spacing: 8) {
                Text("cap")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                TextField("0", text: capBinding())
                    .textFieldStyle(.plain)
                    .keyboardType(.numberPad)
                    .multilineTextAlignment(.leading)
                    .font(.system(.subheadline, design: .monospaced).weight(.semibold))
                    .foregroundStyle(Color.white)
                    .frame(width: 62)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 7)
                    .background(Color.white.opacity(0.07), in: RoundedRectangle(cornerRadius: 9))
                    .overlay(RoundedRectangle(cornerRadius: 9)
                        .strokeBorder(Color.white.opacity(0.10)))
                Text("KB/s")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                Spacer(minLength: 6)
                if atCap {
                    Text("at cap")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(warn)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(warn.opacity(0.16), in: RoundedRectangle(cornerRadius: 7))
                }
            }
            Text("Empty or 0 is uncapped. Changes apply immediately.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func gauge(fraction: Double, atCap: Bool) -> some View {
        GeometryReader { proxy in
            let width = proxy.size.width
            let filled = max(2, width * min(1, max(0, fraction)))
            ZStack(alignment: .leading) {
                Capsule()
                    .fill(Color.white.opacity(0.10))
                Capsule()
                    .fill(atCap ? warn : accent)
                    .frame(width: filled)
                Circle()
                    .fill(atCap ? warn : accent)
                    .frame(width: 9, height: 9)
                    .offset(x: filled - 4.5)
            }
        }
        .frame(height: 9)
        .padding(.vertical, 3)
    }

    private func capFraction(_ detail: I2PSAMSessionDetail) -> Double {
        guard detail.capBytesPerSecond > 0 else { return 0 }
        return detail.sendBytesPerSecond / Double(detail.capBytesPerSecond)
    }

    private func isAtCap(_ detail: I2PSAMSessionDetail) -> Bool {
        capFraction(detail) >= 0.9
    }

    private func rateValue(_ bytesPerSecond: Double) -> String {
        let value = max(0, bytesPerSecond)
        return value >= 1024 ? String(format: "%.1f", value / 1024)
                             : String(format: "%.0f", value)
    }

    private func rateUnit(_ bytesPerSecond: Double) -> String {
        max(0, bytesPerSecond) >= 1024 ? "KB/s" : "B/s"
    }

    // MARK: - Per-session cap editing

    /// Same field, same behaviour as the session row on the SAM screen: the
    /// typed ceiling is applied to the running session at once and saved under
    /// the session key.
    private func capBinding() -> Binding<String> {
        Binding(
            get: { capText },
            set: { text in
                capText = String(text.filter(\.isNumber).prefix(6))
                scheduleCapCommit()
            }
        )
    }

    private func scheduleCapCommit() {
        capCommitTask?.cancel()
        capCommitTask = Task { @MainActor in
            try? await Task.sleep(for: .milliseconds(400))
            guard !Task.isCancelled else { return }
            applyCap()
        }
    }

    private func applyCap() {
        let typed = Int(capText.trimmingCharacters(in: .whitespaces)) ?? 0
        let clamped = I2PSAMSessionCaps.clamp(typed)
        capText = clamped == 0 ? "" : String(clamped)
        guard (detail?.capBytesPerSecond ?? 0) != clamped * 1024 else { return }
        server.setSessionCapKBps(clamped, for: nickname)
        detail = server.sessionDetail(named: nickname)
    }

    // MARK: - Destination

    private func destinationCard(_ detail: I2PSAMSessionDetail) -> some View {
        card(title: "Destination") {
            destinationRow(label: "hash",
                           value: String(detail.destinationHashHex.prefix(12)),
                           copyKey: "hash",
                           copyValue: detail.destinationBase64)
            if let b33 = detail.b33Address {
                destinationRow(label: "b33",
                               value: shortB33(b33),
                               copyKey: "b33",
                               copyValue: b33)
            }
            Divider().opacity(0.2)
            Text("out \(detail.tunnelsOut.count) tunnels · in \(detail.tunnelsIn.count) tunnels · \(detail.leasePublished ? "lease published" : "no lease yet")")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }

    private func destinationRow(label: String, value: String,
                                copyKey: String, copyValue: String) -> some View {
        HStack(spacing: 10) {
            Text(label)
                .font(.footnote)
                .foregroundStyle(.secondary)
                .frame(width: 40, alignment: .leading)
            Text(value)
                .font(.system(.footnote, design: .monospaced))
                .foregroundStyle(.primary)
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer(minLength: 6)
            Button { copy(copyKey, copyValue) } label: {
                Text(copiedField == copyKey ? "Copied" : "Copy")
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(accent)
                    .frame(minWidth: 52, alignment: .trailing)
            }
            .buttonStyle(.plain)
        }
        .padding(.vertical, 2)
    }

    private func shortB33(_ address: String) -> String {
        guard address.count > 14 else { return "b33:\(address)" }
        return "b33:\(address.prefix(5))…\(address.suffix(3))"
    }

    private func copy(_ key: String, _ value: String) {
        UIPasteboard.general.string = value
        copiedField = key
        copyResetTask?.cancel()
        copyResetTask = Task { @MainActor in
            try? await Task.sleep(for: .milliseconds(1400))
            guard !Task.isCancelled else { return }
            if copiedField == key { copiedField = nil }
        }
    }

    // MARK: - Tunnels

    private func tunnelsCard(_ detail: I2PSAMSessionDetail) -> some View {
        card(title: "Tunnels") {
            tunnelRow(label: "outbound",
                      tunnels: detail.tunnelsOut,
                      target: detail.tunnelsOutTarget,
                      tint: outboundGreen)
            tunnelRow(label: "inbound",
                      tunnels: detail.tunnelsIn,
                      target: detail.tunnelsInTarget,
                      tint: inboundCyan)
        }
    }

    private func tunnelRow(label: String, tunnels: [I2PSAMTunnelReading],
                           target: Int, tint: Color) -> some View {
        let next = tunnels.map(\.remainingLifetime).min()
        return VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Text(label)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .frame(width: 78, alignment: .leading)
                Circle()
                    .fill(tunnels.isEmpty ? Color.secondary.opacity(0.5) : tint)
                    .frame(width: 8, height: 8)
                Text(tunnels.isEmpty
                     ? "none live"
                     : "\(tunnels.count) of \(target) · next expiry \(next.map(countdown) ?? "—")")
                    .font(.footnote.weight(.medium))
                    .foregroundStyle(tunnels.isEmpty ? Color.secondary : Color.primary)
                Spacer(minLength: 0)
            }
            poolBar(tunnels: tunnels.count, target: target, tint: tint)
            if !tunnels.isEmpty {
                Text(tunnels.map { countdown($0.remainingLifetime) }.joined(separator: " · "))
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.7)
            }
        }
        .padding(.vertical, 2)
    }

    private func poolBar(tunnels: Int, target: Int, tint: Color) -> some View {
        let fraction = target > 0 ? min(1, Double(tunnels) / Double(target)) : 0
        return GeometryReader { proxy in
            ZStack(alignment: .leading) {
                Capsule()
                    .fill(Color.white.opacity(0.10))
                Capsule()
                    .fill(tint)
                    .frame(width: max(2, proxy.size.width * fraction))
            }
        }
        .frame(height: 6)
    }

    private func countdown(_ seconds: TimeInterval) -> String {
        let total = max(0, Int(seconds))
        return String(format: "%02d:%02d", total / 60, total % 60)
    }

    // MARK: - Traffic

    private func trafficCard(_ detail: I2PSAMSessionDetail) -> some View {
        card(title: "Traffic") {
            HStack(alignment: .top, spacing: 0) {
                trafficColumn(label: "streams",
                              value: "\(detail.streamsSent) sent · \(detail.streamsReceived) received")
                Rectangle()
                    .fill(Color.white.opacity(0.10))
                    .frame(width: 1, height: 44)
                    .padding(.horizontal, 14)
                trafficColumn(label: "datagrams",
                              value: "\(detail.datagramsSent) · \(detail.datagramsReceived)")
                Spacer(minLength: 0)
            }
            Divider().opacity(0.2)
            Text("tx \(bytes(detail.bytesTx)) · rx \(bytes(detail.bytesRx))")
                .font(.system(.footnote, design: .monospaced))
                .foregroundStyle(.secondary)
        }
    }

    private func trafficColumn(label: String, value: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label)
                .font(.caption2)
                .foregroundStyle(.secondary)
            Text(value)
                .font(.system(.footnote, design: .monospaced).weight(.medium))
                .lineLimit(1)
                .minimumScaleFactor(0.7)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func bytes(_ count: Int) -> String {
        let value = Double(count)
        if value >= 1_048_576 { return String(format: "%.1f MB", value / 1_048_576) }
        if value >= 1024 {
            let kb = value / 1024
            return kb < 10 ? String(format: "%.1f KB", kb) : String(format: "%.0f KB", kb)
        }
        return "\(count) B"
    }

    // MARK: - Recent activity

    private func activityCard(_ detail: I2PSAMSessionDetail) -> some View {
        card(title: "Recent activity") {
            if detail.logLines.isEmpty {
                Text("No activity yet on this session.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(Array(detail.logLines.enumerated()), id: \.offset) { item in
                    logRow(item.element)
                }
            }
        }
    }

    private func logRow(_ line: String) -> some View {
        let parts = splitLog(line)
        return HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(parts.time)
                .foregroundStyle(.secondary)
                .frame(width: 68, alignment: .leading)
            Text(parts.text)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.tail)
            Spacer(minLength: 0)
        }
        .font(.system(.caption2, design: .monospaced))
    }

    /// Splits a bridge log line into its timestamp and its message, dropping
    /// the session's own nickname prefix.
    private func splitLog(_ line: String) -> (time: String, text: String) {
        var text = line
        var time = ""
        if line.hasPrefix("["), let close = line.firstIndex(of: "]") {
            time = String(line[line.index(after: line.startIndex)..<close])
            text = String(line[line.index(after: close)...])
                .trimmingCharacters(in: .whitespaces)
        }
        let prefix = "\(nickname): "
        if text.hasPrefix(prefix) {
            text.removeFirst(prefix.count)
        }
        return (time, text)
    }

    // MARK: - Close

    private var closeCard: some View {
        VStack(spacing: 10) {
            Button(action: closeSession) {
                Text("Close session")
                    .font(.headline)
                    .foregroundStyle(Color.red)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 16)
                    .background(Color.red.opacity(0.16), in: RoundedRectangle(cornerRadius: 16))
                    .overlay(RoundedRectangle(cornerRadius: 16)
                        .strokeBorder(Color.red.opacity(0.35)))
            }
            .buttonStyle(.plain)
            Text("Closing tears the session down; its saved cap stays.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(.top, 4)
    }

    private func closeSession() {
        server.closeSession(nickname)
        dismiss()
    }

    // MARK: - Shared pieces

    private var waitingCard: some View {
        card(title: "Session") {
            Text("Reading the running session…")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }

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
