//
//  LifecycleTimelineView.swift
//  Untitled1
//
//  The router's retained lifecycle history as one list: every start and clean
//  stop, and every interruption, newest first. Opened from the Router health
//  screen, next to the samples it explains.
//

import SwiftUI

struct LifecycleTimelineView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var entries: [I2PRouterTimelineEntry] = []
    @State private var filter: Filter = .all

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)
    private let healthy = Color(red: 0.29, green: 0.87, blue: 0.50)
    private let warning = Color(red: 0.98, green: 0.62, blue: 0.24)

    /// What the filter offers. A reader looking for "why was the router down"
    /// wants the interruptions; a reader checking a restart wants the events.
    private enum Filter: String, CaseIterable, Identifiable {
        case all
        case events
        case gaps

        var id: String { rawValue }

        var title: String {
            switch self {
            case .all: return "All"
            case .events: return "Start & stop"
            case .gaps: return "Interruptions"
            }
        }
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    filterPicker

                    if shownEntries.isEmpty {
                        emptyState
                    } else {
                        ForEach(shownEntries) { entry in
                            row(entry)
                        }
                    }

                    Text("Kept on this device for up to seven days. Nothing here leaves the phone.")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .padding(.horizontal, 16)
                .padding(.top, 8)
                .padding(.bottom, 32)
            }
            .background(background.ignoresSafeArea())
            .navigationTitle("Lifecycle history")
            .navigationBarTitleDisplayMode(.large)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                        .tint(accent)
                }
            }
            .task { entries = I2PRouterHealthHistory.shared.timeline() }
        }
        .preferredColorScheme(.dark)
    }

    private var shownEntries: [I2PRouterTimelineEntry] {
        switch filter {
        case .all: return entries
        case .events: return entries.filter(\.isEvent)
        case .gaps: return entries.filter { !$0.isEvent }
        }
    }

    private var filterPicker: some View {
        Picker("Event type", selection: $filter) {
            ForEach(Filter.allCases) { option in
                Text(option.title).tag(option)
            }
        }
        .pickerStyle(.segmented)
        .accessibilityLabel("Filter lifecycle entries")
    }

    private func row(_ entry: I2PRouterTimelineEntry) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Circle()
                .fill(color(for: entry))
                .frame(width: 8, height: 8)
                .padding(.top, 6)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 3) {
                Text(entry.title)
                    .font(.subheadline.weight(.medium))
                Text(subtitle(for: entry))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer(minLength: 8)

            Text(entry.startedAt.formatted(date: .abbreviated, time: .shortened))
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 14))
        .accessibilityElement(children: .combine)
    }

    private func subtitle(for entry: I2PRouterTimelineEntry) -> String {
        guard let duration = entry.duration else {
            return entry.isEvent ? "Lifecycle event" : "Still open · measuring"
        }
        return durationText(duration)
    }

    private func color(for entry: I2PRouterTimelineEntry) -> Color {
        guard let cause = entry.cause else {
            return entry.kind == .started ? healthy : Color.red.opacity(0.85)
        }
        switch cause {
        case .routerStopped: return Color.red.opacity(0.85)
        case .appSuspended: return warning
        case .samplingPaused: return Color.gray
        }
    }

    private var emptyState: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(filter == .all ? "Nothing recorded yet" : "Nothing of this kind yet",
                  systemImage: "clock.arrow.circlepath")
                .font(.subheadline.weight(.semibold))
            Text(entries.isEmpty
                 ? "Router starts, clean stops and interruptions appear here as they happen. The history is kept while the app runs and for up to seven days after."
                 : "No entry matches this filter. Choose All to see everything recorded.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    private func durationText(_ seconds: TimeInterval) -> String {
        let minutes = max(0, Int(seconds / 60))
        if minutes >= 60 { return "\(minutes / 60)h \(minutes % 60)m" }
        if minutes >= 1 { return "\(minutes)m" }
        return "\(max(0, Int(seconds)))s"
    }
}

#Preview {
    LifecycleTimelineView()
        .preferredColorScheme(.dark)
}
