//
//  AlignmentView.swift
//  Untitled1
//
//  The Alignment report screen. Renders the specification truth table live:
//  per-component sections (Crypto, Structures, NetDB, NTCP2, Tunnels, Garlic,
//  I2NP), each row showing its spec section, Java reference class, alignment
//  status and passing test count from the cross-validation suite. A header
//  summary card shows overall coverage and the last-run timestamp, with a
//  Run alignment suite button refreshing everything. Tapping a deviation
//  expands its documented rationale.
//

import SwiftUI

struct AlignmentView: View {
    @State private var results: [I2PCrossValidationResult] = []
    @State private var lastRunAt: Date?
    @State private var isRunning = false
    @State private var expandedRowIDs: Set<String> = []
    /// One sheet slot for this screen: iOS presents one sheet per view
    /// reliably, so the audit report and the product roadmap share it.
    @State private var sheet: Sheet?

    private enum Sheet: String, Identifiable {
        case auditReport
        case roadmap

        var id: String { rawValue }
    }

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    /// Component sections in report order.
    private let components: [I2PSpecComponent] = [
        .crypto, .structures, .netdb, .ntcp2, .tunnels, .garlic, .i2np,
    ]

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    summaryCard
                    auditCard
                    ForEach(components, id: \.self) { component in
                        componentSection(component)
                    }
                }
                .padding(.horizontal, 16)
                .padding(.top, 4)
                .padding(.bottom, 24)
            }
            .background(background.ignoresSafeArea())
            .navigationTitle("Alignment")
            .navigationBarTitleDisplayMode(.large)
            .onAppear { adoptStoredResultsIfAvailable() }
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        sheet = .roadmap
                    } label: {
                        Image(systemName: "map")
                    }
                    .accessibilityLabel("Product roadmap")
                    .accessibilityHint("The product, growth and commercial plan")
                }
            }
            .sheet(item: $sheet) { which in
                switch which {
                case .auditReport:
                    AuditReportView()
                case .roadmap:
                    StrategyView(showsClose: true)
                }
            }
        }
    }

    // MARK: - Suite control

    private func adoptStoredResultsIfAvailable() {
        if !results.isEmpty || isRunning { return }
        let stored = I2PCrossValidation.results
        if !stored.isEmpty {
            results = stored
            lastRunAt = I2PCrossValidation.lastRunAt
        } else {
            runSuite()
        }
    }

    private func runSuite() {
        isRunning = true
        Task {
            let runResults = await I2PCrossValidation.runAll()
            // State mutation happens on the main actor — publishing @State from
            // a background thread crashes the app on modern iOS.
            await MainActor.run {
                results = runResults
                lastRunAt = I2PCrossValidation.lastRunAt
                isRunning = false
            }
        }
    }

    /// Passing / total test counts for one truth-table row.
    private func counts(for rowID: String) -> (passing: Int, total: Int)? {
        let group = results.filter { $0.rowID == rowID }
        guard !group.isEmpty else { return nil }
        return (group.filter(\.passed).count, group.count)
    }

    // MARK: - Header summary card

    private var summaryCard: some View {
        card(title: "Alignment Coverage") {
            let coverage = I2PSpecTruthTable.coverage
            Text("\(coverage.aligned) aligned of \(coverage.total) rows")
                .font(.title3.weight(.semibold))
            Text("truth-table coverage of the implemented router")
                .font(.caption2)
                .foregroundStyle(.secondary)

            HStack(spacing: 8) {
                chip("aligned", count: coverage.aligned, color: .green)
                chip("pending", count: coverage.pendingWireVerification, color: .orange)
                chip("deviations", count: coverage.deviationDocumented, color: .blue)
                chip("defects", count: coverage.defect, color: .red)
            }

            runStateLine
            runButton
            shareControl
        }
    }

    @ViewBuilder
    private var runStateLine: some View {
        if isRunning {
            HStack(spacing: 8) {
                ProgressView()
                    .controlSize(.small)
                Text("Running cross-validation suite…")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        } else if results.isEmpty {
            Text("Cross-validation suite not yet run")
                .font(.footnote)
                .foregroundStyle(.secondary)
        } else {
            let passed = results.filter(\.passed).count
            let allPassed = passed == results.count
            HStack(spacing: 6) {
                Image(systemName: allPassed ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                    .foregroundStyle(allPassed ? Color.green : Color.orange)
                    .font(.caption)
                Text("\(passed) of \(results.count) tests passed")
                Text("·")
                Text(lastRunAt?.formatted(date: .omitted, time: .shortened) ?? "")
            }
            .font(.footnote)
            .foregroundStyle(.secondary)
        }
    }

    private var runButton: some View {
        Button {
            runSuite()
        } label: {
            HStack(spacing: 8) {
                if isRunning {
                    ProgressView()
                        .controlSize(.small)
                        .tint(.white)
                } else {
                    Image(systemName: "arrow.triangle.2.circlepath")
                }
                Text(isRunning ? "Running…" : "Run alignment suite")
            }
            .font(.subheadline.weight(.semibold))
            .frame(maxWidth: .infinity)
            .padding(.vertical, 10)
            .background(accent.opacity(0.18), in: RoundedRectangle(cornerRadius: 12))
        }
        .buttonStyle(.plain)
        .tint(accent)
        .disabled(isRunning)
    }

    // MARK: - Export

    /// The screen's share control: the report as it currently stands — coverage,
    /// the last run, every truth-table row and any failing test — as plain text
    /// in the system share sheet.
    private var shareControl: some View {
        let payload = I2PAlignmentReportShare.payload(results: results,
                                                      lastRunAt: lastRunAt)
        return ShareLink(item: payload.text,
                         subject: Text(payload.subject)) {
            HStack(spacing: 8) {
                Image(systemName: "square.and.arrow.up")
                Text("Share report as text")
            }
            .font(.subheadline.weight(.semibold))
            .frame(maxWidth: .infinity)
            .padding(.vertical, 10)
            .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 12))
        }
        .buttonStyle(.plain)
        .tint(accent)
        .accessibilityLabel("Share alignment report as text")
        .accessibilityHint("Exports the coverage, every truth-table row and any failing tests")
    }

    private func chip(_ label: String, count: Int, color: Color) -> some View {
        VStack(spacing: 2) {
            Text("\(count)")
                .font(.subheadline.weight(.bold))
                .foregroundStyle(color)
            Text(label)
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 8)
        .background(Color.white.opacity(0.05), in: RoundedRectangle(cornerRadius: 10))
    }

    // MARK: - Audit report

    /// Entry point to the written end-to-end audit: an independent assessment
    /// of the table below, the tests actually executed, and the open findings.
    private var auditCard: some View {
        card(title: "Independent audit") {
            Text(I2PAuditReport.title)
                .font(.subheadline.weight(.semibold))
            Text("garlic-router · \(I2PAuditReport.date)")
                .font(.caption2)
                .foregroundStyle(.secondary)

            HStack(spacing: 8) {
                chip("high", count: I2PAuditReport.highSeverity, color: .red)
                chip("medium", count: I2PAuditReport.mediumSeverity, color: .orange)
                chip("low", count: I2PAuditReport.lowSeverity, color: .gray)
            }

            Text(I2PAuditReport.headline)
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Button {
                sheet = .auditReport
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: "doc.text.magnifyingglass")
                    Text("Read audit report")
                }
                .font(.subheadline.weight(.semibold))
                .frame(maxWidth: .infinity)
                .padding(.vertical, 10)
                .background(accent.opacity(0.18), in: RoundedRectangle(cornerRadius: 12))
            }
            .buttonStyle(.plain)
            .tint(accent)
        }
    }

    // MARK: - Component sections

    private func componentSection(_ component: I2PSpecComponent) -> some View {
        let coverage = I2PSpecTruthTable.coverage(for: component)
        return card(title: component.displayName) {
            Text(coverage.summary)
                .font(.caption2)
                .foregroundStyle(.secondary)
            ForEach(I2PSpecTruthTable.rows(in: component)) { row in
                rowView(row)
            }
        }
    }

    // MARK: - Rows

    @ViewBuilder
    private func rowView(_ row: I2PSpecRow) -> some View {
        let rowCounts = counts(for: row.id)
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .top, spacing: 8) {
                Text(row.id)
                    .font(.system(.caption, design: .monospaced).weight(.bold))
                    .foregroundStyle(accent)
                statusPill(row.status)
                Spacer()
                testCountLabel(rowCounts)
            }
            Text(row.requirement)
                .font(.footnote.weight(.medium))
            Text("spec · \(row.specSection)")
                .font(.caption2)
                .foregroundStyle(.secondary)
            Text("java · \(row.javaReference)")
                .font(.caption2)
                .foregroundStyle(.secondary)

            if let deviation = row.deviation {
                deviationDisclosure(row: row, deviation: deviation)
            }
        }
        .padding(.top, 6)
    }

    private func statusPill(_ status: I2PAlignmentStatus) -> some View {
        Text(shortStatus(status))
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 7)
            .padding(.vertical, 2)
            .background(statusColor(status).opacity(0.18), in: Capsule())
            .foregroundStyle(statusColor(status))
    }

    @ViewBuilder
    private func testCountLabel(_ rowCounts: (passing: Int, total: Int)?) -> some View {
        if isRunning {
            Text("running…")
                .font(.caption2)
                .foregroundStyle(.secondary)
        } else if let rowCounts {
            let allPassed = rowCounts.passing == rowCounts.total
            Text("\(rowCounts.passing)/\(rowCounts.total) tests")
                .font(.system(.caption2, design: .monospaced).weight(.semibold))
                .foregroundStyle(allPassed ? Color.green : Color.orange)
        } else {
            Text("not run")
                .font(.caption2)
                .foregroundStyle(.tertiary)
        }
    }

    /// Tapping a deviation row expands its documented rationale.
    @ViewBuilder
    private func deviationDisclosure(row: I2PSpecRow, deviation: I2PDeviationRecord) -> some View {
        let isExpanded = expandedRowIDs.contains(row.id)
        Button {
            withAnimation(reduceMotion ? nil : .easeInOut(duration: 0.2)) {
                if isExpanded {
                    expandedRowIDs.remove(row.id)
                } else {
                    expandedRowIDs.insert(row.id)
                }
            }
        } label: {
            HStack(spacing: 4) {
                Text(deviation.classification == .intentional
                     ? "Deviation — intentional"
                     : "Deviation — defect")
                    .font(.caption2.weight(.semibold))
                Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
                    .font(.caption2.weight(.bold))
                Spacer()
            }
            .foregroundStyle(deviation.classification == .intentional ? Color.blue : Color.red)
        }
        .buttonStyle(.plain)

        if isExpanded {
            VStack(alignment: .leading, spacing: 4) {
                Text(deviation.description)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                if !deviation.rationale.isEmpty {
                    Text("Rationale: \(deviation.rationale)")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                Text("Tracked: \(deviation.trackingRef)")
                    .font(.caption2.weight(.medium))
                    .foregroundStyle(accent)
            }
            .padding(10)
            .background(Color.white.opacity(0.04), in: RoundedRectangle(cornerRadius: 10))
            .transition(.opacity.combined(with: .move(edge: .top)))
        }
    }

    // MARK: - Status mapping

    private func shortStatus(_ status: I2PAlignmentStatus) -> String {
        switch status {
        case .aligned: return "aligned"
        case .pendingWireVerification: return "pending"
        case .deviationDocumented: return "deviation"
        case .defect: return "defect"
        }
    }

    private func statusColor(_ status: I2PAlignmentStatus) -> Color {
        switch status {
        case .aligned: return .green
        case .pendingWireVerification: return .orange
        case .deviationDocumented: return .blue
        case .defect: return .red
        }
    }

    // MARK: - Card shell (matches the Core and Router tabs)

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

#Preview {
    AlignmentView()
        .preferredColorScheme(.dark)
}