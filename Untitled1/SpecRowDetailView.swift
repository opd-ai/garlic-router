//
//  SpecRowDetailView.swift
//  Untitled1
//
//  The spec row detail sheet, opened by tapping a truth-table row on the
//  Alignment report. Everything the row records, read-only: its id and
//  requirement, its spec section, Java reference class and Swift component, the
//  field-by-field wire layout, encoding rules and cryptographic parameters, the
//  edge-case rules the tests cover, the status with the documented deviation and
//  rationale when there is one, and every cross-validation test tagged with the
//  row with its result and detail text.
//
//  Dark theme, violet accent, monospaced spec text — consistent with the
//  Alignment report it opens from.
//

import SwiftUI

struct SpecRowDetailView: View {
    let row: I2PSpecRow
    let results: [I2PCrossValidationResult]

    @Environment(\.dismiss) private var dismiss

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)

    /// The row's detail, assembled from the table row and the suite results the
    /// Alignment screen is showing.
    private var detail: I2PSpecRowDetail {
        I2PSpecRowDetail(row: row, results: results)
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    header
                    card { referenceFields }
                    ForEach(detail.sections) { section in
                        sectionCard(section)
                    }
                    if let deviation = row.deviation {
                        deviationCard(deviation)
                    }
                    testsCard
                }
                .padding(.horizontal, 16)
                .padding(.top, 4)
                .padding(.bottom, 24)
            }
            .background(background.ignoresSafeArea())
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                        .tint(accent)
                }
            }
        }
    }

    // MARK: - Header

    private var header: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Text(row.id)
                    .font(.system(.title3, design: .monospaced).weight(.bold))
                    .foregroundStyle(accent)
                statusPill
                Spacer(minLength: 0)
            }
            Text(row.requirement)
                .font(.title3.weight(.bold))
                .fixedSize(horizontal: false, vertical: true)
            Text(detail.statusExplanation)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var statusPill: some View {
        HStack(spacing: 5) {
            Image(systemName: statusSymbol)
                .font(.caption2.weight(.bold))
            Text(detail.statusTitle)
                .font(.caption.weight(.semibold))
        }
        .padding(.horizontal, 9)
        .padding(.vertical, 4)
        .background(statusColor.opacity(0.18), in: Capsule())
        .foregroundStyle(statusColor)
        .fixedSize()
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Status: \(row.status.displayName)")
    }

    // MARK: - Reference

    private var referenceFields: some View {
        VStack(alignment: .leading, spacing: 8) {
            ForEach(detail.reference) { field in
                HStack(alignment: .top, spacing: 10) {
                    Text(field.label)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .frame(width: 46, alignment: .leading)
                    Text(field.value)
                        .font(.footnote)
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                }
                .accessibilityElement(children: .combine)
            }
        }
    }

    // MARK: - Sections

    private func sectionCard(_ section: I2PSpecRowSection) -> some View {
        card(title: section.title) {
            Text(section.body)
                .font(.system(.footnote, design: .monospaced))
                .foregroundStyle(.primary.opacity(0.92))
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
        }
    }

    // MARK: - Deviation

    private func deviationCard(_ deviation: I2PDeviationRecord) -> some View {
        let isIntentional = deviation.classification == .intentional
        return card(title: "Documented deviation") {
            HStack(spacing: 6) {
                Image(systemName: isIntentional ? "info.circle.fill" : "xmark.circle.fill")
                    .font(.caption)
                Text(isIntentional ? "Intentional" : "Defect")
                    .font(.caption.weight(.semibold))
            }
            .foregroundStyle(isIntentional ? Color.blue : Color.red)

            Text(deviation.description)
                .font(.footnote)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)

            if !deviation.rationale.isEmpty {
                Text("Rationale")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .textCase(.uppercase)
                Text(deviation.rationale)
                    .font(.footnote)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
            }

            Text("Tracked: \(deviation.trackingRef)")
                .font(.system(.caption2, design: .monospaced))
                .foregroundStyle(accent)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    // MARK: - Tests

    private var testsCard: some View {
        card(title: "Cross-validation tests") {
            Text(detail.testSummary)
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if detail.testEntries.isEmpty {
                Text("No cross-validation test is tagged with this row yet.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                ForEach(detail.testEntries) { entry in
                    testRow(entry)
                }
            }
        }
    }

    private func testRow(_ entry: I2PSpecRowTestEntry) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: testSymbol(entry))
                .font(.footnote.weight(.semibold))
                .foregroundStyle(testColor(entry))
                .frame(width: 18)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 3) {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text(entry.name ?? entry.testID)
                        .font(.footnote.weight(.semibold))
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 6)
                    if entry.name != nil {
                        Text(entry.testID)
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .layoutPriority(1)
                    }
                }
                Text(entry.detail)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .accessibilityElement(children: .combine)
    }

    private func testSymbol(_ entry: I2PSpecRowTestEntry) -> String {
        switch entry.passed {
        case .some(true): return "checkmark.circle.fill"
        case .some(false): return "xmark.circle.fill"
        case .none: return "clock"
        }
    }

    private func testColor(_ entry: I2PSpecRowTestEntry) -> Color {
        switch entry.passed {
        case .some(true): return .green
        case .some(false): return .red
        case .none: return .secondary
        }
    }

    // MARK: - Status mapping

    private var statusSymbol: String {
        switch row.status {
        case .aligned: return "checkmark.circle.fill"
        case .pendingWireVerification: return "clock.badge.exclamationmark.fill"
        case .deviationDocumented: return "info.circle.fill"
        case .defect: return "xmark.circle.fill"
        }
    }

    private var statusColor: Color {
        switch row.status {
        case .aligned: return .green
        case .pendingWireVerification: return .orange
        case .deviationDocumented: return .blue
        case .defect: return .red
        }
    }

    // MARK: - Card shell (matches the Alignment, Core and Router tabs)

    private func card<Content: View>(title: String? = nil,
                                     @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            if let title {
                Text(title)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .textCase(.uppercase)
            }
            content()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }
}

#Preview {
    SpecRowDetailView(row: I2PSpecTruthTable.row(id: "NT-M1") ?? I2PSpecTruthTable.rows[0],
                      results: [])
        .preferredColorScheme(.dark)
}
