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
//  expands its documented rationale; tapping a row opens its full requirement
//  detail sheet.
//
//  The summary card also pins a baseline: a snapshot of every row's status and
//  passing test count, held in memory, so a row that a later run leaves worse
//  carries a red Regressed badge naming the value it fell from.
//

import SwiftUI
import Charts

struct AlignmentView: View {
    @State private var results: [I2PCrossValidationResult] = []
    @State private var lastRunAt: Date?
    @State private var isRunning = false
    /// This launch's coverage samples, one per alignment-suite run, drawn as
    /// the summary card's sparkline. The history lives in memory only, so it
    /// starts fresh on launch.
    @State private var coverageHistory: [I2PAlignmentCoverageSample] = []
    /// Whether the sparkline is expanded into the taller per-run chart.
    @State private var isHistoryExpanded = false
    /// Components re-running on their own. Each section runs independently, so
    /// the other sections keep their results and their buttons stay usable.
    @State private var runningComponents: Set<I2PSpecComponent> = []
    @State private var expandedRowIDs: Set<String> = []
    /// The truth-table filter: a free-text query and the statuses switched on.
    /// No status selected means every status passes.
    @State private var searchText = ""
    @State private var activeStatuses: Set<I2PAlignmentStatus> = []
    /// One sheet slot for this screen: iOS presents one sheet per view
    /// reliably, so the row detail, the audit report and the product roadmap
    /// share it.
    @State private var sheet: Sheet?
    /// The JSON export of the truth table, encoded once each time the screen
    /// appears rather than on every body pass: the table's JSON runs to a few
    /// hundred kilobytes, and this screen re-renders on every keystroke in the
    /// filter field.
    @State private var jsonExport: I2PAlignmentJSONExportFile?
    /// The pinned baseline, mirrored from the in-memory store so the screen
    /// renders its badges and its summary line. Nothing about it is persisted.
    @State private var baseline: I2PAlignmentBaselineSnapshot?

    private enum Sheet: Identifiable {
        case rowDetail(String)
        case auditReport
        case roadmap

        var id: String {
            switch self {
            case .rowDetail(let rowID): return "rowDetail-\(rowID)"
            case .auditReport: return "auditReport"
            case .roadmap: return "roadmap"
            }
        }
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
                    summaryCard(regressionMap: regressions)
                    auditCard
                    filterCard
                    ForEach(components, id: \.self) { component in
                        componentSection(component, regressionMap: regressions)
                    }
                }
                .padding(.horizontal, 16)
                .padding(.top, 4)
                .padding(.bottom, 24)
            }
            .background(background.ignoresSafeArea())
            .navigationTitle("Alignment")
            .navigationBarTitleDisplayMode(.large)
            .onAppear {
                adoptStoredResultsIfAvailable()
                prepareJSONExport()
                baseline = I2PAlignmentBaseline.snapshot
            }
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
                case .rowDetail(let rowID):
                    if let row = I2PSpecTruthTable.row(id: rowID) {
                        SpecRowDetailView(row: row, results: results)
                    }
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
            // The suite may already have run this launch from elsewhere (the
            // self-test card, a component re-run) before this screen opened; a
            // run with no sample yet gets one so the chart still starts with it.
            if I2PAlignmentHistory.samples.isEmpty {
                I2PAlignmentHistory.record(ranAt: lastRunAt ?? Date())
            }
        } else {
            runSuite()
        }
        coverageHistory = I2PAlignmentHistory.samples
    }

    /// Encodes the truth table's JSON export for this appearance of the screen,
    /// so the share control hands the share sheet a ready file and the export
    /// date is the day the screen was opened.
    private func prepareJSONExport() {
        jsonExport = I2PAlignmentJSONExport.export()
    }

    private func runSuite() {
        guard !isRunning, runningComponents.isEmpty else { return }
        isRunning = true
        Task {
            let runResults = await I2PCrossValidation.runAll()
            // State mutation happens on the main actor — publishing @State from
            // a background thread crashes the app on modern iOS.
            await MainActor.run {
                results = runResults
                lastRunAt = I2PCrossValidation.lastRunAt
                coverageHistory = I2PAlignmentHistory.samples
                isRunning = false
            }
        }
    }

    /// Re-runs one component's cross-validation tests. Only the rows of that
    /// component are replaced in the stored results, so every other section
    /// keeps the counts it showed; the header summary recomputes from the
    /// combined set this screen adopts.
    private func rerun(_ component: I2PSpecComponent) {
        guard !isRunning, !runningComponents.contains(component) else { return }
        runningComponents.insert(component)
        Task {
            let combined = await I2PCrossValidation.run(component: component)
            await MainActor.run {
                results = combined
                lastRunAt = I2PCrossValidation.lastRunAt
                coverageHistory = I2PAlignmentHistory.samples
                runningComponents.remove(component)
            }
        }
    }

    /// Rows that are worse than the pinned baseline, keyed by row ID. Empty
    /// while no baseline is pinned, and whenever nothing has regressed.
    private var regressions: [String: I2PAlignmentRegression] {
        guard let baseline else { return [:] }
        return I2PAlignmentBaseline.regressions(against: baseline, results: results)
    }

    /// Snapshots the statuses and passing test counts the screen currently
    /// shows. Held in memory only, so a relaunch starts with no baseline.
    private func pinBaseline() {
        withAnimation(baselineAnimation) {
            baseline = I2PAlignmentBaseline.pin(results: results)
        }
    }

    private func clearBaseline() {
        withAnimation(baselineAnimation) {
            I2PAlignmentBaseline.clear()
            baseline = nil
        }
    }

    private var baselineAnimation: Animation? {
        reduceMotion ? nil : .easeInOut(duration: 0.2)
    }

    /// Passing / total test counts for one truth-table row.
    private func counts(for rowID: String) -> (passing: Int, total: Int)? {
        let group = results.filter { $0.rowID == rowID }
        guard !group.isEmpty else { return nil }
        return (group.filter(\.passed).count, group.count)
    }

    /// Passing / total test counts for one component's rows. A component that
    /// has no stored results yet reports zero tests, which the section shows as
    /// "not run".
    private func sectionCounts(for component: I2PSpecComponent) -> (passing: Int, total: Int) {
        let rowIDs = Set(I2PSpecTruthTable.rows(in: component).map(\.id))
        let group = results.filter { rowIDs.contains($0.rowID) }
        return (group.filter(\.passed).count, group.count)
    }

    /// Whether a component's rows should read "running…": the whole suite is
    /// running, or this component is re-running by itself.
    private func isSectionRunning(_ component: I2PSpecComponent) -> Bool {
        isRunning || runningComponents.contains(component)
    }

    // MARK: - Header summary card

    private func summaryCard(regressionMap: [String: I2PAlignmentRegression]) -> some View {
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
            coverageHistoryView
            runButton
            baselineControl(regressedRows: regressionMap.count)
            shareControl
            jsonExportControl
        }
    }

    // MARK: - Pinned baseline

    /// The pinned-baseline controls: pin the statuses and passing counts the
    /// screen shows now, read how many rows have regressed since, and clear the
    /// baseline again. Nothing here is persisted and no setting is added.
    @ViewBuilder
    private func baselineControl(regressedRows: Int) -> some View {
        Rectangle()
            .fill(Color.white.opacity(0.08))
            .frame(height: 1)
            .padding(.vertical, 2)

        if let baseline {
            HStack(spacing: 6) {
                Image(systemName: regressedRows == 0
                      ? "checkmark.seal.fill"
                      : "exclamationmark.triangle.fill")
                    .font(.caption)
                Text(I2PAlignmentBaseline.summaryLine(regressedRows: regressedRows))
                    .font(.footnote.weight(.semibold))
                    .fixedSize(horizontal: false, vertical: true)
            }
            .foregroundStyle(regressedRows == 0 ? Color.secondary : Color.red)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(I2PAlignmentBaseline.summaryLine(regressedRows: regressedRows))

            HStack(spacing: 8) {
                Text("Pinned \(baseline.pinnedAt.formatted(date: .omitted, time: .shortened)) · \(baseline.rowCount) rows")
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.secondary)
                Spacer(minLength: 6)
                Button {
                    clearBaseline()
                } label: {
                    HStack(spacing: 5) {
                        Image(systemName: "xmark.circle")
                            .font(.caption)
                        Text("Clear baseline")
                            .font(.caption2.weight(.semibold))
                    }
                    .padding(.horizontal, 9)
                    .padding(.vertical, 5)
                    .background(Color.white.opacity(0.08), in: Capsule())
                    .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Clear baseline")
                .accessibilityHint("Stops flagging rows against the pinned snapshot")
            }
        } else {
            Text("Pin the statuses and passing test counts shown now to flag any row that gets worse from here. The baseline is kept in memory only.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Button {
                pinBaseline()
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: "pin")
                    Text("Pin baseline")
                }
                .font(.subheadline.weight(.semibold))
                .frame(maxWidth: .infinity)
                .padding(.vertical, 10)
                .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 12))
            }
            .buttonStyle(.plain)
            .tint(accent)
            .disabled(isRunning || !runningComponents.isEmpty)
            .accessibilityLabel("Pin baseline")
            .accessibilityHint("Snapshots the current row statuses and passing test counts so later regressions are flagged")
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
        .disabled(isRunning || !runningComponents.isEmpty)
    }

    // MARK: - Coverage history

    /// One run in the window: where it sits in the chart and the coverage it
    /// recorded.
    private struct CoveragePoint: Identifiable {
        let index: Int
        let sample: I2PAlignmentCoverageSample

        var id: Int { sample.id }
    }

    private var coveragePoints: [CoveragePoint] {
        coverageHistory.enumerated().map {
            CoveragePoint(index: $0.offset, sample: $0.element)
        }
    }

    /// The sparkline of aligned-row coverage under the run line: the oldest
    /// sample's time as its left label, the delta since the last run under it,
    /// and — tapped open — a taller chart labelled per run with a note naming
    /// how pending wire verification and defects moved.
    @ViewBuilder
    private var coverageHistoryView: some View {
        if !coverageHistory.isEmpty {
            let points = coveragePoints
            VStack(alignment: .leading, spacing: 5) {
                if isHistoryExpanded {
                    Text("Aligned rows per run · oldest run on the left")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                Button {
                    withAnimation(reduceMotion ? nil : .easeInOut(duration: 0.2)) {
                        isHistoryExpanded.toggle()
                    }
                } label: {
                    coverageChart(points)
                        .frame(height: isHistoryExpanded ? 152 : 46)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Aligned-row coverage over the last \(coverageHistory.count) alignment runs")
                .accessibilityValue(coverageAccessibilityValue)
                .accessibilityHint(isHistoryExpanded
                                   ? "Double-tap to collapse the per-run chart"
                                   : "Double-tap to expand the per-run chart")

                HStack(spacing: 6) {
                    if let oldest = coverageHistory.first?.ranAt {
                        Text(oldest.formatted(date: .omitted, time: .shortened))
                            .font(.system(.caption2, design: .monospaced))
                    }
                    if isHistoryExpanded, let latest = coverageHistory.last {
                        Text("→")
                        Text(latest.ranAt.formatted(date: .omitted, time: .shortened))
                            .font(.system(.caption2, design: .monospaced))
                    }
                    Spacer(minLength: 6)
                    Text(coverageHistory.count == 1 ? "1 run" : "\(coverageHistory.count) runs")
                        .font(.caption2)
                    Image(systemName: isHistoryExpanded ? "chevron.up" : "chevron.down")
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(.tertiary)
                }
                .foregroundStyle(.secondary)

                if let delta = I2PAlignmentHistory.alignedDelta(coverageHistory),
                   let line = I2PAlignmentHistory.deltaLine(coverageHistory) {
                    HStack(spacing: 5) {
                        Image(systemName: delta > 0 ? "arrow.up.right.circle.fill"
                                       : delta < 0 ? "arrow.down.right.circle.fill"
                                       : "equal.circle.fill")
                        Text(line)
                    }
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(delta > 0 ? Color.green
                                     : delta < 0 ? Color.orange
                                     : Color.secondary)
                }

                if isHistoryExpanded, let note = I2PAlignmentHistory.movementNote(coverageHistory) {
                    Text(note)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(.top, 2)
        }
    }

    /// What VoiceOver reads for the chart: the last run's coverage and, once
    /// there are two runs, the delta.
    private var coverageAccessibilityValue: String {
        guard let latest = coverageHistory.last else { return "" }
        var parts = ["\(latest.aligned) of \(latest.total) rows aligned at the last run"]
        if let line = I2PAlignmentHistory.deltaLine(coverageHistory) {
            parts.append(line)
        }
        return parts.joined(separator: ", ")
    }

    private func coverageChart(_ points: [CoveragePoint]) -> some View {
        let values = points.map(\.sample.aligned)
        let low = values.min() ?? 0
        let high = values.max() ?? 0
        // Room above and below so a flat history still draws its line, and a
        // single-run history has somewhere to sit.
        let padding = max(2, (high - low + 1) / 2)
        let lower = max(0, low - padding)
        let upper = max(lower + 1, high + padding)
        return Chart {
            ForEach(points) { point in
                if points.count > 1 {
                    AreaMark(x: .value("Run", Double(point.index)),
                             y: .value("Aligned rows", Double(point.sample.aligned)))
                        .foregroundStyle(accent.opacity(isHistoryExpanded ? 0.18 : 0.10))
                        .interpolationMethod(.monotone)
                }
                LineMark(x: .value("Run", Double(point.index)),
                         y: .value("Aligned rows", Double(point.sample.aligned)))
                    .foregroundStyle(accent)
                    .lineStyle(StrokeStyle(lineWidth: isHistoryExpanded ? 2 : 1.6, lineCap: .round))
                    .interpolationMethod(.monotone)
                if points.count == 1 || point.index == points.count - 1 {
                    PointMark(x: .value("Run", Double(point.index)),
                              y: .value("Aligned rows", Double(point.sample.aligned)))
                        .foregroundStyle(accent)
                        .symbolSize(isHistoryExpanded ? 36 : 22)
                }
            }
        }
        .chartXScale(domain: coverageXDomain(points))
        .chartYScale(domain: Double(lower)...Double(upper))
        .modifier(CoverageChartAxes(expanded: isHistoryExpanded,
                                    labelIndices: labelledRunIndices(points)))
    }

    private func coverageXDomain(_ points: [CoveragePoint]) -> ClosedRange<Double> {
        guard points.count > 1 else { return -0.5...0.5 }
        return -0.4...(Double(points.count - 1) + 0.4)
    }

    /// Where the taller chart labels its x-axis: every run while they fit, then
    /// every second or third run so the labels stay readable, and always the
    /// newest run.
    private func labelledRunIndices(_ points: [CoveragePoint]) -> [Double] {
        let stride = max(1, Int(ceil(Double(points.count) / 8.0)))
        var indices = points.map { Double($0.index) }.filter { Int($0) % stride == 0 }
        if let last = points.last, indices.last != Double(last.index) {
            indices.append(Double(last.index))
        }
        return indices
    }

    /// Hidden axes on the compact sparkline; a run number per label and an
    /// aligned-row scale once it is expanded.
    private struct CoverageChartAxes: ViewModifier {
        let expanded: Bool
        let labelIndices: [Double]

        @ViewBuilder
        func body(content: Content) -> some View {
            if expanded {
                content
                    .chartXAxis {
                        AxisMarks(values: labelIndices) { value in
                            AxisGridLine().foregroundStyle(Color.white.opacity(0.08))
                            AxisValueLabel {
                                if let index = value.as(Double.self) {
                                    Text("#\(Int(index.rounded()) + 1)")
                                        .font(.caption2)
                                }
                            }
                        }
                    }
                    .chartYAxis {
                        AxisMarks(position: .leading, values: .automatic(desiredCount: 3)) { value in
                            AxisGridLine().foregroundStyle(Color.white.opacity(0.08))
                            AxisValueLabel {
                                if let rows = value.as(Double.self) {
                                    Text("\(Int(rows.rounded()))")
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

    // MARK: - Export

    /// The screen's share control: the report as it currently stands — coverage,
    /// the last run, every truth-table row and any failing test — as plain text
    /// in the system share sheet.
    private var shareControl: some View {
        let payload = I2PAlignmentReportShare.payload(results: results,
                                                      lastRunAt: lastRunAt,
                                                      rows: shownRows)
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
        .accessibilityHint("Exports the coverage, the rows currently shown and any failing tests")
    }

    /// The second export control: the truth table's own JSON representation —
    /// coverage, intentional deviations, defects and every row with its wire
    /// layout, encoding rules, cryptographic parameters and edge cases — handed
    /// to the share sheet as a `.json` file named for the app version and the
    /// export date, so the sheet gets the file itself rather than pasted text.
    @ViewBuilder
    private var jsonExportControl: some View {
        if let export = jsonExport {
            ShareLink(item: export,
                      subject: Text(export.subject),
                      preview: SharePreview(export.fileName,
                                            image: Image(systemName: "curlybraces"))) {
                VStack(spacing: 4) {
                    HStack(spacing: 8) {
                        Image(systemName: "curlybraces")
                        Text("Export truth table as JSON")
                    }
                    .font(.subheadline.weight(.semibold))
                    Text(export.fileName)
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 10)
                .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 12))
            }
            .buttonStyle(.plain)
            .tint(accent)
            .accessibilityLabel("Export truth table as JSON")
            .accessibilityHint("Shares \(export.fileName): the whole truth table with each row's wire layout, encoding rules, cryptographic parameters and edge cases")
        } else {
            HStack(spacing: 8) {
                Image(systemName: "curlybraces")
                Text("Export truth table as JSON")
            }
            .font(.subheadline.weight(.semibold))
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 10)
            .background(Color.white.opacity(0.03), in: RoundedRectangle(cornerRadius: 12))
            .accessibilityLabel("Export truth table as JSON")
            .accessibilityHint("The truth table could not be encoded, so there is no file to export")
        }
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

    // MARK: - Filtering

    /// The status chips in the order the header summary lists them.
    private let statusFilterOrder: [I2PAlignmentStatus] = [
        .aligned, .pendingWireVerification, .deviationDocumented, .defect,
    ]

    private var trimmedQuery: String {
        searchText.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private var isFiltering: Bool {
        !trimmedQuery.isEmpty || !activeStatuses.isEmpty
    }

    /// The rows the screen is showing, in truth-table order.
    private var shownRows: [I2PSpecRow] {
        I2PSpecTruthTable.rows.filter(matches)
    }

    /// Whether a row passes the search field and the status chips. The query is
    /// matched case-insensitively against the row's id, its requirement text and
    /// its Java reference class; no chip selected means every status passes.
    private func matches(_ row: I2PSpecRow) -> Bool {
        if !activeStatuses.isEmpty, !activeStatuses.contains(row.status) {
            return false
        }
        let query = trimmedQuery
        guard !query.isEmpty else { return true }
        return [row.id, row.requirement, row.javaReference].contains {
            $0.range(of: query, options: [.caseInsensitive, .diacriticInsensitive]) != nil
        }
    }

    private func toggleStatus(_ status: I2PAlignmentStatus) {
        if activeStatuses.contains(status) {
            activeStatuses.remove(status)
        } else {
            activeStatuses.insert(status)
        }
    }

    private func clearFilters() {
        searchText = ""
        activeStatuses.removeAll()
    }

    private var filterCard: some View {
        card(title: "Filter rows") {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                TextField("Search id, requirement or Java class", text: $searchText)
                    .font(.footnote)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .submitLabel(.done)
                    .accessibilityLabel("Filter truth-table rows")
                if !searchText.isEmpty {
                    Button {
                        searchText = ""
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("Clear search text")
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 8)
            .background(Color.white.opacity(0.05), in: RoundedRectangle(cornerRadius: 10))

            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    ForEach(statusFilterOrder, id: \.self) { status in
                        statusFilterChip(status)
                    }
                }
                .padding(.vertical, 1)
            }

            HStack {
                Text("\(shownRows.count) of \(I2PSpecTruthTable.rows.count) rows")
                    .font(.footnote.weight(.medium))
                    .foregroundStyle(isFiltering ? accent : .secondary)
                Spacer()
                if isFiltering {
                    Button("Clear") {
                        clearFilters()
                    }
                    .font(.footnote.weight(.semibold))
                    .buttonStyle(.plain)
                    .tint(accent)
                    .accessibilityLabel("Clear filters")
                }
            }
        }
    }

    private func statusFilterChip(_ status: I2PAlignmentStatus) -> some View {
        let isOn = activeStatuses.contains(status)
        return Button {
            toggleStatus(status)
        } label: {
            HStack(spacing: 4) {
                Image(systemName: isOn ? "checkmark.circle.fill" : "circle")
                    .font(.caption2)
                Text(shortStatus(status))
                    .font(.caption2.weight(.semibold))
            }
            .padding(.horizontal, 9)
            .padding(.vertical, 5)
            .background(statusColor(status).opacity(isOn ? 0.28 : 0.12), in: Capsule())
            .foregroundStyle(statusColor(status))
        }
        .buttonStyle(.plain)
        .accessibilityLabel("\(shortStatus(status)) status filter")
        .accessibilityValue(isOn ? "on" : "off")
    }

    // MARK: - Component sections

    /// One component's section. `regressionMap` carries the rows that are worse
    /// than the pinned baseline, so each of its rows can badge itself.
    @ViewBuilder
    private func componentSection(_ component: I2PSpecComponent,
                                  regressionMap: [String: I2PAlignmentRegression]) -> some View {
        let allRows = I2PSpecTruthTable.rows(in: component)
        let shown = allRows.filter(matches)
        if !shown.isEmpty {
            let running = isSectionRunning(component)
            card(title: component.displayName) {
                HStack(spacing: 8) {
                    sectionTestLine(component, running: running)
                    Spacer(minLength: 8)
                    rerunButton(component, running: running)
                }
                Text(isFiltering
                     ? "\(shown.count) of \(allRows.count) rows"
                     : I2PSpecTruthTable.coverage(for: component).summary)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                ForEach(shown) { row in
                    rowView(row, running: running, regression: regressionMap[row.id])
                }
            }
        }
    }

    /// The section's pass line: "running…" while its suite is in flight, "not
    /// run" until it has stored results, otherwise the pass count of the tests
    /// tagged with its rows.
    @ViewBuilder
    private func sectionTestLine(_ component: I2PSpecComponent, running: Bool) -> some View {
        if running {
            Text("running…")
                .font(.caption2)
                .foregroundStyle(.secondary)
        } else {
            let totals = sectionCounts(for: component)
            if totals.total == 0 {
                Text("not run")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            } else {
                let allPassed = totals.passing == totals.total
                Text("\(totals.passing) of \(totals.total) tests passed")
                    .font(.caption2.weight(.medium))
                    .foregroundStyle(allPassed ? Color.green : Color.orange)
            }
        }
    }

    /// Per-section re-run control. It runs only this component's rows, so the
    /// other sections' stored results and buttons are left alone.
    private func rerunButton(_ component: I2PSpecComponent, running: Bool) -> some View {
        Button {
            rerun(component)
        } label: {
            HStack(spacing: 5) {
                if running {
                    ProgressView()
                        .controlSize(.mini)
                        .tint(accent)
                } else {
                    Image(systemName: "play.circle")
                        .font(.caption)
                }
                Text(running ? "Running…" : "Re-run")
                    .font(.caption2.weight(.semibold))
            }
            .padding(.horizontal, 9)
            .padding(.vertical, 5)
            .background(accent.opacity(running ? 0.10 : 0.18), in: Capsule())
            .foregroundStyle(accent)
        }
        .buttonStyle(.plain)
        .tint(accent)
        .disabled(running)
        .accessibilityLabel("Re-run \(component.displayName) tests")
        .accessibilityValue(running ? "running" : "")
        .accessibilityHint("Runs only the cross-validation tests tagged with this section's rows")
    }

    // MARK: - Rows

    @ViewBuilder
    private func rowView(_ row: I2PSpecRow, running: Bool,
                         regression: I2PAlignmentRegression? = nil) -> some View {
        let rowCounts = counts(for: row.id)
        VStack(alignment: .leading, spacing: 6) {
            Button {
                sheet = .rowDetail(row.id)
            } label: {
                VStack(alignment: .leading, spacing: 6) {
                    HStack(alignment: .top, spacing: 8) {
                        Text(row.id)
                            .font(.system(.caption, design: .monospaced).weight(.bold))
                            .foregroundStyle(accent)
                        statusPill(row.status)
                        Spacer()
                        testCountLabel(rowCounts, running: running)
                        Image(systemName: "chevron.right")
                            .font(.caption2.weight(.bold))
                            .foregroundStyle(.tertiary)
                    }
                    if let regression {
                        regressionBadge(regression)
                    }
                    Text(row.requirement)
                        .font(.footnote.weight(.medium))
                        .fixedSize(horizontal: false, vertical: true)
                    Text("spec · \(row.specSection)")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    Text("java · \(row.javaReference)")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel(rowAccessibilityLabel(row, regression: regression))
            .accessibilityHint("Opens the full requirement detail")

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
    private func testCountLabel(_ rowCounts: (passing: Int, total: Int)?, running: Bool) -> some View {
        if running {
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

    /// The red badge on a row that got worse since the baseline was pinned. It
    /// names the baseline value the row fell from — its status, its passing test
    /// count, or both.
    private func regressionBadge(_ regression: I2PAlignmentRegression) -> some View {
        HStack(spacing: 5) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.caption2)
            Text("Regressed")
                .font(.caption2.weight(.bold))
            Text("· \(regression.baselineDescription)")
                .font(.caption2.weight(.medium))
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 3)
        .background(Color.red.opacity(0.18), in: Capsule())
        .foregroundStyle(Color.red)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Regressed since the baseline: \(regression.baselineDescription)")
    }

    /// What VoiceOver reads for a row, including its regression when it has one.
    private func rowAccessibilityLabel(_ row: I2PSpecRow,
                                       regression: I2PAlignmentRegression?) -> String {
        var label = "\(row.id), \(row.status.displayName)"
        if let regression {
            label += ", regressed since the baseline: \(regression.baselineDescription)"
        }
        return label
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