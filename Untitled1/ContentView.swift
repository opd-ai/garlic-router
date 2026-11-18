//
//  ContentView.swift
//  Untitled1
//
//  The audit console (I2P Core) plus the app shell and its one-time
//  first-run screen.
//

import SwiftUI
import UIKit

/// The I2P Core tab: the cryptographic suite, the serialization readings and
/// the five audits. Reached from the shell's "I2P Core" tab.
struct CoreAuditView: View {
    @State private var results: [I2PSelfTestResult] = []
    @State private var readinessResults: [I2PSelfTestResult] = []
    @State private var stabilityResults: [I2PSelfTestResult] = []
    @State private var hardeningResults: [I2PSelfTestResult] = []
    @State private var specResults: [I2PSelfTestResult] = []
    @State private var specRunning = false
    @State private var specCurrentProbe = ""
    @State private var specCompletedChecks = 0
    @State private var productionResults: [I2PSelfTestResult] = []
    @State private var resultsExpanded = false
    @State private var readinessExpanded = false
    @State private var stabilityExpanded = false
    @State private var hardeningExpanded = false
    @State private var specExpanded = false
    @State private var productionExpanded = false
    @State private var readinessRunning = false
    @State private var readinessCurrentProbe = ""
    @State private var readinessCompletedChecks = 0
    @State private var stabilityRunning = false
    @State private var stabilityCurrentProbe = ""
    @State private var stabilityCompletedChecks = 0
    @State private var capturedCrash: CapturedCrash?
    @State private var readinessLastInterruptedPhase: String?
    @State private var mainnetRunning = false
    @State private var mainnetCurrentProbe = ""
    @State private var mainnetCompletedChecks = 0
    @State private var sizes: [(name: String, bytes: Int)] = []

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        coreTab
    }

    private var coreTab: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    capturedCrashBanner
                    cryptoSuiteCard
                    serializationCard
                    selfTestCard
                    readinessCard
                    stabilityCard
                    hardeningCard
                    specCard
                    productionCard
                }
                .padding(.horizontal, 16)
                .padding(.top, 4)
                .padding(.bottom, 24)
            }
            .background(background.ignoresSafeArea())
            .navigationTitle("I2P Core")
            .navigationBarTitleDisplayMode(.large)
            .onAppear {
                if readinessLastInterruptedPhase == nil {
                    readinessLastInterruptedPhase = I2PReadinessAudit.interruptedPhase
                }
                refreshCapturedCrash()
            }
        }
    }

    private func refresh() {
        sizes = I2PSelfTest.sampleByteSizes()
        Task.detached {
            let fresh = await I2PSelfTest.runAll()
            await MainActor.run {
                results = fresh
                resultsExpanded = true
            }
        }
    }

    /// The live mainnet suite runs explicitly (it performs real network
    /// exchanges with reseed servers and floodfill routers), never on launch.
    /// Each probe rides a live-network round trip (HTTPS reseed, NTCP2
    /// handshakes, DHT lookups with 10s waits, a 20s monitor window), so the
    /// run legitimately takes a minute or more — it gets the same running
    /// state, progress surface and background-task lease as the readiness and
    /// spec audits so it visibly runs and survives backgrounding.
    private func runMainnetAudit() {
        guard !mainnetRunning else { return }
        mainnetRunning = true
        results = []
        mainnetCurrentProbe = "Preparing mainnet checks"
        mainnetCompletedChecks = 0
        resultsExpanded = false
        let auditLease = BackgroundTaskLease()
        auditLease.begin(name: "I2P mainnet audit")
        Task.detached(priority: .utility) {
            let fresh = await I2PMainnetVerification.runAll { phase, result in
                await MainActor.run {
                    mainnetCurrentProbe = phase
                    if let result {
                        results.append(I2PSelfTestResult(
                            name: "Mainnet · \(result.name)",
                            passed: result.passed,
                            detail: result.detail))
                        mainnetCompletedChecks += 1
                    }
                }
            }
            await MainActor.run {
                results = fresh.map {
                    I2PSelfTestResult(name: "Mainnet · \($0.name)",
                                      passed: $0.passed,
                                      detail: $0.detail)
                }
                resultsExpanded = true
                mainnetCurrentProbe = ""
                mainnetRunning = false
            }
            auditLease.end()
        }
    }

    /// Runs the complete production probe set once, sequentially. Intermediate
    /// outcomes are surfaced immediately; the audit stores its active probe in
    /// case iOS terminates the process before completion. A background-task
    /// assertion spans the whole run so backgrounding the app mid-audit no
    /// longer kills the process — a suspension kill used to leave the same
    /// "previous run stopped during NTCP2 handshake" banner on every launch.
    private func runReadinessAudit() {
        guard !readinessRunning else { return }
        readinessRunning = true
        readinessResults = []
        readinessCurrentProbe = "Preparing production checks"
        readinessCompletedChecks = 0
        readinessLastInterruptedPhase = nil
        let auditLease = BackgroundTaskLease()
        auditLease.begin(name: "I2P readiness audit")
        Task.detached(priority: .utility) {
            let fresh = await I2PReadinessAudit.runAll { phase, result in
                await MainActor.run {
                    readinessCurrentProbe = phase
                    if let result {
                        readinessResults.append(I2PSelfTestResult(
                            name: "Readiness · \(result.name)",
                            passed: result.passed,
                            detail: result.detail))
                        readinessCompletedChecks += 1
                    }
                }
            }
            await MainActor.run {
                readinessResults = fresh
                readinessExpanded = true
                readinessCurrentProbe = ""
                readinessRunning = false
                readinessLastInterruptedPhase = I2PReadinessAudit.interruptedPhase
            }
            auditLease.end()
        }
    }

    private var readinessCard: some View {
        card(title: "Production readiness") {
            Button {
                runReadinessAudit()
            } label: {
                Label(readinessRunning ? "Running check \(readinessCompletedChecks + 1) of 11…" : "Run readiness audit",
                      systemImage: readinessRunning ? "hourglass" : "stethoscope")
                    .font(.subheadline.weight(.semibold))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .background(accent.opacity(0.15), in: RoundedRectangle(cornerRadius: 12))
            }
            .buttonStyle(.plain)
            .tint(accent)
            .disabled(readinessRunning)

            if readinessRunning {
                VStack(alignment: .leading, spacing: 6) {
                    ProgressView(value: Double(readinessCompletedChecks), total: 11)
                        .tint(accent)
                    Text("\(readinessCompletedChecks) of 11 checks complete · \(readinessCurrentProbe)")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            if let readinessLastInterruptedPhase {
                // The crash report is the authoritative interruption record:
                // its "active probe" line names what the process actually
                // trapped on, while the UserDefaults checkpoint can be stale
                // (an older build's phase-only write, or writes lost on an
                // ephemeral test device). When the crash is at least as fresh
                // as the checkpoint, it leads the banner.
                let checkpoint = I2PReadinessAudit.interruptedCheckpoint
                let crash = I2PCrashReporter.lastCrashContext()
                let crashLeads: Bool = {
                    guard let crash else { return false }
                    return checkpoint?.savedAt.map({ crash.date >= $0 }) ?? true
                }()
                if crashLeads, let crash, let probe = crash.activeProbe {
                    Text("The process crashed during: \(probe). The checkpoint banner below may be stale — judge by the signal report.")
                        .font(.caption2.weight(.medium))
                        .foregroundStyle(.orange)
                        .textSelection(.enabled)
                    Text(I2PCrashReporter.diagnosticHead(maxFrames: 4))
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.orange)
                        .textSelection(.enabled)
                } else {
                    Text(I2PReadinessAudit.interruptionNotice() ?? readinessLastInterruptedPhase)
                        .font(.caption2)
                        .foregroundStyle(.orange)
                        .textSelection(.enabled)
                    // If the process actually crashed mid-audit, the fatal-signal
                    // handler persisted the exact faulting context — show its
                    // header (signal + top stack frames) right under the banner.
                    Text(I2PCrashReporter.diagnosticHead(maxFrames: 4))
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.orange)
                        .textSelection(.enabled)
                }
            }

            if !readinessResults.isEmpty {
                let passed = readinessResults.filter(\.passed).count
                auditResultsSection(passed, of: readinessResults.count,
                                    allPassedSummary: "\(passed) of \(readinessResults.count) readiness checks passed",
                                    findingsSummary: "\(passed) of \(readinessResults.count) readiness checks passed — findings below",
                                    isExpanded: $readinessExpanded) {
                    ForEach(readinessResults.indices, id: \.self) { index in
                        HStack(alignment: .top, spacing: 8) {
                            Image(systemName: readinessResults[index].passed ? "checkmark.circle.fill" : "xmark.circle.fill")
                                .foregroundStyle(readinessResults[index].passed ? Color.green : Color.red)
                                .font(.caption)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(readinessResults[index].name)
                                    .font(.footnote.weight(.medium))
                                Text(readinessResults[index].detail)
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
        }
    }

    /// The systematic crash-safety audit: every checklist category from the
    /// crash-debugging framework is exercised by an executable probe. No
    /// mainnet traffic involved. Progress rides the same onProgress channel
    /// as the readiness audit, and the probe engine checkpoints each probe
    /// through the shared audit-progress slot — so a mid-probe trap leaves a
    /// named crash report and a named checkpoint instead of a silent death.
    private func runStabilityAudit() {
        guard !stabilityRunning else { return }
        stabilityRunning = true
        stabilityResults = []
        stabilityCurrentProbe = "Preparing stability checks"
        stabilityCompletedChecks = 0
        Task.detached(priority: .utility) {
            let fresh = await I2PStabilityAudit.runAll { phase, result in
                await MainActor.run {
                    stabilityCurrentProbe = phase
                    if let result {
                        stabilityResults.append(result)
                        stabilityCompletedChecks += 1
                    }
                }
            }
            await MainActor.run {
                stabilityResults = fresh
                stabilityExpanded = true
                stabilityCurrentProbe = ""
                stabilityRunning = false
            }
        }
    }

    /// The defensive-hardening audit probes every dimension of the hardening
    /// checklist against the live mechanisms. No mainnet traffic involved.
    private func runHardeningAudit() {
        Task.detached {
            let fresh = await I2PHardeningAudit.runAll()
            await MainActor.run {
                hardeningResults = fresh
                hardeningExpanded = true
            }
        }
    }

    private var hardeningCard: some View {
        card(title: "Security hardening") {
            Button {
                runHardeningAudit()
            } label: {
                Label("Run hardening audit", systemImage: "lock.shield")
                    .font(.subheadline.weight(.semibold))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .background(accent.opacity(0.15), in: RoundedRectangle(cornerRadius: 12))
            }
            .buttonStyle(.plain)
            .tint(accent)

            if !hardeningResults.isEmpty {
                let passed = hardeningResults.filter(\.passed).count
                auditResultsSection(passed, of: hardeningResults.count,
                                    allPassedSummary: "\(passed) of \(hardeningResults.count) probes passed — defensive posture verified",
                                    findingsSummary: "\(passed) of \(hardeningResults.count) probes passed — findings below",
                                    isExpanded: $hardeningExpanded) {
                    ForEach(hardeningResults.indices, id: \.self) { index in
                        HStack(alignment: .top, spacing: 8) {
                            Image(systemName: hardeningResults[index].passed ? "checkmark.circle.fill" : "xmark.circle.fill")
                                .foregroundStyle(hardeningResults[index].passed ? Color.green : Color.red)
                                .font(.caption)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(hardeningResults[index].name)
                                    .font(.footnote.weight(.medium))
                                Text(hardeningResults[index].detail)
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }

                Text("Fail closed: ambiguous states are rejected, quotas bound every resource, secrets are erased and redacted from diagnostics.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
    }

    /// The spec-derived conformance audit: every locally-verifiable phase of
    /// the official-spec production checklist rides deterministic probes
    /// (I2NP header format, SSU2 packet-number windows, RFC crypto primitives,
    /// RouterInfo verification) plus a blanket gate over the local conformance
    /// suite. Live-network interop probes ride the mainnet suite.
    ///
    /// The blanket gate runs the ENTIRE local suite (SAM sockets, tunnel
    /// pools, SSU2 loopbacks), so the run legitimately takes a while — it
    /// gets the same progress surface and background-task lease as the
    /// readiness audit, so it visibly runs and survives backgrounding.
    private func runSpecAudit() {
        guard !specRunning else { return }
        specRunning = true
        specResults = []
        specCurrentProbe = "Preparing spec conformance probes"
        specCompletedChecks = 0
        let auditLease = BackgroundTaskLease()
        auditLease.begin(name: "I2P spec conformance audit")
        Task.detached(priority: .utility) {
            let fresh = await I2PSpecConformanceAudit.runAll { phase, result in
                await MainActor.run {
                    specCurrentProbe = phase
                    if let result {
                        specResults.append(I2PSelfTestResult(
                            name: "Spec · \(result.name)",
                            passed: result.passed,
                            detail: result.detail))
                        specCompletedChecks += 1
                    }
                }
            }
            await MainActor.run {
                specResults = fresh.map {
                    I2PSelfTestResult(name: "Spec · \($0.name)",
                                      passed: $0.passed,
                                      detail: $0.detail)
                }
                specExpanded = true
                specCurrentProbe = ""
                specRunning = false
            }
            auditLease.end()
        }
    }

    private var specCard: some View {
        card(title: "Spec conformance") {
            Button {
                runSpecAudit()
            } label: {
                Label(specRunning ? "Running check \(specCompletedChecks + 1) of 6…" : "Run spec conformance audit",
                      systemImage: specRunning ? "hourglass" : "checkmark.seal.fill")
                    .font(.subheadline.weight(.semibold))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .background(accent.opacity(0.15), in: RoundedRectangle(cornerRadius: 12))
            }
            .buttonStyle(.plain)
            .tint(accent)
            .disabled(specRunning)

            if specRunning {
                VStack(alignment: .leading, spacing: 6) {
                    ProgressView(value: Double(specCompletedChecks), total: 6)
                        .tint(accent)
                    Text("\(specCompletedChecks) of 6 checks complete · \(specCurrentProbe)")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            if !specResults.isEmpty {
                let passed = specResults.filter(\.passed).count
                auditResultsSection(passed, of: specResults.count,
                                    allPassedSummary: "\(passed) of \(specResults.count) probes passed — official-spec checklist verified",
                                    findingsSummary: "\(passed) of \(specResults.count) probes passed — findings below",
                                    isExpanded: $specExpanded) {
                    ForEach(specResults.indices, id: \.self) { index in
                        HStack(alignment: .top, spacing: 8) {
                            Image(systemName: specResults[index].passed ? "checkmark.circle.fill" : "xmark.circle.fill")
                                .foregroundStyle(specResults[index].passed ? Color.green : Color.red)
                                .font(.caption)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(specResults[index].name)
                                    .font(.footnote.weight(.medium))
                                Text(specResults[index].detail)
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }

                Text("Locally-verifiable checklist phases run as deterministic probes; live-network interop items (Java I2P / i2pd handshakes, framed message flooding) ride the mainnet suite.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
    }

    /// The final production-readiness audit & remediation pass: every checklist
    /// section (NTCP2/SSU2 transports, RFC crypto vectors, structure trust
    /// boundaries, wire primitives, PQ hybrid leg, modern-crypto policy) runs as
    /// an executable probe against the live mechanisms.
    private func runProductionAudit() {
        Task.detached {
            let fresh = await I2PProductionAudit.runAll()
            await MainActor.run {
                productionResults = fresh
                productionExpanded = true
            }
        }
    }

    private var productionCard: some View {
        card(title: "Production audit") {
            Button {
                runProductionAudit()
            } label: {
                Label("Run production audit", systemImage: "seal.fill")
                    .font(.subheadline.weight(.semibold))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .background(accent.opacity(0.15), in: RoundedRectangle(cornerRadius: 12))
            }
            .buttonStyle(.plain)
            .tint(accent)

            if !productionResults.isEmpty {
                let passed = productionResults.filter(\.passed).count
                auditResultsSection(passed, of: productionResults.count,
                                    allPassedSummary: "\(passed) of \(productionResults.count) checklist sections verified — production readiness closed",
                                    findingsSummary: "\(passed) of \(productionResults.count) sections verified — findings below",
                                    isExpanded: $productionExpanded) {
                    ForEach(productionResults.indices, id: \.self) { index in
                        HStack(alignment: .top, spacing: 8) {
                            Image(systemName: productionResults[index].passed ? "checkmark.circle.fill" : "xmark.circle.fill")
                                .foregroundStyle(productionResults[index].passed ? Color.green : Color.red)
                                .font(.caption)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(productionResults[index].name)
                                    .font(.footnote.weight(.medium))
                                Text(productionResults[index].detail)
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }

                Text("Transport handshakes run end-to-end over real Noise chains and UDP sockets; RFC known-answer vectors are exact; the ML-KEM hybrid leg (FIPS 203) is remediated in with dual-leg KDF binding.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
    }

    /// A captured crash from the previous session, surfaced at launch
    /// regardless of which audit crashed — the readiness card's banner is
    /// gated on the readiness checkpoint, which is empty after a passing
    /// readiness audit, so a stability-audit crash would otherwise be
    /// invisible in the UI even though the signal handler captured it.
    private func refreshCapturedCrash() {
        guard capturedCrash == nil,
              let context = I2PCrashReporter.lastCrashContext() else { return }
        // The surfaced marker is versioned: when the diagnostic-head format
        // changed (app frames now lead the banner instead of the runtime
        // abort chain), previously surfaced reports re-surface once so the
        // actionable frames become visible for an already-captured crash.
        let surfacedKey = "i2p.crash.lastSurfacedAt.v2"
        if let surfaced = UserDefaults.standard.object(forKey: surfacedKey) as? Date,
           context.date <= surfaced {
            return
        }
        UserDefaults.standard.set(context.date, forKey: surfacedKey)
        UserDefaults.standard.synchronize()
        capturedCrash = CapturedCrash(
            capturedAt: context.date,
            probe: context.activeProbe,
            reportHead: I2PCrashReporter.diagnosticHead())
    }

    private var capturedCrashBanner: some View {
        Group {
            if let crash = capturedCrash {
                VStack(alignment: .leading, spacing: 6) {
                    HStack(spacing: 6) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                        Text("Crash captured \(crash.capturedAt.formatted(date: .abbreviated, time: .shortened))")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.orange)
                        Spacer()
                    }
                    Text(crash.probe.map { "The process crashed during: \($0)." }
                            ?? "The process crashed outside a named probe.")
                        .font(.caption2.weight(.medium))
                        .foregroundStyle(.orange)
                        .textSelection(.enabled)
                    Text(crash.reportHead)
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.orange)
                        .textSelection(.enabled)
                }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.orange.opacity(0.10), in: RoundedRectangle(cornerRadius: 16))
            }
        }
    }

    private var stabilityCard: some View {
        card(title: "Crash & stability audit") {
            Button {
                runStabilityAudit()
            } label: {
                Label(stabilityRunning ? "Running stability probes…" : "Run stability audit",
                      systemImage: stabilityRunning ? "hourglass" : "checkmark.shield")
                    .font(.subheadline.weight(.semibold))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .background(accent.opacity(0.15), in: RoundedRectangle(cornerRadius: 12))
            }
            .buttonStyle(.plain)
            .tint(accent)
            .disabled(stabilityRunning)

            if stabilityRunning {
                VStack(alignment: .leading, spacing: 6) {
                    ProgressView(value: Double(stabilityCompletedChecks), total: 6)
                        .tint(accent)
                    Text("\(stabilityCompletedChecks) of 6 probes complete · \(stabilityCurrentProbe)")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            if !stabilityResults.isEmpty {
                let passed = stabilityResults.filter(\.passed).count
                auditResultsSection(passed, of: stabilityResults.count,
                                    allPassedSummary: "\(passed) of \(stabilityResults.count) probes passed — every crash checklist category ran clean",
                                    findingsSummary: "\(passed) of \(stabilityResults.count) probes passed — findings below",
                                    isExpanded: $stabilityExpanded) {
                    ForEach(stabilityResults.indices, id: \.self) { index in
                        HStack(alignment: .top, spacing: 8) {
                            Image(systemName: stabilityResults[index].passed ? "checkmark.circle.fill" : "xmark.circle.fill")
                                .foregroundStyle(stabilityResults[index].passed ? Color.green : Color.red)
                                .font(.caption)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(stabilityResults[index].name)
                                    .font(.footnote.weight(.medium))
                                Text(stabilityResults[index].detail)
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }

                Text("Surviving probes are the systematic equivalent of an empty crash log; failures carry the action-items breakdown (crash type, root cause, verification).")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var cryptoSuiteCard: some View {
        card(title: "Cryptographic Suite") {
            suiteRow("X25519", subtitle: "EncType 4 · key agreement")
            suiteRow("Ed25519", subtitle: "SigType 7 · EdDSA")
            suiteRow("Ed25519ph", subtitle: "SigType 11 · pre-hashed EdDSA")
            suiteRow("ChaCha20-Poly1305", subtitle: "AEAD · NTCP2 transport")
            suiteRow("HKDF-SHA256", subtitle: "key derivation")
            suiteRow("SHA-256 · BLAKE2b", subtitle: "hashing")
        }
    }

    private var serializationCard: some View {
        card(title: "Serialization") {
            if sizes.isEmpty {
                Text("Run round-trip tests to populate sample sizes.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(sizes.indices, id: \.self) { index in
                    HStack {
                        Text(sizes[index].name)
                            .font(.subheadline.weight(.medium))
                        Spacer()
                        Text("\(sizes[index].bytes) B")
                            .font(.system(.footnote, design: .monospaced).weight(.semibold))
                            .foregroundStyle(accent)
                    }
                }
            }
            Text("I2P big-endian wire format · signature-verified on parse")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
    }

    private var selfTestCard: some View {
        card(title: "Self-Test") {
            Button {
                refresh()
            } label: {
                Label("Run round-trip tests", systemImage: "arrow.triangle.2.circlepath")
                    .font(.subheadline.weight(.semibold))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .background(accent.opacity(0.18), in: RoundedRectangle(cornerRadius: 12))
            }
            .buttonStyle(.plain)
            .tint(accent)

            Button {
                runMainnetAudit()
            } label: {
                Label(mainnetRunning ? "Running mainnet check \(mainnetCompletedChecks + 1) of 9…" : "Run mainnet audit (live network)",
                      systemImage: mainnetRunning ? "hourglass" : "antenna.radiowaves.left.and.right")
                    .font(.subheadline.weight(.semibold))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .background(accent.opacity(0.12), in: RoundedRectangle(cornerRadius: 12))
            }
            .buttonStyle(.plain)
            .tint(accent)
            .disabled(mainnetRunning)

            if mainnetRunning {
                VStack(alignment: .leading, spacing: 6) {
                    ProgressView(value: Double(mainnetCompletedChecks), total: 9)
                        .tint(accent)
                    Text("\(mainnetCompletedChecks) of 9 checks complete · \(mainnetCurrentProbe)")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            if !results.isEmpty {
                let passed = results.filter(\.passed).count
                auditResultsSection(passed, of: results.count,
                                    allPassedSummary: "\(passed) of \(results.count) tests passed",
                                    findingsSummary: "\(passed) of \(results.count) passed — failures below",
                                    isExpanded: $resultsExpanded) {
                    ForEach(results.indices, id: \.self) { index in
                        HStack(alignment: .top, spacing: 8) {
                            Image(systemName: results[index].passed ? "checkmark.circle.fill" : "xmark.circle.fill")
                                .foregroundStyle(results[index].passed ? Color.green : Color.red)
                                .font(.caption)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(results[index].name)
                                    .font(.footnote.weight(.medium))
                                Text(results[index].detail)
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
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

    /// Expandable audit-results section: the summary row toggles the detail
    /// list, so long reports collapse out of the way and re-expand on demand.
    /// Runs auto-expand the section when fresh results arrive.
    private func auditResultsSection(_ passed: Int, of total: Int,
                                     allPassedSummary: String,
                                     findingsSummary: String,
                                     isExpanded: Binding<Bool>,
                                     @ViewBuilder rows: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Button {
                // Reduce Motion: the list still expands, without the animation.
                withAnimation(reduceMotion ? nil : .easeInOut(duration: 0.2)) {
                    isExpanded.wrappedValue.toggle()
                }
            } label: {
                HStack(spacing: 8) {
                    Text(passed == total ? allPassedSummary : findingsSummary)
                        .font(.footnote.weight(.medium))
                        .foregroundStyle(passed == total ? Color.green : Color.orange)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    Image(systemName: isExpanded.wrappedValue ? "chevron.up" : "chevron.down")
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(.secondary)
                }
            }
            .buttonStyle(.plain)
            if isExpanded.wrappedValue {
                rows()
            }
        }
    }

    private func suiteRow(_ name: String, subtitle: String) -> some View {
        HStack(spacing: 10) {
            Circle()
                .fill(Color.green)
                .frame(width: 7, height: 7)
            Text(name)
                .font(.subheadline.weight(.medium))
            Spacer()
            Text(subtitle)
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
    }
}

#Preview("I2P Core") {
    CoreAuditView()
}

/// Holds a UIApplication background-task assertion for the duration of a long
/// audit so iOS does not suspend-kill the process while the app is backgrounded
/// mid-run. Ends the assertion from the expiry handler too, so the lease is
/// always released exactly once whichever side fires first.
final class BackgroundTaskLease: @unchecked Sendable {
    private let lock = NSLock()
    private var identifier = UIBackgroundTaskIdentifier.invalid

    func begin(name: String) {
        lock.lock()
        defer { lock.unlock() }
        guard identifier == .invalid else { return }
        identifier = UIApplication.shared.beginBackgroundTask(withName: name) { [weak self] in
            self?.end()
        }
    }

    func end() {
        lock.lock()
        defer { lock.unlock() }
        guard identifier != .invalid else { return }
        UIApplication.shared.endBackgroundTask(identifier)
        identifier = .invalid
    }
}

/// One captured crash: when the process died, which audit probe was running
/// (from the signal handler's report), and the report's header for display.
struct CapturedCrash {
    let capturedAt: Date
    let probe: String?
    let reportHead: String
}

// MARK: - App shell

/// The app shell. Five tabs, because iOS turns anything beyond five into a
/// "More" list that buries whole screens; the product roadmap moved behind the
/// Alignment tab's toolbar, where it stays one tap away.
struct ContentView: View {
    /// Set the first time the first-run screen is dismissed, whichever way it
    /// is left, so a returning user never meets it again.
    @AppStorage("i2p.firstRun.completed") private var firstRunCompleted = false
    @State private var selection: AppTab = .irc
    @State private var showingFirstRun = false

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)

    enum AppTab: Hashable {
        case irc
        case core
        case router
        case sam
        case alignment
    }

    var body: some View {
        TabView(selection: $selection) {
            IRCView()
                .tabItem {
                    Label("IRC", systemImage: "bubble.left.and.bubble.right")
                }
                .tag(AppTab.irc)
            CoreAuditView()
                .tabItem {
                    Label("I2P Core", systemImage: "cpu")
                }
                .tag(AppTab.core)
            RouterDashboardView()
                .tabItem {
                    Label("Router", systemImage: "speedometer")
                }
                .tag(AppTab.router)
            SAMView()
                .tabItem {
                    Label("SAM", systemImage: "terminal")
                }
                .tag(AppTab.sam)
            AlignmentView()
                .tabItem {
                    Label("Alignment", systemImage: "checkmark.seal")
                }
                .tag(AppTab.alignment)
        }
        .tint(accent)
        .preferredColorScheme(.dark)
        .task {
            if !firstRunCompleted { showingFirstRun = true }
        }
        .sheet(isPresented: $showingFirstRun,
               onDismiss: { firstRunCompleted = true }) {
            FirstRunView(
                onStart: {
                    // Land on the Router tab: starting is the first-run
                    // decision, and the dashboard is where its result shows.
                    selection = .router
                    Task { @MainActor in
                        I2PRouterAppContext.shared.start()
                    }
                },
                onSkip: {}
            )
        }
    }
}

// MARK: - First run

/// The one-time introduction: what the app is, what it does with the
/// connection, and the single decision it needs — start now or not. Skippable,
/// and never shown again once dismissed.
struct FirstRunView: View {
    let onStart: () -> Void
    let onSkip: () -> Void

    @Environment(\.dismiss) private var dismiss

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            VStack(alignment: .leading, spacing: 10) {
                Image(systemName: "circle.hexagongrid.fill")
                    .font(.system(.largeTitle, design: .rounded))
                    .foregroundStyle(accent)
                    .accessibilityHidden(true)
                Text("Welcome to Garlic Router")
                    .font(.title2.weight(.bold))
                    .fixedSize(horizontal: false, vertical: true)
                Text("A full I2P router that runs on this phone — no desktop, no daemon.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            VStack(alignment: .leading, spacing: 16) {
                point(icon: "iphone",
                      title: "Runs on this iPhone",
                      body: "The router joins the I2P network directly. There is nothing to configure to start.")
                point(icon: "key.fill",
                      title: "Your identity stays here",
                      body: "Router keys are generated on this device and kept in the iOS Keychain.")
                point(icon: "clock",
                      title: "Runs while the app is open",
                      body: "iOS pauses the router when you leave. Bandwidth caps and quiet hours are in Participation.")
            }

            Spacer(minLength: 8)

            Button {
                onStart()
                dismiss()
            } label: {
                Label("Start the router", systemImage: "play.fill")
                    .font(.subheadline.weight(.semibold))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
                    .background(accent.opacity(0.22), in: RoundedRectangle(cornerRadius: 12))
                    .overlay(
                        RoundedRectangle(cornerRadius: 12)
                            .strokeBorder(accent.opacity(0.35), lineWidth: 1)
                    )
            }
            .buttonStyle(.plain)
            .accessibilityHint("Joins the I2P network now")

            Button {
                onSkip()
                dismiss()
            } label: {
                Text("Not now")
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
            }
            .buttonStyle(.plain)
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(background.ignoresSafeArea())
        .preferredColorScheme(.dark)
        .presentationDetents([.large])
    }

    private func point(icon: String, title: String, body: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon)
                .font(.footnote.weight(.semibold))
                .foregroundStyle(accent)
                .frame(width: 30, height: 30)
                .background(accent.opacity(0.14), in: RoundedRectangle(cornerRadius: 9))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.subheadline.weight(.semibold))
                Text(body)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .accessibilityElement(children: .combine)
    }
}
