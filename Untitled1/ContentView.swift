//
//  ContentView.swift
//  Untitled1
//

import SwiftUI

struct ContentView: View {
    @State private var results: [I2PSelfTestResult] = []
    @State private var readinessResults: [I2PSelfTestResult] = []
    @State private var stabilityResults: [I2PSelfTestResult] = []
    @State private var hardeningResults: [I2PSelfTestResult] = []
    @State private var specResults: [I2PSelfTestResult] = []
    @State private var productionResults: [I2PSelfTestResult] = []
    @State private var sizes: [(name: String, bytes: Int)] = []

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)

    var body: some View {
        TabView {
            coreTab
                .tabItem {
                    Label("I2P Core", systemImage: "cpu")
                }
            RouterDashboardView()
                .tabItem {
                    Label("Router", systemImage: "speedometer")
                }
            SAMView()
                .tabItem {
                    Label("SAM", systemImage: "terminal")
                }
            AlignmentView()
                .tabItem {
                    Label("Alignment", systemImage: "checkmark.seal")
                }
        }
        .tint(accent)
        .preferredColorScheme(.dark)
    }

    private var coreTab: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
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
                // Graceful router restart on launch (and on foreground, via
                // the app's scene-phase handler).
                I2PRouterAppContext.shared.resumeAfterBackground()
                if results.isEmpty { refresh() }
            }
        }
    }

    private func refresh() {
        sizes = I2PSelfTest.sampleByteSizes()
        Task {
            self.results = await I2PSelfTest.runAll()
        }
    }

    /// The live mainnet suite runs explicitly (it performs real network
    /// exchanges with reseed servers and floodfill routers), never on launch.
    private func runMainnetAudit() {
        Task {
            let fresh = await I2PMainnetVerification.runAll()
            await MainActor.run { results = fresh }
        }
    }

    /// The production readiness audit runs the existing compliance machinery
    /// plus dedicated readiness probes; it performs no mainnet traffic.
    private func runReadinessAudit() {
        Task {
            let fresh = await I2PReadinessAudit.runAll()
            await MainActor.run { readinessResults = fresh }
        }
    }

    private var readinessCard: some View {
        card(title: "Production readiness") {
            Button {
                runReadinessAudit()
            } label: {
                Label("Run readiness audit", systemImage: "stethoscope")
                    .font(.subheadline.weight(.semibold))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .background(accent.opacity(0.15), in: RoundedRectangle(cornerRadius: 12))
            }
            .buttonStyle(.plain)
            .tint(accent)

            if !readinessResults.isEmpty {
                let passed = readinessResults.filter(\.passed).count
                Text(passed == readinessResults.count
                     ? "\(passed) of \(readinessResults.count) checks passed"
                     : "\(passed) of \(readinessResults.count) checks passed — findings below")
                    .font(.footnote.weight(.medium))
                    .foregroundStyle(passed == readinessResults.count ? Color.green : Color.orange)
                    .frame(maxWidth: .infinity, alignment: .leading)

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

    /// The systematic crash-safety audit: every checklist category from the
    /// crash-debugging framework is exercised by an executable probe. No
    /// mainnet traffic involved.
    private func runStabilityAudit() {
        Task {
            let fresh = await I2PStabilityAudit.runAll()
            await MainActor.run { stabilityResults = fresh }
        }
    }

    /// The defensive-hardening audit probes every dimension of the hardening
    /// checklist against the live mechanisms. No mainnet traffic involved.
    private func runHardeningAudit() {
        Task {
            let fresh = await I2PHardeningAudit.runAll()
            await MainActor.run { hardeningResults = fresh }
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
                Text(passed == hardeningResults.count
                     ? "\(passed) of \(hardeningResults.count) probes passed — defensive posture verified"
                     : "\(passed) of \(hardeningResults.count) probes passed — findings below")
                    .font(.footnote.weight(.medium))
                    .foregroundStyle(passed == hardeningResults.count ? Color.green : Color.orange)
                    .frame(maxWidth: .infinity, alignment: .leading)

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
    private func runSpecAudit() {
        Task {
            let fresh = await I2PSpecConformanceAudit.runAll()
            await MainActor.run { specResults = fresh }
        }
    }

    private var specCard: some View {
        card(title: "Spec conformance") {
            Button {
                runSpecAudit()
            } label: {
                Label("Run spec conformance audit", systemImage: "checkmark.seal.fill")
                    .font(.subheadline.weight(.semibold))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .background(accent.opacity(0.15), in: RoundedRectangle(cornerRadius: 12))
            }
            .buttonStyle(.plain)
            .tint(accent)

            if !specResults.isEmpty {
                let passed = specResults.filter(\.passed).count
                Text(passed == specResults.count
                     ? "\(passed) of \(specResults.count) probes passed — official-spec checklist verified"
                     : "\(passed) of \(specResults.count) probes passed — findings below")
                    .font(.footnote.weight(.medium))
                    .foregroundStyle(passed == specResults.count ? Color.green : Color.orange)
                    .frame(maxWidth: .infinity, alignment: .leading)

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
        Task {
            let fresh = await I2PProductionAudit.runAll()
            await MainActor.run { productionResults = fresh }
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
                Text(passed == productionResults.count
                     ? "\(passed) of \(productionResults.count) checklist sections verified — production readiness closed"
                     : "\(passed) of \(productionResults.count) sections verified — findings below")
                    .font(.footnote.weight(.medium))
                    .foregroundStyle(passed == productionResults.count ? Color.green : Color.orange)
                    .frame(maxWidth: .infinity, alignment: .leading)

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

                Text("Transport handshakes run end-to-end over real Noise chains and UDP sockets; RFC known-answer vectors are exact; the ML-KEM hybrid leg (FIPS 203) is remediated in with dual-leg KDF binding.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var stabilityCard: some View {
        card(title: "Crash & stability audit") {
            Button {
                runStabilityAudit()
            } label: {
                Label("Run stability audit", systemImage: "checkmark.shield")
                    .font(.subheadline.weight(.semibold))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .background(accent.opacity(0.15), in: RoundedRectangle(cornerRadius: 12))
            }
            .buttonStyle(.plain)
            .tint(accent)

            if !stabilityResults.isEmpty {
                let passed = stabilityResults.filter(\.passed).count
                Text(passed == stabilityResults.count
                     ? "\(passed) of \(stabilityResults.count) probes passed — every crash checklist category ran clean"
                     : "\(passed) of \(stabilityResults.count) probes passed — findings below")
                    .font(.footnote.weight(.medium))
                    .foregroundStyle(passed == stabilityResults.count ? Color.green : Color.orange)
                    .frame(maxWidth: .infinity, alignment: .leading)

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
                Text("Encoding sample structures…")
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
                Label("Run mainnet audit (live network)", systemImage: "antenna.radiowaves.left.and.right")
                    .font(.subheadline.weight(.semibold))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .background(accent.opacity(0.12), in: RoundedRectangle(cornerRadius: 12))
            }
            .buttonStyle(.plain)
            .tint(accent)

            if !results.isEmpty {
                let passed = results.filter(\.passed).count
                Text(passed == results.count
                     ? "\(passed) of \(results.count) tests passed"
                     : "\(passed) of \(results.count) passed — failures below")
                    .font(.footnote.weight(.medium))
                    .foregroundStyle(passed == results.count ? Color.green : Color.orange)
                    .frame(maxWidth: .infinity, alignment: .leading)

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

#Preview {
    ContentView()
}