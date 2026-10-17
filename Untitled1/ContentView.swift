//
//  ContentView.swift
//  Untitled1
//

import SwiftUI

struct ContentView: View {
    @State private var results: [I2PSelfTestResult] = []
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
                }
                .padding(.horizontal, 16)
                .padding(.top, 4)
                .padding(.bottom, 24)
            }
            .background(background.ignoresSafeArea())
            .navigationTitle("I2P Core")
            .navigationBarTitleDisplayMode(.large)
            .onAppear {
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