//
//  EepsiteBrowserView.swift
//  The in-app eepsite browser: an address bar for .i2p / b32 / b33 hosts, a
//  staged loading surface, inline diagnostics that name the failing stage, and
//  a native reader view for the fetched page.
//

import SwiftUI

// MARK: - Model

/// The browser screen's state: the address in the bar, the current load, the
/// stage trail and the rendered page. All published state is mutated on the
/// main thread; the client work runs off it.
final class I2PEepsiteBrowserModel: ObservableObject {
    enum Phase {
        case idle
        case loading
        case loaded(I2PEepsitePage)
        case failed(I2PEepsiteFailure)
    }

    @Published var addressText = ""
    @Published private(set) var phase: Phase = .idle
    @Published private(set) var currentStage: I2PEepsiteStage?
    @Published private(set) var trail: [I2PEepsiteStage] = []
    @Published private(set) var suggestions: [String] = []

    private let client: I2PEepsiteClient
    private let suggestionProvider: () -> [String]
    private var task: Task<Void, Never>?

    init(client: I2PEepsiteClient, suggestions: @escaping () -> [String]) {
        self.client = client
        self.suggestionProvider = suggestions
    }

    var isLoading: Bool {
        if case .loading = phase { return true }
        return false
    }

    func refreshSuggestions() {
        let fresh = suggestionProvider()
        if fresh != suggestions { suggestions = fresh }
    }

    /// Loads the address in the bar (or the one passed in, for links).
    func load(_ raw: String? = nil) {
        let input = (raw ?? addressText).trimmingCharacters(in: .whitespacesAndNewlines)
        guard !input.isEmpty else { return }
        addressText = input
        task?.cancel()
        phase = .loading
        currentStage = .address
        trail = []
        let client = self.client
        task = Task { [weak self] in
            do {
                let page = try await client.load(input) { stage in
                    Task { @MainActor [weak self] in
                        self?.apply(stage)
                    }
                }
                await MainActor.run { [weak self] in
                    guard let self else { return }
                    self.phase = .loaded(page)
                    self.currentStage = nil
                    self.trail = []
                    self.task = nil
                }
            } catch is CancellationError {
                // A newer load (or a cancel) owns the state now.
            } catch let failure as I2PEepsiteFailure {
                await MainActor.run { [weak self] in
                    guard let self else { return }
                    self.phase = .failed(failure)
                    self.currentStage = nil
                    self.task = nil
                }
            } catch {
                await MainActor.run { [weak self] in
                    guard let self else { return }
                    self.phase = .failed(I2PEepsiteFailure(
                        stage: .response,
                        message: "The load failed unexpectedly: \(error)"))
                    self.currentStage = nil
                    self.task = nil
                }
            }
        }
    }

    func cancel() {
        task?.cancel()
        task = nil
        phase = .idle
        currentStage = nil
        trail = []
    }

    /// Advances the stage trail. Main thread only.
    private func apply(_ stage: I2PEepsiteStage) {
        guard case .loading = phase else { return }
        if let current = currentStage, current != stage, !trail.contains(current) {
            trail.append(current)
        }
        currentStage = stage
    }
}

// MARK: - Screen

struct EepsiteBrowserView: View {
    @StateObject private var model = I2PEepsiteBrowserModel.live()
    @FocusState private var addressFocused: Bool

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                addressBar
                switch model.phase {
                case .idle:
                    emptyStateCard
                case .loading:
                    loadingCard
                case .failed(let failure):
                    failureCard(failure)
                case .loaded(let page):
                    pageCard(page)
                }
                footnote
            }
            .padding(.horizontal, 16)
            .padding(.top, 4)
            .padding(.bottom, 24)
        }
        .scrollDismissesKeyboard(.immediately)
        .background(background.ignoresSafeArea())
        .navigationTitle("Eepsite Browser")
        .navigationBarTitleDisplayMode(.large)
        .preferredColorScheme(.dark)
        .onAppear { model.refreshSuggestions() }
    }

    // MARK: Address bar

    private var addressBar: some View {
        HStack(spacing: 10) {
            Image(systemName: "globe")
                .font(.subheadline)
                .foregroundStyle(accent)
            TextField("site.i2p · b32 host · b33 address", text: $model.addressText)
                .font(.system(.footnote, design: .monospaced))
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .keyboardType(.URL)
                .submitLabel(.go)
                .focused($addressFocused)
                .onSubmit { model.load() }
            if model.isLoading {
                Button {
                    model.cancel()
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Stop loading")
            } else if !model.addressText.isEmpty {
                Button {
                    model.addressText = ""
                } label: {
                    Image(systemName: "xmark.circle")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Clear address")
            }
            Button {
                addressFocused = false
                model.load()
            } label: {
                Image(systemName: "arrow.right.circle.fill")
                    .font(.title3)
                    .foregroundStyle(model.addressText.isEmpty ? Color.secondary : accent)
            }
            .buttonStyle(.plain)
            .disabled(model.addressText.isEmpty || model.isLoading)
            .accessibilityLabel("Load page")
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
        .background(accent.opacity(0.10), in: RoundedRectangle(cornerRadius: 16))
        .overlay(
            RoundedRectangle(cornerRadius: 16)
                .strokeBorder(accent.opacity(0.28), lineWidth: 1)
        )
    }

    // MARK: Loading

    private var loadingCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                ProgressView()
                    .tint(accent)
                VStack(alignment: .leading, spacing: 2) {
                    Text(model.currentStage?.summary ?? "Working…")
                        .font(.footnote.weight(.medium))
                        .fixedSize(horizontal: false, vertical: true)
                    Text(model.addressText)
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                Spacer(minLength: 4)
            }
            stageTrail
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    private var stageTrail: some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(model.trail, id: \.self) { stage in
                HStack(spacing: 8) {
                    Image(systemName: "checkmark.circle.fill")
                        .font(.caption2)
                        .foregroundStyle(accent)
                    Text(stage.completedSummary)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
            if let current = model.currentStage {
                HStack(spacing: 8) {
                    ProgressView()
                        .controlSize(.mini)
                        .tint(accent)
                    Text(current.summary)
                        .font(.caption.weight(.medium))
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    // MARK: Failure

    private func failureCard(_ failure: I2PEepsiteFailure) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Couldn't load the page", systemImage: "exclamationmark.triangle.fill")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(.orange)

            HStack(spacing: 8) {
                Text(failure.stage.rawValue)
                    .font(.caption2.weight(.bold))
                    .foregroundStyle(.orange)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .background(Color.orange.opacity(0.15), in: Capsule())
                Text("failing stage")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }

            Text(failure.message)
                .font(.footnote)
                .foregroundStyle(.primary)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)

            if !model.trail.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(model.trail, id: \.self) { stage in
                        HStack(spacing: 8) {
                            Image(systemName: "checkmark.circle")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                            Text(stage.completedSummary)
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }

            Button {
                model.load(model.addressText)
            } label: {
                Label("Try again", systemImage: "arrow.clockwise")
                    .font(.subheadline.weight(.semibold))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .background(accent.opacity(0.15), in: RoundedRectangle(cornerRadius: 12))
            }
            .buttonStyle(.plain)
            .tint(accent)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    // MARK: Page

    private func pageCard(_ page: I2PEepsitePage) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            pageHeader(page)
            if let note = page.note {
                inlineNote(note)
            }
            VStack(alignment: .leading, spacing: 14) {
                if page.blocks.isEmpty {
                    Text("The page carried no readable text.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(page.blocks) { block in
                        blockView(block)
                    }
                }
            }
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
        .environment(\.openURL, OpenURLAction { url in
            model.load(url.absoluteString)
            return .handled
        })
    }

    private func pageHeader(_ page: I2PEepsitePage) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Image(systemName: "globe")
                    .font(.caption)
                    .foregroundStyle(accent)
                Text(page.address)
                    .font(.system(.caption, design: .monospaced).weight(.medium))
                    .foregroundStyle(Color.primary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer(minLength: 6)
                Text("HTTP \(page.statusCode)")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            Text(metaLine(page))
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.horizontal, 18)
        .padding(.top, 16)
        .padding(.bottom, page.note == nil ? 0 : 10)
    }

    private func metaLine(_ page: I2PEepsitePage) -> String {
        let leases = page.leaseCount == 1 ? "1 lease" : "\(page.leaseCount) leases"
        let size = byteText(page.byteCount)
        let elapsed = String(format: "%.1fs", page.elapsed)
        return "\(leases) · \(page.route.rawValue) · \(size) · \(elapsed)"
    }

    private func inlineNote(_ note: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "exclamationmark.circle")
                .font(.caption)
                .foregroundStyle(.orange)
            Text(note)
                .font(.caption2)
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.horizontal, 18)
        .padding(.top, 10)
    }

    @ViewBuilder
    private func blockView(_ block: I2PReadBlock) -> some View {
        switch block.kind {
        case .title:
            Text(block.text)
                .font(.largeTitle.weight(.bold))
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
        case .heading(let level):
            Text(block.text)
                .font(level <= 2 ? .title2.weight(.semibold) : .title3.weight(.semibold))
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 2)
                .textSelection(.enabled)
        case .paragraph:
            Text(block.text)
                .font(.body)
                .lineSpacing(4)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
        case .bullet:
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text("•")
                    .font(.body.weight(.bold))
                    .foregroundStyle(accent)
                Text(block.text)
                    .font(.body)
                    .lineSpacing(3)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
            }
            .padding(.leading, 2)
        case .quote:
            HStack(alignment: .top, spacing: 10) {
                RoundedRectangle(cornerRadius: 2)
                    .fill(accent.opacity(0.6))
                    .frame(width: 3)
                Text(block.text)
                    .font(.callout)
                    .italic()
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
            }
        case .code:
            Text(block.text)
                .font(.system(.callout, design: .monospaced))
                .fixedSize(horizontal: false, vertical: true)
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.black.opacity(0.25), in: RoundedRectangle(cornerRadius: 10))
                .textSelection(.enabled)
        case .rule:
            Rectangle()
                .fill(Color.white.opacity(0.12))
                .frame(height: 1)
                .padding(.vertical, 2)
        }
    }

    private func byteText(_ bytes: Int) -> String {
        if bytes >= 1_048_576 { return String(format: "%.1f MB", Double(bytes) / 1_048_576) }
        if bytes >= 1_024 { return String(format: "%.1f KB", Double(bytes) / 1_024) }
        return "\(bytes) B"
    }

    // MARK: Empty state & footnote

    private var emptyStateCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Browse an eepsite", systemImage: "globe")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(accent)
            Text("Type a .i2p hostname (b32), a b33 address or a base64 destination. The destination is resolved through this router's network database — plain LeaseSets, LeaseSet2, or the blinded key for credentialled b33 hosts — and the page is fetched as a garlic'd stream through the browser's outbound tunnel pool.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if !model.suggestions.isEmpty {
                Text("Credentialled b33 hosts")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .textCase(.uppercase)
                    .padding(.top, 2)
                ForEach(model.suggestions, id: \.self) { address in
                    Button {
                        model.load(address)
                    } label: {
                        HStack(spacing: 8) {
                            Image(systemName: "lock.shield")
                                .font(.caption2)
                                .foregroundStyle(accent)
                            Text(address)
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundStyle(.primary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 8)
                        .background(accent.opacity(0.12), in: RoundedRectangle(cornerRadius: 10))
                    }
                    .buttonStyle(.plain)
                }
            }
            Text("The router must be running with live peers before the tunnel pool can fill.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    private var footnote: some View {
        Text("Pages travel as garlic'd streams over the router's own outbound tunnels and the browser publishes its leases so replies can come back — the eepsite only ever learns a destination hash.")
            .font(.caption2)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 2)
    }
}

// MARK: - Live wiring

extension I2PEepsiteBrowserModel {
    /// The browser bound to the running router: the eepsite client destination
    /// the app context owns, and the b33 hosts its SAM sessions hold
    /// credentials for.
    static func live() -> I2PEepsiteBrowserModel {
        let context = I2PRouterAppContext.shared
        return I2PEepsiteBrowserModel(
            client: context.eepsiteBrowser,
            suggestions: {
                context.samServer.b33Hosts().map(\.address)
            })
    }
}
