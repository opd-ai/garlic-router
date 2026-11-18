//
//  I2PSavedHostsRefresh.swift
//  One "refresh all" pass over the saved hosts: every bookmark is re-fetched
//  through the browser's own client, one at a time, and each row's last visit
//  and result are updated as that fetch ends.
//

import Foundation
import Combine

// MARK: - Refresh pass

/// Drives the Saved hosts screen's refresh pass.
///
/// The pass walks the list in its own order and re-fetches one host at a time,
/// so the router never carries more than one bookmarked page at once. Every
/// host goes through the browser's client, which means a b33 address takes the
/// same blinding path the browser itself uses and a .i2p name the same
/// address-book and netdb lookup — a row therefore records exactly what a
/// visit in the browser would have recorded.
///
/// The published state is only mutated on the main thread (the screen's own
/// actions and the pass's main-actor hops); the fetches run off it.
final class I2PSavedHostsRefreshModel: ObservableObject {
    /// Where the pass is.
    enum Phase: Equatable {
        /// No pass has run since the screen opened.
        case idle
        /// A pass is walking the list: `completed` hosts are done and
        /// `currentHost` is in flight.
        case running
        /// The pass reached the end of the list.
        case finished(ok: Int, failed: Int)
        /// The pass was stopped (or the screen dismissed) part way through.
        case stopped(completed: Int, total: Int)
    }

    /// Re-fetches one host the way the browser does. Throwing
    /// `I2PEepsiteFailure` records that attempt's reason; throwing
    /// `CancellationError` abandons the pass; any other error counts as a
    /// connection failure.
    typealias Probe = (String) async throws -> Void

    @Published private(set) var phase: Phase = .idle
    /// How many hosts this pass walks: the list as it stood when it started.
    @Published private(set) var total = 0
    /// How many hosts have finished; their rows are already updated.
    @Published private(set) var completed = 0
    /// The host being fetched right now, nil when nothing is in flight.
    @Published private(set) var currentHost: String?

    private let store: I2PSavedHostsStore
    private let probe: Probe
    private var task: Task<Void, Never>?
    /// Bumped by every pass and by every stop, so a fetch that was already
    /// past its last cancellation check cannot write into a newer pass's state.
    private var generation = 0

    init(store: I2PSavedHostsStore = .shared, probe: @escaping Probe) {
        self.store = store
        self.probe = probe
    }

    var isRunning: Bool { phase == .running }

    /// 0…1 of the list walked, for the progress line's bar.
    var fraction: Double {
        guard total > 0 else { return 0 }
        return min(1, Double(completed) / Double(total))
    }

    /// The progress line above the list: what the pass is doing now, how the
    /// last one ended, or that it was stopped. Nil before the first pass.
    var progressLine: String? {
        switch phase {
        case .idle:
            return nil
        case .running:
            guard total > 0 else { return nil }
            let index = min(completed + 1, total)
            guard let currentHost else { return "Refreshing \(index) of \(total)" }
            return "Refreshing \(index) of \(total) · \(currentHost)"
        case .finished(let ok, let failed):
            let hosts = total == 1 ? "1 host" : "\(total) hosts"
            if failed == 0 { return "Refreshed \(hosts) · all ok" }
            if ok == 0 { return "Refreshed \(hosts) · all failed" }
            return "Refreshed \(hosts) · \(ok) ok · \(failed) failed"
        case .stopped(let completed, let total):
            let hosts = total == 1 ? "1 host" : "\(total) hosts"
            return "Stopped after \(completed) of \(hosts)"
        }
    }

    // MARK: Starting and stopping

    /// Starts a pass over every saved host, in list order. Returns false when
    /// there is nothing to refresh or a pass is already running.
    @discardableResult
    func start() -> Bool {
        guard !isRunning else { return false }
        let hosts = store.entries.map(\.host)
        guard !hosts.isEmpty else { return false }

        generation &+= 1
        let token = generation
        total = hosts.count
        completed = 0
        currentHost = hosts[0]
        phase = .running

        let probe = self.probe
        let store = self.store
        task = Task { [weak self] in
            guard let self else { return }
            var ok = 0
            var failed = 0

            for (offset, host) in hosts.enumerated() {
                if Task.isCancelled { return }
                await MainActor.run {
                    guard self.generation == token else { return }
                    self.completed = offset
                    self.currentHost = host
                }
                if Task.isCancelled { return }

                let result: I2PSavedHostFetchResult
                do {
                    try await probe(host)
                    result = .ok
                } catch is CancellationError {
                    // A stop (or the screen closing) owns the state now.
                    return
                } catch let failure as I2PEepsiteFailure {
                    result = failure.savedHostResult
                } catch {
                    result = .connectionFailed
                }
                if Task.isCancelled { return }

                if result == .ok { ok += 1 } else { failed += 1 }
                await MainActor.run {
                    guard self.generation == token else { return }
                    store.recordFetch(host, result: result)
                    self.completed = offset + 1
                }
            }

            // Captured into locals before the actor hop: a mutable var captured
            // by a concurrently-executing closure is an error in Swift 6.
            let succeeded = ok
            let failedCount = failed
            await MainActor.run {
                guard self.generation == token else { return }
                self.phase = .finished(ok: succeeded, failed: failedCount)
                self.currentHost = nil
                self.task = nil
            }
        }
        return true
    }

    /// Ends the pass where it stands. The rows it already reached keep this
    /// attempt's result; the hosts it never got to are left as they were.
    func stop() {
        guard isRunning else { return }
        generation &+= 1
        task?.cancel()
        task = nil
        phase = .stopped(completed: completed, total: total)
        currentHost = nil
    }
}

// MARK: - Live wiring

extension I2PSavedHostsRefreshModel {
    /// The refresh bound to the running router: every host is fetched through
    /// the browser's own client, so a b33 address goes through the blinding
    /// path the browser uses and a .i2p name through its address book. A host
    /// that fetches cleanly also replaces its kept copy, exactly as a visit in
    /// the browser does, so what stays readable offline is the last page that
    /// worked.
    static func live() -> I2PSavedHostsRefreshModel {
        let client = I2PRouterAppContext.shared.eepsiteBrowser
        let offline = I2POfflinePageStore.shared
        return I2PSavedHostsRefreshModel(store: .shared) { host in
            let page = try await client.load(host) { _ in }
            await MainActor.run {
                offline.keep(page, address: host)
            }
        }
    }
}

// MARK: - Self-test suite (refresh)

enum I2PSavedHostsRefreshSelfTest {
    static func runAll() async -> [I2PSelfTestResult] {
        var results: [I2PSelfTestResult] = []
        func run(_ name: String, _ body: () async throws -> String) async {
            do {
                let detail = try await body()
                results.append(I2PSelfTestResult(name: name, passed: true, detail: detail))
            } catch {
                results.append(I2PSelfTestResult(name: name, passed: false,
                                                 detail: String(describing: error)))
            }
        }

        await run("saved hosts refresh · re-fetches every host in list order") {
            try await walkCase()
        }

        await run("saved hosts refresh · stop ends the pass and keeps what landed") {
            try await stopCase()
        }

        return results
    }

    // MARK: Cases

    /// A pass over four hosts: one success, one resolve failure, one connection
    /// failure and an unexpected error, which counts as a connection failure.
    @MainActor
    private static func walkCase() async throws -> String {
        let (defaults, key) = makeDefaults("walk")
        defer { defaults.removePersistentDomain(forName: suiteName("walk")) }
        let store = I2PSavedHostsStore(defaults: defaults, storageKey: key)

        guard store.save("i2pwiki.i2p"),
              store.save("planet.i2p"),
              store.save("forum.i2p"),
              store.save(try b33Address()) else {
            throw I2PWireError.invalidFormat
        }
        let order = store.entries.map(\.host)
        // None of the four has been visited since it was saved.
        guard order.count == 4,
              store.entries.allSatisfy({ $0.lastVisitedAt == nil && $0.lastResult == nil }) else {
            throw I2PWireError.invalidFormat
        }
        let expected: [I2PSavedHostFetchResult] = [.ok, .resolveFailed,
                                                   .connectionFailed, .connectionFailed]

        let log = SavedHostRefreshProbeLog()
        let model = I2PSavedHostsRefreshModel(store: store) { host in
            log.append(host)
            switch order.firstIndex(of: host) ?? 0 {
            case 1:
                throw I2PEepsiteFailure(stage: .blinding, message: "self-test: no blinded entry")
            case 2:
                throw I2PEepsiteFailure(stage: .connect, message: "self-test: no stream")
            case 3:
                throw I2PWireError.trailingData
            default:
                return
            }
        }

        // An untouched model has no progress line, and an empty list is not a
        // pass: there is nothing for the button to do.
        guard model.progressLine == nil, !model.isRunning else {
            throw I2PWireError.invalidFormat
        }
        let idleEmpty = I2PSavedHostsRefreshModel(
            store: I2PSavedHostsStore(defaults: defaults, storageKey: "empty-\(key)")) { _ in }
        guard idleEmpty.start() == false, idleEmpty.progressLine == nil else {
            throw I2PWireError.invalidFormat
        }

        guard model.start(), model.total == 4, model.isRunning, model.fraction == 0 else {
            throw I2PWireError.invalidFormat
        }
        // A second pass cannot start on top of a running one.
        guard model.start() == false else { throw I2PWireError.invalidFormat }
        try await waitUntilIdle(model)

        // Every host was fetched once, in the list's own order.
        guard log.snapshot() == order else { throw I2PWireError.invalidFormat }
        guard model.phase == .finished(ok: 1, failed: 3),
              model.completed == 4, model.currentHost == nil,
              model.fraction == 1 else {
            throw I2PWireError.invalidFormat
        }
        // Hosts never visited since being saved became visits, each with this
        // attempt's own reason.
        for (index, entry) in store.entries.enumerated() {
            guard entry.lastResult == expected[index], entry.lastVisitedAt != nil else {
                throw I2PWireError.invalidFormat
            }
        }
        guard let line = model.progressLine,
              line.contains("1 ok"), line.contains("3 failed") else {
            throw I2PWireError.invalidFormat
        }
        // The readings persist exactly like a visit in the browser does.
        let reopened = I2PSavedHostsStore(defaults: defaults, storageKey: key)
        guard reopened.entries.map(\.host) == order,
              reopened.entries.contains(where: { $0.lastResult == .ok && $0.lastVisitedAt != nil }) else {
            throw I2PWireError.invalidFormat
        }
        return "walked \(order.count) hosts in list order (b33 and .i2p together), one at a time; never-visited rows became visits; ok, resolve-failed and connection-failed recorded; progress line '\(line)'"
    }

    /// A stop during the second host: the first row keeps its result, the host
    /// in flight is abandoned and the one after it is never fetched.
    @MainActor
    private static func stopCase() async throws -> String {
        let (defaults, key) = makeDefaults("stop")
        defer { defaults.removePersistentDomain(forName: suiteName("stop")) }
        let store = I2PSavedHostsStore(defaults: defaults, storageKey: key)
        guard store.save("i2pwiki.i2p"),
              store.save("planet.i2p"),
              store.save("forum.i2p") else {
            throw I2PWireError.invalidFormat
        }
        let order = store.entries.map(\.host)

        let log = SavedHostRefreshProbeLog()
        let model = I2PSavedHostsRefreshModel(store: store) { host in
            log.append(host)
            // The second host never returns on its own: only the stop can end
            // it, and the sleep is what makes the cancellation observable.
            if host == order[1] {
                try await Task.sleep(for: .seconds(30))
            }
        }

        guard model.start() else { throw I2PWireError.invalidFormat }
        let deadline = Date().addingTimeInterval(10)
        while model.currentHost != order[1] {
            guard Date() < deadline else { throw I2PWireError.invalidFormat }
            try await Task.sleep(for: .milliseconds(10))
        }
        guard model.isRunning, model.completed == 1 else { throw I2PWireError.invalidFormat }

        model.stop()
        guard !model.isRunning,
              model.phase == .stopped(completed: 1, total: 3),
              model.currentHost == nil,
              model.progressLine == "Stopped after 1 of 3 hosts" else {
            throw I2PWireError.invalidFormat
        }
        // Give the abandoned fetch room to end: it must not record a result,
        // and the host it never reached must not be touched at all.
        try await Task.sleep(for: .milliseconds(150))
        guard log.snapshot() == [order[0], order[1]] else { throw I2PWireError.invalidFormat }
        guard store.entries.count == 3,
              store.entries[0].lastResult == .ok,
              store.entries[0].lastVisitedAt != nil,
              store.entries[1].lastResult == nil,
              store.entries[2].lastResult == nil else {
            throw I2PWireError.invalidFormat
        }
        return "one row kept its result, the fetch in flight was abandoned without recording, the last host was never fetched, and the pass reported '\(model.progressLine ?? "")'"
    }

    // MARK: Helpers

    @MainActor
    private static func waitUntilIdle(_ model: I2PSavedHostsRefreshModel,
                                      timeout: TimeInterval = 15) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while model.isRunning {
            guard Date() < deadline else { throw I2PWireError.invalidFormat }
            try await Task.sleep(for: .milliseconds(10))
        }
    }

    private static func suiteName(_ label: String) -> String {
        "i2p.savedHostsRefresh.selfTest.\(label)"
    }

    private static func makeDefaults(_ label: String) -> (UserDefaults, String) {
        let suite = suiteName(label)
        let defaults = UserDefaults(suiteName: suite) ?? .standard
        defaults.removePersistentDomain(forName: suite)
        return (defaults, "saved-refresh-\(label)")
    }

    private static func b33Address() throws -> String {
        let x25519 = I2PCrypto.generateX25519KeyPair()
        return try I2PB33Blinding.blind(destinationSeed: I2PCrypto.generateEd25519Seed(),
                                        encryptionPublicKey: x25519.publicKey).b33Address
    }
}

/// The order the self-test's probe was called in, kept across the pass's
/// background task and the main-actor assertions.
private final class SavedHostRefreshProbeLog {
    private let lock = NSLock()
    private var hosts: [String] = []

    func append(_ host: String) {
        lock.lock()
        hosts.append(host)
        lock.unlock()
    }

    func snapshot() -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return hosts
    }
}
