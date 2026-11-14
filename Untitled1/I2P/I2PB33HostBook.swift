//
//  I2PB33HostBook.swift
//  The b33 host book: the blinded destinations this router knows about, the
//  credentials it holds for them (live encrypted-LeaseSet2 SAM sessions), and
//  each host's last lease resolution.
//
//  A row is resolvable when the router holds the destination credentials the
//  blinding derivation needs (the Ed25519 seed plus the ECIES X25519 private
//  key), and opaque when it is a stranger host whose encrypted inner body stays
//  sealed. Resolution itself rides the blinded netdb key
//  (I2PNetworkDatabase.lookupEncryptedLeaseSet2), so the unblinded destination
//  hash never goes out on the network.
//

import Foundation
import Combine

// MARK: - Tracked host

/// One tracked b33 host: its blinded address, whether the router currently
/// holds the credentials to unlock it, and the outcome of the last successful
/// resolution.
struct I2PB33HostEntry: Codable, Identifiable, Equatable {
    /// The spec's 57-character b33 address.
    let address: String
    /// True when the router holds the destination credentials that unlock the
    /// encrypted LeaseSet2 (a live encrypted-publication SAM session).
    var credentialled: Bool
    /// Live leases the last successful resolution returned.
    var leaseCount: Int
    /// When the last successful resolution ran (nil until one succeeds).
    var lastResolvedAt: Date?

    var id: String { address }

    /// The monospaced prefix the host book shows, e.g. "bma2ijjduo3cey…".
    var displayPrefix: String { Self.displayPrefix(address) }

    static func displayPrefix(_ address: String) -> String {
        guard address.count > 14 else { return address }
        return "\(address.prefix(13))…"
    }
}

/// Counts for the host book's summary card.
struct I2PB33HostBookSummary {
    let resolvable: Int
    let opaque: Int
    let tracked: Int
}

// MARK: - Host book

/// The host book: merges the hosts whose credentials the router holds with the
/// ones the user pasted, persists the tracked set, and re-runs the blinding
/// lookup on demand. Every mutation is driven from the main thread (SwiftUI
/// actions and `MainActor.run` after a lookup), so the published state stays
/// consistent with the view.
final class I2PB33HostBook: ObservableObject {
    static let defaultsKey = "i2p.b33.hosts"

    @Published private(set) var entries: [I2PB33HostEntry] = []
    /// Addresses whose blinding lookup is in flight.
    @Published private(set) var resolving: Set<String> = []
    /// Per-host resolution failures (the row's inline diagnostic).
    @Published private(set) var failures: [String: String] = [:]
    /// Set when a pasted address cannot be tracked (bad checksum, duplicate).
    @Published var addFailure: String?

    private let defaults: UserDefaults
    private let storageKey: String
    /// Live hosts whose credentials this router holds, keyed by b33 address.
    private let credentialledHosts: () -> [String: I2PB33Credentials]
    /// Runs the blinded lookup for one credential set and returns the number of
    /// live leases it resolved, or nil when no encrypted LeaseSet2 came back.
    private let lookup: (I2PB33Credentials) async -> Int?

    init(defaults: UserDefaults = .standard,
         storageKey: String = I2PB33HostBook.defaultsKey,
         credentialledHosts: @escaping () -> [String: I2PB33Credentials],
         lookup: @escaping (I2PB33Credentials) async -> Int?) {
        self.defaults = defaults
        self.storageKey = storageKey
        self.credentialledHosts = credentialledHosts
        self.lookup = lookup
        self.entries = Self.load(defaults: defaults, key: storageKey)
    }

    /// Summary counts for the header card.
    var summary: I2PB33HostBookSummary {
        let resolvable = entries.filter(\.credentialled).count
        return I2PB33HostBookSummary(resolvable: resolvable,
                                     opaque: entries.count - resolvable,
                                     tracked: entries.count)
    }

    /// The credentials that unlock a host, when the router holds them.
    func credentials(for address: String) -> I2PB33Credentials? {
        credentialledHosts()[address]
    }

    /// Merges live credentialled hosts into the tracked set and re-reads the
    /// resolvable/opaque state of every existing entry.
    func refresh() {
        let live = credentialledHosts()
        var updated = entries
        for index in updated.indices {
            updated[index].credentialled = live[updated[index].address] != nil
        }
        let known = Set(updated.map(\.address))
        let fresh = live.keys
            .filter { !known.contains($0) }
            .sorted()
            .map { I2PB33HostEntry(address: $0, credentialled: true,
                                   leaseCount: 0, lastResolvedAt: nil) }
        entries = fresh + updated
        persist()
    }

    /// Tracks a pasted destination: accepts the 57-character b33 address with
    /// an optional "b33:" prefix, validates it through the b33 codec (checksum
    /// and blinded key), and records it. Returns false with `addFailure` set
    /// when the address is malformed or already tracked.
    @discardableResult
    func track(_ pasted: String) -> Bool {
        var candidate = pasted
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        if candidate.hasPrefix("b33:") {
            candidate = String(candidate.dropFirst(4))
                .trimmingCharacters(in: .whitespacesAndNewlines)
        }
        guard !candidate.isEmpty else {
            addFailure = "Paste a b33 address to track it."
            return false
        }
        guard I2PB33Blinding.b33Decode(candidate) != nil else {
            addFailure = "That is not a b33 address — its checksum or blinded key does not decode."
            return false
        }
        guard !entries.contains(where: { $0.address == candidate }) else {
            addFailure = "That host is already in the book."
            return false
        }
        let credentialled = credentialledHosts()[candidate] != nil
        entries.insert(I2PB33HostEntry(address: candidate,
                                       credentialled: credentialled,
                                       leaseCount: 0,
                                       lastResolvedAt: nil),
                       at: 0)
        addFailure = nil
        persist()
        return true
    }

    /// Drops a host from the book.
    func forget(_ address: String) {
        entries.removeAll { $0.address == address }
        failures[address] = nil
        resolving.remove(address)
        persist()
    }

    /// Re-runs the blinding lookup for one host and refreshes its row inline.
    /// Credentialled hosts resolve under their blinded netdb key; a host whose
    /// credentials the router no longer holds (and any stranger host) fails
    /// closed without touching the network. A failed lookup keeps the last
    /// successful reading and surfaces the failure in the row.
    func resolveNow(_ address: String) async {
        guard !resolving.contains(address) else { return }
        guard let credentials = credentials(for: address) else {
            failures[address] = "No credentials held — this host's encrypted body stays opaque."
            return
        }
        resolving.insert(address)
        failures[address] = nil
        let lookup = self.lookup
        let count = await lookup(credentials)
        await MainActor.run {
            self.resolving.remove(address)
            guard let index = self.entries.firstIndex(where: { $0.address == address }) else { return }
            if let count {
                self.entries[index].leaseCount = count
                self.entries[index].lastResolvedAt = Date()
                self.failures[address] = nil
            } else {
                self.failures[address] = "No encrypted LeaseSet2 for this host at any floodfill."
            }
            self.persist()
        }
    }

    // MARK: Persistence

    private func persist() {
        guard let data = try? JSONEncoder().encode(entries) else { return }
        defaults.set(data, forKey: storageKey)
    }

    private static func load(defaults: UserDefaults, key: String) -> [I2PB33HostEntry] {
        guard let data = defaults.data(forKey: key),
              let decoded = try? JSONDecoder().decode([I2PB33HostEntry].self, from: data) else {
            return []
        }
        return decoded
    }
}

// MARK: - Self-test suite (host book)

enum I2PB33HostBookSelfTest {
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

        await run("b33 host book · paste validation and persistence") {
            let seed = I2PCrypto.generateEd25519Seed()
            let x25519 = I2PCrypto.generateX25519KeyPair()
            let address = try I2PB33Blinding.blind(
                destinationSeed: seed,
                encryptionPublicKey: x25519.publicKey).b33Address
            let (defaults, key) = makeDefaults("track")
            let book = I2PB33HostBook(defaults: defaults, storageKey: key,
                                      credentialledHosts: { [:] },
                                      lookup: { _ in nil })
            // A pasted address (whitespace, "b33:" prefix, uppercase) tracks.
            guard book.track("  b33:\(address.uppercased()) ") else {
                throw I2PWireError.invalidFormat
            }
            guard book.entries.count == 1,
                  let entry = book.entries.first,
                  entry.address == address,
                  entry.credentialled == false,
                  entry.leaseCount == 0,
                  entry.lastResolvedAt == nil else {
                throw I2PWireError.invalidFormat
            }
            // The tracked set survives a relaunch.
            let reopened = I2PB33HostBook(defaults: defaults, storageKey: key,
                                          credentialledHosts: { [:] },
                                          lookup: { _ in nil })
            guard reopened.entries == book.entries else { throw I2PWireError.invalidFormat }
            // A duplicate is refused.
            guard reopened.track(address) == false, reopened.addFailure != nil else {
                throw I2PWireError.invalidFormat
            }
            // A corrupted checksum and a non-b33 string are refused.
            var tampered = Array(address)
            let original = tampered[2]
            let replacement = I2PB33Blinding.b33ChecksumSecond.first { $0 != original } ?? "a"
            tampered[2] = replacement
            guard reopened.track(String(tampered)) == false,
                  reopened.track("not-a-b33-address") == false,
                  reopened.entries.count == 1 else {
                throw I2PWireError.invalidSignature
            }
            defaults.removePersistentDomain(forName: suiteName("track"))
            return "pasted b33 tracked and persisted; duplicate, bad checksum and non-b33 input refused"
        }

        await run("b33 host book · credentialled hosts merge as resolvable") {
            let credentials = sampleCredentials()
            let address = try b33Address(for: credentials)
            let (defaults, key) = makeDefaults("merge")
            // Pasted while no session holds its credentials…
            var live: [String: I2PB33Credentials] = [:]
            let book = I2PB33HostBook(defaults: defaults, storageKey: key,
                                      credentialledHosts: { live },
                                      lookup: { _ in nil })
            book.track(address)
            guard book.entries.first?.credentialled == false else {
                throw I2PWireError.invalidFormat
            }
            // …then observed with live credentials: the refresh marks it
            // resolvable instead of leaving a duplicate stranger row.
            live[address] = credentials
            book.refresh()
            guard let entry = book.entries.first,
                  entry.address == address,
                  entry.credentialled,
                  book.summary.resolvable == 1,
                  book.summary.opaque == 0,
                  book.summary.tracked == 1 else {
                throw I2PWireError.invalidFormat
            }
            // A host whose session goes away flips back to opaque without
            // losing its tracked reading.
            live = [:]
            let after = I2PB33HostBook(defaults: defaults, storageKey: key,
                                       credentialledHosts: { live },
                                       lookup: { _ in nil })
            after.refresh()
            guard after.entries.count == 1,
                  after.entries[0].credentialled == false else {
                throw I2PWireError.invalidFormat
            }
            defaults.removePersistentDomain(forName: suiteName("merge"))
            return "live credentials mark the host resolvable; a departed session flips it back to opaque"
        }

        await run("b33 host book · Resolve now refreshes the row inline") {
            let credentials = sampleCredentials()
            let address = try b33Address(for: credentials)
            let (defaults, key) = makeDefaults("resolve")
            var leases: Int? = 3
            let book = I2PB33HostBook(defaults: defaults, storageKey: key,
                                      credentialledHosts: { [address: credentials] },
                                      lookup: { _ in leases })
            book.track(address)
            book.refresh()
            await book.resolveNow(address)
            guard let resolved = book.entries.first,
                  resolved.leaseCount == 3,
                  resolved.lastResolvedAt != nil,
                  book.failures[address] == nil,
                  book.resolving.isEmpty else {
                throw I2PWireError.invalidFormat
            }
            // The reading persists across a relaunch.
            let reopened = I2PB33HostBook(defaults: defaults, storageKey: key,
                                          credentialledHosts: { [address: credentials] },
                                          lookup: { _ in leases })
            guard reopened.entries.first?.leaseCount == 3,
                  reopened.entries.first?.lastResolvedAt != nil else {
                throw I2PWireError.invalidFormat
            }
            // A failed lookup keeps the last successful reading and surfaces
            // the failure inline.
            leases = nil
            await reopened.resolveNow(address)
            guard let kept = reopened.entries.first,
                  kept.leaseCount == 3,
                  kept.lastResolvedAt != nil,
                  reopened.failures[address] != nil,
                  reopened.resolving.isEmpty else {
                throw I2PWireError.invalidFormat
            }
            // A stranger host never reaches the network: no credentials, no
            // lookup, and the row says why.
            let strangerAddress = try b33Address(for: sampleCredentials())
            reopened.track(strangerAddress)
            await reopened.resolveNow(strangerAddress)
            guard reopened.failures[strangerAddress] != nil,
                  reopened.entries.first(where: { $0.address == strangerAddress })?.leaseCount == 0 else {
                throw I2PWireError.invalidFormat
            }
            defaults.removePersistentDomain(forName: suiteName("resolve"))
            return "row refreshed to 3 leases; failed lookup kept the reading; stranger host failed closed"
        }

        return results
    }

    // MARK: Helpers

    private static func suiteName(_ label: String) -> String {
        "i2p.b33.hostbook.selfTest.\(label)"
    }

    private static func makeDefaults(_ label: String) -> (UserDefaults, String) {
        let suite = suiteName(label)
        let defaults = UserDefaults(suiteName: suite) ?? .standard
        defaults.removePersistentDomain(forName: suite)
        return (defaults, "book-\(label)")
    }

    private static func sampleCredentials() -> I2PB33Credentials {
        let x25519 = I2PCrypto.generateX25519KeyPair()
        return I2PB33Credentials(ed25519Seed: I2PCrypto.generateEd25519Seed(),
                                 x25519PrivateKey: x25519.privateKey)
    }

    private static func b33Address(for credentials: I2PB33Credentials) throws -> String {
        guard let encryptionPublicKey = I2PB33Blinding.destinationEncryptionPublicKey(credentials) else {
            throw I2PWireError.invalidFormat
        }
        return try I2PB33Blinding.blind(destinationSeed: credentials.ed25519Seed,
                                        encryptionPublicKey: encryptionPublicKey).b33Address
    }
}
