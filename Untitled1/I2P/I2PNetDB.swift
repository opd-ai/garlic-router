//
//  I2PNetDB.swift
//  I2P Network Database: Kademlia-style floodfill model with the XOR distance
//  metric, floodfill selection and querying (3-5 floodfills), store/lookup/refresh
//  operations, bounded floodfill replication, expiration (RouterInfo ~1h, LeaseSet ~1h
//  with 10-15 min leases), persistent storage + in-memory cache, and startup
//  bootstrapping that iteratively discovers peers via DatabaseLookup. Entries are
//  only accepted after signature verification.
//

import Foundation

/// Transport abstraction for sending NetDB messages to peers.
/// The future NTCP2 transport layer implements this; tests use the loopback hub.
protocol I2PNetDBTransport: AnyObject {
    func send(to routerHash: Data, message: I2PNetDBMessage) async throws
}

/// Loopback message bus connecting NetDB instances directly (development/test transport).
final class I2PNetDBLoopbackHub {
    private var nodes: [Data: I2PNetworkDatabase] = [:]
    private let lock = NSLock()

    func add(_ node: I2PNetworkDatabase, at hash: Data) {
        lock.lock()
        defer { lock.unlock() }
        nodes[hash] = node
    }

    func remove(at hash: Data) {
        lock.lock()
        defer { lock.unlock() }
        nodes.removeValue(forKey: hash)
    }

    func deliver(to hash: Data, message: I2PNetDBMessage) {
        lock.lock()
        let node = nodes[hash]
        lock.unlock()
        guard let node else { return }
        Task { await node.handleIncoming(message) }
    }
}

final class I2PNetDBLoopbackTransport: I2PNetDBTransport {
    private unowned let hub: I2PNetDBLoopbackHub

    init(hub: I2PNetDBLoopbackHub) {
        self.hub = hub
    }

    func send(to routerHash: Data, message: I2PNetDBMessage) async throws {
        hub.deliver(to: routerHash, message: message)
    }
}

actor I2PNetworkDatabase {
    // MARK: Spec lifetimes

    /// RouterInfo entries live about one hour.
    static let routerInfoLifetime: TimeInterval = 3600
    /// LeaseSet entries live about one hour; individual leases run 10-15 minutes and
    /// the entry is kept a grace period past the last lease expiration.
    static let leaseSetLifetime: TimeInterval = 3600
    static let leaseGracePeriod: TimeInterval = 600

    /// Floodfill selection: lookups query the 3 closest known floodfills,
    /// stores publish to the closest 5.
    static let lookupFloodfillCount = 3
    static let storeFloodfillCount = 5

    /// Floodfill replication: each floodfill gossips a freshly stored entry to the
    /// next 3 floodfills farther from the key than itself, at most once per
    /// deduplication window.
    static let replicationFanout = 3
    static let replicationDedupWindow: TimeInterval = 300

    // MARK: State

    struct StoredEntry {
        let entryType: I2PDatabaseEntryType
        let key: Data
        let raw: Data
        let routerInfo: I2PRouterInfo?
        let leaseSet: I2PLeaseSet?
        let expiresAt: Date
        /// LeaseSet2-family entries (proposal 123 store types 2/3/5).
        var leaseSet2: I2PLeaseSet2? = nil

        func isExpired(_ now: Date = Date()) -> Bool {
            now >= expiresAt
        }
    }

    nonisolated let localRouterHash: Data
    private let transport: any I2PNetDBTransport
    private let storage: I2PNetDBStorage

    /// In-memory cache.
    private(set) var entries: [Data: StoredEntry] = [:]
    private(set) var knownFloodfills: Set<Data> = []
    private(set) var knownPeers: Set<Data> = []
    private var isFloodfillRouter = false
    private var ownRouterInfo: StoredEntry?
    private var ownLeaseSet: StoredEntry?
    private var lastOwnRefresh = Date.distantPast

    private var outgoingStoreTokens: Set<UInt32> = []
    private var outgoingLookupTokens: Set<UInt32> = []
    private var pendingStoreAcks: [UInt32: Int] = [:]
    private var pendingLookupResults: [Data: StoredEntry] = [:]
    /// Keys with an outstanding lookup: a direct DatabaseStore answer carries
    /// the key and no reply token, so it is matched here.
    private var pendingLookupKeys: Set<Data> = []
    private var pendingSearchReplies: [Data: [I2PDatabaseSearchReply]] = [:]
    private var recentlyReplicated: [Data: Date] = [:]
    private var recentlyEchoedTokens: [UInt32: Date] = [:]
    /// Recent inbound DatabaseStores that failed to parse or verify, as
    /// "entryType error" strings. A live run reads this to separate "no peer
    /// answered" from "an answer arrived and we rejected it".
    private(set) var storeRejections: [String] = []
    private var maintenanceTask: Task<Void, Never>?

    init(localRouterHash: Data, transport: any I2PNetDBTransport, storage: I2PNetDBStorage) {
        precondition(localRouterHash.count == 32, "router hash must be 32 bytes")
        self.localRouterHash = localRouterHash
        self.transport = transport
        self.storage = storage
        // The persisted-netdb restore used to run synchronously inside this actor
        // init — on the caller's thread, which is the MAIN thread during app launch.
        // A netdb grown by mainnet audit runs (each restored entry re-parses and
        // re-verifies its Ed25519 signature) then blocked the launch window long
        // enough for the launch watchdog to kill the process (white flash, then dead).
        // The restore now streams in asynchronously on the actor after launch.
        entries = [:]
        let storageForRestore = storage
        Task { [weak self] in
            let restored = Self.restoredEntries(from: storageForRestore)
            await self?.adoptRestored(restored)
        }
    }

    /// Adopts asynchronously restored entries onto the actor. Merges rather
    /// than replaces: live stores that arrive while the restore is running
    /// (the router is published and reachable within seconds of launch) must
    /// survive the adoption.
    ///
    /// The restored RouterInfos also re-populate the routing indexes. A router
    /// that keeps its netdb on disk (as reference routers do) boots with a full
    /// peer table, so the floodfill set — the thing every lookup, publish and
    /// dial is addressed to — must be rebuilt from the persisted identities.
    /// Without it the cache held hundreds of verified RouterInfos while
    /// `knownFloodfills` stayed empty, and every DHT operation found "no peers".
    private func adoptRestored(_ restored: [Data: StoredEntry]) {
        for (key, entry) in restored where entries[key] == nil {
            entries[key] = entry
            if let routerInfo = entry.routerInfo {
                learn(from: routerInfo)
            }
        }
    }

    // MARK: Kademlia XOR distance metric

    /// XOR distance between two router hashes (the Kademlia metric on the netdb key space).
    static func xorDistance(_ a: Data, _ b: Data) -> Data {
        precondition(a.count == 32 && b.count == 32, "XOR distance requires 32-byte hashes")
        var out = Data(count: 32)
        for i in 0..<32 {
            out[i] = a[i] ^ b[i]
        }
        return out
    }

    /// True when hash `a` is closer (by XOR distance) to the target key than hash `b`.
    static func isCloser(_ a: Data, than b: Data, to target: Data) -> Bool {
        let da = xorDistance(a, target)
        let db = xorDistance(b, target)
        for i in 0..<32 {
            if da[i] != db[i] { return da[i] < db[i] }
        }
        return false
    }

    // MARK: Floodfill selection

    /// The `count` known floodfills closest to the key, excluding ourselves.
    /// Defaults to the spec's 3 closest for lookups.
    func selectFloodfills(for key: Data, count: Int = 3) -> [Data] {
        Array(
            knownFloodfills
                .filter { $0 != localRouterHash }
                .sorted { Self.isCloser($0, than: $1, to: key) }
                .prefix(count)
        )
    }

    /// Optional transport reachability probe installed by the running router
    /// (an NTCP2/SSU2 session to this peer exists right now). A lookup consults
    /// it so a query can go out over peers we can send to immediately instead
    /// of waiting on a cold demand-dial to the closest floodfill.
    private(set) var peerIsReachable: ((Data) -> Bool)?

    /// Installs the reachability probe the running router wires to its live
    /// session table.
    func installReachabilityProbe(_ probe: @escaping (Data) -> Bool) {
        peerIsReachable = probe
    }

    /// The peers a lookup should query: the closest floodfills, plus — when the
    /// closest ones are not reachable — the nearest floodfills we do hold
    /// sessions with. All of them are queried at once, so the answer comes from
    /// whichever replies first.
    ///
    /// The reachable set is drawn from *every* known floodfill, not from the
    /// nearest few: on mainnet the floodfills closest to an arbitrary key are
    /// almost never the peers this router happens to hold sessions with, and a
    /// cold demand-dial to them can be refused outright (a peer that has gone
    /// away still looks like a known floodfill). Asking the closest peers we can
    /// actually reach keeps the round trip alive.
    private func lookupCandidates(for key: Data, kind: I2PLookupKind = .routerInfo,
                                  excluding queried: Set<Data>) -> [Data] {
        // A LeaseSet is held by the floodfills closest to *its* key, which live in
        // a different region of the keyspace from the peers this router keeps
        // sessions with (those are chosen relative to our own hash). Ask more of
        // the closest peers for an LS lookup, and every reachable one beyond them.
        let closestCount = kind == .leaseSet ? 8 : Self.lookupFloodfillCount
        var candidates = selectFloodfills(for: key, count: closestCount)
            .filter { !queried.contains($0) }
        guard let reachable = peerIsReachable else { return candidates }
        let liveFanOut = kind == .leaseSet ? 32 : Self.lookupFloodfillCount * 2
        if candidates.contains(where: { !reachable($0) }) {
            let live = knownFloodfills
                .filter { $0 != localRouterHash && !queried.contains($0) && reachable($0) }
                .sorted { Self.isCloser($0, than: $1, to: key) }
                .prefix(liveFanOut)
            candidates = Array(Set(candidates + live))
                .sorted { Self.isCloser($0, than: $1, to: key) }
        }
        return candidates
    }

    /// Sends netdb messages without letting one slow peer delay the rest: a
    /// demand-dial to a floodfill with no session can take seconds, and awaiting
    /// it inline kept a lookup from ever leaving before its round deadline.
    private func broadcast(_ message: I2PNetDBMessage, to targets: [Data]) {
        guard !targets.isEmpty else { return }
        let transport = self.transport
        for target in targets {
            Task {
                try? await transport.send(to: target, message: message)
            }
        }
    }

    func configureLocalFloodfill(_ enabled: Bool) {
        isFloodfillRouter = enabled
    }

    func localFloodfillRole() -> Bool {
        isFloodfillRouter
    }

    /// A one-line summary of inbound stores this router rejected, for live
    /// diagnostics; empty when nothing was rejected.
    func storeRejectionSummary() -> String {
        guard !storeRejections.isEmpty else { return "" }
        var counts: [String: Int] = [:]
        for line in storeRejections { counts[line, default: 0] += 1 }
        let detail = counts.sorted { $0.value > $1.value }
            .prefix(3)
            .map { "\($0.value)× \($0.key)" }
            .joined(separator: "; ")
        return "\(storeRejections.count) inbound store(s) rejected: \(detail)"
    }

    func registerFloodfill(_ hash: Data) {
        precondition(hash.count == 32)
        knownFloodfills.insert(hash)
        knownPeers.insert(hash)
    }

    func isFloodfill(_ hash: Data) -> Bool {
        knownFloodfills.contains(hash) || (hash == localRouterHash && isFloodfillRouter)
    }

    /// Netdb cache quota: neither the in-memory cache nor the persisted store
    /// may grow without bound, no matter how many stores the network floods us
    /// with (the hardening quota in executable form).
    static let maxCacheEntries = 4_000

    /// Makes room for one more entry: expired residents are evicted first, then
    /// the ones farthest from the incoming key by the Kademlia metric — the least
    /// useful cache residents go first, and their disk records are reclaimed too.
    private func enforceCacheQuota(for incomingKey: Data) {
        guard entries.count >= Self.maxCacheEntries else { return }
        var toFree = entries.count + 1 - Self.maxCacheEntries
        let expiredKeys = entries
            .filter { $1.isExpired() }
            .prefix(toFree)
            .map(\.key)
        for key in expiredKeys {
            entries.removeValue(forKey: key)
            storage.remove(key: key)
            toFree -= 1
        }
        guard toFree > 0 else { return }
        let victims = entries.keys
            .filter { $0 != incomingKey }
            .sorted { !Self.isCloser($0, than: $1, to: incomingKey) }
            .prefix(toFree)
        for key in victims {
            entries.removeValue(forKey: key)
            storage.remove(key: key)
        }
    }

    // MARK: Inbound message handling (entry point used by the transport)

    /// Handles an inbound netdb message. The transport layer calls this on delivery.
    func handleIncoming(_ message: I2PNetDBMessage) async {
        switch message {
        case .store(let s): await handleStore(s)
        case .lookup(let l): await handleLookup(l)
        case .searchReply(let r): handleSearchReply(r)
        case .deliveryStatus(let id, _): handleDeliveryStatus(messageID: id)
        }
    }

    /// A DeliveryStatus with our store's reply token acknowledges the publish.
    private func handleDeliveryStatus(messageID: UInt32) {
        guard outgoingStoreTokens.contains(messageID) else { return }
        pendingStoreAcks[messageID, default: 0] += 1
    }

    private func handleStore(_ s: I2PDatabaseStore) async {
        // 1. Ingest — signature verification happens inside the structure parsers.
        let entry: StoredEntry
        do {
            entry = try Self.ingest(s.payload, entryType: s.entryType)
        } catch {
            // A store we could not parse or verify is not silently equivalent to
            // "nothing arrived": keep a short tally so a live run can tell a
            // rejected answer (a codec/verification defect) from a lookup no peer
            // bothered to answer.
            //
            // Name the real cause when the entry's own destination signs with a
            // type this router does not implement: that is a modern-only policy
            // boundary, not a codec bug, and saying so stops the next run from
            // looking like a regression.
            var reason = "\(error)"
            if s.entryType != .routerInfo,
               let code = I2PKeysAndCert.declaredSignatureTypeCode(in: s.payload),
               I2PSigType(rawValue: code) == nil {
                reason = "legacy destination identity (SigType \(code), which this router's modern-only verifier does not implement)"
            }
            storeRejections.append("\(s.entryType) \(reason)")
            if storeRejections.count > 50 { storeRejections.removeFirst() }
            return // unverifiable entry rejected
        }
        if let routerInfo = entry.routerInfo {
            learn(from: routerInfo)
        }
        guard !entry.isExpired() else { return }
        // The cache is keyed by the *verified* identity hash, never by the key
        // field the store arrived with: a peer that ships a valid RouterInfo (or
        // LeaseSet) under a different key must not be able to plant an entry at
        // that key — netdb poisoning. The store's own key is only used to
        // correlate an answer with the lookup that asked for it.
        let key = entry.key
        let answeredKey = s.key
        let now = Date()
        let existing = entries[key]
        let isDuplicate: Bool
        if let existing {
            isDuplicate = existing.raw == s.payload && !existing.isExpired(now)
        } else {
            isDuplicate = false
        }

        // 2. Correlation: a direct DatabaseStore answer to one of our lookups
        // carries the queried key and no reply token, so match it by key.
        // (A token-bound store is honored too for our own loopback path.)
        if pendingLookupKeys.contains(answeredKey) || pendingLookupKeys.contains(key) {
            pendingLookupKeys.remove(answeredKey)
            pendingLookupKeys.remove(key)
            pendingLookupResults[answeredKey] = entry
            if answeredKey != key { pendingLookupResults[key] = entry }
        }
        if s.replyToken > 0 {
            if outgoingStoreTokens.contains(s.replyToken) {
                pendingStoreAcks[s.replyToken, default: 0] += 1
            } else if outgoingLookupTokens.contains(s.replyToken) {
                pendingLookupResults[key] = entry
            }
        }

        // 3. Accept into cache + disk (bounded by the cache quota: eviction
        // removes expired-first, then farthest-from-key, and reclaims their
        // disk records, so neither memory nor disk can run away).
        if !isDuplicate {
            enforceCacheQuota(for: key)
            entries[key] = entry
            try? storage.persist(key: key, record: I2PNetDBStorage.Record(
                entryType: s.entryType.rawValue,
                storedAt: now,
                expiresAt: entry.expiresAt,
                payload: s.payload
            ))
            if entry.entryType == .routerInfo, entry.routerInfo?.identity.hash == localRouterHash {
                ownRouterInfo = entry
            } else if entry.entryType == .leaseSet, entry.leaseSet?.destination.hash == localRouterHash {
                ownLeaseSet = entry
            }
        }

        // 4. A store carrying a reply token asks for a DeliveryStatus
        // acknowledgment with the token as the message ID. Tunnel-routed acks
        // would need the reply tunnel; direct ones go to the reply gateway.
        if s.replyToken > 0, s.replyTunnelId == 0,
           !s.replyGateway.isEmpty, s.replyGateway != localRouterHash,
           !recentlyEchoed(s.replyToken) {
            recentlyEchoedTokens[s.replyToken] = now
            try? await transport.send(to: s.replyGateway,
                                      message: .deliveryStatus(messageID: s.replyToken,
                                                               timestamp: now))
        }

        // 5. Floodfill replication: gossip to the next floodfills farther from the key.
        if isFloodfillRouter {
            let gossip = I2PDatabaseStore(key: key, entryType: s.entryType, replyToken: 0, payload: s.payload)
            for target in gossipTargets(for: key) {
                // Dedup per (entry, target), not per entry: a floodfill that
                // received the entry directly must still ripple it outward to
                // peers farther from the key, or the gossip wave dies after one
                // hop and the farthest floodfills never converge.
                let token = Self.gossipToken(key: key, target: target)
                guard !gossipedRecently(token, now: now) else { continue }
                recentlyReplicated[token] = now
                try? await transport.send(to: target, message: .store(gossip))
            }
        }
    }

    private func handleLookup(_ l: I2PDatabaseLookup) async {
        guard l.fromHash != localRouterHash else { return }
        // A direct reply carries the entry back to `from`. Tunnel-routed and
        // encrypted replies need the reply tunnel/key we do not operate here.
        guard l.replyTunnelId == 0, !l.encryptedReplyRequested else { return }
        let replyTarget = l.fromHash

        if let entry = entries[l.queryKey], !entry.isExpired() {
            // Answer with the entry itself; the reply is a plain store.
            let reply = I2PDatabaseStore(
                key: l.queryKey,
                entryType: entry.entryType,
                replyToken: 0,
                replyTunnelId: 0,
                replyGateway: Data(),
                payload: entry.raw
            )
            try? await transport.send(to: replyTarget, message: .store(reply))
            return
        }

        // Only floodfills answer misses, with the closest known peers for iterative querying.
        guard isFloodfillRouter else { return }
        let excluded = Set(l.excludedPeers).union([l.fromHash, localRouterHash])
        let candidates = entries.values
            .filter { $0.entryType == .routerInfo && !$0.isExpired() }
            .sorted { Self.isCloser($0.key, than: $1.key, to: l.queryKey) }
            .prefix(8)
            .map(\.key)
            .filter { !excluded.contains($0) }
        guard !candidates.isEmpty else { return }
        let reply = I2PDatabaseSearchReply(
            queryKey: l.queryKey,
            fromHash: localRouterHash,
            peerHashes: Array(candidates.prefix(8))
        )
        try? await transport.send(to: replyTarget, message: .searchReply(reply))
    }

    private func handleSearchReply(_ r: I2PDatabaseSearchReply) {
        knownPeers.formUnion(r.peerHashes)
        pendingSearchReplies[r.queryKey, default: []].append(r)
    }

    // MARK: Store / publish

    /// Publishes a signed RouterInfo: stores it locally and replicates it to the
    /// closest floodfills. Returns the number of floodfill acknowledgments.
    @discardableResult
    func publish(routerInfo: I2PRouterInfo, floodfillCount: Int = 5) async -> Int {
        let payload = routerInfo.serialize()
        guard let entry = try? Self.ingest(payload, entryType: .routerInfo) else { return 0 }
        if let routerInfo = entry.routerInfo {
            learn(from: routerInfo)
        }
        ownRouterInfo = entry
        enforceCacheQuota(for: entry.key)
        entries[entry.key] = entry
        try? storage.persist(key: entry.key, record: I2PNetDBStorage.Record(
            entryType: I2PDatabaseEntryType.routerInfo.rawValue,
            storedAt: Date(),
            expiresAt: entry.expiresAt,
            payload: payload
        ))
        return await storeToNetDB(key: entry.key, entryType: .routerInfo, payload: payload, floodfillCount: floodfillCount)
    }

    /// Publishes a signed LeaseSet. Returns the number of floodfill acknowledgments.
    @discardableResult
    func publish(leaseSet: I2PLeaseSet, floodfillCount: Int = 5) async -> Int {
        let payload = leaseSet.serialize()
        guard let entry = try? Self.ingest(payload, entryType: .leaseSet) else { return 0 }
        ownLeaseSet = entry
        enforceCacheQuota(for: entry.key)
        entries[entry.key] = entry
        try? storage.persist(key: entry.key, record: I2PNetDBStorage.Record(
            entryType: I2PDatabaseEntryType.leaseSet.rawValue,
            storedAt: Date(),
            expiresAt: entry.expiresAt,
            payload: payload
        ))
        return await storeToNetDB(key: entry.key, entryType: .leaseSet, payload: payload, floodfillCount: floodfillCount)
    }

    /// Publishes a signed LeaseSet2-family entry under the netdb key its own
    /// destination derives: for a plain LS2 that is the destination hash, and
    /// for an encrypted (b33) LS2 the envelope destination carries the blinded
    /// signing key — so its hash, the blinded netdb key, is the key the store
    /// rides. Returns the number of floodfill acknowledgments.
    @discardableResult
    func publish(leaseSet2: I2PLeaseSet2, floodfillCount: Int = 5) async -> Int {
        let entryType: I2PDatabaseEntryType
        switch leaseSet2.storeType {
        case .plain: entryType = .leaseSet2
        case .encrypted: entryType = .encryptedLeaseSet2
        case .meta: entryType = .metaLeaseSet2
        }
        let payload = leaseSet2.serialize()
        guard let entry = try? Self.ingest(payload, entryType: entryType) else { return 0 }
        enforceCacheQuota(for: entry.key)
        entries[entry.key] = entry
        try? storage.persist(key: entry.key, record: I2PNetDBStorage.Record(
            entryType: entryType.rawValue,
            storedAt: Date(),
            expiresAt: entry.expiresAt,
            payload: payload
        ))
        return await storeToNetDB(key: entry.key, entryType: entryType,
                                  payload: payload, floodfillCount: floodfillCount)
    }

    /// Ingests a verified RouterInfo payload into the local database (no networking).
    func ingestRouterInfo(_ payload: Data) throws {
        let entry = try Self.ingest(payload, entryType: .routerInfo)
        guard !entry.isExpired() else { throw I2PWireError.invalidFormat }
        if let routerInfo = entry.routerInfo {
            learn(from: routerInfo)
        }
        enforceCacheQuota(for: entry.key)
        entries[entry.key] = entry
        try? storage.persist(key: entry.key, record: I2PNetDBStorage.Record(
            entryType: I2PDatabaseEntryType.routerInfo.rawValue,
            storedAt: Date(),
            expiresAt: entry.expiresAt,
            payload: payload
        ))
    }

    /// Ingests a verified LeaseSet payload into the local database (no networking).
    func ingestLeaseSet(_ payload: Data) throws {
        let entry = try Self.ingest(payload, entryType: .leaseSet)
        guard !entry.isExpired() else { throw I2PWireError.invalidFormat }
        enforceCacheQuota(for: entry.key)
        entries[entry.key] = entry
        try? storage.persist(key: entry.key, record: I2PNetDBStorage.Record(
            entryType: I2PDatabaseEntryType.leaseSet.rawValue,
            storedAt: Date(),
            expiresAt: entry.expiresAt,
            payload: payload
        ))
    }

    /// Ingests a verified LeaseSet2 payload (proposal 123 store types 2/3/5)
    /// into the local database (no networking). The entry resolves by its
    /// destination hash through lookup/lookupLeaseSet2.
    func ingestLeaseSet2(_ payload: Data, entryType: I2PDatabaseEntryType) throws {
        guard entryType == .leaseSet2 || entryType == .encryptedLeaseSet2 || entryType == .metaLeaseSet2 else {
            throw I2PWireError.invalidFormat
        }
        let entry = try Self.ingest(payload, entryType: entryType)
        guard !entry.isExpired() else { throw I2PWireError.invalidFormat }
        enforceCacheQuota(for: entry.key)
        entries[entry.key] = entry
        try? storage.persist(key: entry.key, record: I2PNetDBStorage.Record(
            entryType: entryType.rawValue,
            storedAt: Date(),
            expiresAt: entry.expiresAt,
            payload: payload
        ))
    }

    private func storeToNetDB(key: Data, entryType: I2PDatabaseEntryType, payload: Data,
                              floodfillCount: Int, timeout: TimeInterval = 2) async -> Int {
        let targets = selectFloodfills(for: key, count: floodfillCount)
        guard !targets.isEmpty else { return 0 }
        let token = Self.newToken()
        outgoingStoreTokens.insert(token)
        pendingStoreAcks[token] = 0
        for target in targets {
            let message = I2PDatabaseStore(
                key: key,
                entryType: entryType,
                replyToken: token,
                replyTunnelId: 0,
                replyGateway: localRouterHash,
                payload: payload
            )
            // Concurrent: a floodfill with no session demand-dials in its own
            // send task instead of delaying the rest of the store.
            broadcast(.store(message), to: [target])
        }
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if (pendingStoreAcks[token] ?? 0) >= targets.count { break }
            try? await Task.sleep(for: .milliseconds(50))
        }
        let acks = pendingStoreAcks.removeValue(forKey: token) ?? 0
        outgoingStoreTokens.remove(token)
        return acks
    }

    // MARK: Lookup

    /// Looks up an entry: cache first, then an iterative query of the closest
    /// known peers. A search reply names the peers a floodfill considers closest
    /// to the key — the spec has the requester ask *those* next, whether or not
    /// they are floodfills ("The returned peer hashes are not necessarily closer
    /// to the key than the router being queried"), so the next round draws on
    /// them rather than re-deriving a candidate set from the floodfill index.
    ///
    /// The round's lookups go out concurrently (a peer without a session
    /// demand-dials in its own send task), and the per-key answer slots live for
    /// the whole lookup, so an answer that lands between rounds is still
    /// correlated instead of discarded.
    func lookup(_ key: Data, kind: I2PLookupKind = .routerInfo,
                timeoutPerRound: TimeInterval = 1.5, maxRounds: Int = 2) async -> StoredEntry? {
        await lookupAnswering(key, kind: kind,
                              timeoutPerRound: timeoutPerRound, maxRounds: maxRounds).entry
    }

    /// The lookup plus whether anybody answered it at all. A DatabaseSearchReply
    /// is a spec answer too (it names the peers the floodfill considers closest),
    /// so a caller measuring a round trip can tell "no peer replied" apart from
    /// "the network answered, but the entry is not stored there".
    func lookupAnswering(_ key: Data, kind: I2PLookupKind = .routerInfo,
                         timeoutPerRound: TimeInterval = 1.5, maxRounds: Int = 2) async
        -> (entry: StoredEntry?, answered: Bool) {
        precondition(key.count == 32)
        if let entry = entries[key], !entry.isExpired() {
            return (entry, true)
        }
        var answered = false
        var queried: Set<Data> = []
        /// Peers a search reply pointed at, for the next round.
        var queue: [Data] = []
        pendingLookupKeys.insert(key)
        // Clear the per-key answer slots once for the whole lookup. They used to
        // be reset at the start of every round, which discarded a reply that
        // arrived while the gap between rounds was fetching the peers a search
        // reply named — the answer was there and the lookup still timed out.
        pendingLookupResults.removeValue(forKey: key)
        pendingSearchReplies[key] = []
        defer {
            pendingLookupKeys.remove(key)
            pendingLookupResults.removeValue(forKey: key)
            pendingSearchReplies.removeValue(forKey: key)
        }
        for _ in 0..<maxRounds {
            let candidates = (queue.isEmpty
                                ? lookupCandidates(for: key, kind: kind, excluding: queried)
                                : queue.filter { !queried.contains($0) })
            queue = []
            guard !candidates.isEmpty else { break }
            let token = Self.newToken()
            outgoingLookupTokens.insert(token)
            let excluded = Array(candidates.dropFirst().prefix(3))
            for floodfill in candidates {
                queried.insert(floodfill)
                let message = I2PDatabaseLookup(
                    queryKey: key,
                    fromHash: localRouterHash,
                    excludedPeers: excluded,
                    replyTunnels: [],
                    replyToken: token,
                    replyTunnelId: 0,
                    replyGateway: localRouterHash,
                    lookupType: kind
                )
                // Fire-and-forget: a peer with no session demand-dials in its
                // own send task, so the wait below still starts on time.
                broadcast(.lookup(message), to: [floodfill])
            }
            let deadline = Date().addingTimeInterval(timeoutPerRound)
            var discovered: Set<Data> = []
            while Date() < deadline {
                if Task.isCancelled {
                    outgoingLookupTokens.remove(token)
                    return (nil, answered)
                }
                if let found = pendingLookupResults.removeValue(forKey: key) {
                    outgoingLookupTokens.remove(token)
                    return (found, true)
                }
                let replies = pendingSearchReplies[key] ?? []
                pendingSearchReplies[key] = []
                if !replies.isEmpty { answered = true }
                for reply in replies {
                    for peer in reply.peerHashes
                    where !knownFloodfills.contains(peer) && !queried.contains(peer) {
                        discovered.insert(peer)
                    }
                }
                if !discovered.isEmpty { break }
                do {
                    try await Task.sleep(for: .milliseconds(50))
                } catch {
                    outgoingLookupTokens.remove(token)
                    return (nil, answered)
                }
            }
            outgoingLookupTokens.remove(token)
            // Iterative discovery: fetch RouterInfos for the newly named peers
            // (cache-first, so a peer we already know costs nothing) and query
            // them in the next round, nearest first. The prefetch runs
            // concurrently and with a short per-peer budget: doing it one peer
            // at a time between rounds could eat the whole lookup's time.
            if maxRounds >= 2, !discovered.isEmpty {
                let nearest = discovered.sorted { Self.isCloser($0, than: $1, to: key) }.prefix(3)
                let prefetchBudget = min(1.5, timeoutPerRound)
                await withTaskGroup(of: Void.self) { group in
                    for peer in nearest where entries[peer] == nil {
                        group.addTask {
                            _ = await self.lookup(peer, kind: .routerInfo,
                                                  timeoutPerRound: prefetchBudget, maxRounds: 1)
                        }
                    }
                    await group.waitForAll()
                }
                queue = discovered.sorted { Self.isCloser($0, than: $1, to: key) }
            }
        }
        return (nil, answered)
    }

    /// Looks up a router's RouterInfo by its identity hash.
    func lookupRouterInfo(_ routerHash: Data, timeoutPerRound: TimeInterval = 1.5, maxRounds: Int = 2) async -> I2PRouterInfo? {
        await lookup(routerHash, kind: .routerInfo,
                     timeoutPerRound: timeoutPerRound, maxRounds: maxRounds)?.routerInfo
    }

    /// One live DHT round trip that needs no cached entry: query a key the local
    /// cache cannot answer and report whether any floodfill replied. Both spec
    /// answers count — the entry itself (a DatabaseStore) or the closest peers
    /// the floodfill knows (a DatabaseSearchReply). A miss-answer proves the
    /// DatabaseLookup body parsed, the floodfill set is reachable over live
    /// sessions and the reply path works, which is what the live suite's DHT row
    /// measures. Without this, that row could only run immediately after a
    /// reseed (it needed a deferred hash to exist), so a router with a healthy
    /// persisted netdb reported the DHT as broken.
    func probeLookup(_ key: Data, timeoutPerRound: TimeInterval = 3) async
        -> (answered: Bool, servedEntry: Bool, peers: Int) {
        precondition(key.count == 32)
        let candidates = lookupCandidates(for: key, excluding: [])
        guard !candidates.isEmpty else { return (false, false, 0) }
        let token = Self.newToken()
        outgoingLookupTokens.insert(token)
        pendingLookupKeys.insert(key)
        pendingLookupResults.removeValue(forKey: key)
        pendingSearchReplies[key] = []
        defer {
            pendingLookupKeys.remove(key)
            outgoingLookupTokens.remove(token)
            pendingLookupResults.removeValue(forKey: key)
            pendingSearchReplies.removeValue(forKey: key)
        }
        let excluded = Array(candidates.dropFirst().prefix(3))
        for floodfill in candidates {
            let message = I2PDatabaseLookup(queryKey: key,
                                            fromHash: localRouterHash,
                                            excludedPeers: excluded,
                                            replyTunnels: [],
                                            replyToken: token,
                                            lookupType: .exploration)
            broadcast(.lookup(message), to: [floodfill])
        }
        let deadline = Date().addingTimeInterval(timeoutPerRound)
        while Date() < deadline {
            if Task.isCancelled { return (false, false, 0) }
            if pendingLookupResults[key] != nil { return (true, true, 0) }
            if let replies = pendingSearchReplies[key], !replies.isEmpty {
                let peers = replies.reduce(0) { $0 + $1.peerHashes.count }
                if peers > 0 { return (true, false, peers) }
            }
            try? await Task.sleep(for: .milliseconds(50))
        }
        return (false, false, 0)
    }

    /// Resolves a destination (hash of the destination keys-and-certificate, or
    /// the publication key an LS2 store arrived under) to a signature-verified
    /// LeaseSet2 over the cache-first DHT path — the mainnet ECIES eepsite
    /// resolution path (proposal 123 store types 2/3/5).
    func lookupLeaseSet2(_ key: Data, timeoutPerRound: TimeInterval = 1.5, maxRounds: Int = 2) async -> I2PLeaseSet2? {
        await lookup(key, kind: .leaseSet,
                     timeoutPerRound: timeoutPerRound, maxRounds: maxRounds)?.leaseSet2
    }

    // MARK: Encrypted LeaseSet2 (b33) resolution

    /// Resolves an encrypted LeaseSet2 (store type 3) published under its
    /// blinded key for a destination we hold credentials for: derives the
    /// blinded destination key and blinded netdb key per the blinding spec
    /// (I2PB33Blinding), looks the entry up under its blinded netdb key over
    /// the same DHT path any netdb lookup rides, decrypts the authenticated
    /// inner body, and returns the inner plain LeaseSet2 — parse-verified
    /// under the real destination's signing key. Without credentials the
    /// entry stays opaque, exactly as the spec intends.
    func lookupEncryptedLeaseSet2(credentials: I2PB33Credentials,
                                  timeoutPerRound: TimeInterval = 1.5,
                                  maxRounds: Int = 2) async -> I2PLeaseSet2? {
        guard let encryptionPublicKey = I2PB33Blinding.destinationEncryptionPublicKey(credentials) else {
            return nil
        }
        guard let blinded = try? I2PB33Blinding.blind(
            destinationSeed: credentials.ed25519Seed,
            encryptionPublicKey: encryptionPublicKey,
            secret: credentials.secret) else {
            return nil
        }
        guard let entry = await lookup(blinded.netDBKey,
                                       kind: .leaseSet,
                                       timeoutPerRound: timeoutPerRound,
                                       maxRounds: maxRounds),
              let encrypted = entry.leaseSet2,
              encrypted.storeType == .encrypted else {
            return nil
        }
        return try? encrypted.resolveEncryptedBody(credentials: credentials)
    }

    /// Delivery-path resolution for an encrypted (b33) destination: the same
    /// I2PLeaseSet shape plain LS2 resolution feeds garlic delivery with —
    /// the resolved inner LS2's leases ride `resolvedLeaseSet()` unchanged.
    func resolveEncryptedDestination(credentials: I2PB33Credentials,
                                     timeoutPerRound: TimeInterval = 1.5,
                                     maxRounds: Int = 2) async -> I2PLeaseSet? {
        await lookupEncryptedLeaseSet2(credentials: credentials,
                                       timeoutPerRound: timeoutPerRound,
                                       maxRounds: maxRounds)?.resolvedLeaseSet()
    }

    // MARK: Refresh / expiration / maintenance

    /// Re-publishes our own RouterInfo and LeaseSet to the floodfills (periodic refresh).
    @discardableResult
    func refreshOwn() async -> Int {
        let now = Date()
        var acks = 0
        if let own = ownRouterInfo {
            let refreshed = StoredEntry(
                entryType: own.entryType,
                key: own.key,
                raw: own.raw,
                routerInfo: own.routerInfo,
                leaseSet: nil,
                expiresAt: now.addingTimeInterval(Self.routerInfoLifetime)
            )
            entries[own.key] = refreshed
            try? storage.persist(key: own.key, record: I2PNetDBStorage.Record(
                entryType: I2PDatabaseEntryType.routerInfo.rawValue,
                storedAt: now,
                expiresAt: refreshed.expiresAt,
                payload: own.raw
            ))
            acks += await storeToNetDB(key: own.key, entryType: .routerInfo, payload: own.raw, floodfillCount: Self.storeFloodfillCount)
        }
        if let own = ownLeaseSet, let leaseSet = own.leaseSet {
            let latestLease = leaseSet.leases.map(\.expiration).max() ?? now
            let expiry = min(now.addingTimeInterval(Self.leaseSetLifetime),
                             latestLease.addingTimeInterval(Self.leaseGracePeriod))
            let refreshed = StoredEntry(
                entryType: own.entryType,
                key: own.key,
                raw: own.raw,
                routerInfo: nil,
                leaseSet: leaseSet,
                expiresAt: expiry
            )
            entries[own.key] = refreshed
            try? storage.persist(key: own.key, record: I2PNetDBStorage.Record(
                entryType: I2PDatabaseEntryType.leaseSet.rawValue,
                storedAt: now,
                expiresAt: refreshed.expiresAt,
                payload: own.raw
            ))
            acks += await storeToNetDB(key: own.key, entryType: .leaseSet, payload: own.raw, floodfillCount: Self.storeFloodfillCount)
        }
        return acks
    }

    /// Removes expired entries (and stale gossip bookkeeping). Returns how many entries went away.
    @discardableResult
    func pruneExpired(now: Date = Date()) -> Int {
        var removed = 0
        for (key, entry) in entries where entry.isExpired(now) {
            entries.removeValue(forKey: key)
            storage.remove(key: key)
            // An expired RouterInfo no longer vouches for its peer: drop the
            // identity from the routing indexes too, or lookups keep being
            // addressed to floodfills whose netdb entry (and transport
            // address) is an hour stale.
            if entry.routerInfo != nil {
                knownPeers.remove(key)
                knownFloodfills.remove(key)
            }
            removed += 1
        }
        recentlyReplicated = recentlyReplicated.filter { now.timeIntervalSince($0.value) < Self.replicationDedupWindow }
        recentlyEchoedTokens = recentlyEchoedTokens.filter { now.timeIntervalSince($0.value) < Self.replicationDedupWindow }
        return removed
    }

    /// Starts the maintenance loop: prunes expired entries on `interval` and
    /// re-publishes our own RouterInfo/LeaseSet every `refreshInterval`.
    func startMaintenance(interval: TimeInterval = 60, refreshInterval: TimeInterval = 3600) {
        maintenanceTask?.cancel()
        lastOwnRefresh = .distantPast
        maintenanceTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(interval))
                guard let self, !Task.isCancelled else { return }
                _ = await self.pruneExpired()
                await self.maybeRefreshOwn(refreshInterval: refreshInterval)
            }
        }
    }

    func stopMaintenance() {
        maintenanceTask?.cancel()
        maintenanceTask = nil
    }

    private func maybeRefreshOwn(refreshInterval: TimeInterval) async {
        guard Date().timeIntervalSince(lastOwnRefresh) >= refreshInterval else { return }
        lastOwnRefresh = Date()
        _ = await refreshOwn()
    }

    // MARK: Introspection

    /// The signature-verified RouterInfos currently live in the cache — the
    /// candidate pool tunnel hop selection draws on (the Java I2P analogue of
    /// the netdb RouterInfo set the ProfileManager scores). Cache-only: no
    /// network round trip, so selection never blocks on the DHT.
    func cachedRouterInfos(limit: Int = 512) -> [(hash: Data, info: I2PRouterInfo)] {
        let now = Date()
        var result: [(hash: Data, info: I2PRouterInfo)] = []
        for (key, entry) in entries where entry.entryType == .routerInfo {
            guard let info = entry.routerInfo, !entry.isExpired(now) else { continue }
            result.append((key, info))
            if result.count >= limit { break }
        }
        return result
    }

    func entryCount() -> Int { entries.count }
    func hasEntry(_ key: Data) -> Bool { entries[key] != nil }
    func entryExpiration(_ key: Data) -> Date? { entries[key]?.expiresAt }
    func floodfillCount() -> Int { knownFloodfills.count }
    func knownPeerCount() -> Int { knownPeers.count }

    /// Aggregated live status for the router dashboard.
    func status(now: Date = Date()) -> I2PNetDBStatus {
        let live = entries.values.filter { !$0.isExpired(now) }
        return I2PNetDBStatus(
            routerInfoCount: live.filter { $0.entryType == .routerInfo }.count,
            leaseSetCount: live.filter { $0.entryType != .routerInfo }.count,
            floodfillCount: knownFloodfills.count,
            peerCount: knownPeers.count,
            isLocalFloodfill: isFloodfillRouter
        )
    }

    // MARK: Bootstrapping

    /// Startup bootstrapping: takes seed floodfills (from reseed data), fetches their
    /// RouterInfos, then iteratively discovers peers via DatabaseLookup / search replies.
    @discardableResult
    func bootstrap(seedFloodfills: [Data], targetPeers: Int = 16, maxRounds: Int = 6) async -> Int {
        for seed in seedFloodfills {
            registerFloodfill(seed)
        }
        // Fetch the seed floodfills' own RouterInfos (adds entries + learns their caps).
        for seed in seedFloodfills where entries[seed] == nil {
            _ = await lookup(seed, timeoutPerRound: 1.5, maxRounds: 1)
        }
        var round = 0
        while knownPeers.count < targetPeers && round < maxRounds {
            var randomKey = Data(count: 32)
            _ = (0..<32).map { index in
                randomKey[index] = UInt8.random(in: 0...255)
            }
            _ = await lookup(randomKey, kind: .exploration, timeoutPerRound: 1.5, maxRounds: 2)
            // Fetch RouterInfos for any discovered peers we don't have yet.
            let unknown = knownPeers.filter { entries[$0] == nil }
            for peer in unknown.prefix(4) {
                _ = await lookup(peer, timeoutPerRound: 1.5, maxRounds: 1)
            }
            round += 1
        }
        return knownPeers.count
    }

    // MARK: Internals

    /// Parses and verifies a payload, computing spec lifetimes.
    private nonisolated static func ingest(_ payload: Data, entryType: I2PDatabaseEntryType, publishedAt: Date? = nil) throws -> StoredEntry {
        let now = publishedAt ?? Date()
        switch entryType {
        case .routerInfo:
            let routerInfo = try I2PRouterInfo.parse(payload) // verifies the Ed25519 signature
            return StoredEntry(
                entryType: .routerInfo,
                key: routerInfo.identity.hash,
                raw: payload,
                routerInfo: routerInfo,
                leaseSet: nil,
                expiresAt: now.addingTimeInterval(Self.routerInfoLifetime)
            )
        case .leaseSet:
            let leaseSet = try I2PLeaseSet.parse(payload) // verifies the destination signature
            let latestLease = leaseSet.leases.map(\.expiration).max() ?? Date()
            return StoredEntry(
                entryType: .leaseSet,
                key: leaseSet.destination.hash,
                raw: payload,
                routerInfo: nil,
                leaseSet: leaseSet,
                expiresAt: min(now.addingTimeInterval(Self.leaseSetLifetime),
                               latestLease.addingTimeInterval(Self.leaseGracePeriod))
            )
        case .leaseSet2, .encryptedLeaseSet2, .metaLeaseSet2:
            // LeaseSet2 (proposal 123): the payload does not repeat the store
            // type — the DatabaseStore type byte (3/5/7) *is* the type, and the
            // body signature is prepended with it.
            guard let storeType = I2PLeaseSet2Type(rawValue: UInt16(entryType.rawValue)) else {
                throw I2PWireError.unsupportedAlgorithm
            }
            let leaseSet2 = try I2PLeaseSet2.parse(payload, expectedType: storeType)
            let latestLease = leaseSet2.resolvedLeaseSet()?.leases.map(\.expiration).max()
            let expiryCandidate = latestLease ?? leaseSet2.expiresAt
            return StoredEntry(
                entryType: entryType,
                key: leaseSet2.destination.hash,
                raw: payload,
                routerInfo: nil,
                leaseSet: nil,
                expiresAt: min(now.addingTimeInterval(Self.leaseSetLifetime),
                               expiryCandidate.addingTimeInterval(Self.leaseGracePeriod)),
                leaseSet2: leaseSet2
            )
        }
    }

    private func learn(from routerInfo: I2PRouterInfo) {
        let hash = routerInfo.identity.hash
        knownPeers.insert(hash)
        if routerInfo.options["caps"]?.contains("f") == true {
            knownFloodfills.insert(hash)
        }
    }

    /// Restores persisted entries from disk, re-verifying each signature and
    /// discarding unverifiable or expired records.
    private nonisolated static func restoredEntries(from storage: I2PNetDBStorage) -> [Data: StoredEntry] {
        var restored: [Data: StoredEntry] = [:]
        // Launch-survival cap: the persisted netdb grows with every session that
        // ingests mainnet entries, and a crash-looping launch ingests MORE before
        // dying each time — a feedback loop where each successive launch parses and
        // re-verifies a bigger set (CPU + memory spike) and dies sooner. A memory
        // kill is an external SIGKILL that no in-app signal handler can report, so
        // the only durable defense is bounding the restore itself: keep the newest
        // window and reclaim the overflow from disk so the next launch starts smaller.
        var records = storage.loadAll()
        let restoreCap = 1_500
        if records.count > restoreCap {
            records.sort { $0.1.storedAt > $1.1.storedAt }
            for (overflowKey, _) in records.dropFirst(restoreCap) {
                storage.remove(key: overflowKey)
            }
            records = Array(records.prefix(restoreCap))
        }
        for (key, record) in records {
            // Bound the restore's memory spike: oversized persisted records are
            // not spec-shaped netdb entries; drop them.
            guard record.payload.count <= 65_536 else {
                storage.remove(key: key)
                continue
            }
            guard let entryType = I2PDatabaseEntryType(rawValue: record.entryType) else {
                storage.remove(key: key)
                continue
            }
            // Re-parsing re-verifies the signature; unverifiable records are dropped.
            guard let entry = try? ingest(record.payload, entryType: entryType, publishedAt: record.storedAt) else {
                storage.remove(key: key)
                continue
            }
            guard !entry.isExpired() else {
                storage.remove(key: key)
                continue
            }
            restored[entry.key] = entry
        }
        return restored
    }

    /// Floodfills to gossip a freshly stored entry to: the next `replicationFanout`
    /// floodfills farther from the key than ourselves, so replication ripples outward
    /// through the XOR-ordered ring until every floodfill holds the entry.
    private func gossipTargets(for key: Data) -> [Data] {
        Array(
            knownFloodfills
                .filter { $0 != localRouterHash }
                .filter { Self.isCloser(localRouterHash, than: $0, to: key) }
                .sorted { Self.isCloser($0, than: $1, to: key) }
                .prefix(Self.replicationFanout)
        )
    }

    private func gossipedRecently(_ token: Data, now: Date) -> Bool {
        guard let last = recentlyReplicated[token] else { return false }
        return now.timeIntervalSince(last) < Self.replicationDedupWindow
    }

    /// Per (entry, target) dedup key for the replication memo.
    private static func gossipToken(key: Data, target: Data) -> Data {
        I2PCrypto.sha256(key + target)
    }

    private func recentlyEchoed(_ token: UInt32) -> Bool {
        guard let last = recentlyEchoedTokens[token] else { return false }
        return Date().timeIntervalSince(last) < Self.replicationDedupWindow
    }

    private static func newToken() -> UInt32 {
        UInt32.random(in: 1...UInt32.max)
    }
}