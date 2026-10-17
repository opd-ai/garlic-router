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
    private var pendingSearchReplies: [Data: [I2PDatabaseSearchReply]] = [:]
    private var recentlyReplicated: [Data: Date] = [:]
    private var recentlyEchoedTokens: [UInt32: Date] = [:]
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
    private func adoptRestored(_ restored: [Data: StoredEntry]) {
        for (key, entry) in restored where entries[key] == nil {
            entries[key] = entry
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

    func configureLocalFloodfill(_ enabled: Bool) {
        isFloodfillRouter = enabled
    }

    func registerFloodfill(_ hash: Data) {
        precondition(hash.count == 32)
        knownFloodfills.insert(hash)
        knownPeers.insert(hash)
    }

    func isFloodfill(_ hash: Data) -> Bool {
        knownFloodfills.contains(hash) || (hash == localRouterHash && isFloodfillRouter)
    }

    // MARK: Inbound message handling (entry point used by the transport)

    /// Handles an inbound netdb message. The transport layer calls this on delivery.
    func handleIncoming(_ message: I2PNetDBMessage) async {
        switch message {
        case .store(let s): await handleStore(s)
        case .lookup(let l): await handleLookup(l)
        case .searchReply(let r): handleSearchReply(r)
        }
    }

    private func handleStore(_ s: I2PDatabaseStore) async {
        // 1. Ingest — signature verification happens inside the structure parsers.
        let entry: StoredEntry
        do {
            entry = try Self.ingest(s.payload, entryType: s.entryType)
        } catch {
            return // unverifiable entry rejected
        }
        if let routerInfo = entry.routerInfo {
            learn(from: routerInfo)
        }
        guard !entry.isExpired() else { return }
        let key = s.key
        let now = Date()
        let existing = entries[key]
        let isDuplicate: Bool
        if let existing {
            isDuplicate = existing.raw == s.payload && !existing.isExpired(now)
        } else {
            isDuplicate = false
        }

        // 2. Token bookkeeping (acks for our own publishes, results for our own lookups).
        if s.replyToken > 0 {
            if outgoingStoreTokens.contains(s.replyToken) {
                pendingStoreAcks[s.replyToken, default: 0] += 1
            } else if outgoingLookupTokens.contains(s.replyToken) {
                pendingLookupResults[key] = entry
            }
        }

        // 3. Accept into cache + disk.
        if !isDuplicate {
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

        // 4. Acknowledge store requests addressed to someone else.
        if s.replyToken > 0, s.replyGateway != localRouterHash, !recentlyEchoed(s.replyToken) {
            recentlyEchoedTokens[s.replyToken] = now
            let ack = I2PDatabaseStore(
                key: key,
                entryType: s.entryType,
                replyToken: s.replyToken,
                replyTunnelId: s.replyTunnelId,
                replyGateway: s.replyGateway,
                payload: s.payload
            )
            try? await transport.send(to: s.replyGateway, message: .store(ack))
        }

        // 5. Floodfill replication: gossip to the next floodfills farther from the key.
        if isFloodfillRouter, !gossipedRecently(key, now: now) {
            recentlyReplicated[key] = now
            let gossip = I2PDatabaseStore(key: key, entryType: s.entryType, replyToken: 0, payload: s.payload)
            for target in gossipTargets(for: key) {
                try? await transport.send(to: target, message: .store(gossip))
            }
        }
    }

    private func handleLookup(_ l: I2PDatabaseLookup) async {
        guard l.fromHash != localRouterHash else { return }
        guard l.replyToken > 0 else { return }
        let replyTarget = l.replyGateway.isEmpty ? l.fromHash : l.replyGateway

        if let entry = entries[l.queryKey], !entry.isExpired() {
            // Answer with the entry itself.
            let reply = I2PDatabaseStore(
                key: l.queryKey,
                entryType: entry.entryType,
                replyToken: l.replyToken,
                replyTunnelId: l.replyTunnelId,
                replyGateway: replyTarget,
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
        entries[entry.key] = entry
        try? storage.persist(key: entry.key, record: I2PNetDBStorage.Record(
            entryType: I2PDatabaseEntryType.leaseSet.rawValue,
            storedAt: Date(),
            expiresAt: entry.expiresAt,
            payload: payload
        ))
        return await storeToNetDB(key: entry.key, entryType: .leaseSet, payload: payload, floodfillCount: floodfillCount)
    }

    /// Ingests a verified RouterInfo payload into the local database (no networking).
    func ingestRouterInfo(_ payload: Data) throws {
        let entry = try Self.ingest(payload, entryType: .routerInfo)
        guard !entry.isExpired() else { throw I2PWireError.invalidFormat }
        if let routerInfo = entry.routerInfo {
            learn(from: routerInfo)
        }
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
            try? await transport.send(to: target, message: .store(message))
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

    /// Looks up an entry: cache first, then iterative querying of the closest
    /// floodfills. Search replies are harvested to discover new floodfill candidates.
    func lookup(_ key: Data, timeoutPerRound: TimeInterval = 1.5, maxRounds: Int = 2) async -> StoredEntry? {
        precondition(key.count == 32)
        if let entry = entries[key], !entry.isExpired() {
            return entry
        }
        var queried: Set<Data> = []
        for _ in 0..<maxRounds {
            let candidates = selectFloodfills(for: key, count: Self.lookupFloodfillCount)
                .filter { !queried.contains($0) }
            guard !candidates.isEmpty else { break }
            let token = Self.newToken()
            outgoingLookupTokens.insert(token)
            pendingLookupResults.removeValue(forKey: key)
            pendingSearchReplies[key] = []
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
                    replyGateway: localRouterHash
                )
                try? await transport.send(to: floodfill, message: .lookup(message))
            }
            let deadline = Date().addingTimeInterval(timeoutPerRound)
            var discovered: Set<Data> = []
            while Date() < deadline {
                if let found = pendingLookupResults.removeValue(forKey: key) {
                    outgoingLookupTokens.remove(token)
                    return found
                }
                let replies = pendingSearchReplies[key] ?? []
                pendingSearchReplies[key] = []
                for reply in replies {
                    for peer in reply.peerHashes
                    where !knownFloodfills.contains(peer) && !queried.contains(peer) {
                        discovered.insert(peer)
                    }
                }
                if !discovered.isEmpty { break }
                try? await Task.sleep(for: .milliseconds(50))
            }
            outgoingLookupTokens.remove(token)
            // Iterative discovery: fetch RouterInfos for newly discovered peers to
            // learn whether they are floodfills, then query them in the next round.
            if maxRounds >= 2, !discovered.isEmpty {
                for peer in discovered {
                    if entries[peer] == nil {
                        _ = await lookup(peer, timeoutPerRound: timeoutPerRound, maxRounds: 1)
                    }
                }
            }
        }
        return nil
    }

    /// Looks up a router's RouterInfo by its identity hash.
    func lookupRouterInfo(_ routerHash: Data, timeoutPerRound: TimeInterval = 1.5, maxRounds: Int = 2) async -> I2PRouterInfo? {
        await lookup(routerHash, timeoutPerRound: timeoutPerRound, maxRounds: maxRounds)?.routerInfo
    }

    /// Resolves a destination (hash of the destination keys-and-certificate, or
    /// the publication key an LS2 store arrived under) to a signature-verified
    /// LeaseSet2 over the cache-first DHT path — the mainnet ECIES eepsite
    /// resolution path (proposal 123 store types 2/3/5).
    func lookupLeaseSet2(_ key: Data, timeoutPerRound: TimeInterval = 1.5, maxRounds: Int = 2) async -> I2PLeaseSet2? {
        await lookup(key, timeoutPerRound: timeoutPerRound, maxRounds: maxRounds)?.leaseSet2
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
            _ = await lookup(randomKey, timeoutPerRound: 1.5, maxRounds: 2)
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
            // LeaseSet2 (proposal 123): parse verifies the delegation block and
            // the body signature over type+length+data before acceptance.
            let leaseSet2 = try I2PLeaseSet2.parse(payload, expectedType: UInt16(entryType.rawValue))
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
        for (key, record) in storage.loadAll() {
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

    private func gossipedRecently(_ key: Data, now: Date) -> Bool {
        guard let last = recentlyReplicated[key] else { return false }
        return now.timeIntervalSince(last) < Self.replicationDedupWindow
    }

    private func recentlyEchoed(_ token: UInt32) -> Bool {
        guard let last = recentlyEchoedTokens[token] else { return false }
        return Date().timeIntervalSince(last) < Self.replicationDedupWindow
    }

    private static func newToken() -> UInt32 {
        UInt32.random(in: 1...UInt32.max)
    }
}