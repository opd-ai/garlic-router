//
//  I2PRouterAppContext.swift
//  The running router backing the dashboard: real identity (persisted in
//  the Keychain), netdb with persistent storage, NTCP2 transport, tunnel pool
//  and I2NP router, all wired through the status engine's event stream.
//

import Foundation
import CryptoKit
import Security

final class I2PRouterAppContext {
    static let shared = I2PRouterAppContext()

    let engine: I2PRouterStatusEngine

    private let routerHash: Data
    private let signingSeed: Data
    private let encryptionKey: Curve25519.KeyAgreement.PrivateKey
    private let identity: I2PRouterIdentity
    private let netDB: I2PNetworkDatabase
    private let ntcp2: NTCP2Transport
    private let deliveryTransport: I2PNTCP2DeliveryTransport
    private let i2npRouter: I2NPMessageRouter
    private let tunnelPool: I2PTunnelPool
    private let tunnelBuildTransport: I2PTunnelBuildTransport
    private let tunnelParticipant: I2PTunnelParticipant
    private let tunnelPeerProvider: I2PMainnetTunnelPeerProvider
    private(set) var mainnetRouterInfo: I2PRouterInfo
    private(set) var lifecycleState: LifecycleState = .suspended
    private var started = false
    private var startedNetDBMaintenance = false
    private var ntcp2Bridge: NTCP2I2NPBridge?

    // MARK: Live bootstrap state
    /// The reseed → dial → explore keep-alive loop (spawns once per process).
    private var bootstrapTask: Task<Void, Never>?
    /// Last successful reseed; RouterInfos expire after ~1h, so the loop
    /// re-reseeds on a floor interval rather than waiting for the cache to drain.
    private var lastReseedAt = Date.distantPast
    /// Dial bookkeeping so concurrent demand-dials (netdb delivery, tunnel
    /// builds, the bootstrap dialer) never stack duplicate connection attempts.
    private let dialTracker = DemandDialTracker()
    /// Keep-alive cadence: reseed refresh, session re-dialing and DHT exploration.
    private static let bootstrapCycleInterval: TimeInterval = 900
    /// Re-reseed floor: the netdb prunes RouterInfos after an hour; a successful
    /// reseed older than this always refetches fresh verified seed data.
    private static let reseedFloorInterval: TimeInterval = 2700

    /// Router lifecycle states: running (transports, pools, SAM socket live)
    /// or suspended (clean shutdown — netdb state rides persistent storage).
    enum LifecycleState {
        case running
        case suspended
    }

    /// The SAMv3.3 API socket bound to this router (port 7656 by default).
    lazy var samServer: I2PSAMServer = {
        let core = I2PSAMRouterCore(
            routerHash: self.routerHash,
            netDB: self.netDB,
            participant: self.tunnelParticipant,
            buildTransport: self.tunnelBuildTransport,
            peerProvider: self.tunnelPeerProvider,
            delivery: self.deliveryTransport,
            i2npRouter: self.i2npRouter,
            controlledRouter: { [weak self] hash in
                guard let self, hash == self.routerHash else { return nil }
                return self.i2npRouter
            }
        )
        return I2PSAMServer(core: core, port: 7656)
    }()

    /// Live-network verification handles for the CI mainnet suite.
    var mainnetNetDB: I2PNetworkDatabase { netDB }
    var mainnetNTCP2: NTCP2Transport { ntcp2 }
    var mainnetTunnelPool: I2PTunnelPool { tunnelPool }
    var mainnetI2NPRouter: I2NPMessageRouter { i2npRouter }
    var mainnetRouterHash: Data { routerHash }
    var mainnetSignedRouterInfo: I2PRouterInfo { mainnetRouterInfo }
    var mainnetTunnelParticipant: I2PTunnelParticipant { tunnelParticipant }
    var mainnetEncryptionKey: Curve25519.KeyAgreement.PrivateKey { encryptionKey }

    private init() {
        // Router identity: an Ed25519 signing key plus an X25519 encryption
        // key, generated once per installation, persisted in the Keychain
        // (never in unprotected user-defaults storage) and reused on later
        // launches so the RouterHash is stable for the router's lifetime.
        let defaults = UserDefaults.standard
        // Migration: keys persisted in UserDefaults by earlier builds move into
        // the Keychain and are removed from the unprotected store.
        if I2PRouterKeychain.read(account: "signingSeed") == nil,
           let legacy = defaults.string(forKey: "i2p.router.signingSeed"),
           var data = Data(base64Encoded: legacy), data.count == 32 {
            I2PRouterKeychain.write(data, account: "signingSeed")
            I2PHardenedMemory.zeroize(&data)
            defaults.removeObject(forKey: "i2p.router.signingSeed")
        }
        if I2PRouterKeychain.read(account: "encryptionKey") == nil,
           let legacy = defaults.string(forKey: "i2p.router.encryptionKey"),
           var data = Data(base64Encoded: legacy), data.count == 32 {
            I2PRouterKeychain.write(data, account: "encryptionKey")
            I2PHardenedMemory.zeroize(&data)
            defaults.removeObject(forKey: "i2p.router.encryptionKey")
        }
        func hardenedIdentityKeys() -> (signingKey: Curve25519.Signing.PrivateKey,
                                         encryptionKey: Curve25519.KeyAgreement.PrivateKey) {
            if let storedSeed = I2PRouterKeychain.read(account: "signingSeed"),
               let storedEncryption = I2PRouterKeychain.read(account: "encryptionKey") {
                do {
                    // Zero trust for restored key material: length and degenerate-key
                    // checks run before the keys are used for anything. A poisoned
                    // or corrupted Keychain entry fails closed.
                    try I2PHardenedKeys.validate(storedSeed, context: "restored signing seed")
                    try I2PHardenedKeys.validate(storedEncryption, context: "restored encryption key")
                    let restoredSigning = try Curve25519.Signing.PrivateKey(rawRepresentation: storedSeed)
                    let restoredEncryption = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: storedEncryption)
                    I2PSecurityAuditLog.append(category: "identity", detail: "persisted identity restored and validated")
                    return (restoredSigning, restoredEncryption)
                } catch {
                    // Fail closed: unusable persisted identity is replaced with a
                    // freshly generated one rather than operated on.
                    let freshSigning = Curve25519.Signing.PrivateKey()
                    let freshEncryption = Curve25519.KeyAgreement.PrivateKey()
                    I2PRouterKeychain.write(freshSigning.rawRepresentation, account: "signingSeed")
                    I2PRouterKeychain.write(freshEncryption.rawRepresentation, account: "encryptionKey")
                    I2PSecurityAuditLog.append(category: "identity", detail: "persisted identity failed validation; regenerated fresh keys")
                    return (freshSigning, freshEncryption)
                }
            }
            let freshSigning = Curve25519.Signing.PrivateKey()
            let freshEncryption = Curve25519.KeyAgreement.PrivateKey()
            I2PRouterKeychain.write(freshSigning.rawRepresentation, account: "signingSeed")
            I2PRouterKeychain.write(freshEncryption.rawRepresentation, account: "encryptionKey")
            return (freshSigning, freshEncryption)
        }
        let identityKeys = hardenedIdentityKeys()
        let signingKey = identityKeys.signingKey
        let encryptionKey = identityKeys.encryptionKey
        self.encryptionKey = encryptionKey
        signingSeed = signingKey.rawRepresentation
        identity = I2PRouterIdentity(
            encryptionPublicKey: encryptionKey.publicKey.rawRepresentation,
            signingPublicKey: signingKey.publicKey.rawRepresentation
        )
        routerHash = identity.hash

        engine = I2PRouterStatusEngine(localRouterHash: routerHash)

        // NTCP2 transport with a signed RouterInfo; the delivery adapter
        // carries I2NP envelopes over established sessions and counts bytes.
        let routerInfo = try! Self.makeRouterInfo(
            identity: identity,
            encryptionPublicKey: encryptionKey.publicKey.rawRepresentation,
            signingSeed: signingSeed
        )
        mainnetRouterInfo = routerInfo
        let transport = NTCP2Transport(localRouterInfo: routerInfo, staticKey: encryptionKey)
        ntcp2 = transport
        deliveryTransport = I2PNTCP2DeliveryTransport(ntcp2: transport)
        deliveryTransport.onSent = { [weak engine] bytes in
            engine?.recordOutgoing(bytes: bytes)
        }

        // I2NP router with netdb bridging: netdb bodies flow both ways.
        i2npRouter = I2NPMessageRouter(localRouterHash: routerHash)
        i2npRouter.deliveryTransport = deliveryTransport
        let netdbAdapter = I2PNetDBI2NPAdapter(delivery: deliveryTransport)
        let storage = try! I2PNetDBStorage()
        netDB = I2PNetworkDatabase(
            localRouterHash: routerHash,
            transport: netdbAdapter,
            storage: storage
        )
        i2npRouter.addBodyHandler { [weak netDB] message, _ in
            guard let netDB, let netdbMessage = I2PNetDBI2NPBridge.inbound(message) else { return }
            Task { await netDB.handleIncoming(netdbMessage) }
        }
        engine.attach(netDB: netDB)
        engine.attach(to: i2npRouter)

        // Tunnel pool + hop participation: build messages and build replies
        // ride live NTCP2 sessions (surfaced by the mainnet CI suite — the
        // loopback build bus could never carry tunnel-build traffic to or
        // from real hops). The I2NP router dispatches tunnel builds and build
        // replies arriving over live sessions to the registered participant,
        // completing organic inbound acceptance and the originator reply path.
        let buildTransport = I2PNTCP2TunnelBuildTransport(ntcp2: transport)
        let participant = I2PTunnelParticipant(
            localRouterHash: routerHash,
            localEncryptionKey: encryptionKey,
            transport: buildTransport
        )
        i2npRouter.addTunnelParticipant(participant)
        tunnelBuildTransport = buildTransport
        tunnelParticipant = participant
        // Real hop candidates: signature-verified RouterInfos from the netdb,
        // refreshed by the bootstrap cycle, so the tunnel pool can build once
        // peers are known (the placeholder provider returned zero candidates
        // forever — "no tunnels yet" was structural, not a bootstrap timing issue).
        let netdbPeerProvider = I2PMainnetTunnelPeerProvider(netDB: netDB)
        tunnelPeerProvider = netdbPeerProvider
        tunnelPool = I2PTunnelPool(
            localRouterHash: routerHash,
            participant: participant,
            transport: buildTransport,
            peerProvider: netdbPeerProvider
        )
        engine.attach(tunnelPool: tunnelPool)
        // The dashboard and peer inspector read session counts and per-peer
        // readings through the status engine — it must observe the transport.
        engine.attach(ntcp2: transport)

        // Demand-dial hooks: a netdb delivery or tunnel build that finds no
        // session resolves the peer's RouterInfo (netdb cache-first, so the
        // hook never recurses into a network lookup for reseeded peers) and
        // dials it. Assigned after full initialization so the closures can
        // capture self safely.
        deliveryTransport.dialPeer = { [weak self] hash in
            guard let self else { return false }
            return await self.dial(routerHash: hash)
        }
        buildTransport.dialPeer = { [weak self] hash in
            guard let self else { return false }
            return await self.dial(routerHash: hash)
        }
    }

    /// Starts the router: listener, netdb maintenance, the live bootstrap
    /// cycle (reseed → floodfill dialing → DHT exploration → tunnel-hop
    /// refresh), the tunnel pool maintenance, the status engine's event stream,
    /// and the SAMv3.3 socket.
    func start() {
        guard !started else { return }
        started = true
        lifecycleState = .running
        _ = try? ntcp2.startListener(port: 0)
        let bridge = NTCP2I2NPBridge(router: i2npRouter)
        ntcp2Bridge = bridge
        ntcp2.delegate = bridge
        // The netdb maintenance loop spawns exactly once for the process
        // lifetime; resume cycles must not duplicate it.
        if !startedNetDBMaintenance {
            startedNetDBMaintenance = true
            Task { await netDB.startMaintenance() }
        }
        // The live bootstrap pipeline: this is what turns an empty netdb
        // (own RouterInfo only) into a connected router — reseed the netdb
        // from public reseed servers, dial floodfill sessions, publish the
        // advertised RouterInfo to them, explore the DHT, and refresh tunnel
        // hop candidates. Re-runs every cycle interval until shutdown, since
        // RouterInfos expire after about an hour and sessions decay.
        if bootstrapTask == nil {
            bootstrapTask = Task { [weak self] in
                await self?.bootstrapLoop()
            }
        }
        tunnelPool.start()
        engine.start()
        samServer.start()
    }

    /// Clean shutdown for app termination or background suspension: stops the
    /// NTCP2 listener and sessions, the bootstrap cycle, the tunnel pool's
    /// maintenance loop and the SAM socket. Netdb state rides persistent
    /// storage, so suspension loses nothing; a later resume restarts everything
    /// gracefully.
    func shutdownForTermination() {
        guard started else { return }
        started = false
        lifecycleState = .suspended
        bootstrapTask?.cancel()
        bootstrapTask = nil
        ntcp2.shutdown()
        tunnelPool.stop()
        samServer.stop()
    }

    /// Graceful restart on launch or after a background suspension. Re-running
    /// the reachability advertisement picks up network-interface changes.
    func resumeAfterBackground() {
        guard !started else { return }
        start()
    }

    /// Binds the NTCP2 listener, discovers our public IPv4 address over
    /// clearnet HTTPS, re-signs the RouterInfo with that address and
    /// re-publishes it to the floodfills. A no-op when the listener, the
    /// address probe or the floodfill set is unavailable.
    private func advertiseReachableAddress() async {
        try? await Task.sleep(for: .seconds(2))
        guard let port = ntcp2.listenerPort, port > 0 else { return }
        guard let address = try? await I2PExternalAddressDiscovery.publicIPv4Address() else { return }
        guard let advertised = try? Self.makeRouterInfo(
            identity: identity,
            encryptionPublicKey: identity.encryptionPublicKey,
            signingSeed: signingSeed,
            ntcp2Host: address,
            ntcp2Port: port
        ) else { return }
        mainnetRouterInfo = advertised
        _ = await netDB.publish(routerInfo: advertised)
    }

    // MARK: Live bootstrap

    /// The keep-alive bootstrap loop: one full pipeline cycle, then a rest,
    /// until shutdown. Failed cycles (a reseed host down, a handshake refused)
    /// simply retry on the next cycle.
    private func bootstrapLoop() async {
        while !Task.isCancelled {
            await bootstrapOnce()
            try? await Task.sleep(for: .seconds(Self.bootstrapCycleInterval))
        }
    }

    /// One live bootstrap cycle, in dependency order:
    /// reseed (floodfill RouterInfos, Ed25519-verified) → dial NTCP2 sessions
    /// to the closest floodfills → advertise our external address (a store
    /// needs reachable floodfill targets) → iterative DHT exploration through
    /// the established sessions → refresh tunnel-hop candidates.
    private func bootstrapOnce() async {
        let now = Date()
        let knownFloodfills = await netDB.floodfillCount()
        let reseedDue = now.timeIntervalSince(lastReseedAt) >= Self.reseedFloorInterval
            || knownFloodfills < 8
        if reseedDue {
            if (try? await I2PReseedService.reseed(into: netDB)) != nil {
                lastReseedAt = now
            }
        }
        await dialFloodfills(targetSessions: 4)
        await advertiseReachableAddress()
        let seeds = await netDB.selectFloodfills(for: routerHash, count: 8)
        _ = await netDB.bootstrap(seedFloodfills: seeds, targetPeers: 32, maxRounds: 4)
        await tunnelPeerProvider.refreshCandidates(limit: 12)
    }

    /// Dials NTCP2 sessions to the closest known floodfills until
    /// `targetSessions` are established, so netdb traffic has live transports.
    /// Every candidate's RouterInfo is already in the netdb cache (reseeded),
    /// so endpoint resolution is cache-first and never recurses into a lookup.
    private func dialFloodfills(targetSessions: Int) async {
        let candidates = await netDB.selectFloodfills(for: routerHash, count: 24)
        for hash in candidates {
            guard !ntcp2.hasSession(for: hash) else { continue }
            _ = await dial(routerHash: hash)
            let deadline = Date().addingTimeInterval(4)
            while !ntcp2.hasSession(for: hash), Date() < deadline {
                try? await Task.sleep(for: .milliseconds(250))
            }
            if ntcp2.sessionCount() >= targetSessions { break }
        }
    }

    /// Resolves a peer's NTCP2 endpoint from the netdb (cache-first) and
    /// initiates a dial. Returns true when a session already exists, a fresh
    /// dial was initiated, or another dial for the same peer is already in
    /// flight (the caller then waits for the session to appear). Reentrancy is
    /// serialized through the dial tracker so duplicate connection attempts
    /// never stack.
    private func dial(routerHash: Data) async -> Bool {
        if ntcp2.hasSession(for: routerHash) { return true }
        guard await dialTracker.claim(routerHash) else { return true }
        defer {
            Task { await dialTracker.release(routerHash) }
        }
        guard let info = await netDB.lookupRouterInfo(routerHash, timeoutPerRound: 1, maxRounds: 1),
              let endpoint = info.addresses.compactMap({ NTCP2PeerEndpoint(routerAddress: $0) }).first else {
            return false
        }
        guard !ntcp2.hasSession(for: routerHash) else { return true }
        ntcp2.connect(host: endpoint.host, port: endpoint.port, remoteStaticKey: endpoint.staticKey)
        return true
    }

    /// A signed RouterInfo for our own identity (real key material).
    private static func makeRouterInfo(identity: I2PRouterIdentity,
                                       encryptionPublicKey: Data,
                                       signingSeed: Data,
                                       ntcp2Host: String = "127.0.0.1",
                                       ntcp2Port: UInt16 = 0) throws -> I2PRouterInfo {
        let address = I2PRouterAddress(
            cost: 5,
            transportStyle: "NTCP2",
            expiration: nil,
            options: [
                "host": ntcp2Host,
                "port": String(ntcp2Port),
                "s": Self.urlSafeBase64(encryptionPublicKey)
            ]
        )
        var routerInfo = I2PRouterInfo(
            identity: identity,
            published: Date(),
            addresses: [address],
            options: ["caps": ""]
        )
        try routerInfo.sign(withSeed: signingSeed)
        return routerInfo
    }

    private static func urlSafeBase64(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
    }
}

/// Bridges established NTCP2 sessions into the I2NP router.
private final class NTCP2I2NPBridge: NTCP2TransportDelegate {
    private let router: I2NPMessageRouter

    init(router: I2NPMessageRouter) {
        self.router = router
    }

    func transport(_ transport: NTCP2Transport, sessionEstablished session: NTCP2Session) {}

    func transport(_ transport: NTCP2Transport, session: NTCP2Session, didReceiveData data: Data) {
        let source = session.remoteRouterHash ?? Data()
        // Data blocks carry one short-header I2NP message (converted to the
        // full internal framing by the session) or raw test payloads.
        if let message = try? I2NPMessage.parse(data) {
            Task { await router.handleIncoming(message, from: source) }
        }
    }

    func transport(_ transport: NTCP2Transport, sessionDidClose session: NTCP2Session) {}
}

// MARK: - Identity keychain

/// The router's private identity material lives in the Keychain (generic
/// password class, after-first-unlock accessibility) — never in unprotected
/// user-defaults storage, so the RouterHash is stable for the router's
/// lifetime and the raw keys never sit in an unencrypted plist.
enum I2PRouterKeychain {
    private static let service = "i2p.router.identity"

    static func read(account: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else { return nil }
        return result as? Data
    }

    @discardableResult
    static func write(_ data: Data, account: String) -> Bool {
        let attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(attributes as CFDictionary)
        var query = attributes
        query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        return SecItemAdd(query as CFDictionary, nil) == errSecSuccess
    }

    static func delete(account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)
    }
}