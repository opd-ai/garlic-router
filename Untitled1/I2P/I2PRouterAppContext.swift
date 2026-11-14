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
    /// When our RouterInfo was last (re-)published with the current caps.
    private(set) var lastRouterInfoPublishedAt: Date?
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

    /// The router surface the app's local clients build their sessions on:
    /// the SAMv3.3 bridge and the in-app eepsite browser.
    lazy var routerCore: I2PSAMRouterCore = {
        I2PSAMRouterCore(
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
    }()

    /// The SAMv3.3 API socket bound to this router (port 7656 by default).
    lazy var samServer: I2PSAMServer = {
        I2PSAMServer(core: self.routerCore, port: 7656)
    }()

    /// The eepsite browser's client destination (created on its first fetch):
    /// its own tunnel pool, published leases and the garlic stream machinery.
    /// Credentialled b33 hosts and address-book names come from the SAM bridge,
    /// which is where those destinations live.
    lazy var eepsiteBrowser: I2PEepsiteClient = {
        I2PEepsiteClient(
            core: self.routerCore,
            credentials: { [weak self] address in
                self?.samServer.b33Hosts().first { $0.address == address }?.credentials
            },
            addressBook: { [weak self] name in
                self?.samServer.addressbook[name]
            }
        )
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

        // Persisted participation controls apply before anything is published:
        // the bandwidth governor starts enforcing the saved caps, and the
        // RouterInfo carries the saved floodfill capability.
        let participation = I2PParticipationSettings.shared
        participation.applyBandwidthCaps()

        // NTCP2 transport with a signed RouterInfo; the delivery adapter
        // carries I2NP envelopes over established sessions and counts bytes.
        // One static key encoding end to end: the RouterInfo "s" option, the
        // static key inside SessionConfirmed part 1, and the key peers derive
        // from this router's identity must all be the same 32 bytes (peers
        // memcmp them, and i2pd rejects a RouterAddress whose "s" has the
        // X25519 top bit set).
        let publishedStaticKey = I2PCrypto.canonicalX25519PublicKey(encryptionKey.publicKey.rawRepresentation)
        let routerInfo = try! Self.makeRouterInfo(
            identity: identity,
            encryptionPublicKey: publishedStaticKey,
            signingSeed: signingSeed,
            floodfill: participation.floodfillEnabled
        )
        mainnetRouterInfo = routerInfo
        let transport = NTCP2Transport(localRouterInfo: routerInfo, staticKey: encryptionKey,
                                        localStaticPublicKey: publishedStaticKey)
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
        let database = I2PNetworkDatabase(
            localRouterHash: routerHash,
            transport: netdbAdapter,
            storage: storage
        )
        netDB = database
        // The netdb floodfill role is actor state: apply the persisted setting
        // as soon as the database exists.
        Task {
            await database.configureLocalFloodfill(participation.floodfillEnabled)
        }
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
        // The pool's own outbound builds need the same two things the live build
        // row had to add by hand: a reply route for the endpoint (an existing
        // inbound tunnel of ours, or our own router with a registered endpoint),
        // and a gateway handler for every endpoint this router owns — without
        // them a build reply has nowhere to land and every pool build times out.
        let pool = tunnelPool
        pool.replyRouteProvider = { [weak pool] in
            guard let pool,
                  let inbound = pool.inboundTunnels.first,
                  let gateway = inbound.hops.first?.routerHash else { return nil }
            return (gateway: gateway, tunnelID: inbound.gatewayTunnelID)
        }
        pool.installLocalEndpoint = { [weak router = i2npRouter] endpoint in
            router?.registerGateway(tunnelID: endpoint) { message, source in
                // Deliver the inner message back through the router so build
                // replies reach the participants' pending builds.
                Task { await router?.handleIncoming(message, from: source) }
            }
        }
        // Participation controls: the status engine reads live hop states for
        // the share reading, and the share ratio caps the tunnels we carry.
        participant.setTransitBudget(
            I2PTunnelParticipant.transitTunnelBudget(forSharePercent: participation.tunnelSharePercent)
        )
        engine.attach(participant: participant)
        engine.recordFloodfillAdvertisement(advertised: participation.floodfillEnabled,
                                           publishedAt: nil)
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
        // Let netdb lookups prefer floodfills we already have a session to, so
        // a cold DHT round trip does not burn its whole window on demand-dials.
        let sessionProbe = transport
        Task {
            await database.installReachabilityProbe { hash in
                sessionProbe.hasSession(for: hash)
            }
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
        // Re-apply the persisted participation controls (caps, share, netdb
        // role) so a resumed router matches what the screen shows.
        Task { await applyParticipationSettings() }
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

    // MARK: Participation controls

    /// Pushes the persisted participation controls onto the running router:
    /// the bandwidth caps into the governor, the tunnel-share ratio into the
    /// participating-tunnel budget, and the floodfill role into the netdb.
    /// The caps and the budget gate traffic immediately; the netdb role is
    /// effective the moment the actor applies it.
    func applyParticipationSettings() async {
        let settings = I2PParticipationSettings.shared
        settings.applyBandwidthCaps()
        tunnelParticipant.setTransitBudget(
            I2PTunnelParticipant.transitTunnelBudget(forSharePercent: settings.tunnelSharePercent)
        )
        await netDB.configureLocalFloodfill(settings.floodfillEnabled)
    }

    /// Turns the local netdb floodfill role on or off and re-publishes our
    /// RouterInfo carrying (or dropping) the floodfill capability, so peers
    /// learn the new role from the netdb rather than an out-of-band hint.
    func setFloodfillEnabled(_ enabled: Bool) async {
        I2PParticipationSettings.shared.floodfillEnabled = enabled
        await netDB.configureLocalFloodfill(enabled)
        await republishRouterInfo(floodfill: enabled)
    }

    /// Re-signs our RouterInfo with the currently advertised addresses and the
    /// given floodfill capability, then publishes it to the floodfills.
    func republishRouterInfo(floodfill: Bool) async {
        var options = mainnetRouterInfo.options
        options["caps"] = floodfill ? "f" : ""
        var advertised = I2PRouterInfo(
            identity: identity,
            published: Date(),
            addresses: mainnetRouterInfo.addresses,
            options: options
        )
        guard (try? advertised.sign(withSeed: signingSeed)) != nil else { return }
        mainnetRouterInfo = advertised
        lastRouterInfoPublishedAt = Date()
        engine.recordFloodfillAdvertisement(advertised: floodfill,
                                           publishedAt: lastRouterInfoPublishedAt)
        // Sessions must present the freshly signed address in message 3.
        ntcp2.updateLocalRouterInfo(advertised)
        _ = await netDB.publish(routerInfo: advertised)
    }

    /// Publishes our reachable address now instead of waiting for the next
    /// bootstrap cycle. Live-network checks call this before dialing: the
    /// handshake's message 3 carries the RouterInfo, and peers that compare the
    /// observed endpoint against the published address drop the session when it
    /// is still the bootstrap placeholder.
    func ensureReachableAddress() async {
        await advertiseReachableAddress()
    }

    /// Binds the NTCP2 listener, discovers our public IPv4 address over
    /// clearnet HTTPS, re-signs the RouterInfo with that address and
    /// re-publishes it to the floodfills. A no-op when the listener, the
    /// address probe or the floodfill set is unavailable.
    private func advertiseReachableAddress() async {
        try? await Task.sleep(for: .seconds(2))
        guard let port = ntcp2.listenerPort, port > 0 else { return }
        guard let address = try? await I2PExternalAddressDiscovery.publicIPv4Address() else { return }
        let floodfill = I2PParticipationSettings.shared.floodfillEnabled
        guard let advertised = try? Self.makeRouterInfo(
            identity: identity,
            // Use the exact key the transport handshakes with, so the "s"
            // option matches the static key in message 3 part 1.
            encryptionPublicKey: encryptionKey.publicKey.rawRepresentation,
            signingSeed: signingSeed,
            ntcp2Host: address,
            ntcp2Port: port,
            floodfill: floodfill
        ) else { return }
        mainnetRouterInfo = advertised
        lastRouterInfoPublishedAt = Date()
        engine.recordFloodfillAdvertisement(advertised: floodfill,
                                           publishedAt: lastRouterInfoPublishedAt)
        // From here on every handshake advertises the reachable address, so
        // peers that compare the observed endpoint against it keep the session.
        ntcp2.updateLocalRouterInfo(advertised)
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
    /// reseed (SU3 container verified against a bundled signer certificate,
    /// floodfill RouterInfos Ed25519-verified) → dial NTCP2 sessions
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
        // Advertise our reachable address before dialing: the handshake's
        // message 3 carries this RouterInfo, and peers drop sessions whose
        // published address does not match the endpoint they observe.
        await advertiseReachableAddress()
        await dialFloodfills(targetSessions: 8)
        let seeds = await netDB.selectFloodfills(for: routerHash, count: 8)
        _ = await netDB.bootstrap(seedFloodfills: seeds, targetPeers: 32, maxRounds: 4)
        await tunnelPeerProvider.refreshCandidates()
    }

    /// Dials NTCP2 sessions to the closest known floodfills until
    /// `targetSessions` are established, so netdb traffic has live transports.
    /// A deeper session set matters for the DHT: a lookup asks the floodfills
    /// closest to the *target key*, and only the peers we already hold sessions
    /// with can be queried without a cold demand-dial.
    /// Every candidate's RouterInfo is already in the netdb cache (reseeded),
    /// so endpoint resolution is cache-first and never recurses into a lookup.
    private func dialFloodfills(targetSessions: Int) async {
        let candidates = await netDB.selectFloodfills(for: routerHash, count: 24).prefix(16)
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
              let endpoint = NTCP2PeerEndpoint.preferred(from: info.addresses) else {
            return false
        }
        guard !ntcp2.hasSession(for: routerHash) else { return true }
        ntcp2.connect(host: endpoint.host, port: endpoint.port,
                      remoteRouterHash: info.identity.hash,
                      remoteStaticKey: endpoint.staticKey,
                      remoteIV: endpoint.iv)
        return true
    }

    /// A signed RouterInfo for our own identity (real key material). The
    /// `floodfill` capability follows the participation setting so every
    /// re-publication keeps the advertised role.
    private static func makeRouterInfo(identity: I2PRouterIdentity,
                                       encryptionPublicKey: Data,
                                       signingSeed: Data,
                                       ntcp2Host: String = "127.0.0.1",
                                       ntcp2Port: UInt16 = 0,
                                       floodfill: Bool = false) throws -> I2PRouterInfo {
        // NTCP2 §Published Router Info: a dialable address carries host, port,
        // the static key "s", the handshake IV "i" and v=2. A router that is not
        // listening yet publishes the spec's "unpublished" form instead — "s"
        // and "v" only — because advertising a host/port it does not serve makes
        // peers compare the observed endpoint against it and ban the router
        // right after message 3.
        let staticKey = I2PCrypto.canonicalX25519PublicKey(encryptionPublicKey)
        var options: [String: String] = [
            // "s" and "i" use the I2P base64 alphabet: '-' for '+' and '~' for
            // '/'. The trailing '=' padding is part of the wire form: reference
            // routers decode these options with EVP_DecodeBlock (i2pd), which
            // rejects unpadded input and then marks the whole RouterAddress
            // invalid — the address disappears and peers silently drop every
            // session right after SessionConfirmed.
            "s": I2PCrypto.i2pBase64(staticKey),
            "v": "2"
        ]
        let published = ntcp2Port != 0 && !Self.isLoopback(ntcp2Host)
        if published {
            options["host"] = ntcp2Host
            options["port"] = String(ntcp2Port)
            // The 16-byte AES IV peers obfuscate their ephemeral key with
            // (§SessionRequest). Derived from our router hash so it is stable
            // across restarts — a peer that cached an earlier RouterInfo still
            // de-obfuscates our inbound sessions.
            options["i"] = I2PCrypto.i2pBase64(Data(I2PCrypto.sha256(identity.hash).prefix(16)))
        }
        let address = I2PRouterAddress(
            cost: published ? 5 : 14,
            transportStyle: "NTCP2",
            expiration: nil,
            options: options
        )
        var routerInfo = I2PRouterInfo(
            identity: identity,
            published: Date(),
            addresses: [address],
            options: [
                // Peers compare this against their minimum supported router
                // version and drop (or ban) anything older that does not also
                // advertise a high-bandwidth capability tier.
                "router.version": "0.9.70",
                // Required by reference routers: i2pd marks a RouterInfo that
                // carries no `netId` option unreachable (its ReadFromBuffer
                // `!isNetId` check) and then terminates the session right after
                // SessionConfirmed with no reason — the silent post-message-3
                // close that kept every mainnet handshake from surviving.
                "netId": String(NTCP2Handshake.networkID),
                "caps": floodfill ? "fO" : "O"
            ]
        )
        try routerInfo.sign(withSeed: signingSeed)
        return routerInfo
    }

    private static func isLoopback(_ host: String) -> Bool {
        host.isEmpty || host == "127.0.0.1" || host == "0.0.0.0"
            || host == "::1" || host.hasPrefix("127.")
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
            Task {
                // Inbound bandwidth cap: the message waits for its tokens, so
                // a lowered cap slows ingress immediately.
                await I2PBandwidthGovernor.shared.admitInbound(bytes: data.count)
                await router.handleIncoming(message, from: source)
            }
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