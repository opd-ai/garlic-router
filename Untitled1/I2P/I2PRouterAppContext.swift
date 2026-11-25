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
    private let ssu2: SSU2Transport
    /// The introduction key our SSU2 RouterAddress publishes ("i"): header
    /// obfuscation and the listener's responder sessions both key off it, so it
    /// must be identical to the option peers read.
    private let ssu2IntroKey: Data
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
    /// Strongly held: `SSU2Transport.delegate` is weak, and a bridge released
    /// here would silently drop every inbound SSU2 I2NP message.
    private var ssu2Bridge: SSU2I2NPBridge?

    // MARK: Live bootstrap state
    /// The reseed → dial → explore keep-alive loop (spawns once per process).
    private var bootstrapTask: Task<Void, Never>?
    /// Last successful reseed; RouterInfos expire after ~1h, so the loop
    /// re-reseeds on a floor interval rather than waiting for the cache to drain.
    /// Read by the live-interoperability screen, which reports the bootstrap
    /// this router actually used.
    private(set) var lastReseedAt = Date.distantPast
    /// The report of the most recent successful reseed (memory only): the
    /// source, the RouterInfos it carried and what survived verification.
    private(set) var lastReseedReport: I2PReseedReport?
    /// Dial bookkeeping so concurrent demand-dials (netdb delivery, tunnel
    /// builds, the bootstrap dialer) never stack duplicate connection attempts.
    private let dialTracker = DemandDialTracker()
    /// Peer handshake failure profiles (memory only, bounded): a dial that just
    /// failed is scheduled for its next attempt instead of being repeated by
    /// chance, and peers still inside their backoff are skipped where the
    /// router picks targets.
    private var handshakeBackoff: I2PPeerHandshakeBackoff { I2PPeerHandshakeBackoff.shared }
    /// How long a dial's session is watched for its handshake outcome. The
    /// transport bounds the connect at 8s and the handshake at 20s of its own,
    /// so this window only catches a session that outlives both.
    private static let handshakeWatchWindow: TimeInterval = 30
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

    /// The IRC client's connection: one client destination with its own tunnel
    /// pool, reused across server connections so the nick the server sees keeps
    /// the same destination. A b33 server and an address-book name resolve
    /// through the SAM bridge, which is where those destinations live.
    lazy var ircClient: I2PIRCClient = {
        I2PIRCClient(
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
    /// The UDP transport the running router dials and accepts SSU2 sessions on.
    var mainnetSSU2: SSU2Transport { ssu2 }
    /// The introduction key our published SSU2 address carries.
    var mainnetSSU2IntroKey: Data { ssu2IntroKey }
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
        // The SSU2 introduction key our RouterAddress publishes: header
        // obfuscation, the listener's responder sessions and every peer's
        // SessionRequest all derive from it, so it is derived from our identity
        // hash and therefore stable across restarts (a peer that cached an
        // earlier RouterInfo still de-obfuscates our inbound handshakes).
        let introKey = Self.ssu2IntroductionKey(for: routerHash)
        ssu2IntroKey = introKey
        let routerInfo = try! Self.makeRouterInfo(
            identity: identity,
            encryptionPublicKey: publishedStaticKey,
            signingSeed: signingSeed,
            ssu2IntroKey: introKey,
            floodfill: participation.floodfillEnabled
        )
        mainnetRouterInfo = routerInfo
        let transport = NTCP2Transport(localRouterInfo: routerInfo, staticKey: encryptionKey,
                                        localStaticPublicKey: publishedStaticKey)
        ntcp2 = transport
        // The UDP transport beside it: same identity, same signed RouterInfo,
        // handshaking with the exact static-key encoding the RouterAddress
        // publishes ("s"), so peers that compare the two agree.
        let udpTransport = SSU2Transport(localStaticKey: encryptionKey,
                                         introKey: introKey,
                                         localRouterInfo: routerInfo,
                                         localStaticPublicKey: publishedStaticKey)
        ssu2 = udpTransport
        deliveryTransport = I2PNTCP2DeliveryTransport(ntcp2: transport)
        deliveryTransport.ssu2 = udpTransport
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
        // Builds travel to hops with no NTCP2 session (or no NTCP2 address) over
        // SSU2: the envelopes are the same I2NP bodies on the UDP transport.
        buildTransport.ssu2 = udpTransport
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
        // Prefer hops this router already holds a session to: the first build
        // record has to reach its hop now, and demand-dialing a cold RouterInfo
        // spends the build window on a handshake that often stalls — which is
        // why the live pool logged attempts and adopted nothing.
        netdbPeerProvider.isConnected = { [weak transport, weak udpTransport] hash in
            (transport?.hasSession(for: hash) ?? false)
                || (udpTransport?.hasSession(forRouterHash: hash) ?? false)
        }
        // A blocked peer is never a hop, whatever the selector's scores say.
        let blocklist = I2PPeerBlocklist.shared
        netdbPeerProvider.isBlocked = { hash in blocklist.isBlocked(hash) }
        // A peer whose handshake just failed is held out of hop selection until
        // its backoff runs out: selecting it would spend the build's first
        // record on a handshake that is known to be failing right now.
        let backoff = I2PPeerHandshakeBackoff.shared
        netdbPeerProvider.isHandshakeHeldBack = { hash in backoff.isHeldBack(hash) }
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
            I2PTunnelParticipant.transitTunnelBudget(
                forSharePercent: participation.effectiveTunnelSharePercent())
        )
        engine.attach(participant: participant)
        engine.recordFloodfillAdvertisement(advertised: participation.floodfillEnabled,
                                           publishedAt: nil)
        // The dashboard and peer inspector read session counts and per-peer
        // readings through the status engine — it must observe both transports.
        engine.attach(ntcp2: transport)
        engine.attach(ssu2: udpTransport)
        // The handshake-failure profiles: the transport card counts the peers
        // the dial paths are holding back, and the peer inspector names each
        // peer's last failure and when its next attempt is due.
        engine.heldBackPeerCount = { backoff.heldBackCount() }
        engine.handshakeBackoffReading = { hash in backoff.reading(identityHex: hash) }

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
        let udpProbe = udpTransport
        Task {
            await database.installReachabilityProbe { hash in
                sessionProbe.hasSession(for: hash) || udpProbe.hasSession(forRouterHash: hash)
            }
        }
        // The blocklist also keeps blocked peers out of netdb lookups.
        Task {
            await database.installBlocklistProbe { hash in
                blocklist.isBlocked(hash)
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
        // The SSU2 listener: inbound SessionRequests demultiplex by our static
        // key, so peers that learned our RouterAddress can hand us SSU2 sessions
        // exactly as they hand us TCP ones.
        _ = try? ssu2.startListener(port: 0)
        let udpBridge = SSU2I2NPBridge(router: i2npRouter)
        ssu2Bridge = udpBridge
        ssu2.delegate = udpBridge
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
        startRepublishLoop()
        startQuietHoursWatchdog()
        startBlocklistSweep()
        startHandshakeBackoffSweep()
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
        republishTask?.cancel()
        republishTask = nil
        quietHoursTask?.cancel()
        quietHoursTask = nil
        blocklistTask?.cancel()
        blocklistTask = nil
        handshakeBackoffTask?.cancel()
        handshakeBackoffTask = nil
        ntcp2.shutdown()
        ssu2.shutdown()
        tunnelPool.stop()
        engine.stop()
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
    /// participating-tunnel budget (zero while quiet hours are in effect), and
    /// the floodfill role into the netdb. The caps and the budget gate traffic
    /// immediately; the netdb role is effective the moment the actor applies it.
    func applyParticipationSettings() async {
        let settings = I2PParticipationSettings.shared
        settings.applyBandwidthCaps()
        applyTransitBudget(for: settings)
        await netDB.configureLocalFloodfill(settings.floodfillEnabled)
    }

    /// Sets the participating-tunnel ceiling from the share ratio the schedule
    /// allows right now: the saved ratio outside quiet hours, zero inside them.
    private func applyTransitBudget(for settings: I2PParticipationSettings) {
        tunnelParticipant.setTransitBudget(
            I2PTunnelParticipant.transitTunnelBudget(
                forSharePercent: settings.effectiveTunnelSharePercent())
        )
    }

    /// Re-applies the transit budget every so often so a quiet window's start and
    /// end take effect on the running router without the screen open: the ceiling
    /// is zero inside the window and the saved share ratio outside it.
    private func startQuietHoursWatchdog() {
        guard quietHoursTask == nil else { return }
        quietHoursTask = Task { [weak self] in
            while let self, !Task.isCancelled {
                self.applyTransitBudget(for: I2PParticipationSettings.shared)
                try? await Task.sleep(for: .seconds(20))
            }
        }
    }

    /// Closes the session to every blocked peer. Called when the blocklist
    /// changes and by the periodic sweep, so a peer blocked mid-session — or one
    /// that reconnected — loses its connection on the next maintenance tick.
    func enforcePeerBlocklist() {
        let blocklist = I2PPeerBlocklist.shared
        guard blocklist.count > 0 else { return }
        for summary in ntcp2.sessionSummaries() where blocklist.isBlocked(summary.hash) {
            ntcp2.closeSession(for: summary.hash)
        }
        for summary in ssu2.sessionSummaries() where blocklist.isBlocked(summary.hash) {
            ssu2.closeSession(forRouterHash: summary.hash)
        }
    }

    /// Runs the blocklist enforcement on a short maintenance beat.
    private func startBlocklistSweep() {
        guard blocklistTask == nil else { return }
        blocklistTask = Task { [weak self] in
            while let self, !Task.isCancelled {
                self.enforcePeerBlocklist()
                try? await Task.sleep(for: .seconds(20))
            }
        }
    }

    // MARK: Handshake retry ladder

    /// Starts the retry beat: the backoff windows are minutes long, so a peer
    /// whose next attempt falls due is dialed here instead of waiting for the
    /// next build of the route table.
    private func startHandshakeBackoffSweep() {
        guard handshakeBackoffTask == nil else { return }
        handshakeBackoffTask = Task { [weak self] in
            while let self, !Task.isCancelled {
                await self.retryDueHandshakes()
                try? await Task.sleep(for: .seconds(20))
            }
        }
    }

    /// Dials the peers whose handshake backoff has run out, at most `limit` per
    /// beat. Only a peer this router holds no session to is attempted: a
    /// backoff window never closes a session that already handshook.
    @discardableResult
    func retryDueHandshakes(limit: Int = 3) async -> Int {
        var dialed = 0
        for hash in handshakeBackoff.dispatchableRetries(limit: limit) {
            guard !I2PPeerBlocklist.shared.isBlocked(hash) else { continue }
            if hasSession(to: hash) {
                // A manual dial or an inbound session won the race: the failure
                // is history and the schedule resets.
                handshakeBackoff.recordSuccess(hash)
                continue
            }
            guard await dial(routerHash: hash) else { continue }
            dialed += 1
        }
        return dialed
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
        // The republish cadence must be at most ~10 minutes: reference
        // routers republish every 10 minutes, and a RouterInfo entry expires
        // from the netdb after an hour of no republishes.
        republishInterval = min(60 * 10, republishInterval)
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
        // SSU2 sessions carry the same RouterInfo (in the SessionConfirmed for
        // an initiator, the SessionCreated payload for a responder).
        ssu2.updateLocalRouterInfo(advertised)
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
        // Either listener is enough to be dialable: a router whose TCP port is
        // taken still takes SSU2 sessions on the UDP port.
        let tcpPort = ntcp2.listenerPort ?? 0
        let udpPort = ssu2.listenerPort ?? 0
        guard tcpPort > 0 || udpPort > 0 else { return }
        guard let address = try? await I2PExternalAddressDiscovery.publicIPv4Address() else { return }
        let floodfill = I2PParticipationSettings.shared.floodfillEnabled
        guard let advertised = try? Self.makeRouterInfo(
            identity: identity,
            // Use the exact key the transport handshakes with, so the "s"
            // option matches the static key in message 3 part 1.
            encryptionPublicKey: encryptionKey.publicKey.rawRepresentation,
            signingSeed: signingSeed,
            ntcp2Host: address,
            ntcp2Port: tcpPort,
            ssu2Host: address,
            ssu2Port: udpPort,
            ssu2IntroKey: ssu2IntroKey,
            floodfill: floodfill
        ) else { return }
        mainnetRouterInfo = advertised
        lastRouterInfoPublishedAt = Date()
        engine.recordFloodfillAdvertisement(advertised: floodfill,
                                           publishedAt: lastRouterInfoPublishedAt)
        // From here on every handshake advertises the reachable address, so
        // peers that compare the observed endpoint against it keep the session.
        ntcp2.updateLocalRouterInfo(advertised)
        ssu2.updateLocalRouterInfo(advertised)
        ssu2.updatePublishedEndpoint(udpPort > 0 ? SSU2Endpoint(host: address, port: udpPort) : nil)
        _ = await netDB.publish(routerInfo: advertised)
    }

    /// The RouterInfo republish cadence (reference routers republish on a
    /// ~10-minute cycle; the live pool's inbound tunnel re-publish rides the
    /// same hook). Set by `advertiseReachableAddress` and the cycle.
    private var republishInterval: TimeInterval = 60 * 10
    /// The periodic republish/keepalive loop.
    private var republishTask: Task<Void, Never>?
    /// Re-applies the transit budget as the quiet-hours window opens and closes.
    private var quietHoursTask: Task<Void, Never>?
    /// Closes sessions to blocked peers on a maintenance beat.
    private var blocklistTask: Task<Void, Never>?
    /// Dispatches the handshake retries whose backoff has run out.
    private var handshakeBackoffTask: Task<Void, Never>?

    /// Starts the periodic republish loop (the router's publication
    /// heartbeat): a re-signed RouterInfo goes out on the cadence
    /// `republishInterval`, so a live netdb never holds a stale RouterInfo
    /// for us — the one prerequisite inbound tunnel participation and
    /// inbound handshakes have that nothing else supplies.
    private func startRepublishLoop() {
        guard republishTask == nil else { return }
        republishTask = Task { [weak self] in
            while let self, !Task.isCancelled {
                try? await Task.sleep(for: .seconds(self.republishInterval))
                guard !Task.isCancelled else { break }
                await self.republishRouterInfo(
                    floodfill: I2PParticipationSettings.shared.floodfillEnabled)
            }
        }
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
            if let report = try? await I2PReseedService.reseed(into: netDB) {
                lastReseedAt = now
                lastReseedReport = report
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
            // Peers held back after a failed handshake are skipped here: the
            // selection would otherwise spend a dial window on a peer that is
            // known to be failing right now.
            guard !handshakeBackoff.isHeldBack(hash) else { continue }
            _ = await dial(routerHash: hash)
            let deadline = Date().addingTimeInterval(4)
            while !ntcp2.hasSession(for: hash), Date() < deadline {
                try? await Task.sleep(for: .milliseconds(250))
            }
            if ntcp2.sessionCount() >= targetSessions { break }
        }
    }

    /// Dials the closest floodfills until at least `target` NTCP2 sessions are
    /// live or `within` seconds pass (best effort; returns the live count).
    ///
    /// Organic participation — a peer forwarding a tunnel build to us — rides a
    /// live session in either direction, because an NTCP2 session is
    /// bidirectional. The size of the live session set is what a participation
    /// window's chance rests on, so this keeps dialing candidates until the set
    /// is healthy instead of accepting whatever an earlier row left behind.
    @discardableResult
    func ensureSessions(atLeast target: Int, within: TimeInterval) async -> Int {
        let deadline = Date().addingTimeInterval(within)
        var attempted: Set<Data> = []
        while Date() < deadline, ntcp2.sessionCount() < target {
            let candidates = await netDB.selectFloodfills(for: routerHash, count: 32)
            for hash in candidates {
                guard ntcp2.sessionCount() < target else { break }
                guard !ntcp2.hasSession(for: hash), !attempted.contains(hash) else { continue }
                // A peer inside its handshake backoff is skipped, not retried.
                guard !handshakeBackoff.isHeldBack(hash) else { continue }
                attempted.insert(hash)
                _ = await dial(routerHash: hash)
            }
            if ntcp2.sessionCount() >= target { break }
            try? await Task.sleep(for: .milliseconds(500))
        }
        return ntcp2.sessionCount()
    }

    /// Resolves a peer's NTCP2 endpoint from the netdb (cache-first) and
    /// initiates a dial. Returns true when a session already exists, a fresh
    /// dial was initiated, or another dial for the same peer is already in
    /// flight (the caller then waits for the session to appear). Reentrancy is
    /// serialized through the dial tracker so duplicate connection attempts
    /// never stack.
    private func dial(routerHash: Data) async -> Bool {
        // A blocked peer is never dialed: the user asked us to have nothing to
        // do with it, so demand-dials and session top-ups skip it.
        guard !I2PPeerBlocklist.shared.isBlocked(routerHash) else { return false }
        // A peer still inside its handshake backoff is skipped as well: repeating
        // a handshake that just failed spends the dial window on nothing. The
        // retry beat dials it again once the window has run out.
        guard !handshakeBackoff.isHeldBack(routerHash) else { return false }
        if hasSession(to: routerHash) { return true }
        guard await dialTracker.claim(routerHash) else { return true }
        defer {
            Task { await dialTracker.release(routerHash) }
        }
        guard let info = await netDB.lookupRouterInfo(routerHash, timeoutPerRound: 1, maxRounds: 1) else {
            return false
        }
        guard !hasSession(to: routerHash) else { return true }
        // TCP first: an NTCP2 session is the cheaper path wherever a peer
        // publishes an NTCP2 address.
        if let endpoint = NTCP2PeerEndpoint.preferred(from: info.addresses) {
            let session = ntcp2.connect(host: endpoint.host, port: endpoint.port,
                                        remoteRouterHash: info.identity.hash,
                                        remoteStaticKey: endpoint.staticKey,
                                        remoteIV: endpoint.iv)
            // The attempt's ending is recorded against the peer's profile, so a
            // failed dial schedules the next attempt instead of leaving the peer
            // to chance.
            watchHandshake(of: session, peer: info.identity.hash)
            // SSU2 is the fallback when that handshake never lands, so a peer
            // reachable only over UDP does not stay unreachable.
            scheduleSSU2Fallback(routerInfo: info)
            return true
        }
        // No NTCP2 address works at all: dial the peer over SSU2 instead.
        if let endpoint = SSU2PeerEndpoint.preferred(from: info.addresses) {
            try? ssu2.connect(host: endpoint.host, port: endpoint.port,
                              remoteStaticKey: endpoint.staticKey,
                              remoteIntroKey: endpoint.introKey)
            return true
        }
        return false
    }

    /// Whether either transport holds a live session to the peer.
    private func hasSession(to routerHash: Data) -> Bool {
        ntcp2.hasSession(for: routerHash) || ssu2.hasSession(forRouterHash: routerHash)
    }

    /// Watches one dial's session and folds its ending into the peer's handshake
    /// profile: a session that handshakes at all resets the retry schedule, and a
    /// session that never establishes records its failure and moves the peer to
    /// the next rung. Nothing is closed here — the transport owns its own connect
    /// and handshake timers, and an established session is left alone.
    private func watchHandshake(of session: NTCP2Session?, peer hash: Data) {
        guard let session else { return }
        let backoff = handshakeBackoff
        Task {
            let deadline = Date().addingTimeInterval(Self.handshakeWatchWindow)
            while Date() < deadline {
                if session.isEstablished || session.state == .closed { break }
                try? await Task.sleep(for: .milliseconds(250))
            }
            if session.isEstablished || session.establishedAt != nil {
                backoff.recordSuccess(hash)
                return
            }
            // A session still handshaking past its own window is a handshake
            // timeout; a closed one names its own ending.
            let reason: I2PPeerHandshakeFailureReason?
            if session.state == .closed {
                reason = I2PPeerHandshakeFailureReason.classify(closeReason: session.closeReason)
            } else if session.state == .handshaking {
                reason = .handshakeTimeout
            } else {
                reason = nil
            }
            if let reason { backoff.recordFailure(hash, reason: reason) }
        }
    }

    /// Waits out the NTCP2 handshake window and, when no TCP session appeared,
    /// dials the same peer over SSU2. The dial path itself stays non-blocking,
    /// so callers keep the timing they already budget for.
    private func scheduleSSU2Fallback(routerInfo: I2PRouterInfo) {
        guard SSU2PeerEndpoint.preferred(from: routerInfo.addresses) != nil else { return }
        let hash = routerInfo.identity.hash
        Task { [weak self] in
            try? await Task.sleep(for: .seconds(4))
            guard let self, !Task.isCancelled else { return }
            guard !self.ntcp2.hasSession(for: hash),
                  !self.ssu2.hasSession(forRouterHash: hash) else { return }
            _ = await self.dialSSU2(routerInfo: routerInfo, timeout: 4)
        }
    }

    // MARK: SSU2 dialing

    /// Dials a peer over SSU2 through the running transport and waits for the
    /// session to establish: the route taken when a peer publishes no NTCP2
    /// address, when its TCP handshake never lands, and by the wiring suite.
    @discardableResult
    func dialSSU2(routerInfo: I2PRouterInfo, timeout: TimeInterval = 8) async -> Bool {
        let hash = routerInfo.identity.hash
        guard !I2PPeerBlocklist.shared.isBlocked(hash) else { return false }
        if ssu2.hasSession(forRouterHash: hash) { return true }
        guard let endpoint = SSU2PeerEndpoint.preferred(from: routerInfo.addresses) else { return false }
        try? ssu2.connect(host: endpoint.host, port: endpoint.port,
                          remoteStaticKey: endpoint.staticKey,
                          remoteIntroKey: endpoint.introKey)
        let deadline = Date().addingTimeInterval(timeout)
        while !ssu2.hasSession(forRouterHash: hash), Date() < deadline {
            try? await Task.sleep(for: .milliseconds(150))
        }
        let established = ssu2.hasSession(forRouterHash: hash)
        // A successful SSU2 handshake resets the peer's retry schedule exactly as
        // a TCP one does: the peer is not failing, it just answers over UDP.
        if established { handshakeBackoff.recordSuccess(hash) }
        return established
    }

    /// Sends one I2NP envelope down the running router's delivery path, which
    /// rides whichever transport holds a session to the peer.
    func sendEnvelope(_ i2npBytes: Data, to routerHash: Data) async throws {
        try await deliveryTransport.deliver(i2npBytes, to: routerHash)
    }

    /// A signed RouterInfo for our own identity (real key material). The
    /// `floodfill` capability follows the participation setting so every
    /// re-publication keeps the advertised role.
    private static func makeRouterInfo(identity: I2PRouterIdentity,
                                       encryptionPublicKey: Data,
                                       signingSeed: Data,
                                       ntcp2Host: String = "127.0.0.1",
                                       ntcp2Port: UInt16 = 0,
                                       ssu2Host: String = "127.0.0.1",
                                       ssu2Port: UInt16 = 0,
                                       ssu2IntroKey: Data,
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
        // The SSU2 address beside it: the same static key "s" (the bytes the
        // handshake carries), the introduction key "i" that keys header
        // obfuscation, and v=2. It follows the NTCP2 publication rule — a
        // router that is not listening publishes "s"/"i"/"v" without a host or
        // port, because advertising an endpoint it does not serve makes peers
        // drop it.
        var udpOptions: [String: String] = [
            "s": I2PCrypto.i2pBase64(staticKey),
            "i": I2PCrypto.i2pBase64(ssu2IntroKey),
            "v": "2"
        ]
        let udpPublished = ssu2Port != 0 && !Self.isLoopback(ssu2Host)
        if udpPublished {
            udpOptions["host"] = ssu2Host
            udpOptions["port"] = String(ssu2Port)
        }
        let udpAddress = I2PRouterAddress(
            cost: udpPublished ? 6 : 14,
            transportStyle: "SSU2",
            expiration: nil,
            options: udpOptions
        )
        var routerInfo = I2PRouterInfo(
            identity: identity,
            published: Date(),
            addresses: [address, udpAddress],
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

    /// The introduction key our SSU2 RouterAddress publishes ("i"): header
    /// obfuscation, the listener's responder sessions and every peer's
    /// SessionRequest derive from it, so it is derived from the identity hash
    /// and stays the same across launches — a peer that cached an earlier
    /// RouterInfo still de-obfuscates our inbound handshakes.
    private static func ssu2IntroductionKey(for routerHash: Data) -> Data {
        var material = routerHash
        material.append(Data("SSU2 introduction key".utf8))
        return I2PCrypto.sha256(material)
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

    func transport(_ transport: NTCP2Transport, sessionEstablished session: NTCP2Session) {
        // Any successful handshake — ours or the peer's — resets that peer's
        // retry schedule.
        if let hash = session.remoteRouterHash {
            I2PPeerHandshakeBackoff.shared.recordSuccess(hash)
        }
    }

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

/// Bridges established SSU2 sessions into the I2NP router: the UDP transport
/// hands over the same I2NP bytes an NTCP2 session does, so netdb traffic,
/// garlic messages, tunnel data and tunnel builds travel it unchanged.
private final class SSU2I2NPBridge: SSU2TransportDelegate {
    private let router: I2NPMessageRouter

    init(router: I2NPMessageRouter) {
        self.router = router
    }

    func transport(_ transport: SSU2Transport, sessionEstablished session: SSU2Session) {
        // The UDP session is the peer answering after all: reset its schedule.
        if let hash = session.remoteRouterHash {
            I2PPeerHandshakeBackoff.shared.recordSuccess(hash)
        }
    }

    func transport(_ transport: SSU2Transport, session: SSU2Session, didReceiveData data: Data) {
        let source = session.remoteRouterHash ?? Data()
        if let message = try? I2NPMessage.parse(data) {
            Task {
                // Inbound bandwidth cap: the message waits for its tokens, the
                // same admission an NTCP2 data block passes through.
                await I2PBandwidthGovernor.shared.admitInbound(bytes: data.count)
                await router.handleIncoming(message, from: source)
            }
        }
    }

    func transport(_ transport: SSU2Transport, sessionDidClose session: SSU2Session) {}
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