//
//  I2PRouterAppContext.swift
//  The running router backing the dashboard: real identity (persisted),
//  netdb with persistent storage, NTCP2 transport, tunnel pool and I2NP
//  router, all wired through the status engine's event stream.
//

import Foundation
import CryptoKit

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
    private let tunnelPeerProvider: I2PTunnelPeerProvider
    private(set) var mainnetRouterInfo: I2PRouterInfo
    private var started = false
    private var ntcp2Bridge: NTCP2I2NPBridge?

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
        // key, generated once per installation and reused on later launches.
        let defaults = UserDefaults.standard
        let signingKey: Curve25519.Signing.PrivateKey
        let encryptionKey: Curve25519.KeyAgreement.PrivateKey
        if let storedSeed = defaults.string(forKey: "i2p.router.signingSeed"),
           let seed = Data(base64Encoded: storedSeed), seed.count == 32,
           let storedEnc = defaults.string(forKey: "i2p.router.encryptionKey"),
           let encData = Data(base64Encoded: storedEnc), encData.count == 32,
           let restoredSigning = try? Curve25519.Signing.PrivateKey(rawRepresentation: seed),
           let restoredEncryption = try? Curve25519.Signing.PrivateKey(rawRepresentation: encData) {
            signingKey = restoredSigning
            encryptionKey = restoredEncryption
        } else {
            signingKey = Curve25519.Signing.PrivateKey()
            encryptionKey = Curve25519.KeyAgreement.PrivateKey()
            defaults.set(signingKey.rawRepresentation.base64EncodedString(), forKey: "i2p.router.signingSeed")
            defaults.set(encryptionKey.rawRepresentation.base64EncodedString(), forKey: "i2p.router.encryptionKey")
        }
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
        tunnelPeerProvider = EmptyTunnelPeerProvider()
        tunnelPool = I2PTunnelPool(
            localRouterHash: routerHash,
            participant: participant,
            transport: buildTransport,
            peerProvider: tunnelPeerProvider
        )
        engine.attach(tunnelPool: tunnelPool)
    }

    /// Starts the router: listener, netdb maintenance, tunnel pool
    /// maintenance, the status engine's event stream, and the SAMv3.3 socket.
    func start() {
        guard !started else { return }
        started = true
        _ = try? ntcp2.startListener(port: 0)
        let bridge = NTCP2I2NPBridge(router: i2npRouter)
        ntcp2Bridge = bridge
        ntcp2.delegate = bridge
        Task { await netDB.startMaintenance() }
        // Reachability advertisement (surfaced by the mainnet CI suite): a
        // real router publishes its external address so mainnet peers can
        // dial us for inbound tunnel participation.
        Task { await advertiseReachableAddress() }
        tunnelPool.start()
        engine.start()
        samServer.start()
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