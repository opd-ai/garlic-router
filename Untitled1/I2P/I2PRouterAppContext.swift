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
    private let identity: I2PRouterIdentity
    private let netDB: I2PNetworkDatabase
    private let ntcp2: NTCP2Transport
    private let deliveryTransport: I2PNTCP2DeliveryTransport
    private let i2npRouter: I2NPMessageRouter
    private let tunnelPool: I2PTunnelPool
    private var started = false
    private var ntcp2Bridge: NTCP2I2NPBridge?

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
           let restoredEncryption = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: encData) {
            signingKey = restoredSigning
            encryptionKey = restoredEncryption
        } else {
            signingKey = Curve25519.Signing.PrivateKey()
            encryptionKey = Curve25519.KeyAgreement.PrivateKey()
            defaults.set(signingKey.rawRepresentation.base64EncodedString(), forKey: "i2p.router.signingSeed")
            defaults.set(encryptionKey.rawRepresentation.base64EncodedString(), forKey: "i2p.router.encryptionKey")
        }
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

        // Tunnel pool: participants + build bus until NTCP2 peers carry builds.
        let buildHub = I2PTunnelBuildHub()
        let buildTransport = I2PTunnelLoopbackTransport(hub: buildHub, localRouterHash: routerHash)
        let participant = I2PTunnelParticipant(
            localRouterHash: routerHash,
            localEncryptionKey: encryptionKey,
            transport: buildTransport
        )
        buildHub.register(participant)
        tunnelPool = I2PTunnelPool(
            localRouterHash: routerHash,
            participant: participant,
            transport: buildTransport,
            peerProvider: EmptyTunnelPeerProvider()
        )
        engine.attach(tunnelPool: tunnelPool)
    }

    /// Starts the router: listener, netdb maintenance, tunnel pool
    /// maintenance and the status engine's event stream.
    func start() {
        guard !started else { return }
        started = true
        _ = try? ntcp2.startListener(port: 0)
        let bridge = NTCP2I2NPBridge(router: i2npRouter)
        ntcp2Bridge = bridge
        ntcp2.delegate = bridge
        Task { await netDB.startMaintenance() }
        tunnelPool.start()
        engine.start()
    }

    /// A signed RouterInfo for our own identity (real key material).
    private static func makeRouterInfo(identity: I2PRouterIdentity,
                                       encryptionPublicKey: Data,
                                       signingSeed: Data) throws -> I2PRouterInfo {
        let address = I2PRouterAddress(
            cost: 5,
            transportStyle: "NTCP2",
            expiration: nil,
            options: [
                "host": "127.0.0.1",
                "port": "0",
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
        for message in Self.i2npMessages(in: data) {
            Task { await router.handleIncoming(message, from: source) }
        }
    }

    func transport(_ transport: NTCP2Transport, sessionDidClose session: NTCP2Session) {}

    /// NTCP2 data blocks carry one or more concatenated I2NP messages.
    private static func i2npMessages(in data: Data) -> [I2NPMessage] {
        var out: [I2NPMessage] = []
        var buffer = data
        while buffer.count >= I2NPMessage.headerLength {
            guard let header = try? I2NPMessage.parseHeader(buffer) else { break }
            let total = I2NPMessage.headerLength + header.size
            guard buffer.count >= total, let message = try? I2NPMessage.parse(buffer.prefix(total)) else { break }
            out.append(message)
            buffer = Data(buffer.dropFirst(total))
        }
        return out
    }
}
