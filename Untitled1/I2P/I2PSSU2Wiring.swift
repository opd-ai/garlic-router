//
//  I2PSSU2Wiring.swift
//  Brings the SSU2 module into the running router: the RouterAddress a peer
//  dials (host, port, static key and introduction key), and the suite checks
//  that prove the wired transport is reachable through the app context rather
//  than only through the module's own tests.
//

import Foundation
import CryptoKit

// MARK: - Peer endpoint

/// A peer endpoint taken from an SSU2 RouterAddress: the host and port to dial,
/// the static key the Noise_XK handshake runs against ("s"), and the
/// introduction key that keys header obfuscation ("i"). Both are 32 bytes in
/// the I2P base 64 alphabet.
struct SSU2PeerEndpoint {
    let host: String
    let port: UInt16
    let staticKey: Data
    let introKey: Data

    init?(routerAddress: I2PRouterAddress) {
        guard routerAddress.transportStyle == "SSU2" else { return nil }
        guard let encodedKey = routerAddress.options["s"],
              let key = I2PCrypto.i2pBase64Decode(encodedKey),
              key.count == 32 else { return nil }
        guard let encodedIntro = routerAddress.options["i"],
              let intro = I2PCrypto.i2pBase64Decode(encodedIntro),
              intro.count == 32 else { return nil }
        guard let portText = routerAddress.options["port"], let port = UInt16(portText) else { return nil }
        self.host = routerAddress.options["host"] ?? "127.0.0.1"
        self.port = port
        self.staticKey = key
        self.introKey = intro
    }

    private init(host: String, port: UInt16, staticKey: Data, introKey: Data) {
        self.host = host
        self.port = port
        self.staticKey = staticKey
        self.introKey = introKey
    }

    /// The endpoint to dial out of a peer's RouterInfo: a published IPv4 SSU2
    /// address first, then any dialable one (IPv6-only candidates cannot be
    /// reached on cellular).
    static func preferred(from addresses: [I2PRouterAddress]) -> SSU2PeerEndpoint? {
        let endpoints = addresses.compactMap { SSU2PeerEndpoint(routerAddress: $0) }
        return endpoints.first(where: { !$0.host.contains(":") }) ?? endpoints.first
    }

    /// The cryptographic material a published SSU2 address carries, whether or
    /// not it is dialable yet: a router that is still binding its listener
    /// publishes the spec's unpublished shape ("s" and "i", no host/port), and
    /// that address still has to parse.
    static func publishedMaterial(in info: I2PRouterInfo) -> (staticKey: Data, introKey: Data)? {
        for address in info.addresses where address.transportStyle == "SSU2" {
            guard let s = address.options["s"],
                  let i = address.options["i"],
                  let staticKey = I2PCrypto.i2pBase64Decode(s), staticKey.count == 32,
                  let introKey = I2PCrypto.i2pBase64Decode(i), introKey.count == 32 else { continue }
            return (staticKey, introKey)
        }
        return nil
    }
}

// MARK: - Suite checks

/// The SSU2 half of the transport wiring, exercised through the app context the
/// app actually runs (the module's own suite covers the protocol layer):
/// the SSU2 address our published RouterInfo carries, and a dial over real UDP
/// loopback that goes through the running router's transport and delivery path.
enum I2PRouterTransportWiringSelfTest {
    static func runAll() async -> [I2PSelfTestResult] {
        var results: [I2PSelfTestResult] = []
        do {
            results.append(I2PSelfTestResult(name: "SSU2 wiring · published RouterInfo carries a parseable SSU2 address",
                                             passed: true,
                                             detail: try publishedAddressTest()))
        } catch {
            results.append(I2PSelfTestResult(name: "SSU2 wiring · published RouterInfo carries a parseable SSU2 address",
                                             passed: false,
                                             detail: "\(error)"))
        }
        do {
            results.append(I2PSelfTestResult(name: "SSU2 wiring · app-context dial and I2NP delivery over UDP loopback",
                                             passed: true,
                                             detail: try await wiredDialTest()))
        } catch {
            results.append(I2PSelfTestResult(name: "SSU2 wiring · app-context dial and I2NP delivery over UDP loopback",
                                             passed: false,
                                             detail: "\(error)"))
        }
        return results
    }

    /// Our published RouterInfo must carry an SSU2 address beside the NTCP2 one,
    /// and the key material in it must be the key material the running transport
    /// handshakes and obfuscates with — a RouterInfo that advertises a different
    /// static or introduction key makes every inbound SSU2 handshake fail.
    static func publishedAddressTest() throws -> String {
        let context = I2PRouterAppContext.shared
        // The wire form peers receive: parse verifies the signature whole.
        let parsed = try I2PRouterInfo.parse(context.mainnetRouterInfo.serialize())
        guard parsed.identity.hash == context.mainnetRouterHash else {
            throw SSU2Error.testFailed("published RouterInfo is not this router's identity")
        }
        let styles = parsed.addresses.map(\.transportStyle).sorted()
        guard styles.contains("NTCP2") else {
            throw SSU2Error.testFailed("published RouterInfo lost its NTCP2 address")
        }
        guard let material = SSU2PeerEndpoint.publishedMaterial(in: parsed) else {
            throw SSU2Error.testFailed("published RouterInfo carries no parseable SSU2 address")
        }
        let expectedStaticKey = I2PCrypto.canonicalX25519PublicKey(
            context.mainnetEncryptionKey.publicKey.rawRepresentation)
        guard material.staticKey == expectedStaticKey else {
            throw SSU2Error.testFailed("the SSU2 's' option is not the key the transport handshakes with")
        }
        guard material.introKey == context.mainnetSSU2IntroKey else {
            throw SSU2Error.testFailed("the SSU2 'i' option is not the introduction key the listener uses")
        }
        let dialable = context.mainnetRouterInfo.addresses.contains {
            $0.transportStyle == "SSU2" && SSU2PeerEndpoint(routerAddress: $0) != nil
        }
        return "addresses \(styles.joined(separator: "+")); SSU2 s/i decode to the transport's own keys"
            + (dialable ? "; dialable host+port published" : "; unpublished binding shape (no host/port yet)")
    }

    /// Dials a peer over SSU2 through the app context's transport — not through
    /// the module — over real UDP loopback, then sends an I2NP envelope down the
    /// same delivery path the netdb, garlic and tunnel builds ride.
    static func wiredDialTest() async throws -> String {
        let context = I2PRouterAppContext.shared
        let peerKey = Curve25519.KeyAgreement.PrivateKey()
        let peerSeed = I2PCrypto.generateEd25519Seed()
        let peerIntroKey = I2PCrypto.randomBytes(32)
        let peerIdentity = I2PRouterIdentity(
            encryptionPublicKey: peerKey.publicKey.rawRepresentation,
            signingPublicKey: I2PCrypto.ed25519PublicKey(fromSeed: peerSeed)
        )
        // The peer's listener binds an ephemeral port; the bootstrap RouterInfo
        // only has to be parseable until the bound port is known.
        let bootstrap = try peerRouterInfo(identity: peerIdentity, signingSeed: peerSeed,
                                           staticKey: peerKey.publicKey.rawRepresentation,
                                           introKey: peerIntroKey, host: "127.0.0.1", port: 0)
        let peerTransport = SSU2Transport(localStaticKey: peerKey, introKey: peerIntroKey,
                                          localRouterInfo: bootstrap,
                                          publishedEndpoint: SSU2Endpoint(host: "127.0.0.1", port: 0))
        defer { peerTransport.shutdown() }
        let collector = ReceivedI2NPCollector()
        peerTransport.delegate = collector
        defer { withExtendedLifetime(collector) {} }

        _ = try peerTransport.startListener(port: 0)
        var port: UInt16 = 0
        let bindDeadline = Date().addingTimeInterval(5)
        while port == 0, Date() < bindDeadline {
            try? await Task.sleep(for: .milliseconds(100))
            port = peerTransport.listenerPort ?? 0
        }
        guard port > 0 else { throw SSU2Error.testFailed("the peer listener never bound a port") }

        // The published address is what the dial reads, exactly as the router
        // reads a peer's address out of the netdb.
        let peerInfo = try peerRouterInfo(identity: peerIdentity, signingSeed: peerSeed,
                                          staticKey: peerKey.publicKey.rawRepresentation,
                                          introKey: peerIntroKey, host: "127.0.0.1", port: port)
        peerTransport.updateLocalRouterInfo(peerInfo)
        guard SSU2PeerEndpoint.preferred(from: peerInfo.addresses) != nil else {
            throw SSU2Error.testFailed("the peer's SSU2 address does not parse")
        }

        guard await context.dialSSU2(routerInfo: peerInfo, timeout: 10) else {
            throw SSU2Error.testFailed("the running router did not establish an SSU2 session")
        }
        guard context.mainnetSSU2.hasSession(forRouterHash: peerInfo.identity.hash) else {
            throw SSU2Error.testFailed("the established session is not indexed by the peer's router hash")
        }

        // I2NP delivery over the wired transport: the envelope a netdb store or
        // a tunnel build send would produce, at the same entry point.
        let envelope = I2NPMessage(type: .dataMessage,
                                   payload: Data("ssu2 wired delivery".utf8)).serialize()
        try await context.sendEnvelope(envelope, to: peerInfo.identity.hash)
        let deliveryDeadline = Date().addingTimeInterval(10)
        while !collector.hasReceived(envelope), Date() < deliveryDeadline {
            try? await Task.sleep(for: .milliseconds(100))
        }
        guard collector.hasReceived(envelope) else {
            throw SSU2Error.testFailed("the peer received no I2NP envelope over the SSU2 session")
        }

        let snapshot = await context.engine.snapshot()
        guard snapshot.ssu2SessionCount >= 1 else {
            throw SSU2Error.testFailed("the dashboard snapshot does not count the SSU2 session")
        }
        // Leave the running router as we found it: the loopback peer is torn
        // down with this test, so its session must not linger in the app's
        // transport count as a connected peer that no longer exists.
        context.mainnetSSU2.closeSession(forRouterHash: peerIdentity.hash)
        return "app context dialed the loopback peer, \(envelope.count)-byte I2NP envelope delivered over"
            + " the SSU2 session, dashboard reads \(snapshot.ssu2SessionCount) SSU2 / "
            + "\(snapshot.ntcp2SessionCount) NTCP2 session(s)"
    }

    /// A signed RouterInfo for the loopback peer, carrying one SSU2 address in
    /// the shape the router publishes.
    private static func peerRouterInfo(identity: I2PRouterIdentity, signingSeed: Data,
                                       staticKey: Data, introKey: Data,
                                       host: String, port: UInt16) throws -> I2PRouterInfo {
        var options: [String: String] = [
            "s": I2PCrypto.i2pBase64(staticKey),
            "i": I2PCrypto.i2pBase64(introKey),
            "v": "2"
        ]
        if port != 0 {
            options["host"] = host
            options["port"] = String(port)
        }
        let address = I2PRouterAddress(cost: port != 0 ? 6 : 14,
                                       transportStyle: "SSU2",
                                       expiration: nil,
                                       options: options)
        var info = I2PRouterInfo(
            identity: identity,
            published: Date(),
            addresses: [address],
            options: ["router.version": "0.9.70", "netId": "2", "caps": "O"]
        )
        try info.sign(withSeed: signingSeed)
        return info
    }

    /// Collects I2NP payloads the loopback peer's transport delivers.
    private final class ReceivedI2NPCollector: SSU2TransportDelegate {
        private let lock = NSLock()
        private var payloads: [Data] = []

        func hasReceived(_ payload: Data) -> Bool {
            lock.lock()
            defer { lock.unlock() }
            return payloads.contains(payload)
        }

        func transport(_ transport: SSU2Transport, sessionEstablished session: SSU2Session) {}

        func transport(_ transport: SSU2Transport, session: SSU2Session, didReceiveData data: Data) {
            lock.lock()
            payloads.append(data)
            lock.unlock()
        }

        func transport(_ transport: SSU2Transport, sessionDidClose session: SSU2Session) {}
    }
}
