//
//  I2PNTCP2Tests.swift
//  I2P
//
//  Self-tests for the NTCP2 transport: in-memory Noise_XK handshake, data-phase
//  framing/blocks, and full TCP sessions over loopback.
//

import Foundation
import CryptoKit

enum I2PTestTimeout: Error { case timedOut }

private func waitUntil(_ condition: @escaping () -> Bool,
                       timeout: TimeInterval = 10,
                       _ message: String = "condition") async throws {
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        if condition() { return }
        try await Task.sleep(for: .milliseconds(50))
    }
    if condition() { return }
    throw I2PTestTimeout.timedOut
}

enum I2PNTCP2SelfTest {
    static func runAll() async -> [I2PSelfTestResult] {
        var results: [I2PSelfTestResult] = []
        func run(_ name: String, _ body: () async throws -> String) async {
            do {
                let detail = try await body()
                results.append(I2PSelfTestResult(name: name, passed: true, detail: detail))
            } catch {
                results.append(I2PSelfTestResult(name: name, passed: false, detail: String(describing: error)))
            }
        }
        await run("NTCP2 Noise_XK handshake (in-memory)") { try inMemoryHandshakeTest() }
        await run("NTCP2 data framing & blocks") { try framingTest() }
        await run("NTCP2 TCP sessions (loopback)") { try await tcpLoopbackTest() }
        return results
    }

    // MARK: - Helpers

    private static func makeSignedRouterInfo(addressOptions: [String: String]? = nil) throws -> I2PRouterInfo {
        let seed = I2PCrypto.generateEd25519Seed()
        let x25519 = I2PCrypto.generateX25519KeyPair()
        let identity = I2PKeysAndCert(encryptionPublicKey: x25519.publicKey,
                                      signingPublicKey: I2PCrypto.ed25519PublicKey(fromSeed: seed))
        var options = ["router.version": "0.9.62"]
        if let addressOptions { options = addressOptions }
        var info = I2PRouterInfo(identity: identity,
                                 published: Date(),
                                 addresses: [I2PRouterAddress(cost: 5,
                                                              transportStyle: "NTCP2",
                                                              expiration: nil,
                                                              options: addressOptions ?? ["host": "127.0.0.1", "port": "0"])],
                                 options: options)
        try info.sign(withSeed: seed)
        return info
    }

    private static func performHandshake(riA: I2PRouterInfo, riB: I2PRouterInfo) throws -> (
        initiator: NTCP2InitiatorHandshake,
        responder: NTCP2ResponderHandshake
    ) {
        let aliceStatic = Curve25519.KeyAgreement.PrivateKey()
        let bobStatic = Curve25519.KeyAgreement.PrivateKey()
        let initiator = try NTCP2InitiatorHandshake(localStaticKey: aliceStatic,
                                                    remoteStaticKey: bobStatic.publicKey.rawRepresentation)
        let responder = NTCP2ResponderHandshake(localStaticKey: bobStatic)
        let request = try initiator.makeSessionRequest(routerInfo: riA.serialize(), padding: 13)
        let created = try responder.processSessionRequest(request, padding: 7)
        guard created.consumed == request.count else {
            throw NTCP2Error.handshakeFailed("message 1 consumed length mismatch")
        }
        let confirm = try initiator.processSessionCreated(created.reply)
        guard confirm.consumed == created.reply.count else {
            throw NTCP2Error.handshakeFailed("message 2 consumed length mismatch")
        }
        _ = try responder.processSessionConfirm(confirm.message)
        return (initiator, responder)
    }

    // MARK: - Tests

    private static func inMemoryHandshakeTest() throws -> String {
        let riA = try makeSignedRouterInfo()
        let riB = try makeSignedRouterInfo()
        let (initiator, responder) = try performHandshake(riA: riA, riB: riB)

        let aliceKeys = try initiator.complete()
        let bobKeys = try responder.complete()
        guard aliceKeys.sendKeys.aeadKey == bobKeys.recvKeys.aeadKey,
              aliceKeys.recvKeys.aeadKey == bobKeys.sendKeys.aeadKey,
              aliceKeys.sendKeys.sipKey == bobKeys.recvKeys.sipKey else {
            throw NTCP2Error.handshakeFailed("direction keys disagree")
        }
        guard responder.remoteRouterInfo == riA.serialize() else {
            throw NTCP2Error.handshakeFailed("responder RouterInfo mismatch")
        }
        return "XK handshake: direction keys derived, static keys exchanged"
    }

    private static func framingTest() throws -> String {
        let riA = try makeSignedRouterInfo()
        let riB = try makeSignedRouterInfo()
        let (initiator, responder) = try performHandshake(riA: riA, riB: riB)
        let aliceKeys = try initiator.complete()
        let bobKeys = try responder.complete()

        var tx = NTCP2FrameCodec(directionKeys: aliceKeys.sendKeys)
        var rx = NTCP2FrameCodec(directionKeys: bobKeys.recvKeys)

        let timestamp = Date(timeIntervalSince1970: 1_700_000_000)
        let blocks: [NTCP2Block] = [
            .data(Data("i2np payload".utf8)),
            .options(["ntcp2": "1"]),
            .time(timestamp),
            .termination(reason: 0, validTime: Date(timeIntervalSince1970: 1_700_000_100)),
        ]
        var wire = Data()
        wire += try tx.frame(NTCP2Block.aligned(try NTCP2Block.encode(blocks)))
        wire += try tx.frame(NTCP2Block.aligned(try NTCP2Block.encode([.data(Data(repeating: 0xAB, count: 200))])))
        wire += try tx.frame(NTCP2Block.aligned(try NTCP2Block.encode([.padding(4)])))

        var remaining = wire
        var decodedSets: [[NTCP2Block]] = []
        while !remaining.isEmpty {
            guard let result = try rx.unframe(remaining) else {
                throw NTCP2Error.invalidFrame
            }
            decodedSets.append(try NTCP2Block.decode(result.payload))
            remaining = Data(remaining.dropFirst(result.consumed))
        }
        guard decodedSets.count == 3 else { throw NTCP2Error.invalidFrame }
        guard case .data(let first) = decodedSets[0][0], first == Data("i2np payload".utf8),
              case .options(let mapping) = decodedSets[0][1], mapping["ntcp2"] == "1",
              case .time(let time) = decodedSets[0][2], abs(time.timeIntervalSince(timestamp)) < 0.01,
              case .termination(let reason, _) = decodedSets[0][3], reason == 0,
              case .data(let second) = decodedSets[1][0], second == Data(repeating: 0xAB, count: 200) else {
            throw NTCP2Error.invalidBlock
        }
        // Tampered frames must fail authentication.
        var tx3 = NTCP2FrameCodec(directionKeys: aliceKeys.sendKeys)
        var rx3 = NTCP2FrameCodec(directionKeys: bobKeys.recvKeys)
        let frame = try tx3.frame(NTCP2Block.aligned(try NTCP2Block.encode([.data(Data("tamper".utf8))])))
        var tampered = frame
        tampered[tampered.count - 1] ^= 0xFF
        do {
            if let result = try rx3.unframe(tampered) {
                _ = try NTCP2Block.decode(result.payload)
            }
            throw NTCP2Error.handshakeFailed("tampered frame accepted")
        } catch NTCP2Error.decryptFailed {
            // expected
        }
        return "frames & blocks round-tripped, tamper rejected"
    }

    private static func tcpLoopbackTest() async throws -> String {
        final class Collector: NTCP2TransportDelegate {
            private let lock = NSLock()
            private var establishedTotal = 0
            private var received: [Data] = []
            private var closedTotal = 0
            func transport(_ transport: NTCP2Transport, sessionEstablished session: NTCP2Session) {
                lock.lock(); establishedTotal += 1; lock.unlock()
            }
            func transport(_ transport: NTCP2Transport, session: NTCP2Session, didReceiveData data: Data) {
                lock.lock(); received.append(data); lock.unlock()
            }
            func transport(_ transport: NTCP2Transport, sessionDidClose session: NTCP2Session) {
                lock.lock(); closedTotal += 1; lock.unlock()
            }
            var establishedCount: Int { lock.lock(); defer { lock.unlock() }; return establishedTotal }
            var receivedData: [Data] { lock.lock(); defer { lock.unlock() }; return received }
            var closedCount: Int { lock.lock(); defer { lock.unlock() }; return closedTotal }
        }

        let collectorA = Collector()
        let collectorB = Collector()

        let staticKeyA = Curve25519.KeyAgreement.PrivateKey()
        let ivA = I2PCrypto.randomBytes(16)
        let riA = try makeSignedRouterInfo(addressOptions: [
            "host": "127.0.0.1", "port": "0",
            "s": staticKeyA.publicKey.rawRepresentation.base64EncodedString(),
            "i": ivA.base64EncodedString(),
        ])
        let riB = try makeSignedRouterInfo()
        let staticKeyB = Curve25519.KeyAgreement.PrivateKey()

        let transportA = NTCP2Transport(localRouterInfo: riA, staticKey: staticKeyA)
        let transportB = NTCP2Transport(localRouterInfo: riB, staticKey: staticKeyB)
        transportA.delegate = collectorA
        transportB.delegate = collectorB
        defer {
            transportA.shutdown()
            transportB.shutdown()
        }

        _ = try transportA.startListener(port: 0)
        try await waitUntil({ transportA.listenerPort != nil && transportA.listenerPort != 0 },
                            timeout: 10, "listener bind")
        guard let port = transportA.listenerPort else {
            throw NTCP2Error.handshakeFailed("listener port unavailable")
        }

        transportB.connect(host: "127.0.0.1", port: port, remoteStaticKey: staticKeyA.publicKey.rawRepresentation)

        try await waitUntil({ collectorB.establishedCount >= 1 && collectorA.establishedCount >= 1 },
                            timeout: 10, "handshake")
        // Initiator learns the responder's router hash from its RouterInfo block.
        try await waitUntil({ transportB.hasSession(for: riA.identity.hash) },
                            timeout: 10, "session map")

        let payload = Data("ping over NTCP2".utf8)
        try transportB.send(to: riA.identity.hash, data: payload)
        try await waitUntil({ collectorA.receivedData.contains(payload) }, timeout: 10, "data delivery")

        // Second concurrent peer session against the same listener.
        let riC = try makeSignedRouterInfo()
        transportB.connect(host: "127.0.0.1", port: port, remoteStaticKey: staticKeyA.publicKey.rawRepresentation)
        _ = riC
        try await waitUntil({ transportA.sessionCount() >= 2 }, timeout: 10, "second session")

        // Graceful termination in both directions.
        transportB.closeSession(for: riA.identity.hash)
        try await waitUntil({ collectorA.closedCount >= 1 && collectorB.closedCount >= 1 },
                            timeout: 10, "graceful close")

        return "handshake, \(collectorA.receivedData.count) data frame(s), 2 sessions, graceful close on port \(port)"
    }
}