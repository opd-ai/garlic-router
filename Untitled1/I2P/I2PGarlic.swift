//
//  I2PGarlic.swift
//  Garlic routing: clove sets, certificates, session tags.
//

import Foundation
import CryptoKit

enum I2PGarlicError: Error {
    case invalidPayload
    case decryptFailed
    case unknownSession
}

/// Garlic certificate: a type byte plus type-specific bytes (null = none).
struct I2PGarlicCertificate {
    let type: UInt8
    let payload: Data

    static let null = I2PGarlicCertificate(type: 0, payload: Data())

    func serialize() -> Data {
        var w = I2PWriter()
        w.byte(type)
        w.short(UInt16(payload.count))
        w.raw(payload)
        return w.data
    }

    static func parse(_ r: inout I2PReader) throws -> I2PGarlicCertificate {
        let type = try r.byte()
        let length = Int(try r.short())
        return I2PGarlicCertificate(type: type, payload: try r.raw(length))
    }
}

/// One garlic clove: delivery instructions, the encapsulated I2NP message
/// and a per-clove certificate. Delivery instructions reuse the I2NP layer's
/// I2PDeliveryInstructions (local, tunnel and router modes with delay).
struct I2PGarlicClove {
    let deliveryInstructions: I2PDeliveryInstructions
    let message: I2NPMessage
    let certificate: I2PGarlicCertificate

    init(deliveryInstructions: I2PDeliveryInstructions,
         message: I2NPMessage,
         certificate: I2PGarlicCertificate = .null) {
        self.deliveryInstructions = deliveryInstructions
        self.message = message
        self.certificate = certificate
    }

    /// [delivery instructions][I2NP message bytes][certificate]
    func serialize() throws -> Data {
        var w = I2PWriter()
        w.raw(deliveryInstructions.serialize())
        w.raw(message.serialize())
        w.raw(certificate.serialize())
        return w.data
    }

    /// Returns the clove and how many bytes it consumed from `data`.
    static func parse(_ data: Data) throws -> (clove: I2PGarlicClove, consumed: Int) {
        let (instructions, instructionsBytes) = try I2PDeliveryInstructions.parse(data)
        let rest = Data(data.dropFirst(instructionsBytes))
        guard rest.count >= I2NPMessage.headerLength else { throw I2PGarlicError.invalidPayload }
        let header = try I2NPMessageHeader.parse(rest)
        let messageBytes = I2NPMessage.headerLength + Int(header.size)
        guard rest.count >= messageBytes + 3 else { throw I2PGarlicError.invalidPayload }
        let inner = try I2NPMessage.parse(rest.prefix(messageBytes))
        var certReader = I2PReader(rest.subdata(in: messageBytes..<rest.count))
        let certificate = try I2PGarlicCertificate.parse(&certReader)
        let consumed = instructionsBytes + messageBytes + (rest.count - messageBytes - certReader.remaining)
        return (I2PGarlicClove(deliveryInstructions: instructions,
                               message: inner,
                               certificate: certificate),
                consumed)
    }
}




/// Garlic clove set framing: version, expiration, message ID, certificate
/// and one or more cloves. The whole set is the encrypted garlic payload.
struct I2PGarlicCloveSet {
    static let version: UInt8 = 0
    let expiration: Date
    let messageID: UInt32
    let certificate: I2PGarlicCertificate
    let cloves: [I2PGarlicClove]

    init(expiration: Date, messageID: UInt32,
         certificate: I2PGarlicCertificate = .null,
         cloves: [I2PGarlicClove]) throws {
        guard !cloves.isEmpty else { throw I2PGarlicError.invalidPayload }
        self.expiration = expiration
        self.messageID = messageID
        self.certificate = certificate
        self.cloves = cloves
    }

    /// [version][expiration ms (8)][message ID (4)][certificate][count (1)][cloves...]
    func serialize() throws -> Data {
        var w = I2PWriter()
        w.byte(Self.version)
        w.long(UInt64((expiration.timeIntervalSince1970 * 1000).rounded()))
        w.integer(messageID)
        w.raw(certificate.serialize())
        w.byte(UInt8(cloves.count))
        for clove in cloves { w.raw(try clove.serialize()) }
        return w.data
    }

    static func parse(_ data: Data) throws -> I2PGarlicCloveSet {
        var r = I2PReader(data)
        guard try r.byte() == Self.version else { throw I2PGarlicError.invalidPayload }
        let ms = try r.long()
        let messageID = try r.integer()
        let certificate = try I2PGarlicCertificate.parse(&r)
        let count = Int(try r.byte())
        let headerBytes = 1 + 8 + 4 + (3 + certificate.payload.count) + 1
        var remainder = Data(data.dropFirst(headerBytes))
        var cloves: [I2PGarlicClove] = []
        for _ in 0..<count {
            let (clove, consumed) = try I2PGarlicClove.parse(remainder)
            cloves.append(clove)
            remainder = Data(remainder.dropFirst(consumed))
        }
        return try I2PGarlicCloveSet(expiration: Date(timeIntervalSince1970: Double(ms) / 1000),
                                 messageID: messageID,
                                 certificate: certificate,
                                 cloves: cloves)
    }
}
/// One lease from a remote LeaseSet: where to deliver garlic messages.
struct I2PGarlicLease {
    let gatewayRouterHash: Data
    let tunnelID: UInt32
    let expiration: Date
}

/// ECIES-X25519 garlic primitives (ChaCha20-Poly1305 AEAD, HKDF-SHA256).
/// New sessions use an ephemeral X25519 exchange; tag-based messages reuse
/// the session key via a single-use 32-byte session tag.
enum I2PGarlicCrypto {
    static let tagLength = 32
    static let infoSession = "i2p-garlic-ecies-x25519"
    static let infoTagNonce = "i2p-garlic-tag-nonce"

    /// Session key for a new-session garlic message: HKDF(DH(ephemeral, peer)).
    static func sessionKey(sharedSecret: Data, ephemeralPublicKey: Data) -> Data {
        I2PCrypto.hkdfSHA256(inputKeyMaterial: sharedSecret,
                             salt: ephemeralPublicKey,
                             info: Data(infoSession.utf8),
                             outputLength: 32)
    }

    static func sessionKey(ephemeral: Curve25519.KeyAgreement.PrivateKey,
                           peerPublicKey: Curve25519.KeyAgreement.PublicKey) throws -> Data {
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: peerPublicKey)
        let ikm = shared.withUnsafeBytes { Data($0) }
        return sessionKey(sharedSecret: ikm, ephemeralPublicKey: ephemeral.publicKey.rawRepresentation)
    }

    /// Deterministic 12-byte nonce bound to a single-use session tag.
    static func tagNonce(tag: Data) -> Data {
        I2PCrypto.hkdfSHA256(inputKeyMaterial: tag,
                             salt: Data(),
                             info: Data(infoTagNonce.utf8),
                             outputLength: 12)
    }

    /// [ephemeral public key (32)][AEAD ciphertext] for new sessions.
    static func sealNewSession(_ plaintext: Data,
                               peerPublicKey: Curve25519.KeyAgreement.PublicKey) throws -> Data {
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let key = try sessionKey(ephemeral: ephemeral, peerPublicKey: peerPublicKey)
        let box = try ChaChaPoly.seal(plaintext, using: SymmetricKey(data: key))
        return ephemeral.publicKey.rawRepresentation + box.combined
    }

    static func openNewSession(_ payload: Data,
                               localKey: Curve25519.KeyAgreement.PrivateKey) throws -> Data {
        guard payload.count > 32 + 16 else { throw I2PGarlicError.invalidPayload }
        let ephemeral = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: payload.subdata(in: 0..<32))
        let shared = try localKey.sharedSecretFromKeyAgreement(with: ephemeral)
        let ikm = shared.withUnsafeBytes { Data($0) }
        let key = sessionKey(sharedSecret: ikm, ephemeralPublicKey: ephemeral.rawRepresentation)
        let box = try ChaChaPoly.SealedBox(combined: payload.subdata(in: 32..<payload.count))
        guard let plain = try? ChaChaPoly.open(box, using: SymmetricKey(data: key)) else {
            throw I2PGarlicError.decryptFailed
        }
        return plain
    }
}
/// Session tag record carried inside a new-session clove set so the peer
/// can register single-use tags bound to the derived session key.
struct I2PGarlicSessionTagsRecord {
    static let marker: UInt8 = 1
    let tags: [Data] // 32 bytes each

    func serialize() -> Data {
        var out = Data([Self.marker, UInt8(tags.count)])
        tags.forEach { out.append($0) }
        return out
    }

    static func parse(_ payload: Data) -> I2PGarlicSessionTagsRecord? {
        let bytes = Array(payload)
        guard bytes.count >= 2, bytes[0] == marker, bytes[1] > 0,
              bytes.count == 2 + Int(bytes[1]) * I2PGarlicCrypto.tagLength else { return nil }
        var tags: [Data] = []
        for index in 0..<Int(bytes[1]) {
            let start = 2 + index * I2PGarlicCrypto.tagLength
            tags.append(Data(bytes[start..<(start + I2PGarlicCrypto.tagLength)]))
        }
        return I2PGarlicSessionTagsRecord(tags: tags)
    }
}

/// Tracks single-use inbound session tags → session key bindings.
final class I2PGarlicInboundTagManager {
    private let lock = NSLock()
    private var bindings: [Data: Data] = [:] // tag → session key

    func register(_ tags: [Data], sessionKey: Data) {
        lock.lock()
        for tag in tags where tag.count == I2PGarlicCrypto.tagLength { bindings[tag] = sessionKey }
        lock.unlock()
    }

    func consume(_ tag: Data) -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return bindings.removeValue(forKey: tag)
    }

    var count: Int { lock.lock(); defer { lock.unlock() }; return bindings.count }
}

/// Decrypts inbound garlic payloads: tag-based or new-session, registering
/// any session tags the new-session payload carries.
final class I2PGarlicInboundSessionManager {
    let localKey: Curve25519.KeyAgreement.PrivateKey
    let tagManager = I2PGarlicInboundTagManager()
    private let lock = NSLock()
    private(set) var establishedPeers: Int = 0

    init(localKey: Curve25519.KeyAgreement.PrivateKey) {
        self.localKey = localKey
    }

    /// Returns the decrypted clove-set bytes for a garlic message payload.
    func unwrapPayload(_ encrypted: Data) throws -> I2PGarlicCloveSet {
        if encrypted.count > I2PGarlicCrypto.tagLength + 16 {
            let tag = encrypted.prefix(I2PGarlicCrypto.tagLength)
            if let key = tagManager.consume(Data(tag)) {
                let body = encrypted.subdata(in: I2PGarlicCrypto.tagLength..<encrypted.count)
                let box = try ChaChaPoly.SealedBox(
                    nonce: ChaChaPoly.Nonce(data: I2PGarlicCrypto.tagNonce(tag: Data(tag))),
                    ciphertext: body.dropLast(16),
                    tag: body.suffix(16))
                guard let plain = try? ChaChaPoly.open(
                    box, using: SymmetricKey(data: key)) else {
                    throw I2PGarlicError.decryptFailed
                }
                return try I2PGarlicCloveSet.parse(plain)
            }
        }
        let plain = try I2PGarlicCrypto.openNewSession(encrypted, localKey: localKey)
        lock.lock(); establishedPeers += 1; lock.unlock()
        let cloveSet = try I2PGarlicCloveSet.parse(plain)
        // Register any tags the peer announced inside the new-session payload.
        if encrypted.count > 32 + 16 {
            let ephemeral = try Curve25519.KeyAgreement.PublicKey(
                rawRepresentation: encrypted.subdata(in: 0..<32))
            let shared = try localKey.sharedSecretFromKeyAgreement(with: ephemeral)
            let ikm = shared.withUnsafeBytes { Data($0) }
            let key = I2PGarlicCrypto.sessionKey(sharedSecret: ikm,
                                                 ephemeralPublicKey: ephemeral.rawRepresentation)
            for clove in cloveSet.cloves {
                if clove.message.type == .dataMessage,
                   let record = I2PGarlicSessionTagsRecord.parse(clove.message.payload) {
                    tagManager.register(record.tags, sessionKey: key)
                }
            }
        }
        return cloveSet
    }
}
/// Outbound garlic session: wraps clove sets, handshaking with a new-session
/// message that embeds single-use session tags, then tag-based encryption.
final class I2PGarlicSession {
    private let peerPublicKey: Curve25519.KeyAgreement.PublicKey
    private let tagsPerHandshake: Int
    private var sessionKey: Data?
    private var pendingTags: [Data] = []
    private let lock = NSLock()

    init(peerPublicKey: Curve25519.KeyAgreement.PublicKey, tagsPerHandshake: Int = 4) {
        self.peerPublicKey = peerPublicKey
        self.tagsPerHandshake = tagsPerHandshake
    }

    var isEstablished: Bool { lock.lock(); defer { lock.unlock() }; return sessionKey != nil }

    /// True when the next clove set must carry a session-tags record
    /// (i.e. the next wrap will be a new-session handshake).
    func nextSendEmbedsTagsRecord() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return sessionKey == nil || pendingTags.isEmpty
    }

    /// Prepares the tag pool for a pending new-session handshake and returns
    /// the tags to offer in the session-tags record. Returns nil when the
    /// next send will use an existing session tag instead.
    func prepareHandshakeTags() -> [Data]? {
        lock.lock()
        defer { lock.unlock() }
        if sessionKey != nil, !pendingTags.isEmpty { return nil }
        if pendingTags.isEmpty {
            pendingTags = (0..<tagsPerHandshake).map { _ in
                I2PCrypto.randomBytes(I2PGarlicCrypto.tagLength)
            }
        }
        return pendingTags
    }

    /// Tags to embed in the next session-tags record.
    func offeredTags() -> [Data] {
        lock.lock()
        defer { lock.unlock() }
        return pendingTags
    }

    /// Wraps a serialized clove set: tag-based when a tag is available,
    /// otherwise a new-session handshake that also refreshes the tag pool.
    func wrapCloveSet(_ cloveSetBytes: Data) throws -> Data {
        lock.lock()
        if let key = sessionKey, let tag = pendingTags.first {
            pendingTags.removeFirst()
            lock.unlock()
            let nonce = I2PGarlicCrypto.tagNonce(tag: tag)
            let box = try ChaChaPoly.seal(cloveSetBytes, using: SymmetricKey(data: key), nonce: ChaChaPoly.Nonce(data: nonce))
            return tag + box.combined
        }
        lock.unlock()
        // New session: fresh ephemeral exchange. Keep any tag pool already
        // prepared by prepareHandshakeTags() so the offered tags match the
        // session key derived in this handshake.
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let key = try I2PGarlicCrypto.sessionKey(ephemeral: ephemeral, peerPublicKey: peerPublicKey)
        lock.lock()
        if pendingTags.isEmpty {
            pendingTags = (0..<tagsPerHandshake).map { _ in
                I2PCrypto.randomBytes(I2PGarlicCrypto.tagLength)
            }
        }
        sessionKey = key
        lock.unlock()
        let box = try ChaChaPoly.seal(cloveSetBytes, using: SymmetricKey(data: key))
        return ephemeral.publicKey.rawRepresentation + box.combined
    }
}
/// The result of sending a garlic message toward a LeaseSet lease: the
/// tunnel-gateway envelope plus where it must be delivered next (through the
/// sender's outbound tunnel pool in production).
struct I2PGarlicTransmission {
    let message: I2NPMessage
    let nextHopRouterHash: Data
    let inboundTunnelID: UInt32
}

/// End-to-end garlic pipeline: a destination wraps an I2NP message in a clove
/// set addressed to a LeaseSet lease, encrypts it (ECIES / session tags) and
/// returns a TunnelGateway envelope whose inner delivery instructions point
/// at the lease's inbound tunnel gateway.
enum I2PGarlicEndToEndPipeline {
    /// Builds and encrypts the garlic envelope for `message` toward `lease`.
    static func sendMessage(_ message: I2NPMessage,
                            to lease: I2PGarlicLease,
                            session: I2PGarlicSession,
                            expiration: Date? = nil) throws -> I2PGarlicTransmission {
        let expiry = expiration ?? Date().addingTimeInterval(300)
        // The lease routes the garlic envelope itself (the TunnelGateway
        // wrapper below carries the lease's tunnel ID and gateway); the
        // clove's own delivery is local to the destination.
        let delivery = I2PDeliveryInstructions(mode: .local,
                                               tunnelID: nil,
                                               routerHash: nil,
                                               delayMilliseconds: nil)
        var cloves = [I2PGarlicClove(deliveryInstructions: delivery, message: message)]
        if let offered = session.prepareHandshakeTags() {
            let tagsRecord = I2PGarlicSessionTagsRecord(tags: offered).serialize()
            let tagsMessage = I2NPMessage(type: .dataMessage, payload: tagsRecord)
            cloves.append(I2PGarlicClove(
                deliveryInstructions: I2PDeliveryInstructions(mode: .local,
                                                              tunnelID: nil,
                                                              routerHash: nil,
                                                              delayMilliseconds: nil),
                message: tagsMessage))
        }
        let cloveSet = try I2PGarlicCloveSet(expiration: expiry,
                                             messageID: UInt32.random(in: 1...UInt32.max),
                                             cloves: cloves).serialize()
        let encrypted = try session.wrapCloveSet(cloveSet)
        let garlic = I2NPMessage(type: .garlic, payload: encrypted)
        // Route to the lease's gateway: tunnel-gateway delivery instructions.
        let envelope = I2PTunnelGatewayPayload(
            gatewayID: lease.tunnelID,
            message: garlic.serialize()).serialize()
        return I2PGarlicTransmission(
            message: I2NPMessage(type: .tunnelGateway, payload: envelope),
            nextHopRouterHash: lease.gatewayRouterHash,
            inboundTunnelID: lease.tunnelID)
    }

    /// Routes a transmission through one of the destination's outbound tunnels
    /// (selected from the tunnel pool), producing the tunnel data payload and
    /// the first hop the sender must deliver it to.
    static func routeThroughTunnelPool(_ transmission: I2PGarlicTransmission,
                                       via outboundTunnel: I2PTunnel) throws -> (payload: I2PTunnelDataPayload, firstHopRouterHash: Data) {
        let preprocessed = try I2PTunnelDataProcessor.preprocess(
            transmission.message.serialize(), via: outboundTunnel)
        return (preprocessed, outboundTunnel.hops[0].routerHash)
    }
}
/// Router-level garlic handling: unwraps inbound garlic messages through the
/// session manager and dispatches each clove per its delivery instructions
/// (local consumers, tunnel-gateway re-emission, router delivery, delay).
final class I2PGarlicMessageHandler {
    private let sessionManager: I2PGarlicInboundSessionManager
    private weak var deliveryTransport: I2PDeliveryTransport?
    private let lock = NSLock()
    private var localConsumers: [(I2NPMessage, Data) -> Void] = []

    init(sessionManager: I2PGarlicInboundSessionManager,
         deliveryTransport: I2PDeliveryTransport?) {
        self.sessionManager = sessionManager
        self.deliveryTransport = deliveryTransport
    }

    func addLocalConsumer(_ consumer: @escaping (I2NPMessage, Data) -> Void) {
        lock.lock()
        localConsumers.append(consumer)
        lock.unlock()
    }

    func handle(_ message: I2NPMessage, from source: Data) {
        guard message.type == .garlic else { return }
        guard let cloveSet = try? sessionManager.unwrapPayload(message.payload) else { return }
        guard cloveSet.expiration > Date() else { return } // expiration enforcement
        for clove in cloveSet.cloves {
            // Skip the session-tags handshake record (already registered).
            if clove.message.type == .dataMessage,
               I2PGarlicSessionTagsRecord.parse(clove.message.payload) != nil { continue }
            switch clove.deliveryInstructions.mode {
            case .local:
                let consumers: [(I2NPMessage, Data) -> Void] = {
                    lock.lock()
                    defer { lock.unlock() }
                    return localConsumers
                }()
                consumers.forEach { $0(clove.message, source) }
            case .tunnel:
                guard let transport = deliveryTransport,
                      let tunnelID = clove.deliveryInstructions.tunnelID,
                      let routerHash = clove.deliveryInstructions.routerHash else { continue }
                let gateway = I2PTunnelGatewayPayload(gatewayID: tunnelID,
                                                      message: clove.message.serialize())
                let envelope = I2NPMessage(type: .tunnelGateway, payload: gateway.serialize())
                Task { try? await transport.deliver(envelope.serialize(), to: routerHash) }
            case .router:
                guard let transport = deliveryTransport,
                      let routerHash = clove.deliveryInstructions.routerHash else { continue }
                Task { try? await transport.deliver(clove.message.serialize(), to: routerHash) }
            }
            // Delay-flagged cloves would sleep `delayMilliseconds` before
            // delivery; the dispatch above applies to immediate delivery.
        }
    }
}


// garlic self-test below
enum I2PGarlicSelfTest {
    static func runAll() async -> [I2PSelfTestResult] {
        var results: [I2PSelfTestResult] = []
        func run(_ name: String, _ body: () async throws -> String) async {
            do { results.append(I2PSelfTestResult(name: name, passed: true, detail: try await body())) }
            catch { results.append(I2PSelfTestResult(name: name, passed: false, detail: "\(error)")) }
        }
        await run("Garlic clove set framing round-trip", garlicCloveSetTest)
        await run("ECIES session tags: single-use enforcement", garlicSessionTagsTest)
        await run("Garlic end-to-end via tunnel pools", garlicEndToEndTest)
        return results
    }
}

// Garlic suite harness and tests (file-scoped).

private enum I2PGarlicTestTimeout: Error { case timedOut }

private func garlicWaitUntil(timeout: TimeInterval = 20,
                             _ condition: () -> Bool) async throws {
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        if condition() { return }
        try await Task.sleep(for: .milliseconds(50))
    }
    if condition() { return }
    throw I2PGarlicTestTimeout.timedOut
}

private func sameMessage(_ a: I2NPMessage, _ b: I2NPMessage) -> Bool {
    a.type == b.type && a.messageID == b.messageID && a.payload == b.payload
}
// Test: clove set framing round-trip across all delivery modes.

private func garlicCloveSetTest() async throws -> String {
    let payloadA = Data("clove A".utf8)
    let payloadB = Data("clove B".utf8)
    let payloadC = Data("clove C".utf8)
    let messageA = I2NPMessage(type: .dataMessage, payload: payloadA)
    let messageB = I2NPMessage(type: .dataMessage, payload: payloadB)
    let messageC = I2NPMessage(type: .deliveryStatus, messageID: 7, payload: payloadC)

    let local = I2PDeliveryInstructions(mode: .local, tunnelID: nil,
                                        routerHash: nil, delayMilliseconds: nil)
    let tunnel = I2PDeliveryInstructions(mode: .tunnel, tunnelID: 0x11223344,
                                         routerHash: I2PCrypto.randomBytes(32),
                                         delayMilliseconds: 500)
    let router = I2PDeliveryInstructions(mode: .router, tunnelID: nil,
                                         routerHash: I2PCrypto.randomBytes(32),
                                         delayMilliseconds: nil)
    let cert = I2PGarlicCertificate(type: 5, payload: Data([0xAA, 0xBB]))

    let expiration = Date().addingTimeInterval(120)
    let set = try I2PGarlicCloveSet(expiration: expiration, messageID: 0x00C10AFF,
                                    certificate: cert,
                                    cloves: [
                                        I2PGarlicClove(deliveryInstructions: local, message: messageA),
                                        I2PGarlicClove(deliveryInstructions: tunnel, message: messageB,
                                                       certificate: I2PGarlicCertificate(type: 1, payload: Data([0x01]))),
                                        I2PGarlicClove(deliveryInstructions: router, message: messageC),
                                    ])
    let parsed = try I2PGarlicCloveSet.parse(try set.serialize())

    guard abs(parsed.expiration.timeIntervalSince(expiration)) < 1 else { throw I2PGarlicError.invalidPayload }
    guard parsed.messageID == 0x00C10AFF else { throw I2PGarlicError.invalidPayload }
    guard parsed.certificate.type == 5 && parsed.certificate.payload == Data([0xAA, 0xBB]) else { throw I2PGarlicError.invalidPayload }
    guard parsed.cloves.count == 3 else { throw I2PGarlicError.invalidPayload }

    let modes = parsed.cloves.map { $0.deliveryInstructions.mode }
    guard modes == [.local, .tunnel, .router] else { throw I2PGarlicError.invalidPayload }
    guard parsed.cloves[1].deliveryInstructions.tunnelID == 0x11223344,
          parsed.cloves[1].deliveryInstructions.delayMilliseconds == 500,
          parsed.cloves[1].deliveryInstructions.routerHash == tunnel.routerHash else { throw I2PGarlicError.invalidPayload }
    guard parsed.cloves[1].certificate.type == 1 else { throw I2PGarlicError.invalidPayload }
    guard sameMessage(parsed.cloves[0].message, messageA),
          sameMessage(parsed.cloves[1].message, messageB),
          sameMessage(parsed.cloves[2].message, messageC) else { throw I2PGarlicError.invalidPayload }
    return "3 cloves across all delivery modes, delay + certificates intact"
}
// Test: ECIES-X25519 sessions — new-session handshake, tag-based follow-up,
// single-use tag enforcement.

private func garlicSessionTagsTest() async throws -> String {
    let aliceKey = Curve25519.KeyAgreement.PrivateKey()
    let aliceManager = I2PGarlicInboundSessionManager(localKey: aliceKey)
    let bobSession = I2PGarlicSession(peerPublicKey: aliceKey.publicKey, tagsPerHandshake: 4)
    let localDelivery = I2PDeliveryInstructions(mode: .local, tunnelID: nil,
                                                routerHash: nil, delayMilliseconds: nil)

    func dataClove(_ id: UInt32, _ text: String) throws -> I2PGarlicClove {
        I2PGarlicClove(deliveryInstructions: localDelivery,
                       message: I2NPMessage(type: .dataMessage, payload: Data(text.utf8)))
    }

    guard bobSession.nextSendEmbedsTagsRecord() else { throw I2PGarlicError.invalidPayload }
    // First message: new-session handshake carrying the session-tags record.
    let tagsRecord = I2PGarlicSessionTagsRecord(tags: bobSession.prepareHandshakeTags() ?? []).serialize()
    let firstSet = try I2PGarlicCloveSet(expiration: Date().addingTimeInterval(300),
                                         messageID: 0x1234,
                                         cloves: [try dataClove(0x1234, "first"),
                                                  I2PGarlicClove(deliveryInstructions: localDelivery,
                                                                 message: I2NPMessage(type: .dataMessage,
                                                                                      payload: tagsRecord))])
    let first = try bobSession.wrapCloveSet(try firstSet.serialize())
    let set1 = try aliceManager.unwrapPayload(first)
    guard set1.messageID == 0x1234 else { throw I2PGarlicError.invalidPayload }
    guard aliceManager.tagManager.count == 4 else { throw I2PGarlicError.invalidPayload }
    guard aliceManager.establishedPeers == 1 else { throw I2PGarlicError.invalidPayload }
    guard bobSession.isEstablished, !bobSession.nextSendEmbedsTagsRecord() else { throw I2PGarlicError.invalidPayload }

    // Second message: tag-based encryption over the established session.
    let secondSet = try I2PGarlicCloveSet(expiration: Date().addingTimeInterval(300),
                                          messageID: 0x5678,
                                          cloves: [try dataClove(0x5678, "second")])
    let second = try bobSession.wrapCloveSet(try secondSet.serialize())
    let set2 = try aliceManager.unwrapPayload(second)
    guard set2.messageID == 0x5678 else { throw I2PGarlicError.invalidPayload }
    guard aliceManager.tagManager.count == 3 else { throw I2PGarlicError.invalidPayload }

    // A replayed tag-based payload must fail: the tag was consumed.
    do {
        _ = try aliceManager.unwrapPayload(second)
        throw I2PGarlicError.invalidPayload
    } catch let error as I2PGarlicError {
        guard case .decryptFailed = error else { throw error }
    }
    guard aliceManager.tagManager.count == 3 else { throw I2PGarlicError.invalidPayload }
    return "new-session handshake registered 4 tags, tag follow-up decrypted, replay rejected"
}
// Test: full end-to-end chain — garlic through Bob's outbound tunnel pool
// to a LeaseSet gateway, injected into Alice's inbound tunnel and unwrapped.

private final class GarlicTestBox {
    private let lock = NSLock()
    private var items: [I2NPMessage] = []
    func add(_ message: I2NPMessage) {
        lock.lock(); defer { lock.unlock() }
        items.append(message)
    }
    var count: Int { lock.lock(); defer { lock.unlock() }; return items.count }
    func contains(_ needle: I2NPMessage) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return items.contains { sameMessage($0, needle) }
    }
}

private final class GarlicTestNode {
    let routerHash: Data
    let encryptionKey: Curve25519.KeyAgreement.PrivateKey
    let participant: I2PTunnelParticipant
    let router: I2NPMessageRouter
    let deliveryTransport: I2NPLoopbackDeliveryTransport

    init(buildHub: I2PTunnelBuildHub, deliveryHub: I2NPLoopbackDeliveryHub) {
        routerHash = I2PCrypto.randomBytes(32)
        encryptionKey = Curve25519.KeyAgreement.PrivateKey()
        let buildTransport = I2PTunnelLoopbackTransport(hub: buildHub, localRouterHash: routerHash)
        participant = I2PTunnelParticipant(localRouterHash: routerHash,
                                           localEncryptionKey: encryptionKey,
                                           transport: buildTransport)
        buildHub.register(participant)
        router = I2NPMessageRouter(localRouterHash: routerHash)
        deliveryTransport = I2NPLoopbackDeliveryTransport(hub: deliveryHub,
                                                          localRouterHash: routerHash)
        router.deliveryTransport = deliveryTransport
        deliveryHub.attach(router)
    }

    var peer: I2PTunnelPeer {
        I2PTunnelPeer(routerHash: routerHash,
                      encryptionPublicKey: encryptionKey.publicKey.rawRepresentation)
    }
}
private func garlicEndToEndTest() async throws -> String {
    let buildHub = I2PTunnelBuildHub()
    let deliveryHub = I2NPLoopbackDeliveryHub()
    let alice = GarlicTestNode(buildHub: buildHub, deliveryHub: deliveryHub)
    let g1 = GarlicTestNode(buildHub: buildHub, deliveryHub: deliveryHub)
    let g2 = GarlicTestNode(buildHub: buildHub, deliveryHub: deliveryHub)
    let bob = GarlicTestNode(buildHub: buildHub, deliveryHub: deliveryHub)
    let b1 = GarlicTestNode(buildHub: buildHub, deliveryHub: deliveryHub)
    let b2 = GarlicTestNode(buildHub: buildHub, deliveryHub: deliveryHub)

    let aliceBuilder = I2PTunnelBuilder(localRouterHash: alice.routerHash,
                                        participant: alice.participant,
                                        transport: I2PTunnelLoopbackTransport(hub: buildHub,
                                                                              localRouterHash: alice.routerHash))
    let aliceTunnel = try await aliceBuilder.buildTunnel(
        direction: .inbound, hops: [g1.peer, g2.peer], lifetime: 900, timeout: 10)
    let bobBuilder = I2PTunnelBuilder(localRouterHash: bob.routerHash,
                                      participant: bob.participant,
                                      transport: I2PTunnelLoopbackTransport(hub: buildHub,
                                                                            localRouterHash: bob.routerHash))
    let bobTunnel = try await bobBuilder.buildTunnel(
        direction: .outbound, hops: [b1.peer, b2.peer], lifetime: 900, timeout: 10)

    g1.router.addTunnelParticipant(g1.participant)
    g2.router.addTunnelParticipant(g2.participant)
    b1.router.addTunnelParticipant(b1.participant)
    b2.router.addTunnelParticipant(b2.participant)

    let lease = I2PGarlicLease(gatewayRouterHash: g1.routerHash,
                               tunnelID: aliceTunnel.gatewayTunnelID,
                               expiration: Date().addingTimeInterval(600))
    let aliceKey = Curve25519.KeyAgreement.PrivateKey()
    let aliceManager = I2PGarlicInboundSessionManager(localKey: aliceKey)
    let aliceHandler = I2PGarlicMessageHandler(
        sessionManager: aliceManager,
        deliveryTransport: I2NPLoopbackDeliveryTransport(hub: deliveryHub,
                                                         localRouterHash: alice.routerHash))
    let box = GarlicTestBox()
    aliceHandler.addLocalConsumer { message, _ in box.add(message) }
    alice.router.addBodyHandler { message, source in aliceHandler.handle(message, from: source) }
// OBEP glue: Bob's outbound endpoint hands the inner message to the
    // lease's gateway router (the inter-router hop in production).
    b1.router.registerGateway(tunnelID: bobTunnel.hops[0].receiveTunnelID) { inner, _ in
        Task {
            try? await b1.router.deliveryTransport?.deliver(inner.serialize(),
                                                            to: lease.gatewayRouterHash)
        }
    }
    // IBGW glue: the lease gateway injects the garlic message into Alice's
    // inbound tunnel, applying the remaining hop layers.
    g1.router.registerGateway(tunnelID: lease.tunnelID) { inner, _ in
        Task {
            do {
                let pre = try I2PTunnelDataProcessor.preprocess(inner.serialize(), via: aliceTunnel)
                let envelope = I2NPMessage(type: .tunnelData, payload: pre.serialize())
                try? await g1.router.deliveryTransport?.deliver(envelope.serialize(), to: g1.routerHash)
            } catch {}
        }
    }

    let bobSession = I2PGarlicSession(peerPublicKey: aliceKey.publicKey, tagsPerHandshake: 4)
    let messageA = I2NPMessage(type: .dataMessage, payload: Data("garlic payload A".utf8))
    let messageB = I2NPMessage(type: .dataMessage, payload: Data("garlic payload B".utf8))

    // First message: new-session handshake through the full chain.
    let transmissionA = try I2PGarlicEndToEndPipeline.sendMessage(messageA, to: lease, session: bobSession)
    let (payloadA, firstHopA) = try I2PGarlicEndToEndPipeline.routeThroughTunnelPool(transmissionA, via: bobTunnel)
    let dataA = I2NPMessage(type: .tunnelData, payload: payloadA.serialize())
    await deliveryHub.deliver(from: bob.routerHash, dataA.serialize(), to: firstHopA)
    guard bobSession.isEstablished else { throw I2PGarlicError.invalidPayload }
    try await garlicWaitUntil { box.count >= 1 }

    // Second message: tag-based encryption over the established session.
    let transmissionB = try I2PGarlicEndToEndPipeline.sendMessage(messageB, to: lease, session: bobSession)
    let (payloadB, firstHopB) = try I2PGarlicEndToEndPipeline.routeThroughTunnelPool(transmissionB, via: bobTunnel)
    let dataB = I2NPMessage(type: .tunnelData, payload: payloadB.serialize())
    await deliveryHub.deliver(from: bob.routerHash, dataB.serialize(), to: firstHopB)
    try await garlicWaitUntil { box.count >= 2 }

    guard box.contains(messageA), box.contains(messageB) else { throw I2PGarlicError.invalidPayload }
    guard aliceManager.tagManager.count == 3 else { throw I2PGarlicError.invalidPayload }
    return "garlic via outbound pool -> lease gateway -> inbound tunnel -> ECIES unwrap; new-session + tag sends"
}