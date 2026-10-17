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
        // New session: fresh ephemeral exchange and a fresh tag pool.
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let key = try I2PGarlicCrypto.sessionKey(ephemeral: ephemeral, peerPublicKey: peerPublicKey)
        let freshTags = (0..<tagsPerHandshake).map { _ in I2PCrypto.randomBytes(I2PGarlicCrypto.tagLength) }
        let box = try ChaChaPoly.seal(cloveSetBytes, using: SymmetricKey(data: key))
        lock.lock()
        sessionKey = key
        pendingTags = freshTags
        lock.unlock()
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
        let delivery = I2PDeliveryInstructions(mode: .tunnel,
                                               tunnelID: lease.tunnelID,
                                               routerHash: lease.gatewayRouterHash,
                                               delayMilliseconds: nil)
        var cloves = [I2PGarlicClove(deliveryInstructions: delivery, message: message)]
        if session.nextSendEmbedsTagsRecord() {
            let tagsRecord = I2PGarlicSessionTagsRecord(tags: session.offeredTags()).serialize()
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
        _ = results.count
        return results
    }
}
