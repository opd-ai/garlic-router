//
//  I2PGarlic.swift
//  Garlic routing: ECIES-X25519 envelopes, payload blocks, session tags.
//

import Foundation
import CryptoKit

enum I2PGarlicError: Error {
    case invalidPayload
    case decryptFailed
    case unknownSession
}

// MARK: - Delivery instructions

/// Garlic clove delivery instructions inside an I2NP payload block. The clove
/// form is the I2NP flag-byte format and delegates to `I2PDeliveryInstructions`
/// so both paths share one encoding: local 0x00, destination 0x20, router 0x40,
/// tunnel 0x60, with the "to" hash before the tunnel ID.
struct I2PGarlicDeliveryInstructions {
    let deliveryInstructions: I2PDeliveryInstructions

    init(_ deliveryInstructions: I2PDeliveryInstructions) {
        self.deliveryInstructions = deliveryInstructions
    }

    func serialize() -> Data {
        deliveryInstructions.serialize()
    }

    /// Returns the instructions and how many bytes of `body` they consumed.
    static func parse(_ body: Data) throws -> (instructions: I2PDeliveryInstructions, consumed: Int) {
        try I2PDeliveryInstructions.parse(body)
    }
}

// MARK: - Payload blocks

/// ECIES-X25519 garlic payload block types (DateTime, I2NP, Options,
/// Termination, Padding).
enum I2PGarlicBlockType: UInt8 {
    case dateTime = 0
    case i2np = 1
    case options = 3
    case termination = 4
    case padding = 254
}

/// One typed garlic payload block. Every block frames as
/// [type (1)][length (2 BE)][body]; unknown block types are skipped on decode.
enum I2PGarlicBlock {
    /// [unix seconds (4 BE)] — carries the envelope expiration.
    case dateTime(Date)
    /// Garlic delivery instructions + the encapsulated I2NP message (the clove).
    case i2np(deliveryInstructions: I2PDeliveryInstructions, message: I2NPMessage)
    /// Session-tag set delivery: [tag set seed (32)][tag count (1)].
    case options(tagSetSeed: Data, tagCount: Int)
    /// [reason code (1)] — the sender is closing the session.
    case termination(reason: UInt8)
    /// Random bytes — length obfuscation.
    case padding(Data)

    static func encode(_ blocks: [I2PGarlicBlock]) throws -> Data {
        var w = I2PWriter()
        for block in blocks {
            switch block {
            case .dateTime(let date):
                let seconds = UInt32(date.timeIntervalSince1970.rounded())
                w.byte(I2PGarlicBlockType.dateTime.rawValue)
                w.short(4)
                w.integer(seconds)
            case .i2np(let deliveryInstructions, let message):
                let body = I2PGarlicDeliveryInstructions(deliveryInstructions).serialize() + message.serialize()
                w.byte(I2PGarlicBlockType.i2np.rawValue)
                w.short(UInt16(body.count))
                w.raw(body)
            case .options(let tagSetSeed, let tagCount):
                guard tagSetSeed.count == I2PGarlicCrypto.tagLength else { throw I2PGarlicError.invalidPayload }
                w.byte(I2PGarlicBlockType.options.rawValue)
                w.short(33)
                w.raw(tagSetSeed)
                w.byte(UInt8(tagCount))
            case .termination(let reason):
                w.byte(I2PGarlicBlockType.termination.rawValue)
                w.short(1)
                w.byte(reason)
            case .padding(let bytes):
                w.byte(I2PGarlicBlockType.padding.rawValue)
                w.short(UInt16(bytes.count))
                w.raw(bytes)
            }
        }
        return w.data
    }

    static func decode(_ data: Data) throws -> [I2PGarlicBlock] {
        var r = I2PReader(data)
        var blocks: [I2PGarlicBlock] = []
        while r.remaining > 0 {
            // A payload section may be aligned with trailing zero padding, which
            // is not a block: stop rather than misread it as a zero-length
            // DateTime block (which would reject an otherwise valid envelope).
            if r.bytes[r.offset...].allSatisfy({ $0 == 0 }) { break }
            let type = try r.byte()
            let length = Int(try r.short())
            let body = try r.raw(length)

            switch type {
            case I2PGarlicBlockType.dateTime.rawValue:
                guard body.count == 4 else { throw I2PGarlicError.invalidPayload }
                var br = I2PReader(body)
                blocks.append(.dateTime(Date(timeIntervalSince1970: Double(try br.integer()))))
            case I2PGarlicBlockType.i2np.rawValue:
                let (instructions, consumed) = try I2PGarlicDeliveryInstructions.parse(body)
                let message = try I2NPMessage.parse(Data(body.dropFirst(consumed)))
                blocks.append(.i2np(deliveryInstructions: instructions, message: message))
            case I2PGarlicBlockType.options.rawValue:
                guard body.count >= 33 else { throw I2PGarlicError.invalidPayload }
                blocks.append(.options(tagSetSeed: body.subdata(in: 0..<32), tagCount: Int(body[32])))
            case I2PGarlicBlockType.termination.rawValue:
                guard body.count == 1 else { throw I2PGarlicError.invalidPayload }
                blocks.append(.termination(reason: body[0]))
            case I2PGarlicBlockType.padding.rawValue:
                blocks.append(.padding(body))
            default:
                continue // unknown block types are skipped per spec
            }
        }
        return blocks
    }
}

// MARK: - Clove sets

/// One garlic clove: delivery instructions and the encapsulated I2NP message.
struct I2PGarlicClove {
    let deliveryInstructions: I2PDeliveryInstructions
    let message: I2NPMessage

    init(deliveryInstructions: I2PDeliveryInstructions, message: I2NPMessage) {
        self.deliveryInstructions = deliveryInstructions
        self.message = message
    }

    /// The I2NP block body: garlic delivery instructions + the I2NP message.
    func serialize() throws -> Data {
        var w = I2PWriter()
        w.raw(I2PGarlicDeliveryInstructions(deliveryInstructions).serialize())
        w.raw(message.serialize())
        return w.data
    }

    static func parse(_ body: Data) throws -> I2PGarlicClove {
        let (instructions, consumed) = try I2PGarlicDeliveryInstructions.parse(body)
        let message = try I2NPMessage.parse(Data(body.dropFirst(consumed)))
        return I2PGarlicClove(deliveryInstructions: instructions, message: message)
    }
}

/// Garlic clove set: the logical payload of an ECIES-X25519 garlic envelope.
/// Serialization is the spec's typed payload blocks — a DateTime block
/// carrying the expiration, one I2NP block per clove (delivery instructions +
/// message), an Options block when the envelope carries a session-tag set
/// seed, and optional Termination/Padding blocks. The message ID and
/// expiration also ride in the wrapping GarlicMessage's I2NP header.
struct I2PGarlicCloveSet {
    let expiration: Date
    let messageID: UInt32
    let cloves: [I2PGarlicClove]
    let tagSetSeed: Data?
    let tagCount: Int
    let terminated: Bool

    init(expiration: Date, messageID: UInt32, cloves: [I2PGarlicClove],
         tagSetSeed: Data? = nil, tagCount: Int = 0) throws {
        guard !cloves.isEmpty, cloves.count <= 255 else { throw I2PGarlicError.invalidPayload }
        if tagSetSeed != nil { guard tagCount > 0, tagCount <= 255 else { throw I2PGarlicError.invalidPayload } }
        self.expiration = expiration
        self.messageID = messageID
        self.cloves = cloves
        self.tagSetSeed = tagSetSeed
        self.tagCount = tagCount
        self.terminated = false
    }

    private init(expiration: Date, messageID: UInt32, cloves: [I2PGarlicClove],
                 tagSetSeed: Data?, tagCount: Int, terminated: Bool) {
        self.expiration = expiration
        self.messageID = messageID
        self.cloves = cloves
        self.tagSetSeed = tagSetSeed
        self.tagCount = tagCount
        self.terminated = terminated
    }

    func serialize() throws -> Data {
        var blocks: [I2PGarlicBlock] = [.dateTime(expiration)]
        for clove in cloves {
            blocks.append(.i2np(deliveryInstructions: clove.deliveryInstructions, message: clove.message))
        }
        if let seed = tagSetSeed {
            blocks.append(.options(tagSetSeed: seed, tagCount: tagCount))
        }
        return try I2PGarlicBlock.encode(blocks)
    }

    /// Parses the payload-block plaintext. The message ID arrives from the
    /// wrapping GarlicMessage's I2NP header.
    static func parse(_ data: Data, messageID: UInt32 = 0) throws -> I2PGarlicCloveSet {
        var expiration = Date.distantFuture
        var cloves: [I2PGarlicClove] = []
        var tagSetSeed: Data?
        var tagCount = 0
        var terminated = false
        for block in try I2PGarlicBlock.decode(data) {
            switch block {
            case .dateTime(let date): expiration = date
            case .i2np(let deliveryInstructions, let message):
                cloves.append(I2PGarlicClove(deliveryInstructions: deliveryInstructions, message: message))
            case .options(let seed, let count):
                tagSetSeed = seed
                tagCount = count
            case .termination: terminated = true
            case .padding: break // length obfuscation
            }
        }
        guard !terminated, !cloves.isEmpty, cloves.count <= 255 else { throw I2PGarlicError.invalidPayload }
        return I2PGarlicCloveSet(expiration: expiration, messageID: messageID, cloves: cloves,
                                 tagSetSeed: tagSetSeed, tagCount: tagCount, terminated: false)
    }
}

/// One lease from a remote LeaseSet: where to deliver garlic messages.
struct I2PGarlicLease {
    let gatewayRouterHash: Data
    let tunnelID: UInt32
    let expiration: Date
}

// MARK: - ECIES-X25519 crypto

/// ECIES-X25519 garlic primitives (ChaCha20-Poly1305 AEAD, HKDF-SHA256
/// context binding, HMAC-SHA256 ratchets) per proposal 145: three-section
/// new-session envelopes, typed payload blocks, spec context info strings,
/// and tag-set ratchets with 32-byte single-use session tags.
enum I2PGarlicCrypto {
    /// Session tags are 32 bytes per spec.
    static let tagLength = 32

    /// The ECIES-X25519 protocol context (proposal 145). Every HKDF
    /// derivation in the envelope binds its output to this context via the
    /// info string, and the KDF chain starts from its SHA-256.
    static let protocolName = "ECIES-X25519-AEAD-RATCHET"
    /// HKDF info string for the static-key section's AEAD key.
    static let infoStaticSection = Data(protocolName.utf8)
    /// HKDF info string for the payload section's AEAD key.
    static let infoPayloadSection = Data(protocolName.utf8)

    private static func hmac(_ message: Data, key: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key)))
    }

    private static func sha256(_ data: Data) -> Data {
        I2PCrypto.sha256(data)
    }

    /// The 12-byte all-zero nonce: every section of the envelope is sealed under
    /// a freshly derived single-use key, so the nonce carries no reuse risk and
    /// rides implicitly (it is part of the section key's context, not the wire).
    static let zeroNonce = Data(repeating: 0, count: 12)

    // New-session KDF (Noise-faithful):
    //   h0 = ck0 = SHA-256(protocolName)
    //   ephemeral section rides cleartext; MixHash: h1 = SHA-256(h0 ‖ e)
    //   es = DH(e, receiver static); temp = HMAC(ck0, es); ck1 = HMAC(temp, 0x01)
    //   static section key = HMAC(temp, ck1)
    //   MixHash: h2 = SHA-256(h1 ‖ static section ciphertext)
    //   ss = DH(sender static, receiver static); temp2 = HMAC(ck1, ss)
    //   ck2 = HMAC(temp2, 0x01); payload key = HMAC(temp2, ck2 ‖ h2)

    /// The new-session envelope: [ephemeral (32)][static section (48)][payload section].
    /// Static section: ChaChaPoly(k_static, nonce 0, sender static public key) —
    /// 32-byte ciphertext plus the 16-byte tag. Payload section:
    /// ChaChaPoly(k_payload, nonce 0, blocks) — the payload blocks plus the tag.
    /// The nonce is implicit zeros and never on the wire: each section key is
    /// derived fresh per envelope, so the fixed nonce cannot repeat under a key.
    static func sealNewSession(_ payloadBlocks: Data,
                               peerStatic: Curve25519.KeyAgreement.PublicKey,
                               senderStatic: Curve25519.KeyAgreement.PrivateKey) throws -> Data {
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let ephemeralPublic = ephemeral.publicKey.rawRepresentation
        let h0 = sha256(Data(protocolName.utf8))
        let h1 = sha256(h0 + ephemeralPublic)
        let es = try ephemeral.sharedSecretFromKeyAgreement(with: peerStatic)
        let temp = hmac(es.withUnsafeBytes { Data($0) }, key: h0)
        let ck1 = hmac(Data([0x01]), key: temp)
        let staticSectionKey = hmac(ck1, key: temp)
        let staticSection = try I2PCrypto.chacha20Poly1305Seal(
            key: staticSectionKey, nonce: zeroNonce,
            plaintext: senderStatic.publicKey.rawRepresentation)
        let h2 = sha256(h1 + staticSection)
        let ss = try senderStatic.sharedSecretFromKeyAgreement(with: peerStatic)
        let temp2 = hmac(ss.withUnsafeBytes { Data($0) }, key: ck1)
        let ck2 = hmac(Data([0x01]), key: temp2)
        let payloadKey = hmac(ck2 + h2, key: temp2)
        let payloadSection = try I2PCrypto.chacha20Poly1305Seal(
            key: payloadKey, nonce: zeroNonce, plaintext: payloadBlocks)
        return ephemeralPublic + staticSection + payloadSection
    }

    /// Opens a new-session envelope: returns the decrypted payload-block
    /// plaintext and the sender's static public key (section 2 plaintext).
    static func openNewSession(_ payload: Data,
                               localKey: Curve25519.KeyAgreement.PrivateKey) throws -> (blocks: Data, senderStatic: Data) {
        // Sections: ephemeral (32) + static (32 plaintext + 16 tag = 48) + payload (n + 16).
        guard payload.count > 32 + 48 + 16 else { throw I2PGarlicError.invalidPayload }
        let ephemeralPublic = payload.subdata(in: 0..<32)
        let h0 = sha256(Data(protocolName.utf8))
        let h1 = sha256(h0 + ephemeralPublic)
        let ephemeral = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephemeralPublic)
        let es = try localKey.sharedSecretFromKeyAgreement(with: ephemeral)
        let temp = hmac(es.withUnsafeBytes { Data($0) }, key: h0)
        let ck1 = hmac(Data([0x01]), key: temp)
        let staticSectionKey = hmac(ck1, key: temp)
        let staticSection = payload.subdata(in: 32..<80)
        guard let staticPlain = try? I2PCrypto.chacha20Poly1305Open(
                key: staticSectionKey, nonce: zeroNonce,
                ciphertextAndTag: staticSection),
              staticPlain.count == 32 else {
            throw I2PGarlicError.decryptFailed
        }
        let h2 = sha256(h1 + staticSection)
        let senderStatic = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: staticPlain)
        let ss = try localKey.sharedSecretFromKeyAgreement(with: senderStatic)
        let temp2 = hmac(ss.withUnsafeBytes { Data($0) }, key: ck1)
        let ck2 = hmac(Data([0x01]), key: temp2)
        let payloadKey = hmac(ck2 + h2, key: temp2)
        let payloadSection = payload.subdata(in: 80..<payload.count)
        guard let blocks = try? I2PCrypto.chacha20Poly1305Open(
                key: payloadKey, nonce: zeroNonce,
                ciphertextAndTag: payloadSection) else {
            throw I2PGarlicError.decryptFailed
        }
        return (blocks, staticPlain)
    }

    /// Tag-set ratchet (proposal 145 tag rules): from a 32-byte seed the
    /// chain advances per tag; every tag is single-use and binds to its own
    /// ratcheted AEAD key. Tag i and its key derive from chain state k_i:
    ///   k_0 = HMAC(HMAC(seed, 0x01), 0x02)
    ///   tag_i = HMAC(k_i, 0x03)[0:32]; key_i = HMAC(k_i, 0x04)
    ///   k_{i+1} = HMAC(k_i, 0x01)
    static func tagSet(seed: Data, count: Int) -> [(tag: Data, key: Data)] {
        precondition(seed.count == tagLength)
        precondition(count >= 1 && count <= 255)
        var tagKey = hmac(hmac(Data([0x01]), key: seed), key: Data([0x02]))
        var entries: [(tag: Data, key: Data)] = []
        for _ in 0..<count {
            let tag = Data(hmac(Data([0x03]), key: tagKey).prefix(tagLength))
            let key = hmac(Data([0x04]), key: tagKey)
            entries.append((tag, key))
            tagKey = hmac(Data([0x01]), key: tagKey)
        }
        return entries
    }
}

// MARK: - Inbound session handling

/// Tracks single-use inbound session tags → ratcheted session-key bindings.
final class I2PGarlicInboundTagManager {
    private let lock = NSLock()
    private var bindings: [Data: Data] = [:] // tag → per-tag AEAD key
    /// Tags this session already spent, oldest first. Keeping them is what makes
    /// single-use enforcement real: a replayed envelope is recognised as a spent
    /// tag and rejected, instead of being misread as a new-session ephemeral key.
    private var consumed: Set<Data> = []
    private var consumedOrder: [Data] = []
    private static let rememberedTagLimit = 4096

    /// Called after a new tag set is installed, so envelopes that arrived
    /// before the new-session message that armed it can be retried.
    var onRegistered: (() -> Void)?

    /// Registers a tag set delivered in an Options block: the seed ratchets
    /// into `count` tags, each binding to its own ratcheted AEAD key.
    func register(tagSetSeed seed: Data, count: Int) {
        let entries = I2PGarlicCrypto.tagSet(seed: seed, count: count)
        lock.lock()
        for entry in entries where entry.tag.count == I2PGarlicCrypto.tagLength {
            bindings[entry.tag] = entry.key
        }
        lock.unlock()
        onRegistered?()
    }

    /// Spends a tag and returns its per-tag AEAD key (nil when never issued or
    /// already spent).
    func consume(_ tag: Data) -> Data? {
        lock.lock()
        defer { lock.unlock() }
        guard let key = bindings.removeValue(forKey: tag) else { return nil }
        consumed.insert(tag)
        consumedOrder.append(tag)
        if consumedOrder.count > Self.rememberedTagLimit {
            let dropped = consumedOrder.removeFirst()
            consumed.remove(dropped)
        }
        return key
    }

    /// True when the tag was issued and already spent (a replay).
    func wasConsumed(_ tag: Data) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return consumed.contains(tag)
    }

    var count: Int { lock.lock(); defer { lock.unlock() }; return bindings.count }
}

/// Decrypts inbound garlic payloads: tag-based or three-section new-session,
/// registering the tag set the new-session Options block carries.
final class I2PGarlicInboundSessionManager {
    let localKey: Curve25519.KeyAgreement.PrivateKey
    let tagManager = I2PGarlicInboundTagManager()
    private let lock = NSLock()
    private(set) var establishedPeers: Int = 0

    init(localKey: Curve25519.KeyAgreement.PrivateKey) {
        self.localKey = localKey
    }

    /// Returns the decrypted clove set for a garlic message payload.
    /// `messageID` is the wrapping GarlicMessage's I2NP header message ID.
    func unwrapPayload(_ encrypted: Data, messageID: UInt32 = 0) throws -> I2PGarlicCloveSet {
        if encrypted.count > I2PGarlicCrypto.tagLength + 16 {
            let tag = Data(encrypted.prefix(I2PGarlicCrypto.tagLength))
            if let key = tagManager.consume(tag) {
                guard let plain = try? I2PCrypto.chacha20Poly1305Open(
                    key: key, nonce: I2PGarlicCrypto.zeroNonce,
                    ciphertextAndTag: encrypted.subdata(in: I2PGarlicCrypto.tagLength..<encrypted.count)) else {
                    throw I2PGarlicError.decryptFailed
                }
                return try I2PGarlicCloveSet.parse(plain, messageID: messageID)
            }
            // A tag we issued and already spent is a replay: reject it here
            // rather than letting the spent tag masquerade as a new-session
            // ephemeral key.
            if tagManager.wasConsumed(tag) {
                throw I2PGarlicError.decryptFailed
            }
        }
        let (blocks, _) = try I2PGarlicCrypto.openNewSession(encrypted, localKey: localKey)
        lock.lock(); establishedPeers += 1; lock.unlock()
        let cloveSet = try I2PGarlicCloveSet.parse(blocks, messageID: messageID)
        // Register the tag set the new-session Options block carries.
        if let seed = cloveSet.tagSetSeed {
            tagManager.register(tagSetSeed: seed, count: cloveSet.tagCount)
        }
        return cloveSet
    }
}

// MARK: - Outbound session

/// Outbound garlic session: ECIES-X25519 new-session handshakes (three
/// sections over the receiver's static key) carrying the next tag set seed
/// in an Options block, then tag-based continuation with the ratcheted
/// per-tag keys.
final class I2PGarlicSession {
    private let peerPublicKey: Curve25519.KeyAgreement.PublicKey
    private let staticKey: Curve25519.KeyAgreement.PrivateKey
    private let tagsPerHandshake: Int
    private var tagSetSeed: Data?
    private var tagEntries: [(tag: Data, key: Data)] = []
    private let lock = NSLock()
    private let sendLock = NSLock()

    /// Serialises one whole send decision (tag-set embedding + sealing).
    func withSendLock<T>(_ body: () throws -> T) rethrows -> T {
        sendLock.lock()
        defer { sendLock.unlock() }
        return try body()
    }

    init(peerPublicKey: Curve25519.KeyAgreement.PublicKey,
         staticKey: Curve25519.KeyAgreement.PrivateKey = Curve25519.KeyAgreement.PrivateKey(),
         tagsPerHandshake: Int = 4) {
        self.peerPublicKey = peerPublicKey
        self.staticKey = staticKey
        self.tagsPerHandshake = tagsPerHandshake
    }

    /// Established while unused session tags remain; a new handshake is
    /// needed once the tag set exhausts.
    var isEstablished: Bool { lock.lock(); defer { lock.unlock() }; return !tagEntries.isEmpty }

    /// True when the next clove set must be a new-session handshake
    /// carrying a session-tag set in its Options block.
    func nextSendEmbedsTagsRecord() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return tagEntries.isEmpty
    }

    /// The tag-set seed and count to embed in the next new-session's Options
    /// block, generating the seed if needed. Returns nil when the next send
    /// is tag-based over the established session.
    func prepareHandshakeTags() -> (seed: Data, count: Int)? {
        lock.lock()
        defer { lock.unlock() }
        guard tagEntries.isEmpty else { return nil }
        if tagSetSeed == nil {
            tagSetSeed = I2PCrypto.randomBytes(I2PGarlicCrypto.tagLength)
        }
        return (tagSetSeed!, tagsPerHandshake)
    }

    /// Wraps serialized payload blocks: tag-based when an unused tag remains,
    /// otherwise a three-section ECIES-X25519 new-session envelope that also
    /// arms the pending tag set.
    func wrapCloveSet(_ cloveSetBytes: Data) throws -> Data {
        lock.lock()
        if let entry = tagEntries.first {
            tagEntries.removeFirst()
            lock.unlock()
            // Tag frame: [tag (32)][ciphertext + 16-byte tag]. The per-tag key
            // is single-use, so the AEAD nonce is the implicit zero nonce.
            let box = try I2PCrypto.chacha20Poly1305Seal(
                key: entry.key, nonce: I2PGarlicCrypto.zeroNonce, plaintext: cloveSetBytes)
            return entry.tag + box
        }
        lock.unlock()
        // New session: three-section envelope; arm the tag set (the seed
        // rides inside the encrypted payload as an Options block).
        lock.lock()
        let seed: Data
        if let pending = tagSetSeed {
            seed = pending
        } else {
            seed = I2PCrypto.randomBytes(I2PGarlicCrypto.tagLength)
            tagSetSeed = seed
        }
        tagEntries = I2PGarlicCrypto.tagSet(seed: seed, count: tagsPerHandshake)
        tagSetSeed = nil
        lock.unlock()
        return try I2PGarlicCrypto.sealNewSession(cloveSetBytes,
                                                  peerStatic: peerPublicKey,
                                                  senderStatic: staticKey)
    }
}

// MARK: - End-to-end pipeline

/// The result of sending a garlic message toward a LeaseSet lease: the
/// tunnel-gateway envelope plus where it must be delivered next (through the
/// sender's outbound tunnel pool in production).
struct I2PGarlicTransmission {
    let message: I2NPMessage
    let nextHopRouterHash: Data
    let inboundTunnelID: UInt32
}

/// End-to-end garlic pipeline: a destination wraps an I2NP message in a clove
/// set addressed to a LeaseSet lease, encrypts it in an ECIES-X25519 envelope
/// (new-session or tag-based) and returns a TunnelGateway envelope whose
/// inner GarlicMessage I2NP header carries the message ID and expiration.
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
                                               routerHash: nil)
        let cloves = [I2PGarlicClove(deliveryInstructions: delivery, message: message)]
        // Deciding whether this envelope carries a tag set and sealing it must
        // be one atomic step per session. Concurrent sends (the chunks of a
        // fragmented datagram, parallel stream writes) otherwise interleave:
        // one send sees "tags remain" and embeds no Options block, another
        // spends the last tag, and the first then seals as a NEW SESSION with
        // no tag set while the sender arms tags the receiver never learned,
        // stranding every later tagged frame.
        let (_, cloveSet, encrypted) = try session.withSendLock {
            let tagSet = session.prepareHandshakeTags()
            let cloveSet = try I2PGarlicCloveSet(expiration: expiry,
                                                 messageID: UInt32.random(in: 1...UInt32.max),
                                                 cloves: cloves,
                                                 tagSetSeed: tagSet?.seed,
                                                 tagCount: tagSet?.count ?? 0)
            let encrypted = try session.wrapCloveSet(try cloveSet.serialize())
            return (tagSet, cloveSet, encrypted)
        }
        // The GarlicMessage I2NP header carries the message ID and expiration.
        let garlic = I2NPMessage(type: .garlic,
                                 messageID: cloveSet.messageID,
                                 expiration: expiry,
                                 payload: encrypted)
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

    /// Optional diagnostics hook: a garlic message that fails to unwrap is
    /// otherwise dropped silently, which is undebuggable from a caller.
    var onError: ((String) -> Void)?
    /// Optional diagnostics hook for a successfully opened envelope.
    var onMessage: ((String) -> Void)?

    init(sessionManager: I2PGarlicInboundSessionManager,
         deliveryTransport: I2PDeliveryTransport?) {
        self.sessionManager = sessionManager
        self.deliveryTransport = deliveryTransport
        // A new tag set lets envelopes that arrived too early be retried.
        sessionManager.tagManager.onRegistered = { [weak self] in
            self?.retryDeferred()
        }
    }

    func addLocalConsumer(_ consumer: @escaping (I2NPMessage, Data) -> Void) {
        lock.lock()
        localConsumers.append(consumer)
        lock.unlock()
    }

    func handle(_ message: I2NPMessage, from source: Data) {
        guard message.type == .garlic else { return }
        do {
            let cloveSet = try sessionManager.unwrapPayload(message.payload,
                                                           messageID: message.messageID)
            deliver(cloveSet, from: source)
        } catch let error as I2PGarlicError {
            // A tag-based envelope can overtake the new-session message that
            // armed its tag set: hops deliver concurrently, so the small
            // continuation frames can arrive before the (larger) new-session
            // envelope. Hold it briefly and retry when the tags appear.
            if message.payload.count > I2PGarlicCrypto.tagLength + 16,
               error == .decryptFailed || error == .invalidPayload {
                // `invalidPayload` covers short tag frames (acks, FINs): too
                // small to parse as a new-session envelope, so the fall-through
                // reports a size error rather than an authentication failure.
                deferEnvelope(message, from: source)
            } else {
                onError?("garlic unwrap failed: \(error) (\(message.payload.count)B)")
            }
        } catch {
            onError?("garlic unwrap failed: \(error) (\(message.payload.count)B)")
        }
    }

    private func deliver(_ cloveSet: I2PGarlicCloveSet, from source: Data) {
        guard cloveSet.expiration > Date() else {
            onError?("garlic clove set expired")
            return
        }
        onMessage?("garlic ok: cloves=\(cloveSet.cloves.count) tags=\(cloveSet.tagSetSeed == nil ? "none" : "\(cloveSet.tagCount)")")
        for clove in cloveSet.cloves {
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
            case .destination:
                // Addressed to a destination this acceptor does not own.
                continue
            }
            // Delay is never present in the spec's 1/33/37-byte forms; every
            // dispatched clove is delivered immediately.
        }
    }

    // MARK: Envelopes that outran their tag set

    private struct DeferredEnvelope {
        let message: I2NPMessage
        let source: Data
        let since: Date
    }

    private var deferredEnvelopes: [DeferredEnvelope] = []
    private static let maximumDeferred = 64
    /// How long an envelope waits for its tag set. The wait is bounded by age,
    /// not by retry count: any session's tag registration triggers a retry
    /// pass, so with several sessions running a count-based limit is used up
    /// by registrations that have nothing to do with the held envelope.
    private static let deferralLifetime: TimeInterval = 30

    private func deferEnvelope(_ message: I2NPMessage, from source: Data) {
        lock.lock()
        if deferredEnvelopes.count >= Self.maximumDeferred { deferredEnvelopes.removeFirst() }
        deferredEnvelopes.append(DeferredEnvelope(message: message, source: source, since: Date()))
        lock.unlock()
        onMessage?("garlic held: \(message.payload.count)B awaiting its tag set")
        // The tag set may have been registered between the failed unwrap and
        // this append (the registration's retry pass saw an empty queue), so
        // look once more now that the envelope is queued.
        retryDeferred()
    }

    private func retryDeferred() {
        // A registration that lands while another pass is mid-flight sees an
        // empty queue (the pass drained it) and would otherwise retry nothing,
        // stranding an envelope the pass re-queues after its own failed
        // unwrap. The generation counter makes the pass repeat in that case.
        lock.lock()
        registrationGeneration &+= 1
        if retryInFlight {
            lock.unlock()
            return
        }
        retryInFlight = true
        lock.unlock()
        while true {
            lock.lock()
            let generation = registrationGeneration
            let pending = deferredEnvelopes
            deferredEnvelopes.removeAll()
            lock.unlock()
            if !pending.isEmpty { retry(pending) }
            lock.lock()
            if registrationGeneration == generation || deferredEnvelopes.isEmpty {
                retryInFlight = false
                lock.unlock()
                return
            }
            lock.unlock()
        }
    }

    private var registrationGeneration: UInt64 = 0
    private var retryInFlight = false

    private func retry(_ pending: [DeferredEnvelope]) {
        let now = Date()
        for item in pending {
            do {
                let cloveSet = try sessionManager.unwrapPayload(item.message.payload,
                                                               messageID: item.message.messageID)
                deliver(cloveSet, from: item.source)
            } catch {
                if now.timeIntervalSince(item.since) < Self.deferralLifetime {
                    lock.lock()
                    deferredEnvelopes.append(item)
                    lock.unlock()
                } else {
                    onError?("garlic held envelope dropped after \(Int(Self.deferralLifetime))s: \(error)")
                }
            }
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
        await run("Garlic payload blocks + clove set round-trip", garlicCloveSetTest)
        await run("ECIES three-section envelope + session tags: single-use enforcement", garlicSessionTagsTest)
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

// Test: payload-block encoding and clove-set round-trip across delivery modes.

private func garlicCloveSetTest() async throws -> String {
    let messageA = I2NPMessage(type: .dataMessage, payload: Data("clove A".utf8))
    let messageB = I2NPMessage(type: .dataMessage, payload: Data("clove B".utf8))
    let messageC = I2NPMessage(type: .deliveryStatus, messageID: 7, payload: Data("clove C".utf8))

    let local = I2PDeliveryInstructions(mode: .local, tunnelID: nil, routerHash: nil)
    let tunnel = I2PDeliveryInstructions(mode: .tunnel, tunnelID: 0x11223344,
                                         routerHash: I2PCrypto.randomBytes(32))
    let router = I2PDeliveryInstructions(mode: .router, tunnelID: nil,
                                         routerHash: I2PCrypto.randomBytes(32))

    let expiration = Date().addingTimeInterval(120)
    let messageID: UInt32 = 0x00C10AFF
    let set = try I2PGarlicCloveSet(expiration: expiration, messageID: messageID,
                                    cloves: [
                                        I2PGarlicClove(deliveryInstructions: local, message: messageA),
                                        I2PGarlicClove(deliveryInstructions: tunnel, message: messageB),
                                        I2PGarlicClove(deliveryInstructions: router, message: messageC),
                                    ])
    let bytes = try set.serialize()
    let parsed = try I2PGarlicCloveSet.parse(bytes, messageID: messageID)

    guard abs(parsed.expiration.timeIntervalSince(expiration)) < 2 else { throw I2PGarlicError.invalidPayload }
    guard parsed.messageID == messageID else { throw I2PGarlicError.invalidPayload }
    guard parsed.cloves.count == 3 else { throw I2PGarlicError.invalidPayload }

    let modes = parsed.cloves.map { $0.deliveryInstructions.mode }
    guard modes == [.local, .tunnel, .router] else { throw I2PGarlicError.invalidPayload }
    guard parsed.cloves[1].deliveryInstructions.tunnelID == 0x11223344,
          parsed.cloves[1].deliveryInstructions.routerHash == tunnel.routerHash else { throw I2PGarlicError.invalidPayload }
    guard sameMessage(parsed.cloves[0].message, messageA),
          sameMessage(parsed.cloves[1].message, messageB),
          sameMessage(parsed.cloves[2].message, messageC) else { throw I2PGarlicError.invalidPayload }

    // The blocks must round-trip byte-for-byte through the codec too.
    guard try I2PGarlicBlock.encode(try I2PGarlicBlock.decode(bytes)) == bytes else {
        throw I2PGarlicError.invalidPayload
    }
    // Unknown block types are skipped per spec.
    var withUnknown = I2PWriter()
    withUnknown.byte(0x7A) // unknown type
    withUnknown.short(3)
    withUnknown.raw(Data([1, 2, 3]))
    withUnknown.raw(bytes)
    guard try I2PGarlicCloveSet.parse(withUnknown.data, messageID: messageID).cloves.count == 3 else {
        throw I2PGarlicError.invalidPayload
    }
    return "DateTime/I2NP blocks round-trip byte-for-byte; 3 cloves across all delivery modes; unknown blocks skipped"
}

// Test: ECIES-X25519 three-section envelope, tag-set delivery in Options
// blocks, and single-use tag enforcement.

private func garlicSessionTagsTest() async throws -> String {
    let aliceKey = Curve25519.KeyAgreement.PrivateKey()
    let aliceManager = I2PGarlicInboundSessionManager(localKey: aliceKey)
    let bobSession = I2PGarlicSession(peerPublicKey: aliceKey.publicKey, tagsPerHandshake: 4)
    let localDelivery = I2PDeliveryInstructions(mode: .local, tunnelID: nil,
                                                routerHash: nil)

    func dataClove(_ text: String) throws -> I2PGarlicClove {
        I2PGarlicClove(deliveryInstructions: localDelivery,
                       message: I2NPMessage(type: .dataMessage, payload: Data(text.utf8)))
    }

    guard bobSession.nextSendEmbedsTagsRecord() else { throw I2PGarlicError.invalidPayload }
    // First message: three-section new-session envelope carrying the tag set
    // in its Options block.
    let tagSet = bobSession.prepareHandshakeTags()
    guard let tagSet, tagSet.seed.count == 32, tagSet.count == 4 else { throw I2PGarlicError.invalidPayload }
    let firstSet = try I2PGarlicCloveSet(expiration: Date().addingTimeInterval(300),
                                         messageID: 0x1234,
                                         cloves: [try dataClove("first")],
                                         tagSetSeed: tagSet.seed, tagCount: tagSet.count)
    let first = try bobSession.wrapCloveSet(try firstSet.serialize())
    // Three sections: ephemeral (32) + static (48) + payload section.
    guard first.count > 32 + 48 + 16 else { throw I2PGarlicError.invalidPayload }
    _ = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: first.prefix(32)) // ephemeral section
    let set1 = try aliceManager.unwrapPayload(first, messageID: 0x1234)
    guard set1.messageID == 0x1234 else { throw I2PGarlicError.invalidPayload }
    guard aliceManager.tagManager.count == 4 else { throw I2PGarlicError.invalidPayload }
    guard aliceManager.establishedPeers == 1 else { throw I2PGarlicError.invalidPayload }
    guard bobSession.isEstablished, !bobSession.nextSendEmbedsTagsRecord() else { throw I2PGarlicError.invalidPayload }

    // Second message: tag-based continuation with the ratcheted tag key.
    let secondSet = try I2PGarlicCloveSet(expiration: Date().addingTimeInterval(300),
                                          messageID: 0x5678,
                                          cloves: [try dataClove("second")])
    let secondBytes = try secondSet.serialize()
    let second = try bobSession.wrapCloveSet(secondBytes)
    // Tag framing: [tag (32)][ciphertext ‖ 16-byte tag].
    guard second.count == 32 + secondBytes.count + 16 else { throw I2PGarlicError.invalidPayload }
    let set2 = try aliceManager.unwrapPayload(second, messageID: 0x5678)
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
    return "three-section new-session envelope registered 4 ratcheted tags, tag follow-up decrypted, replay rejected"
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

    // First message: three-section new-session envelope through the full chain.
    let transmissionA = try I2PGarlicEndToEndPipeline.sendMessage(messageA, to: lease, session: bobSession)
    let (payloadA, firstHopA) = try I2PGarlicEndToEndPipeline.routeThroughTunnelPool(transmissionA, via: bobTunnel)
    let dataA = I2NPMessage(type: .tunnelData, payload: payloadA.serialize())
    await deliveryHub.deliver(from: bob.routerHash, dataA.serialize(), to: firstHopA)
    guard bobSession.isEstablished else { throw I2PGarlicError.invalidPayload }
    try await garlicWaitUntil { box.count >= 1 }

    // Second message: tag-based continuation over the established session.
    let transmissionB = try I2PGarlicEndToEndPipeline.sendMessage(messageB, to: lease, session: bobSession)
    let (payloadB, firstHopB) = try I2PGarlicEndToEndPipeline.routeThroughTunnelPool(transmissionB, via: bobTunnel)
    let dataB = I2NPMessage(type: .tunnelData, payload: payloadB.serialize())
    await deliveryHub.deliver(from: bob.routerHash, dataB.serialize(), to: firstHopB)
    try await garlicWaitUntil { box.count >= 2 }

    guard box.contains(messageA), box.contains(messageB) else { throw I2PGarlicError.invalidPayload }
    guard aliceManager.tagManager.count == 3 else { throw I2PGarlicError.invalidPayload }
    return "garlic via outbound pool -> lease gateway -> inbound tunnel -> ECIES unwrap; three-section new-session + tag sends"
}