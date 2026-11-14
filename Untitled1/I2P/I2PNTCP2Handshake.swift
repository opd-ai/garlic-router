//
//  I2PNTCP2Handshake.swift
//  I2P
//
//  NTCP2 handshake engines for the SessionRequest / SessionCreated /
//  SessionConfirmed exchange of Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256.
//
//  Wire layouts (spec §SessionRequest, §SessionCreated, §SessionConfirmed):
//    message 1: X(32, AES-CBC) ‖ AEAD(options 16) ‖ MAC(16) ‖ padding
//    message 2: Y(32, AES-CBC) ‖ AEAD(options 16) ‖ MAC(16) ‖ padding
//    message 3: AEAD(s 32) ‖ MAC(16) ‖ AEAD(blocks, m3p2len including MAC)
//  Messages 1 and 2 are fixed-length AEAD frames: there is no length prefix.
//

import Foundation
import CryptoKit

final class NTCP2InitiatorHandshake {
    enum Stage { case awaitingSessionCreated, established }

    /// Fixed message-1 envelope ahead of the padding: the 32-byte obfuscated
    /// ephemeral key plus the 16-byte options block and its 16-byte tag.
    static let requestOverhead = 64
    /// Fixed message-2 envelope: the same 64 bytes.
    static let createdOverhead = 64
    /// Message 3 part 1: the encrypted 32-byte static key and its tag.
    static let confirmPart1Length = 48

    private(set) var stage: Stage = .awaitingSessionCreated

    private var chain = NTCP2NoiseChain()
    private let localStatic: Curve25519.KeyAgreement.PrivateKey
    /// Canonical wire bytes of `localStatic`'s public key: message 3 part 1
    /// must carry exactly the bytes the RouterInfo publishes as "s", and
    /// responders memcmp them.
    private let localStaticPublicKey: Data
    private let remoteStatic: Curve25519.KeyAgreement.PublicKey
    private var obfuscator: NTCP2HandshakeObfuscator
    private var ephemeral: Curve25519.KeyAgreement.PrivateKey?
    /// Message 3 part 2 plaintext: the RouterInfo block. Fixed when message 1
    /// is built so m3p2len states its exact frame size.
    private var part2Payload = Data()
    /// The m3p2len value written into the SessionRequest options block — the
    /// wire contract for message 3 part 2, MAC included.
    private(set) var announcedPart2Length: Int = 0

    init(localStaticKey: Curve25519.KeyAgreement.PrivateKey,
         localStaticPublicKey: Data? = nil,
         remoteStaticKey: Data,
         remoteRouterHash: Data,
         remoteIV: Data) throws {
        guard remoteStaticKey.count == 32 else {
            throw NTCP2Error.handshakeFailed("invalid remote static key length")
        }
        localStatic = localStaticKey
        self.localStaticPublicKey = localStaticPublicKey
            ?? I2PCrypto.canonicalX25519PublicKey(localStaticKey.publicKey.rawRepresentation)
        remoteStatic = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: remoteStaticKey)
        obfuscator = try NTCP2HandshakeObfuscator(routerHash: remoteRouterHash, iv: remoteIV)
        // Noise pre-message: <- s. The null prologue is already mixed by
        // NTCP2NoiseChain.init, so this is the message-1 KDF prefix.
        chain.mixHash(remoteStaticKey)
    }

    /// Message 1 (SessionRequest).
    func makeSessionRequest(routerInfo: Data, padding: Int = 0) throws -> Data {
        guard stage == .awaitingSessionCreated else {
            throw NTCP2Error.handshakeFailed("session request already sent")
        }
        guard (0...Int(UInt16.max)).contains(padding) else {
            throw NTCP2Error.handshakeFailed("invalid SessionRequest padding length")
        }

        // Message 3 part 2 carries the RouterInfo block alone. Its frame size
        // (plaintext + 16-byte tag) is the m3p2len message 1 must announce, and
        // it must be exact: the responder frames part 2 by that number.
        part2Payload = try NTCP2Block.encode([.routerInfo(routerInfo)])
        announcedPart2Length = part2Payload.count + 16
        guard announcedPart2Length <= Int(UInt16.max) else {
            throw NTCP2Error.handshakeFailed("RouterInfo too large for SessionConfirmed")
        }

        let e = Curve25519.KeyAgreement.PrivateKey()
        ephemeral = e
        let ephemeralPublic = e.publicKey.rawRepresentation

        // "e": MixHash(e.pubkey)
        chain.mixHash(ephemeralPublic)
        // "es": MixKey(DH(e, rs))
        let es = try e.sharedSecretFromKeyAgreement(with: remoteStatic)
        chain.mixKey(es.withUnsafeBytes { Data($0) })

        // Options block (16 bytes, big-endian):
        // id(1) ver(1) padLen(2) m3p2len(2) Rsvd(2) tsA(4) Reserved(4).
        var options = I2PWriter()
        options.byte(NTCP2Handshake.networkID)
        options.byte(NTCP2Handshake.version)
        options.short(UInt16(padding))
        options.short(UInt16(announcedPart2Length))
        options.short(0)
        options.raw(NTCP2Time.seconds(Date()))
        options.integer(0)
        let optionsFrame = try chain.encrypt(options.data)

        let obfuscatedE = try obfuscator.encrypt(ephemeralPublic)
        var message = obfuscatedE
        message.append(optionsFrame)
        if padding > 0 {
            let paddingBytes = I2PCrypto.randomBytes(padding)
            message.append(paddingBytes)
            // Spec's message-2 KDF folds the message-1 padding into h (it is
            // authenticated only through the next message's AEAD).
            chain.mixHash(paddingBytes)
        }
        return message
    }

    /// Consumes message 2 (SessionCreated) and returns message 3 (SessionConfirmed).
    func processSessionCreated(_ data: Data) throws -> (message: Data, consumed: Int) {
        let bytes = Array(data)
        guard bytes.count >= Self.createdOverhead else { throw NTCP2Error.needMoreData }
        guard let ephemeral else {
            throw NTCP2Error.handshakeFailed("no session request sent")
        }

        // Work on copies so an incomplete message leaves the chain (and the
        // CBC state) untouched for the retry.
        var work = chain
        var workObfuscator = obfuscator

        let e2raw = try workObfuscator.decrypt(Data(bytes[0..<32]))
        let e2 = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: e2raw)
        // "e": MixHash(e.pubkey)
        work.mixHash(e2raw)
        // "ee": MixKey(DH(e, re))
        let ee = try ephemeral.sharedSecretFromKeyAgreement(with: e2)
        work.mixKey(ee.withUnsafeBytes { Data($0) })
        // Message 2's AEAD frame is fixed at 16-byte options + tag.
        let optionsPlain = try work.decrypt(Data(bytes[32..<64]))
        let plain = Array(optionsPlain)
        guard plain.count == 16 else {
            throw NTCP2Error.handshakeFailed("SessionCreated options block must be 16 bytes")
        }

        let paddingLength = (Int(plain[2]) << 8) | Int(plain[3])
        let total = Self.createdOverhead + paddingLength
        guard bytes.count >= total else { throw NTCP2Error.needMoreData }
        let paddingBytes = Data(bytes[Self.createdOverhead..<total])
        if !paddingBytes.isEmpty {
            // Spec's message-3 part-1 KDF folds message 2's padding into h.
            work.mixHash(paddingBytes)
        }
        chain = work
        obfuscator = workObfuscator

        // "s": EncryptAndHash(our static) — nonce 1, since message 2's options
        // frame used nonce 0 in this key epoch.
        let staticCiphertext = try chain.encrypt(localStaticPublicKey)
        // "se": MixKey(DH(s, re))
        let se = try localStatic.sharedSecretFromKeyAgreement(with: e2)
        chain.mixKey(se.withUnsafeBytes { Data($0) })
        // Part 2: AEAD over the blocks, nonce 0, exactly m3p2len on the wire.
        let payloadCiphertext = try chain.encrypt(part2Payload)
        guard payloadCiphertext.count == announcedPart2Length else {
            throw NTCP2Error.handshakeFailed("message 3 part 2 is \(payloadCiphertext.count) bytes but m3p2len announced \(announcedPart2Length)")
        }

        stage = .established
        let split = chain.split()
        sessionKeys = NTCP2SessionKeys(sendKeys: split.ab, recvKeys: split.ba)
        return (staticCiphertext + payloadCiphertext, total)
    }

    private var sessionKeys: NTCP2SessionKeys?

    func complete() throws -> NTCP2SessionKeys {
        guard stage == .established, let sessionKeys else {
            throw NTCP2Error.handshakeFailed("handshake not complete")
        }
        return sessionKeys
    }
}

/// Responder side. Holds its own static key, router hash and published IV; the
/// initiator's static key and RouterInfo arrive inside message 3.
final class NTCP2ResponderHandshake {
    enum Stage { case awaitingRequest, awaitingConfirm, established }

    private(set) var stage: Stage = .awaitingRequest

    private var chain = NTCP2NoiseChain()
    private let localStatic: Curve25519.KeyAgreement.PrivateKey
    private let localStaticPublicKey: Data
    private var obfuscator: NTCP2HandshakeObfuscator
    private var ephemeral: Curve25519.KeyAgreement.PrivateKey?
    private var pendingPart2Length: UInt16 = 0
    private var staticKeyProcessed = false
    private(set) var remoteStaticKey: Data?
    private(set) var remoteRouterInfo: Data?
    private var sessionKeys: NTCP2SessionKeys?

    init(localStaticKey: Curve25519.KeyAgreement.PrivateKey,
         localStaticPublicKey: Data? = nil,
         localRouterHash: Data,
         localIV: Data) throws {
        localStatic = localStaticKey
        self.localStaticPublicKey = localStaticPublicKey
            ?? I2PCrypto.canonicalX25519PublicKey(localStaticKey.publicKey.rawRepresentation)
        obfuscator = try NTCP2HandshakeObfuscator(routerHash: localRouterHash, iv: localIV)
        // Noise pre-message: <- s (our own static key, in the same canonical
        // encoding the RouterInfo publishes).
        chain.mixHash(self.localStaticPublicKey)
    }

    /// Consumes message 1 (SessionRequest) and returns message 2 (SessionCreated).
    func processSessionRequest(_ data: Data, padding: Int = 0) throws -> (reply: Data, consumed: Int) {
        let bytes = Array(data)
        guard bytes.count >= NTCP2InitiatorHandshake.requestOverhead else { throw NTCP2Error.needMoreData }
        guard (0...Int(UInt16.max)).contains(padding) else {
            throw NTCP2Error.handshakeFailed("invalid SessionCreated padding length")
        }

        var work = chain
        var workObfuscator = obfuscator

        let e1raw = try workObfuscator.decrypt(Data(bytes[0..<32]))
        let e1 = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: e1raw)
        // "e": MixHash(e.pubkey)
        work.mixHash(e1raw)
        // "es": MixKey(DH(rs, re))
        let es = try localStatic.sharedSecretFromKeyAgreement(with: e1)
        work.mixKey(es.withUnsafeBytes { Data($0) })
        let optionsPlain = try work.decrypt(Data(bytes[32..<64]))
        let plain = Array(optionsPlain)
        guard plain.count == 16 else {
            throw NTCP2Error.handshakeFailed("SessionRequest options block must be 16 bytes")
        }
        guard plain[0] == NTCP2Handshake.networkID else {
            throw NTCP2Error.handshakeFailed("peer network ID \(plain[0]) is not this network's")
        }
        guard plain[1] == NTCP2Handshake.version else {
            throw NTCP2Error.handshakeFailed("unsupported NTCP2 version \(plain[1])")
        }
        let paddingLength = (Int(plain[2]) << 8) | Int(plain[3])
        let announcedPart2 = (UInt16(plain[4]) << 8) | UInt16(plain[5])
        guard announcedPart2 > 16 else {
            throw NTCP2Error.handshakeFailed("invalid message 3 part 2 length")
        }
        let total = NTCP2InitiatorHandshake.requestOverhead + paddingLength
        guard bytes.count >= total else { throw NTCP2Error.needMoreData }
        let paddingBytes = Data(bytes[NTCP2InitiatorHandshake.requestOverhead..<total])
        if !paddingBytes.isEmpty {
            // Spec's message-2 KDF folds message 1's padding into h.
            work.mixHash(paddingBytes)
        }
        chain = work
        obfuscator = workObfuscator
        pendingPart2Length = announcedPart2

        // Message 2.
        let e2 = Curve25519.KeyAgreement.PrivateKey()
        ephemeral = e2
        // "e": MixHash(e.pubkey)
        chain.mixHash(e2.publicKey.rawRepresentation)
        // "ee": MixKey(DH(e', re))
        let ee = try e2.sharedSecretFromKeyAgreement(with: e1)
        chain.mixKey(ee.withUnsafeBytes { Data($0) })

        // Options block (16 bytes, big-endian): Rsvd(2) padLen(2) Reserved(4)
        // tsB(4) Reserved(4).
        var options = I2PWriter()
        options.short(0)
        options.short(UInt16(padding))
        options.integer(0)
        options.raw(NTCP2Time.seconds(Date()))
        options.integer(0)
        let optionsFrame = try chain.encrypt(options.data)

        var replyPadding = Data()
        if padding > 0 {
            replyPadding = I2PCrypto.randomBytes(padding)
            // Spec's message-3 part-1 KDF folds message 2's padding into h.
            chain.mixHash(replyPadding)
        }
        let obfuscatedE2 = try obfuscator.encrypt(e2.publicKey.rawRepresentation)
        var reply = obfuscatedE2
        reply.append(optionsFrame)
        reply.append(replyPadding)
        stage = .awaitingConfirm
        return (reply, total)
    }

    /// Consumes message 3 (SessionConfirmed): part 1 = AEAD(static key),
    /// part 2 = AEAD(RouterInfo block and optional padding). May be called
    /// repeatedly with partial data.
    func processSessionConfirm(_ data: Data) throws -> Int {
        let bytes = Array(data)

        if !staticKeyProcessed {
            guard bytes.count >= NTCP2InitiatorHandshake.confirmPart1Length else {
                throw NTCP2Error.needMoreData
            }
            let staticKey = Array(try chain.decrypt(Data(bytes[0..<NTCP2InitiatorHandshake.confirmPart1Length])))
            guard staticKey.count == 32 else {
                throw NTCP2Error.handshakeFailed("invalid static key in SessionConfirmed")
            }
            remoteStaticKey = Data(staticKey)
            staticKeyProcessed = true
            let peerStatic = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data(staticKey))
            guard let ephemeral else {
                throw NTCP2Error.handshakeFailed("missing responder ephemeral key")
            }
            // "se": MixKey(DH(e', s))
            let se = try ephemeral.sharedSecretFromKeyAgreement(with: peerStatic)
            chain.mixKey(se.withUnsafeBytes { Data($0) })
        }

        let total = NTCP2InitiatorHandshake.confirmPart1Length + Int(pendingPart2Length)
        guard bytes.count >= total else { throw NTCP2Error.needMoreData }
        let plaintext = try chain.decrypt(Data(bytes[NTCP2InitiatorHandshake.confirmPart1Length..<total]))
        var routerInfo: Data?
        for block in try NTCP2Block.decode(plaintext) {
            if case .routerInfo(let info) = block {
                routerInfo = info
                break
            }
        }
        guard let routerInfo else {
            throw NTCP2Error.handshakeFailed("message 3 part 2 carried no RouterInfo block")
        }
        remoteRouterInfo = routerInfo

        stage = .established
        let split = chain.split()
        // Responder sends on the ba direction, receives on ab.
        sessionKeys = NTCP2SessionKeys(sendKeys: split.ba, recvKeys: split.ab)
        return total
    }

    func complete() throws -> NTCP2SessionKeys {
        guard stage == .established, let sessionKeys else {
            throw NTCP2Error.handshakeFailed("handshake not complete")
        }
        return sessionKeys
    }
}
