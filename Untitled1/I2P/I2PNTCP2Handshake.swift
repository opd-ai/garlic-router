//
//  I2PNTCP2Handshake.swift
//  I2P
//
//  NTCP2 handshake engines for the Noise_XK_25519_ChaChaPoly_SHA256
//  SessionRequest / SessionCreated / SessionConfirm exchange.
//

import Foundation
import CryptoKit

/// Initiator side. The responder's static key is known out-of-band from its
/// RouterInfo ("s" option), per the Noise XK pattern.
final class NTCP2InitiatorHandshake {
    enum Stage { case awaitingSessionCreated, established }

    private(set) var stage: Stage = .awaitingSessionCreated

    private var chain = NTCP2NoiseChain()
    private let localStatic: Curve25519.KeyAgreement.PrivateKey
    private let remoteStatic: Curve25519.KeyAgreement.PublicKey
    private var ephemeral: Curve25519.KeyAgreement.PrivateKey?
    private var ourRouterInfo = Data()
    private var sessionKeys: NTCP2SessionKeys?

    init(localStaticKey: Curve25519.KeyAgreement.PrivateKey, remoteStaticKey: Data) throws {
        guard remoteStaticKey.count == 32 else {
            throw NTCP2Error.handshakeFailed("invalid remote static key length")
        }
        localStatic = localStaticKey
        remoteStatic = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: remoteStaticKey)
        // Noise pre-message: <- s
        chain.mixHash(remoteStaticKey)
    }

    /// Message 1 (SessionRequest): obfuscated e (AES-256-CBC per the spec KDF)
    /// + 2-byte options length prefix + AEAD(options) + padding.
    /// Options (16 bytes): version(1)=12, paddingLen(1), m3p2len(2), timestamp(8), reserved(4).
    func makeSessionRequest(routerInfo: Data, padding: Int = 0) throws -> Data {
        guard stage == .awaitingSessionCreated else {
            throw NTCP2Error.handshakeFailed("session request already sent")
        }
        guard routerInfo.count + 16 <= 0xFFFF else {
            throw NTCP2Error.handshakeFailed("RouterInfo too large for SessionRequest")
        }
        ourRouterInfo = routerInfo

        let e = Curve25519.KeyAgreement.PrivateKey()
        ephemeral = e
        let ephemeralPublic = e.publicKey.rawRepresentation
        chain.mixHash(ephemeralPublic)
        // "es": MixKey(DH(e, rs))
        let es = try e.sharedSecretFromKeyAgreement(with: remoteStatic)
        chain.mixKey(es.withUnsafeBytes { Data($0) })

        let part2Length = routerInfo.count + 16
        var options = Data(repeating: 0, count: 16)
        options[0] = 12
        options[1] = UInt8(padding)
        options[2] = UInt8((part2Length >> 8) & 0xff)
        options[3] = UInt8(part2Length & 0xff)
        options.replaceSubrange(4..<12, with: NTCP2Time.milliseconds(Date()))
        let ciphertext = try chain.encrypt(options)

        // Spec obfuscation: AES-256-CBC under the KDF derived from the
        // responder's static key, bound to the initial chaining key.
        let obfuscatedE = try NTCP2KeyObfuscation.encrypt(ephemeralPublic,
                                                          chainingKey: NTCP2NoiseChain.initialChainingKey,
                                                          material: remoteStatic.rawRepresentation)
        var message = obfuscatedE
        let optionsLengthHigh = UInt8((ciphertext.count >> 8) & 0xff)
        let optionsLengthLow = UInt8(ciphertext.count & 0xff)
        message.append(optionsLengthHigh)
        message.append(optionsLengthLow)
        message.append(ciphertext)
        if padding > 0 {
            message.append(contentsOf: I2PCrypto.randomBytes(padding))
        }
        return message
    }

    /// Consumes message 2 (SessionCreated): obfuscated e' + 2-byte options length
    /// prefix + AEAD(options) + padding. Returns message 3 bytes to send.
    /// Message 3 = part 1 (AEAD of our static key, 48 bytes) + part 2 (AEAD of our RouterInfo).
    func processSessionCreated(_ data: Data) throws -> (message: Data, consumed: Int) {
        let bytes = Array(data)
        guard bytes.count >= 66 else { throw NTCP2Error.needMoreData }
        guard let ephemeral else {
            throw NTCP2Error.handshakeFailed("no session request sent")
        }

        // Deobfuscate the responder's ephemeral key via the spec KDF bound to
        // our plaintext ephemeral. Run on a scratch copy so an incomplete
        // message leaves the chain untouched.
        var work = chain
        let e2raw = try NTCP2KeyObfuscation.decrypt(Data(bytes[0..<32]),
                                                    chainingKey: NTCP2NoiseChain.initialChainingKey,
                                                    material: ephemeral.publicKey.rawRepresentation)
        let e2 = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: e2raw)
        work.mixHash(e2raw)
        // "ee": MixKey(DH(e, re))
        let ee = try ephemeral.sharedSecretFromKeyAgreement(with: e2)
        work.mixKey(ee.withUnsafeBytes { Data($0) })
        // 2-byte options length prefix, then the AEAD-encrypted options block.
        let optionsLength = (Int(bytes[32]) << 8) | Int(bytes[33])
        guard bytes.count >= 34 + optionsLength else { throw NTCP2Error.needMoreData }
        let options = try work.decrypt(Data(bytes[34..<34 + optionsLength]))
        guard options.count == 16, options[0] == 12 else {
            throw NTCP2Error.handshakeFailed("unsupported NTCP2 version")
        }
        let paddingLength = Int(options[1])
        let total = 34 + optionsLength + paddingLength
        guard bytes.count >= total else { throw NTCP2Error.needMoreData }
        chain = work

        // "s": EncryptAndHash(our static) under the ee-stage key
        let staticCiphertext = try chain.encrypt(localStatic.publicKey.rawRepresentation)
        // "es": MixKey(DH(s, re))
        let es = try localStatic.sharedSecretFromKeyAgreement(with: e2)
        chain.mixKey(es.withUnsafeBytes { Data($0) })
        let payloadCiphertext = try chain.encrypt(ourRouterInfo)

        stage = .established
        let split = chain.split()
        sessionKeys = NTCP2SessionKeys(sendKeys: split.ab, recvKeys: split.ba)
        return (staticCiphertext + payloadCiphertext, total)
    }

    func complete() throws -> NTCP2SessionKeys {
        guard stage == .established, let sessionKeys else {
            throw NTCP2Error.handshakeFailed("handshake not complete")
        }
        return sessionKeys
    }
}

/// Responder side. Holds its own static key; the initiator's static key and
/// RouterInfo arrive inside message 3.
final class NTCP2ResponderHandshake {
    enum Stage { case awaitingRequest, awaitingConfirm, established }

    private(set) var stage: Stage = .awaitingRequest

    private var chain = NTCP2NoiseChain()
    private let localStatic: Curve25519.KeyAgreement.PrivateKey
    private var ephemeral: Curve25519.KeyAgreement.PrivateKey?
    private var pendingPart2Length: UInt16 = 0
    private var staticKeyProcessed = false
    private(set) var remoteStaticKey: Data?
    private(set) var remoteRouterInfo: Data?
    private var sessionKeys: NTCP2SessionKeys?

    init(localStaticKey: Curve25519.KeyAgreement.PrivateKey) {
        localStatic = localStaticKey
        // Noise pre-message: <- s (our own static key)
        chain.mixHash(localStatic.publicKey.rawRepresentation)
    }

    /// Consumes message 1 (SessionRequest): obfuscated e + 2-byte options length
    /// prefix + AEAD(options) + padding. Returns message 2 (SessionCreated) bytes.
    func processSessionRequest(_ data: Data, padding: Int = 0) throws -> (reply: Data, consumed: Int) {
        let bytes = Array(data)
        guard bytes.count >= 66 else { throw NTCP2Error.needMoreData }

        var work = chain
        // Deobfuscate the initiator's ephemeral key: AES-256-CBC under the spec
        // KDF bound to our static key and the initial chaining key.
        let e1raw = try NTCP2KeyObfuscation.decrypt(Data(bytes[0..<32]),
                                                    chainingKey: NTCP2NoiseChain.initialChainingKey,
                                                    material: localStatic.publicKey.rawRepresentation)
        let e1 = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: e1raw)
        work.mixHash(e1raw)
        // "es": MixKey(DH(rs, re))
        let shared = try localStatic.sharedSecretFromKeyAgreement(with: e1)
        work.mixKey(shared.withUnsafeBytes { Data($0) })
        // 2-byte options length prefix, then the AEAD-encrypted options block.
        let optionsLength = (Int(bytes[32]) << 8) | Int(bytes[33])
        guard bytes.count >= 34 + optionsLength else { throw NTCP2Error.needMoreData }
        let options = try work.decrypt(Data(bytes[34..<34 + optionsLength]))
        guard options.count == 16, options[0] == 12 else {
            throw NTCP2Error.handshakeFailed("unsupported NTCP2 version")
        }
        let paddingLength = Int(options[1])
        let announcedPart2 = (UInt16(options[2]) << 8) | UInt16(options[3])
        guard announcedPart2 >= 16 else {
            throw NTCP2Error.handshakeFailed("invalid message 3 part 2 length")
        }
        let total = 34 + optionsLength + paddingLength
        guard bytes.count >= total else { throw NTCP2Error.needMoreData }
        chain = work
        pendingPart2Length = announcedPart2

        // Message 2: obfuscated e' (AES-256-CBC under the KDF bound to the
        // initiator's plaintext ephemeral) + 2-byte options length prefix
        // + AEAD(options) + padding.
        let e2 = Curve25519.KeyAgreement.PrivateKey()
        ephemeral = e2
        chain.mixHash(e2.publicKey.rawRepresentation)
        // "ee": MixKey(DH(e', re))
        let ee = try e2.sharedSecretFromKeyAgreement(with: e1)
        chain.mixKey(ee.withUnsafeBytes { Data($0) })

        var options2 = Data(repeating: 0, count: 16)
        options2[0] = 12
        options2[1] = UInt8(padding)
        options2.replaceSubrange(4..<12, with: NTCP2Time.milliseconds(Date()))
        let ciphertext = try chain.encrypt(options2)
        let obfuscatedE2 = try NTCP2KeyObfuscation.encrypt(e2.publicKey.rawRepresentation,
                                                           chainingKey: NTCP2NoiseChain.initialChainingKey,
                                                           material: e1raw)
        var reply = obfuscatedE2
        let replyOptionsLengthHigh = UInt8((ciphertext.count >> 8) & 0xff)
        let replyOptionsLengthLow = UInt8(ciphertext.count & 0xff)
        reply.append(replyOptionsLengthHigh)
        reply.append(replyOptionsLengthLow)
        reply.append(ciphertext)
        if padding > 0 {
            reply.append(contentsOf: I2PCrypto.randomBytes(padding))
        }
        stage = .awaitingConfirm
        return (reply, total)
    }

    /// Consumes message 3 (SessionConfirm): part 1 = AEAD(remote static, 48 bytes),
    /// part 2 = AEAD(remote RouterInfo). May be called repeatedly with partial data.
    func processSessionConfirm(_ data: Data) throws -> Int {
        let bytes = Array(data)

        if !staticKeyProcessed {
            guard bytes.count >= 48 else { throw NTCP2Error.needMoreData }
            let staticKey = try chain.decrypt(Data(bytes[0..<48]))
            guard staticKey.count == 32 else {
                throw NTCP2Error.handshakeFailed("invalid static key in SessionConfirm")
            }
            remoteStaticKey = staticKey
            staticKeyProcessed = true
            let peerStatic = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: staticKey)
            // "es": MixKey(DH(e', s))
            let es = try ephemeral!.sharedSecretFromKeyAgreement(with: peerStatic)
            chain.mixKey(es.withUnsafeBytes { Data($0) })
        }

        let part2Length = Int(pendingPart2Length)
        let total = 48 + part2Length
        guard bytes.count >= total else { throw NTCP2Error.needMoreData }
        remoteRouterInfo = try chain.decrypt(Data(bytes[48..<total]))

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