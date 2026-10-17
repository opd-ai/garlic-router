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
    private let obfuscationKey: Data
    private var ourRouterInfo = Data()
    private var sessionKeys: NTCP2SessionKeys?

    init(localStaticKey: Curve25519.KeyAgreement.PrivateKey, remoteStaticKey: Data) throws {
        guard remoteStaticKey.count == 32 else {
            throw NTCP2Error.handshakeFailed("invalid remote static key length")
        }
        localStatic = localStaticKey
        remoteStatic = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: remoteStaticKey)
        obfuscationKey = NTCP2KeyObfuscation.key(remoteStatic: remoteStaticKey)
        // Noise pre-message: <- s
        chain.mixHash(remoteStaticKey)
    }

    /// Message 1 (SessionRequest): IV || obfuscated e || AEAD(options) || padding.
    /// Options (16 bytes): version(1)=12, paddingLen(1), m3p2len(2), timestamp(8), reserved(4).
    func makeSessionRequest(routerInfo: Data, padding: Int = 0) throws -> Data {
        guard stage == .awaitingSessionCreated else {
            throw NTCP2Error.handshakeFailed("session request already sent")
        }
        guard routerInfo.count + 16 <= 0xFFFF else {
            throw NTCP2Error.handshakeFailed("RouterInfo too large for SessionRequest")
        }
        ourRouterInfo = routerInfo

        let iv = I2PCrypto.randomBytes(16)
        chain.mixHash(iv)

        let e = Curve25519.KeyAgreement.PrivateKey()
        ephemeral = e
        chain.mixHash(e.publicKey.rawRepresentation)
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

        let obfuscatedE = NTCP2KeyObfuscation.apply(e.publicKey.rawRepresentation,
                                                    obfuscationKey: obfuscationKey,
                                                    counter: 0)
        var message = iv + obfuscatedE + ciphertext
        if padding > 0 { message += I2PCrypto.randomBytes(padding) }
        return message
    }

    /// Consumes message 2 (SessionCreated); returns message 3 bytes to send.
    /// Message 3 = part 1 (AEAD of our static key, 48 bytes) + part 2 (AEAD of our RouterInfo).
    func processSessionCreated(_ data: Data) throws -> (message: Data, consumed: Int) {
        let bytes = Array(data)
        guard bytes.count >= 64 else { throw NTCP2Error.needMoreData }

        // Run on a scratch copy so an incomplete message leaves the chain untouched.
        var work = chain
        let e2raw = NTCP2KeyObfuscation.apply(Data(bytes[0..<32]), obfuscationKey: obfuscationKey, counter: 1)
        let e2 = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: e2raw)
        work.mixHash(e2raw)
        // "ee": MixKey(DH(e, re))
        let ee = try ephemeral!.sharedSecretFromKeyAgreement(with: e2)
        work.mixKey(ee.withUnsafeBytes { Data($0) })
        let options = try work.decrypt(Data(bytes[32..<64]))
        guard options.count == 16, options[0] == 12 else {
            throw NTCP2Error.handshakeFailed("unsupported NTCP2 version")
        }
        let paddingLength = Int(options[1])
        let total = 64 + paddingLength
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
    private let obfuscationKey: Data
    private var ephemeral: Curve25519.KeyAgreement.PrivateKey?
    private var pendingPart2Length: UInt16 = 0
    private var staticKeyProcessed = false
    private(set) var remoteStaticKey: Data?
    private(set) var remoteRouterInfo: Data?
    private var sessionKeys: NTCP2SessionKeys?

    init(localStaticKey: Curve25519.KeyAgreement.PrivateKey) {
        localStatic = localStaticKey
        obfuscationKey = NTCP2KeyObfuscation.key(remoteStatic: localStatic.publicKey.rawRepresentation)
        // Noise pre-message: <- s (our own static key)
        chain.mixHash(localStatic.publicKey.rawRepresentation)
    }

    /// Consumes message 1 (SessionRequest); returns message 2 (SessionCreated) bytes.
    func processSessionRequest(_ data: Data, padding: Int = 0) throws -> (reply: Data, consumed: Int) {
        let bytes = Array(data)
        guard bytes.count >= 80 else { throw NTCP2Error.needMoreData }

        var work = chain
        let iv = Data(bytes[0..<16])
        work.mixHash(iv)
        let e1raw = NTCP2KeyObfuscation.apply(Data(bytes[16..<48]), obfuscationKey: obfuscationKey, counter: 0)
        let e1 = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: e1raw)
        work.mixHash(e1raw)
        // "es": MixKey(DH(rs, re))
        let shared = try localStatic.sharedSecretFromKeyAgreement(with: e1)
        work.mixKey(shared.withUnsafeBytes { Data($0) })
        let options = try work.decrypt(Data(bytes[48..<80]))
        guard options.count == 16, options[0] == 12 else {
            throw NTCP2Error.handshakeFailed("unsupported NTCP2 version")
        }
        let paddingLength = Int(options[1])
        let announcedPart2 = (UInt16(options[2]) << 8) | UInt16(options[3])
        guard announcedPart2 >= 16 else {
            throw NTCP2Error.handshakeFailed("invalid message 3 part 2 length")
        }
        let total = 80 + paddingLength
        guard bytes.count >= total else { throw NTCP2Error.needMoreData }
        chain = work
        pendingPart2Length = announcedPart2

        // Message 2: obfuscated e' || AEAD(options) || padding
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
        let obfuscatedE2 = NTCP2KeyObfuscation.apply(e2.publicKey.rawRepresentation,
                                                     obfuscationKey: obfuscationKey,
                                                     counter: 1)
        var reply = obfuscatedE2 + ciphertext
        if padding > 0 { reply += I2PCrypto.randomBytes(padding) }
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