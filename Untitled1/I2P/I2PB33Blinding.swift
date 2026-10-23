//
//  I2PB33Blinding.swift
//  Encrypted LeaseSet2 (b33) resolution per the I2P blinding spec
//  (encrypted-leaseset spec / proposal 123 ECIES LS2).
//
//  Blinded key derivation:
//    - salt  = SHA256(AS_01 || B || CT_01) with AS_01 = blind scheme
//      (0x0000, Ed25519-SHA-256) and CT_01 = enc type (0x0004, ECIES-X25519)
//      of the unblinded signing public key B.
//    - seed  = HKDF-SHA256(ikm = b33 secret (may be empty), salt, info = "i2pblinding1", 32)
//    - alpha = clamp(SHA512(seed)[0..<32])  (standard Ed25519 scalar clamp)
//    - blinded signing key  K  = alpha · B           (point multiplication)
//    - blinded private key  k' = alpha · k mod L     (k = clamp(SHA512(destSeed)[0..<32]))
//      — the scalar the envelope signature is made with.
//    - blinded netdb key = SHA-256 of the envelope destination: the blinded
//      signing key K carried in a key certificate alongside the destination's
//      real ECIES X25519 key (which the envelope delivers for keying).
//      Lookups for encrypted LS2 entries ride that blinded key, never the
//      unblinded destination hash.
//
//  b33 address: "b" + 2 checksum chars + base32(flag 0x00, scheme 0x00,
//  encType 0x04, K). The checksum replaces the first two base32 characters:
//  c = SHA256(body)[0] & 0x1f, split 2 + 3 bits into two constrained-alphabet
//  characters so a wrong checksum cannot decode.
//
//  Encrypted body (the type-3 payload's opaque body) — authentication section
//  then encrypted data section:
//    authType (1: 0 none / 1 DH client auth / 3 PSK client auth)
//    if != 0: sectionSalt (32) + clientCount (1) + per client:
//        clientID (8)  = SHA256(authKey)[0..<8]
//        clientDataLength (2 BE) + clientData:
//            type 1: authEphemeralPublicKey (32) + ChaChaPoly box of the PSK
//            type 3: empty (authorization rides the clientID match)
//    encType (1, 4 = ECIES-X25519) + ephemeralPublicKey (32) +
//    ChaChaPoly box (inner plain LeaseSet2 payload, full type+length+data+sig)
//  Key derivation:
//    authKey (type 1) = HKDF-SHA256(X25519(authEphemeral, clientPriv), salt: sectionSalt, info: "ELS2SAC", 32)
//    authKey (type 3) = HKDF-SHA256(clientPSK, salt: sectionSalt, info: "ELS2SAC", 32)
//    body key         = HKDF-SHA256(X25519(bodyEphemeral, destPriv), salt: sectionSalt (zeros for type 0), info: "ELS2SAD", 32)
//    boxes seal/open with the 12-byte zero nonce (single-use, key-bound).
//
//  The decrypted inner payload is a complete plain LeaseSet2 carrying the real
//  destination — parse-verified fail closed — whose leases surface through the
//  same resolvedLeaseSet() delivery path plain LS2s already use.
//

import Foundation
import CryptoKit

/// Credentials held for one destination: the Ed25519 signing seed drives the
/// blinding derivation, the ECIES X25519 private key opens the encrypted
/// inner body, and the optional client credentials authorize auth'd publications.
struct I2PB33Credentials {
    let ed25519Seed: Data
    let x25519PrivateKey: Data
    /// Optional b33 secret binding the blinding derivation (empty for plain b33s).
    var secret: Data = Data()
    /// ECIES X25519 private keys held as DH client-auth credentials (auth type 1).
    var clientECIESPrivateKeys: [Data] = []
    /// PSKs held as PSK client-auth credentials (auth type 3).
    var clientPSKs: [Data] = []
}

/// One authorized client in an encrypted LS2's authentication section (publisher side).
struct I2PELS2AuthClient {
    enum Kind: UInt8 {
        case dh = 1     // DH client auth: client holds an ECIES X25519 private key
        case psk = 3    // PSK client auth: client holds the shared PSK
    }
    let kind: Kind
    /// Type 1: the client's ECIES X25519 public key. Type 3: unused (empty).
    let clientPublicKey: Data
    /// The 32-byte PSK sealed to the client inside the auth section.
    let psk: Data
}

enum I2PB33Blinding {
    // MARK: Spec constants
    static let blindingInfo = Data("i2pblinding1".utf8)
    static let els2BodyInfo = Data("ELS2SAD".utf8)   // encrypted LS2 body key
    static let els2AuthInfo = Data("ELS2SAC".utf8)   // LS2 auth client key
    static let aadZero = Data()

    /// Ed25519-SHA-256 blind scheme, ECIES-X25519-Ratchet enc type (2-byte big-endian codes).
    static let blindSchemeCode: [UInt8] = [0x00, 0x00]
    static let encTypeCode: [UInt8] = [0x00, 0x04]

    // MARK: Blinded key derivation

    struct BlindedKey {
        /// The blinded Ed25519 signing public key K = alpha·B (32 bytes).
        let blindedPublicKey: Data
        /// The blinded private key k' = alpha·k mod L — signs the envelope.
        let blindedSigningScalar: Data
        /// Envelope destination: blinded signing key + the destination's real
        /// ECIES X25519 key. Its SHA-256 is the blinded netdb key.
        let envelopeDestination: I2PDestination
        /// The blinded netdb key lookups ride (SHA-256 of the envelope destination).
        let netDBKey: Data
        /// The spec's b33 address for the blinded key.
        let b33Address: String
    }

    /// Derives the blinded key set per the blinding spec.
    static func blind(destinationSeed: Data, encryptionPublicKey: Data,
                      secret: Data = Data()) throws -> BlindedKey {
        guard destinationSeed.count == 32, encryptionPublicKey.count == 32 else {
            throw I2PWireError.invalidFormat
        }
        let unblindedKey = I2PCrypto.ed25519PublicKey(fromSeed: destinationSeed)
        // alpha = clamp(SHA512(HKDF(secret, salt, "i2pblinding1"))[0..<32])
        let salt = I2PCrypto.sha256(Data(blindSchemeCode) + unblindedKey + Data(encTypeCode))
        let seed = I2PCrypto.hkdfSHA256(inputKeyMaterial: secret, salt: salt,
                                        info: blindingInfo, outputLength: 32)
        let h = Ed25519Pure.sha512(Array(seed))
        let alpha = Ed25519Pure.clampScalar(Array(h[0..<32]))

        // K = alpha · B (point multiplication of the unblinded signing key).
        guard let bPoint = GePoint(compressed: Array(unblindedKey)) else {
            throw I2PWireError.invalidFormat
        }
        let blindedPublicKey = Data(GePoint.multiply(bPoint, alpha).encode())

        // k' = alpha · k mod L — the blinded private key (k = clamp(SHA512(seed)[0..<32])).
        let kh = Ed25519Pure.sha512(Array(destinationSeed))
        let k = Ed25519Pure.clampScalar(Array(kh[0..<32]))
        let alphaLimbs = Ed25519Scalar.bytesToLimbs(alpha, limbCount: 4)
        let kLimbs = Ed25519Scalar.bytesToLimbs(k, limbCount: 4)
        let blindedScalar = Data(Ed25519Scalar.limbsToBytes(
            Ed25519Scalar.reduceModL(Ed25519Scalar.mulWide(alphaLimbs, kLimbs))))

        // Envelope destination: blinded signing key + the real ECIES key for keying.
        let envelopeDestination = I2PKeysAndCert(
            encryptionPublicKey: encryptionPublicKey,
            signingPublicKey: blindedPublicKey)
        return BlindedKey(
            blindedPublicKey: blindedPublicKey,
            blindedSigningScalar: blindedScalar,
            envelopeDestination: envelopeDestination,
            netDBKey: envelopeDestination.hash,
            b33Address: b33Address(blindedPublicKey: blindedPublicKey))
    }

    /// The destination ECIES public key matching a credential set (rides the envelope).
    static func destinationEncryptionPublicKey(_ credentials: I2PB33Credentials) -> Data? {
        I2PCrypto.x25519PublicKey(fromPrivateKey: credentials.x25519PrivateKey)
    }

    // MARK: b33 address codec

    static let b33ChecksumFirst = "aeim"       // 2 checksum bits (index c >> 3)
    static let b33ChecksumSecond = "aeimquy2"  // 3 checksum bits (index c & 0x07)

    /// The 35-byte b33 body: flag 0x00 + scheme 0x00 (Ed25519-SHA-256) +
    /// encType 0x04 (ECIES-X25519) + the blinded public key.
    static func b33Body(blindedPublicKey: Data) -> Data {
        precondition(blindedPublicKey.count == 32)
        return Data([0x00, 0x00, 0x04]) + blindedPublicKey
    }

    /// Encodes the b33 address: "b" + 2 checksum chars + base32(body) minus
    /// its first two characters (those bits are the zero flag/scheme prefix,
    /// recovered as "aa" on decode).
    static func b33Address(blindedPublicKey: Data) -> String {
        let body = b33Body(blindedPublicKey: blindedPublicKey)
        let encoded = base32Encode(body)
        let c = Int(I2PCrypto.sha256(body)[0]) & 0x1f
        let first = b33ChecksumFirst[b33ChecksumFirst.index(b33ChecksumFirst.startIndex, offsetBy: c >> 3)]
        let second = b33ChecksumSecond[b33ChecksumSecond.index(b33ChecksumSecond.startIndex, offsetBy: c & 0x07)]
        return "b" + String(first) + String(second) + encoded.dropFirst(2)
    }

    /// Decodes a b33 address, verifying the checksum and the flag/scheme/encType
    /// bytes. Returns the blinded public key.
    static func b33Decode(_ address: String) -> Data? {
        guard address.count == 57, address.first == "b" else { return nil }
        let payload = address.dropFirst()
        let firstChar = payload.first!
        let secondChar = payload.dropFirst().first!
        guard let firstIdx = b33ChecksumFirst.firstIndex(of: firstChar),
              let secondIdx = b33ChecksumSecond.firstIndex(of: secondChar) else {
            return nil
        }
        let remainder = payload.dropFirst(2)
        guard let body = base32Decode("aa" + remainder) else { return nil }
        guard body.count == 35, body[0] == 0x00, body[1] == 0x00, body[2] == 0x04 else {
            return nil
        }
        let c = Int(I2PCrypto.sha256(body)[0]) & 0x1f
        guard (c >> 3) == b33ChecksumFirst.distance(from: b33ChecksumFirst.startIndex, to: firstIdx),
              (c & 0x07) == b33ChecksumSecond.distance(from: b33ChecksumSecond.startIndex, to: secondIdx) else {
            return nil
        }
        return body.dropFirst(3)
    }

    // MARK: RFC 4648 base32 (lowercase, no padding)

    static func base32Encode(_ data: Data) -> String {
        let alphabet = Array("abcdefghijklmnopqrstuvwxyz234567")
        var out = ""
        var buffer = 0
        var bits = 0
        for byte in data {
            buffer = (buffer << 8) | Int(byte)
            bits += 8
            while bits >= 5 {
                bits -= 5
                out.append(alphabet[(buffer >> bits) & 0x1f])
            }
        }
        if bits > 0 {
            out.append(alphabet[(buffer << (5 - bits)) & 0x1f])
        }
        return out
    }

    static func base32Decode(_ string: String) -> Data? {
        let alphabet = Array("abcdefghijklmnopqrstuvwxyz234567")
        var out: [UInt8] = []
        var buffer = 0
        var bits = 0
        for ch in string.lowercased() {
            guard let value = alphabet.firstIndex(of: ch) else { return nil }
            buffer = (buffer << 5) | value
            bits += 5
            if bits >= 8 {
                bits -= 8
                out.append(UInt8((buffer >> bits) & 0xff))
            }
        }
        return Data(out)
    }

    // MARK: Encrypted body — seal (publisher)

    /// Builds the encrypted body for a type-3 LS2 envelope: the authentication
    /// section (auth types 1/3) and the encrypted data section carrying the
    /// inner plain LeaseSet2 payload.
    static func buildEncryptedBody(innerPayload: Data, destinationEncryptionPublicKey: Data,
                                   authClients: [I2PELS2AuthClient]) throws -> Data {
        guard destinationEncryptionPublicKey.count == 32 else {
            throw I2PWireError.invalidFormat
        }
        var w = I2PWriter()
        let sectionSalt = I2PCrypto.randomBytes(32)
        if authClients.isEmpty {
            w.byte(0)
        } else {
            let kinds = Set(authClients.map(\.kind))
            guard kinds.count == 1, let kind = kinds.first else {
                throw I2PWireError.invalidFormat // one auth scheme per publication
            }
            w.byte(kind.rawValue)
            w.hash(sectionSalt)
            w.byte(UInt8(authClients.count))
            for client in authClients {
                guard client.psk.count == 32 else { throw I2PWireError.invalidFormat }
                let authKey: Data
                switch kind {
                case .dh:
                    guard client.clientPublicKey.count == 32 else { throw I2PWireError.invalidFormat }
                    let ephemeral = I2PCrypto.generateX25519KeyPair()
                    authKey = I2PCrypto.hkdfSHA256(
                        inputKeyMaterial: try I2PCrypto.x25519SharedSecret(
                            privateKey: ephemeral.privateKey, peerPublicKey: client.clientPublicKey),
                        salt: sectionSalt, info: els2AuthInfo, outputLength: 32)
                    w.hash(clientID(authKey: authKey))
                    var clientData = ephemeral.publicKey
                    clientData.append(try I2PCrypto.chacha20Poly1305Seal(
                        key: authKey, nonce: zeroNonce, plaintext: client.psk, aad: aadZero))
                    w.short(UInt16(clientData.count))
                    w.raw(clientData)
                case .psk:
                    authKey = I2PCrypto.hkdfSHA256(
                        inputKeyMaterial: client.psk, salt: sectionSalt,
                        info: els2AuthInfo, outputLength: 32)
                    w.hash(clientID(authKey: authKey))
                    w.short(0) // authorization rides the clientID match
                }
            }
        }
        // Encrypted data section: encType 4 + ephemeral + ChaChaPoly(inner LS2).
        w.byte(4)
        let ephemeral = I2PCrypto.generateX25519KeyPair()
        w.raw(ephemeral.publicKey)
        let dh = try I2PCrypto.x25519SharedSecret(
            privateKey: ephemeral.privateKey, peerPublicKey: destinationEncryptionPublicKey)
        let bodyKey = I2PCrypto.hkdfSHA256(inputKeyMaterial: dh, salt: sectionSalt,
                                           info: els2BodyInfo, outputLength: 32)
        let box = try I2PCrypto.chacha20Poly1305Seal(
            key: bodyKey, nonce: zeroNonce, plaintext: innerPayload, aad: aadZero)
        w.short(UInt16(box.count))
        w.raw(box)
        return w.data
    }

    private static var zeroNonce: Data { Data(repeating: 0, count: 12) }
    private static func clientID(authKey: Data) -> Data { I2PCrypto.sha256(authKey).prefix(8) }

    // MARK: Encrypted body — open (resolution)

    /// Decrypts the encrypted body of a type-3 LS2 for a destination whose
    /// credentials we hold (and, for auth'd publications, an authorized client
    /// we hold credentials for). Returns the inner plain LeaseSet2 payload.
    static func openEncryptedBody(_ body: Data, credentials: I2PB33Credentials) throws -> Data {
        var r = I2PReader(body)
        let authType = try r.byte()
        var sectionSalt = Data(repeating: 0, count: 32)
        if authType != 0 {
            sectionSalt = try r.hash()
            let clientCount = Int(try r.byte())
            guard clientCount >= 1, clientCount <= 16 else { throw I2PWireError.invalidFormat }
            var authorized = false
            for _ in 0..<clientCount {
                let entryClientID = try r.raw(8)
                let clientDataLength = Int(try r.short())
                let clientData = try r.raw(clientDataLength)
                guard !authorized else { continue }
                switch authType {
                case 1:
                    guard clientData.count >= 32 + 16 else { throw I2PWireError.invalidFormat }
                    let authEphemeral = Data(clientData.prefix(32))
                    let box = Data(clientData.dropFirst(32))
                    for clientPriv in credentials.clientECIESPrivateKeys {
                        let authData = try I2PCrypto.x25519SharedSecret(
                            privateKey: clientPriv, peerPublicKey: authEphemeral)
                        let authKey = I2PCrypto.hkdfSHA256(
                            inputKeyMaterial: authData, salt: sectionSalt,
                            info: els2AuthInfo, outputLength: 32)
                        guard I2PCrypto.sha256(authKey).prefix(8) == entryClientID else { continue }
                        guard (try? I2PCrypto.chacha20Poly1305Open(
                            key: authKey, nonce: zeroNonce,
                            ciphertextAndTag: box, aad: aadZero)) != nil else { continue }
                        authorized = true
                        break
                    }
                case 3:
                    for psk in credentials.clientPSKs {
                        let authKey = I2PCrypto.hkdfSHA256(
                            inputKeyMaterial: psk, salt: sectionSalt,
                            info: els2AuthInfo, outputLength: 32)
                        if I2PCrypto.sha256(authKey).prefix(8) == entryClientID {
                            authorized = true
                            break
                        }
                    }
                default:
                    throw I2PWireError.unsupportedAlgorithm
                }
            }
            // Fail closed: an auth'd publication resolves only for holders of
            // authorized client credentials.
            guard authorized else { throw I2PWireError.invalidSignature }
        }
        let encType = try r.byte()
        guard encType == 4 else { throw I2PWireError.unsupportedAlgorithm }
        let ephemeralPublicKey = try r.hash()
        let boxLength = Int(try r.short())
        let box = try r.raw(boxLength)
        guard r.remaining == 0 else { throw I2PWireError.trailingData }

        let dh = try I2PCrypto.x25519SharedSecret(
            privateKey: credentials.x25519PrivateKey, peerPublicKey: ephemeralPublicKey)
        let bodyKey = I2PCrypto.hkdfSHA256(inputKeyMaterial: dh, salt: sectionSalt,
                                           info: els2BodyInfo, outputLength: 32)
        return try I2PCrypto.chacha20Poly1305Open(
            key: bodyKey, nonce: zeroNonce, ciphertextAndTag: box, aad: aadZero)
    }

    // MARK: Publisher — encrypted LS2 envelope under the blinded key

    /// Publishes an encrypted LeaseSet2 under the destination's blinded key:
    /// the envelope destination carries the blinded signing key (its hash is
    /// the blinded netdb key), the inner plain LS2 rides the encrypted body,
    /// and the envelope signature is made by the blinded private key k'.
    static func buildEncryptedLeaseSet2(inner: I2PLeaseSet2, credentials: I2PB33Credentials,
                                        authClients: [I2PELS2AuthClient] = []) throws -> I2PLeaseSet2 {
        guard inner.storeType == .plain else { throw I2PWireError.invalidFormat }
        guard let encryptionPublicKey = destinationEncryptionPublicKey(credentials) else {
            throw I2PWireError.invalidFormat
        }
        let blinded = try blind(destinationSeed: credentials.ed25519Seed,
                                encryptionPublicKey: encryptionPublicKey,
                                secret: credentials.secret)
        let body = try buildEncryptedBody(
            innerPayload: inner.raw,
            destinationEncryptionPublicKey: encryptionPublicKey,
            authClients: authClients)
        // Build with a throwaway seed signature, then re-sign with the blinded
        // scalar per the blinding spec's blinded private key.
        var envelope = try I2PLeaseSet2.build(
            storeType: .encrypted,
            destination: blinded.envelopeDestination,
            published: inner.published,
            expiresOffsetSeconds: inner.expiresOffsetSeconds,
            flags: 0,
            encryptedBody: body,
            signingSeed: I2PCrypto.generateEd25519Seed())
        let contents = envelope.serializedSignedContents()
        guard let signature = I2PCrypto.ed25519SignWithScalar(
            message: contents, scalar: blinded.blindedSigningScalar,
            noncePrefix: I2PCrypto.randomBytes(32)) else {
            throw I2PWireError.invalidFormat
        }
        envelope.signature = signature
        envelope.raw = envelope.raw.dropLast(64) + signature
        return envelope
    }
}

// MARK: - Resolution (encrypted LS2 → delivery-usable inner LeaseSet2)

extension I2PLeaseSet2 {
    /// Decrypts the spec's encrypted body and returns the inner plain
    /// LeaseSet2 (full type+length+data+signature framing, parse-verified
    /// fail closed under the real destination's signing key).
    func resolveEncryptedBody(credentials: I2PB33Credentials) throws -> I2PLeaseSet2 {
        guard storeType == .encrypted, !encryptedBody.isEmpty else {
            throw I2PWireError.invalidFormat
        }
        let innerPayload = try I2PB33Blinding.openEncryptedBody(encryptedBody, credentials: credentials)
        return try I2PLeaseSet2.parse(innerPayload, expectedType: I2PLeaseSet2Type.plain.rawValue)
    }
}

// MARK: - Self-test suite (b33 blinding resolution)

enum I2PB33BlindingSelfTest {
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

        await run("b33 blinding · blinded key derivation") {
            let seed = I2PCrypto.generateEd25519Seed()
            let x25519 = I2PCrypto.generateX25519KeyPair()
            let blinded = try I2PB33Blinding.blind(
                destinationSeed: seed,
                encryptionPublicKey: x25519.publicKey)
            // The blinded scalar signs and any conformant verifier accepts
            // against K' = k'·G (CryptoKit cross-implementation check).
            let message = I2PCrypto.randomBytes(160)
            guard let signature = I2PCrypto.ed25519SignWithScalar(
                message: message, scalar: blinded.blindedSigningScalar,
                noncePrefix: I2PCrypto.randomBytes(32)) else {
                throw I2PWireError.invalidFormat
            }
            guard I2PCrypto.ed25519Verify(signature: signature, message: message,
                                          publicKey: blinded.blindedPublicKey) else {
                throw I2PWireError.invalidSignature
            }
            // The blinded key is genuinely blinded: distinct from the
            // unblinded key, deterministic for the same inputs, secret-bound,
            // and a different secret yields a different blinded key.
            guard blinded.blindedPublicKey != I2PCrypto.ed25519PublicKey(fromSeed: seed) else {
                throw I2PWireError.invalidFormat
            }
            let again = try I2PB33Blinding.blind(
                destinationSeed: seed, encryptionPublicKey: x25519.publicKey)
            guard again.blindedPublicKey == blinded.blindedPublicKey,
                  again.netDBKey == blinded.netDBKey else {
                throw I2PWireError.invalidFormat
            }
            let withSecret = try I2PB33Blinding.blind(
                destinationSeed: seed, encryptionPublicKey: x25519.publicKey,
                secret: Data("i2psecret".utf8))
            guard withSecret.blindedPublicKey != blinded.blindedPublicKey else {
                throw I2PWireError.invalidFormat
            }
            return "K = alpha·B derived, blinded scalar verifies under CryptoKit, secret-bound and deterministic"
        }

        await run("b33 address encode/decode with checksum") {
            let seed = I2PCrypto.generateEd25519Seed()
            let x25519 = I2PCrypto.generateX25519KeyPair()
            let blinded = try I2PB33Blinding.blind(
                destinationSeed: seed, encryptionPublicKey: x25519.publicKey)
            let address = blinded.b33Address
            guard address.hasPrefix("b"), address.count == 57 else {
                throw I2PWireError.invalidFormat
            }
            guard let decoded = I2PB33Blinding.b33Decode(address),
                  decoded == blinded.blindedPublicKey else {
                throw I2PWireError.invalidFormat
            }
            // A corrupted checksum character must fail the decode.
            var tampered = Array(address)
            let original = tampered[2]
            let replacement = I2PB33Blinding.b33ChecksumSecond
                .first { $0 != original } ?? "a"
            guard replacement != original else { throw I2PWireError.invalidFormat }
            tampered[2] = replacement
            guard I2PB33Blinding.b33Decode(String(tampered)) == nil else {
                throw I2PWireError.invalidSignature
            }
            return "\(address.prefix(12))… round-tripped; corrupted checksum rejected"
        }

        await run("Encrypted LS2 · inner body decryption (auth type 0)") {
            let seed = I2PCrypto.generateEd25519Seed()
            let x25519 = I2PCrypto.generateX25519KeyPair()
            let credentials = I2PB33Credentials(ed25519Seed: seed, x25519PrivateKey: x25519.privateKey)
            let destination = I2PKeysAndCert(
                encryptionPublicKey: x25519.publicKey,
                signingPublicKey: I2PCrypto.ed25519PublicKey(fromSeed: seed))
            let inner = try makeInnerLeaseSet2(destination: destination, seed: seed)
            let envelope = try I2PB33Blinding.buildEncryptedLeaseSet2(
                inner: inner, credentials: credentials)
            let reparsed = try I2PLeaseSet2.parse(envelope.serialize(),
                                                  expectedType: I2PLeaseSet2Type.encrypted.rawValue)
            // The envelope lives under the blinded netdb key and is signed by
            // the blinded private key.
            let blinded = try I2PB33Blinding.blind(
                destinationSeed: seed, encryptionPublicKey: x25519.publicKey)
            guard reparsed.destination.hash == blinded.netDBKey else {
                throw I2PWireError.invalidFormat
            }
            // Resolution: the inner plain LS2 comes back whole.
            let resolved = try reparsed.resolveEncryptedBody(credentials: credentials)
            guard resolved.storeType == .plain,
                  resolved.destination.hash == destination.hash,
                  resolved.leases == inner.leases else {
                throw I2PWireError.invalidFormat
            }
            // Same delivery path plain LS2s use.
            guard let delivery = resolved.resolvedLeaseSet(), delivery.leases.count == 2 else {
                throw I2PWireError.invalidFormat
            }
            // Fail closed: wrong credentials and a tampered body both reject.
            let wrong = I2PB33Credentials(
                ed25519Seed: I2PCrypto.generateEd25519Seed(),
                x25519PrivateKey: I2PCrypto.generateX25519KeyPair().privateKey)
            guard (try? reparsed.resolveEncryptedBody(credentials: wrong)) == nil else {
                throw I2PWireError.invalidSignature
            }
            // Fail closed: a re-signed envelope with a tampered body rejects.
            var tamperedBody = reparsed.encryptedBody
            tamperedBody[20] ^= 0xff
            let tamperedEnvelope = I2PLeaseSet2(
                storeType: reparsed.storeType,
                destination: reparsed.destination,
                published: reparsed.published,
                expiresOffsetSeconds: reparsed.expiresOffsetSeconds,
                flags: reparsed.flags,
                offlineSignature: reparsed.offlineSignature,
                leases: [],
                encryptedBody: tamperedBody,
                metaEntries: [],
                signature: reparsed.signature,
                raw: Data())
            guard (try? tamperedEnvelope.resolveEncryptedBody(credentials: credentials)) == nil else {
                throw I2PWireError.invalidSignature
            }
            return "inner LS2 decrypted to \(inner.leases.count) leases; wrong credentials and tampered body rejected"
        }

        await run("Encrypted LS2 · DH client auth (type 1) + PSK auth (type 3)") {
            let seed = I2PCrypto.generateEd25519Seed()
            let x25519 = I2PCrypto.generateX25519KeyPair()
            let credentials = I2PB33Credentials(ed25519Seed: seed, x25519PrivateKey: x25519.privateKey)
            let destination = I2PKeysAndCert(
                encryptionPublicKey: x25519.publicKey,
                signingPublicKey: I2PCrypto.ed25519PublicKey(fromSeed: seed))
            let inner = try makeInnerLeaseSet2(destination: destination, seed: seed)
            let dhClient = I2PCrypto.generateX25519KeyPair()
            let psk = I2PCrypto.randomBytes(32)
            let envelope = try I2PB33Blinding.buildEncryptedLeaseSet2(
                inner: inner, credentials: credentials,
                authClients: [
                    I2PELS2AuthClient(kind: .dh, clientPublicKey: dhClient.publicKey, psk: psk),
                    I2PELS2AuthClient(kind: .psk, clientPublicKey: Data(), psk: psk),
                ])
            let reparsed = try I2PLeaseSet2.parse(envelope.serialize(),
                                                  expectedType: I2PLeaseSet2Type.encrypted.rawValue)
            // The DH client resolves with its ECIES private key.
            var dhCredentials = credentials
            dhCredentials.clientECIESPrivateKeys = [dhClient.privateKey]
            guard let resolvedDH = try? reparsed.resolveEncryptedBody(credentials: dhCredentials),
                  resolvedDH.leases == inner.leases else {
                throw I2PWireError.invalidFormat
            }
            // The PSK client resolves with the shared PSK.
            var pskCredentials = credentials
            pskCredentials.clientPSKs = [psk]
            guard let resolvedPSK = try? reparsed.resolveEncryptedBody(credentials: pskCredentials),
                  resolvedPSK.leases == inner.leases else {
                throw I2PWireError.invalidFormat
            }
            // An unauthorized client (wrong ECIES key / wrong PSK) fails closed.
            var stranger = credentials
            stranger.clientECIESPrivateKeys = [I2PCrypto.generateX25519KeyPair().privateKey]
            guard (try? reparsed.resolveEncryptedBody(credentials: stranger)) == nil else {
                throw I2PWireError.invalidSignature
            }
            var wrongPSK = credentials
            wrongPSK.clientPSKs = [I2PCrypto.randomBytes(32)]
            guard (try? reparsed.resolveEncryptedBody(credentials: wrongPSK)) == nil else {
                throw I2PWireError.invalidSignature
            }
            // And the destination holder with no client credentials at all
            // cannot decrypt an auth'd publication.
            guard (try? reparsed.resolveEncryptedBody(credentials: credentials)) == nil else {
                throw I2PWireError.invalidSignature
            }
            return "DH client + PSK client resolved; unauthorized keys and bare destination credentials rejected"
        }

        await run("NetDB · b33 resolution end-to-end through the DHT") {
            let seed = I2PCrypto.generateEd25519Seed()
            let x25519 = I2PCrypto.generateX25519KeyPair()
            let credentials = I2PB33Credentials(ed25519Seed: seed, x25519PrivateKey: x25519.privateKey)
            let destination = I2PKeysAndCert(
                encryptionPublicKey: x25519.publicKey,
                signingPublicKey: I2PCrypto.ed25519PublicKey(fromSeed: seed))
            let inner = try makeInnerLeaseSet2(destination: destination, seed: seed)
            let envelope = try I2PB33Blinding.buildEncryptedLeaseSet2(
                inner: inner, credentials: credentials)
            let blinded = try I2PB33Blinding.blind(
                destinationSeed: seed, encryptionPublicKey: x25519.publicKey)

            // A floodfill holds the entry under its blinded netdb key; a second
            // router resolves it over the DHT with the destination credentials.
            let hub = I2PNetDBLoopbackHub()
            let floodfillHash = I2PCrypto.sha256(Data("b33-floodfill".utf8))
            let resolverHash = I2PCrypto.sha256(Data("b33-resolver".utf8))
            let storage = try I2PNetDBStorage(
                directory: FileManager.default.temporaryDirectory
                    .appendingPathComponent("b33-\(UUID().uuidString)", isDirectory: true))
            let floodfill = I2PNetworkDatabase(
                localRouterHash: floodfillHash,
                transport: I2PNetDBLoopbackTransport(hub: hub),
                storage: storage)
            let resolver = I2PNetworkDatabase(
                localRouterHash: resolverHash,
                transport: I2PNetDBLoopbackTransport(hub: hub),
                storage: storage)
            hub.add(floodfill, at: floodfillHash)
            hub.add(resolver, at: resolverHash)
            await floodfill.configureLocalFloodfill(true)
            await resolver.registerFloodfill(floodfillHash)

            try await floodfill.ingestLeaseSet2(envelope.serialize(),
                                                entryType: .encryptedLeaseSet2)

            // The entry does NOT resolve under the unblinded destination hash.
            guard await resolver.lookupLeaseSet2(destination.hash) == nil else {
                throw I2PWireError.invalidFormat
            }
            // The blinded netdb key resolution path: lookup under the blinded
            // key, decrypt the authenticated inner body, surface the leases
            // through the same delivery path plain LS2s use.
            guard let resolved = await resolver.lookupEncryptedLeaseSet2(credentials: credentials),
                  resolved.storeType == .plain,
                  resolved.leases == inner.leases else {
                throw I2PWireError.invalidFormat
            }
            guard let delivery = await resolver.resolveEncryptedDestination(credentials: credentials),
                  delivery.destination.hash == destination.hash,
                  delivery.leases.count == inner.leases.count else {
                throw I2PWireError.invalidFormat
            }
            // Credentials for a different destination find nothing at all.
            let stranger = I2PB33Credentials(
                ed25519Seed: I2PCrypto.generateEd25519Seed(),
                x25519PrivateKey: I2PCrypto.generateX25519KeyPair().privateKey)
            guard await resolver.lookupEncryptedLeaseSet2(credentials: stranger) == nil else {
                throw I2PWireError.invalidSignature
            }
            return "encrypted LS2 resolved under blinded key \(blinded.netDBKey.hex.prefix(12))… — \(delivery.leases.count) leases surfaced through the delivery path"
        }

        return results
    }

    /// Builds a signed plain LeaseSet2 for the real destination with two leases.
    private static func makeInnerLeaseSet2(destination: I2PDestination, seed: Data) throws -> I2PLeaseSet2 {
        try I2PLeaseSet2.build(
            storeType: .plain,
            destination: destination,
            published: Date(),
            expiresOffsetSeconds: 600,
            leases: [
                I2PLease2(gatewayHash: I2PCrypto.sha256(Data("b33-gateway-1".utf8)),
                          tunnelId: 0x1122_3344,
                          expiration: Date().addingTimeInterval(600), cost: 3),
                I2PLease2(gatewayHash: I2PCrypto.sha256(Data("b33-gateway-2".utf8)),
                          tunnelId: 0x5566_7788,
                          expiration: Date().addingTimeInterval(700), cost: 5),
            ],
            signingSeed: seed)
    }
}
