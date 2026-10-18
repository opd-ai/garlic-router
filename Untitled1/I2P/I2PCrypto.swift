//
//  I2PCrypto.swift
//  I2P cryptographic foundation built on CryptoKit:
//  X25519 key agreement (EncType 4/5), Ed25519 (SigType 7), Ed25519ph (SigType 11),
//  ChaCha20-Poly1305 AEAD, HKDF-SHA256 key derivation and SHA-256 hashing.
//

import Foundation
import CryptoKit

// MARK: - Algorithm registries (I2P spec numbering)

enum I2PSigType: UInt16, CaseIterable {
    case ed25519 = 7
    case ed25519ph = 11

    var publicKeyLength: Int { 32 }
    var signatureLength: Int { 64 }
}

enum I2PEncType: UInt16, CaseIterable {
    case x25519 = 4
    case eciesX25519 = 5

    var publicKeyLength: Int { 32 }
}

// MARK: - Crypto facade

enum I2PCrypto {
    struct X25519KeyPair {
        let publicKey: Data
        let privateKey: Data
    }

    static func randomBytes(_ count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        var generator = SystemRandomNumberGenerator()
        for i in 0..<count {
            bytes[i] = UInt8.random(in: UInt8.min...UInt8.max, using: &generator)
        }
        return Data(bytes)
    }

    // MARK: X25519 (EncType 4)

    static func generateX25519KeyPair() -> X25519KeyPair {
        let secret = Curve25519.KeyAgreement.PrivateKey()
        return X25519KeyPair(
            publicKey: secret.publicKey.rawRepresentation,
            privateKey: secret.rawRepresentation
        )
    }

    static func x25519SharedSecret(privateKey: Data, peerPublicKey: Data) throws -> Data {
        let secret = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
        let peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublicKey)
        let shared = try secret.sharedSecretFromKeyAgreement(with: peer)
        return shared.withUnsafeBytes { Data($0) }
    }

    // MARK: HKDF-SHA256 key derivation

    static func hkdfSHA256(inputKeyMaterial: Data, salt: Data, info: Data, outputLength: Int) -> Data {
        let ikm = SymmetricKey(data: inputKeyMaterial)
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: ikm,
            salt: salt,
            info: info,
            outputByteCount: outputLength
        )
        return key.withUnsafeBytes { Data($0) }
    }

    // MARK: Hashing

    static func sha256(_ data: Data) -> Data {
        SHA256.hash(data: data).withUnsafeBytes { Data($0) }
    }

    // MARK: ChaCha20-Poly1305 AEAD (12-byte nonce, combined ciphertext || 16-byte tag)

    static func chacha20Poly1305Seal(key: Data, nonce: Data, plaintext: Data, aad: Data = Data()) throws -> Data {
        let box = try ChaChaPoly.seal(
            plaintext,
            using: SymmetricKey(data: key),
            nonce: ChaChaPoly.Nonce(data: nonce),
            authenticating: aad
        )
        // Wire format: ciphertext || tag. The nonce rides implicitly (it is an
        // input to this call), never prefixed onto the output blob.
        return box.ciphertext + box.tag
    }

    static func chacha20Poly1305Open(key: Data, nonce: Data, ciphertextAndTag: Data, aad: Data = Data()) throws -> Data {
        guard ciphertextAndTag.count > 16 else { throw I2PWireError.invalidFormat }
        // Split via dropLast/suffix, never subdata(in:) with absolute ranges:
        // Data carries its own index base (a slice of another Data can start
        // at any offset), and subdata(in: 0..<n) traps with SIGTRAP when the
        // receiver's indices are not zero-based. dropLast/suffix are immune.
        let box = try ChaChaPoly.SealedBox(
            nonce: try ChaChaPoly.Nonce(data: nonce),
            ciphertext: Data(ciphertextAndTag.dropLast(16)),
            tag: Data(ciphertextAndTag.suffix(16)))
        return try ChaChaPoly.open(box, using: SymmetricKey(data: key), authenticating: aad)
    }

    // MARK: Ed25519 (SigType 7) — CryptoKit-backed

    static func generateEd25519Seed() -> Data { randomBytes(32) }

    static func ed25519PublicKey(fromSeed seed: Data) -> Data {
        (try? Curve25519.Signing.PrivateKey(rawRepresentation: seed))?.publicKey.rawRepresentation ?? Data()
    }

    static func ed25519Sign(_ message: Data, seed: Data) throws -> Data {
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        return try key.signature(for: message)
    }

    static func ed25519Verify(signature: Data, message: Data, publicKey: Data) -> Bool {
        guard let key = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey) else { return false }
        return key.isValidSignature(signature, for: message)
    }

    // MARK: Ed25519ph (SigType 11) — pure-Swift pre-hashed EdDSA

    static func ed25519phSign(_ message: Data, seed: Data) -> Data? {
        Ed25519Pure.sign(message: Array(message), seed: Array(seed), prehashed: true).map { Data($0) }
    }

    static func ed25519phVerify(signature: Data, message: Data, publicKey: Data) -> Bool {
        Ed25519Pure.verify(message: Array(message), signature: Array(signature), publicKey: Array(publicKey), prehashed: true)
    }

    // MARK: Pure Ed25519 (SigType 7) — cross-validated against CryptoKit in self-tests

    static func ed25519PureSign(_ message: Data, seed: Data) -> Data? {
        Ed25519Pure.sign(message: Array(message), seed: Array(seed), prehashed: false).map { Data($0) }
    }

    static func ed25519PureVerify(signature: Data, message: Data, publicKey: Data) -> Bool {
        Ed25519Pure.verify(message: Array(message), signature: Array(signature), publicKey: Array(publicKey), prehashed: false)
    }

    static func ed25519PurePublicKey(fromSeed seed: Data) -> Data {
        Data(Ed25519Pure.publicKey(seed: Array(seed)))
    }
}

// MARK: - Modern crypto policy (legacy removal audit + regression guard)

/// The modern-only crypto mandate, enforced two ways:
///
/// 1. **Type safety** — the algorithm registries above contain only the
///    modern cases (SigType 7/11, EncType 4/5). There is no legacy case to
///    construct and no legacy code path to call: requesting a legacy
///    algorithm from wire data fails `init?(rawValue:)` and every structure
///    parser throws `unsupportedAlgorithm` — compile/type errors, never
///    silent fallbacks.
/// 2. **Regression test** — `audit()` pins the registries to exactly the
///    modern cases and is exercised by the cross-validation policy tests, so
///    any reintroduction of a legacy enum case or parse path fails the suite.
///
/// Audit outcome (legacy-removal sweep): the router implements none of the
/// legacy algorithms inventoried in the compliance review — no asymmetric
/// ElGamal-style key establishment, no broken signature suites, no obsolete
/// block ciphers, no MD5/SHA-1 digest paths, and no ad-hoc un-HKDF'd key
/// stretching anywhere in the codebase. The two AES-256-CBC call sites are
/// spec-mandated components of the modern protocols themselves (the NTCP2
/// ephemeral-key obfuscation keystream in `NTCP2KeyObfuscation` and the tunnel
/// layer cipher in `I2PTunnelLayerCipher`), not legacy session crypto — both
/// are recorded as aligned in the truth table and retained.
enum I2PCryptoPolicy {
    /// The approved inventory: the full modern suite.
    static let approvedSignatureTypes: [I2PSigType] = I2PSigType.allCases
    static let approvedEncryptionTypes: [I2PEncType] = I2PEncType.allCases

    /// The banned-algorithm inventory from the audit, kept as documentation of
    /// what must never appear in the codebase (and what the policy tests scan
    /// the registries and parse boundaries against).
    static let bannedAlgorithms: [String] = [
        "ElGamal-2048 (EncType 0)",
        "3DES",
        "DSA-SHA1 (SigType 0)",
        "RSA-2048-SHA1 (SigType 1)",
        "ECDSA-P256 (SigType 3)",
        "ECDSA-P384 (SigType 4)",
        "ECDSA-P521 (SigType 5)",
        "RSA-4096-SHA512 (SigType 6)",
        "MD5",
        "SHA-1",
    ]

    /// Runtime audit: the registries contain exactly the modern cases, no
    /// legacy type code can construct a case, and identity key material is
    /// the modern 32-byte shape. Throws on any policy violation.
    static func audit() throws {
        guard I2PSigType.allCases.map(\.rawValue) == [7, 11] else {
            throw I2PWireError.unsupportedAlgorithm
        }
        guard I2PEncType.allCases.map(\.rawValue) == [4, 5] else {
            throw I2PWireError.unsupportedAlgorithm
        }
        // No legacy or unapproved type code may construct a registry case.
        for legacyCode: UInt16 in [0, 1, 2, 3, 6, 8, 9, 10] where I2PSigType(rawValue: legacyCode) != nil {
            throw I2PWireError.unsupportedAlgorithm
        }
        for legacyCode: UInt16 in [0, 1, 2, 3, 6, 7, 8] where I2PEncType(rawValue: legacyCode) != nil {
            throw I2PWireError.unsupportedAlgorithm
        }
        // Identity key material is the modern shape: EncType 4/5 and SigType
        // 7/11 public keys are 32 bytes, signatures 64.
        for sigType in approvedSignatureTypes {
            guard sigType.publicKeyLength == 32, sigType.signatureLength == 64 else {
                throw I2PWireError.unsupportedAlgorithm
            }
        }
        for encType in approvedEncryptionTypes where encType.publicKeyLength != 32 {
            throw I2PWireError.unsupportedAlgorithm
        }
    }
}