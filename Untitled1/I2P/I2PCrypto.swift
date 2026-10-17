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
        return box.combined
    }

    static func chacha20Poly1305Open(key: Data, nonce: Data, ciphertextAndTag: Data, aad: Data = Data()) throws -> Data {
        let box = try ChaChaPoly.SealedBox(combined: ciphertextAndTag)
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