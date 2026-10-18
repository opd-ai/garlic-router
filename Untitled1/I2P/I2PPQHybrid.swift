//
//  I2PPQHybrid.swift
//  Post-quantum hybrid key establishment for the SSU2 transport (long-header
//  handshake versions 3 and 4, per the production-readiness checklist):
//
//  • ML-KEM-512 (FIPS 203) ENCAPS output is a 768-byte ciphertext + 32-byte shared secret.
//  • ML-KEM-768 (FIPS 203) ENCAPS output is a 1088-byte ciphertext + 32-byte shared secret.
//  • The FIPS 203 shapes are produced by the router's pure-Swift ML-KEM
//    (I2PMLKEM.swift — Keccak sponge, NTT ring arithmetic, K-PKE/ML-KEM with
//    implicit rejection): encapsulation keys are 800 bytes (ML-KEM-512) /
//    1184 bytes (ML-KEM-768), both variants stay within the SSU2 datagram
//    budget once appended to the handshake sections.
//  • The hybrid KDF binds BOTH legs: the classical X25519 shared secret is the HKDF
//    input key material, and the ML-KEM encapsulation (shared secret + ciphertext
//    binding) rides the info parameter — session material is only reproducible by a
//    peer that completed both, and a classical-only peer derives different keys.
//  • Decapsulation is fail-closed: the decapsulated secret must match the peer's
//    ENCAPS output before the KDF runs, and the SSU2 long-header version byte is
//    bound to the encapsulation shape (version 3 ⇔ ML-KEM-512, version 4 ⇔ ML-KEM-768).
//

import Foundation

/// SSU2 long-header handshake versions that carry an ML-KEM hybrid leg.
enum I2PSSU2PQVersion: UInt8 {
    case mlKem512 = 3   // long-header version 3: ML-KEM-512 hybrid
    case mlKem768 = 4   // long-header version 4: ML-KEM-768 hybrid

    /// FIPS 203 ENCAPS ciphertext length for this parameter set
    /// (ML-KEM-512 → 768 bytes, ML-KEM-768 → 1088 bytes).
    var mlKemCiphertextLength: Int {
        switch self {
        case .mlKem512: return 768
        case .mlKem768: return 1088
        }
    }

    /// FIPS 203 encapsulation-key (public key) length for this parameter set.
    var mlKemEncapsulationKeyLength: Int {
        self == .mlKem512 ? 800 : 1184
    }

    var name: String {
        self == .mlKem512 ? "ML-KEM-512" : "ML-KEM-768"
    }
}

/// One ML-KEM encapsulation leg: the FIPS 203 ciphertext plus the shared secret
/// it encapsulates. Size contracts are enforcible at construction (fail closed).
struct I2PMLKEMEncapsulation {
    let ciphertext: Data
    let sharedSecret: Data

    init(ciphertext: Data, sharedSecret: Data) throws {
        guard ciphertext.count == 768 || ciphertext.count == 1088 else {
            throw I2PWireError.invalidFormat
        }
        guard sharedSecret.count == 32 else {
            throw I2PWireError.invalidFormat
        }
        self.ciphertext = ciphertext
        self.sharedSecret = sharedSecret
    }

    var version: I2PSSU2PQVersion {
        ciphertext.count == 768 ? .mlKem512 : .mlKem768
    }
}

enum I2PPQHybrid {
    /// The hybrid session KDF. The classical X25519 shared secret is the HKDF
    /// input; the ML-KEM encapsulation rides the info parameter so the output
    /// binds to exactly one PQ leg. Deterministic in its inputs.
    static func sessionKeyMaterial(classicalSharedSecret: Data,
                                   encapsulation: I2PMLKEMEncapsulation,
                                   context: Data,
                                   outputLength: Int = 32) -> Data {
        let info = context + encapsulation.ciphertext + encapsulation.sharedSecret
        return I2PCrypto.hkdfSHA256(
            inputKeyMaterial: classicalSharedSecret,
            salt: Data("SSU2-PQ-HYBRID-v1".utf8),
            info: info,
            outputLength: outputLength
        )
    }

    /// Peer-side decapsulation contract: the ML-KEM DECAPS output must equal the
    /// peer's ENCAPS shared secret before any session material is derived.
    static func validateDecapsulation(decapsulated: Data, peerEncapsulation: I2PMLKEMEncapsulation) throws {
        guard decapsulated.count == 32 else { throw I2PWireError.invalidFormat }
        guard decapsulated == peerEncapsulation.sharedSecret else {
            throw I2PWireError.invalidSignature
        }
    }

    /// Binds the SSU2 long-header version byte to the encapsulation shape.
    static func validateVersionBinding(versionRawValue: UInt8, encapsulation: I2PMLKEMEncapsulation) throws {
        guard let version = I2PSSU2PQVersion(rawValue: versionRawValue),
              version.mlKemCiphertextLength == encapsulation.ciphertext.count else {
            throw I2PWireError.unsupportedAlgorithm
        }
    }
}

// MARK: - Real ML-KEM (FIPS 203) key establishment

import CryptoKit

/// The accept-side FIPS 203 ML-KEM key pair. The encapsulation key is the
/// exact 800/1184-byte wire shape bound to the long-header version byte;
/// decapsulation runs the real K-PKE decrypt + re-encrypt check and falls
/// back to FIPS 203 implicit rejection on any mismatch.
final class I2PMLKEMSecretKey {
    let version: I2PSSU2PQVersion
    private let keyPair: MLKEM.KeyPair
    let encapsulationKeyData: Data

    init(version: I2PSSU2PQVersion) {
        self.version = version
        let parameters: MLKEM.Parameters = version == .mlKem512 ? .mlKem512 : .mlKem768
        self.keyPair = MLKEM.keyGen(parameters)
        self.encapsulationKeyData = keyPair.ek
    }

    /// DECAPS: recovers the 32-byte encapsulated secret from the ciphertext,
    /// bound to this key pair (fail-closed via implicit rejection).
    func decapsulate(_ ciphertext: Data) throws -> Data {
        guard ciphertext.count == version.mlKemCiphertextLength else {
            throw I2PWireError.invalidFormat
        }
        return keyPair.decapsulate(ciphertext)
    }
}

/// A peer's advertised ML-KEM encapsulation key; the length binds the
/// parameter set, mirroring the SSU2 long-header version byte on the wire.
struct I2PMLKEMPublicKey {
    let version: I2PSSU2PQVersion
    let keyData: Data

    init(keyData: Data) throws {
        guard keyData.count == I2PSSU2PQVersion.mlKem512.mlKemEncapsulationKeyLength
                || keyData.count == I2PSSU2PQVersion.mlKem768.mlKemEncapsulationKeyLength else {
            throw I2PWireError.invalidFormat
        }
        self.keyData = keyData
        self.version = keyData.count == I2PSSU2PQVersion.mlKem512.mlKemEncapsulationKeyLength
            ? .mlKem512 : .mlKem768
    }

    /// ENCAPS: the FIPS 203 capsule — a version-bound ciphertext plus the
    /// 32-byte shared secret the peer's decapsulation reproduces exactly.
    func encapsulate() throws -> I2PMLKEMEncapsulation {
        let result = try MLKEM.encapsulate(encapsulationKey: keyData)
        return try I2PMLKEMEncapsulation(ciphertext: result.ciphertext,
                                         sharedSecret: result.sharedSecret)
    }
}

// MARK: - Session KDF integration

enum I2PSSU2PQKDF {
    /// Mixes the ML-KEM encapsulation output into the SSU2 session KDF via the
    /// dual-leg binding: the classical chaining key is the HKDF input key
    /// material, the encapsulation (ciphertext + shared secret) rides the info
    /// parameter, and the output feeds one MixKey so the split rides both legs.
    /// Both sides mix at the same chain point (right after the options payload
    /// is encrypted/decrypted), so the split states stay aligned.
    static func mix(_ chain: inout SSU2NoiseChain, encapsulation: I2PMLKEMEncapsulation) {
        let material = I2PPQHybrid.sessionKeyMaterial(
            classicalSharedSecret: chain.chainingKey,
            encapsulation: encapsulation,
            context: chain.hash)
        chain.mixKey(material)
    }
}