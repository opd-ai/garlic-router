//
//  I2PPQHybrid.swift
//  Post-quantum hybrid key establishment for the SSU2 transport (long-header
//  handshake versions 3 and 4, per the production-readiness checklist):
//
//  • ML-KEM-512 (FIPS 203) ENCAPS output is a 1088-byte ciphertext + 32-byte shared secret.
//  • ML-KEM-768 (FIPS 203) ENCAPS output is a 1568-byte ciphertext + 32-byte shared secret.
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

    /// FIPS 203 ENCAPS ciphertext length for this parameter set.
    var mlKemCiphertextLength: Int {
        switch self {
        case .mlKem512: return 1088
        case .mlKem768: return 1568
        }
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
        guard ciphertext.count == 1088 || ciphertext.count == 1568 else {
            throw I2PWireError.invalidFormat
        }
        guard sharedSecret.count == 32 else {
            throw I2PWireError.invalidFormat
        }
        self.ciphertext = ciphertext
        self.sharedSecret = sharedSecret
    }

    var version: I2PSSU2PQVersion {
        ciphertext.count == 1088 ? .mlKem512 : .mlKem768
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