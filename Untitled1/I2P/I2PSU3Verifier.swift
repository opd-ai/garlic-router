//
//  I2PSU3Verifier.swift
//  SU3 container parsing and signature verification — the format the I2P
//  reseed spec (proposal 123, the "SU3 file" format Java I2P's SU3File.java
//  writes and i2pd's Reseeder verifies) puts around a reseed archive.
//
//  Header (40 bytes, all multi-byte fields big-endian):
//
//    offset  size  field
//    0       6     magic "I2Psu3"
//    6       1     unused (0)
//    7       1     file format version (0)
//    8       2     signature type (I2P SigType code)
//    10      2     signature length
//    12      1     unused (0)
//    13      1     version string length (min 16; the string is zero-padded)
//    14      1     unused (0)
//    15      1     signer ID length (1-255)
//    16      8     content length
//    24      1     unused (0)
//    25      1     file type (0 = zip)
//    26      1     unused (0)
//    27      1     content type (3 = reseed data)
//    28      12    unused (0)
//
//  Then: version string, signer ID (UTF-8), content, signature. There is no
//  padding section between the content and the signature — the field at offset
//  12 that earlier revisions of this code read as a padding length is one of
//  the header's unused bytes.
//
//  What the signature covers: the WHOLE container prefix from byte 0 through
//  the last content byte — the header included. Java I2P digests the file from
//  position 0 (DigestInputStream rewound before verifyHeader reads the header
//  again) and i2pd takes tbs = bytes[0 ..< contentEnd]. Signing the header too
//  is what makes the declared lengths and signature type tamper-evident.
//
//  Signer identity: the header carries a signer ID string; trust comes from a
//  bundled certificate for that signer (Java I2P's DirKeyRing under
//  certificates/reseed, i2pd's contrib/certificates/reseed set). An unknown
//  signer is rejected exactly as both reference routers reject it — the
//  container's authenticity never rests on the HTTPS transport alone.
//
//  Signature types: the spec admits RSA (SigType 4/5/6), ECDSA (1/2/3),
//  Ed25519 (7) and Ed25519ph (8). Real reseed servers sign with RSA-4096
//  (SigType 6, the format's default). Java I2P's SU3File hands its RSA engine
//  the digest it computed over the container prefix, and that engine pads the
//  BARE digest in PKCS#1 v1.5 — 00 01 FF..FF 00 || SHA-512(prefix), with no
//  DigestInfo wrapper in front. That is why i2pd says it "can't use RSA_verify
//  due wrong padding in SU3" and compares the raw s^e mod n block instead. This
//  build verifies both shapes: Security's standard PKCS#1 v1.5 verifier first
//  (for signers that do emit a DigestInfo), then the raw block with its
//  padding validated and the digest at the tail. ECDSA verifies as X9.62 DER,
//  retrying the fixed-length r||s form the I2P Signature class writes; Ed25519
//  types ride CryptoKit over the SHA-512 digest SU3File signs, with the RFC
//  8032 form as the retry. Anything not in that set fails closed.
//

import Foundation
import CryptoKit
import Security

enum I2PSU3Error: Error, CustomStringConvertible {
    case invalidContainer(String)
    case unsupportedSignatureType(UInt16)
    case unknownSigner(String)
    case signatureRejected(String)

    var description: String {
        switch self {
        case .invalidContainer(let message):
            return message
        case .unsupportedSignatureType(let code):
            return "unsupported SU3 signature type \(code)"
        case .unknownSigner(let signer):
            return "unknown SU3 signer \(signer)"
        case .signatureRejected(let message):
            return message
        }
    }
}

// MARK: - Signature types

/// The I2P SigType codes a SU3 container may declare (SigType.java), with the
/// fixed signature lengths SU3File enforces against the header.
enum I2PSU3SignatureType: UInt16, CaseIterable {
    case ecdsaSHA256P256 = 1
    case ecdsaSHA384P384 = 2
    case ecdsaSHA512P521 = 3
    case rsaSHA256_2048 = 4
    case rsaSHA384_3072 = 5
    case rsaSHA512_4096 = 6
    case ed25519 = 7
    case ed25519ph = 8

    var name: String {
        switch self {
        case .ecdsaSHA256P256: return "ECDSA-SHA256-P256"
        case .ecdsaSHA384P384: return "ECDSA-SHA384-P384"
        case .ecdsaSHA512P521: return "ECDSA-SHA512-P521"
        case .rsaSHA256_2048: return "RSA-SHA256-2048"
        case .rsaSHA384_3072: return "RSA-SHA384-3072"
        case .rsaSHA512_4096: return "RSA-SHA512-4096"
        case .ed25519: return "EdDSA-SHA512-Ed25519"
        case .ed25519ph: return "EdDSA-SHA512-Ed25519ph"
        }
    }

    /// Signature length SigType.getSigLen() declares for the type.
    var signatureLength: Int {
        switch self {
        case .ecdsaSHA256P256: return 64
        case .ecdsaSHA384P384: return 96
        case .ecdsaSHA512P521: return 132
        case .rsaSHA256_2048: return 256
        case .rsaSHA384_3072: return 384
        case .rsaSHA512_4096: return 512
        case .ed25519, .ed25519ph: return 64
        }
    }

    /// ECDSA signatures are r||s of two equal halves.
    var isECDSA: Bool {
        switch self {
        case .ecdsaSHA256P256, .ecdsaSHA384P384, .ecdsaSHA512P521: return true
        default: return false
        }
    }

    var isRSA: Bool {
        switch self {
        case .rsaSHA256_2048, .rsaSHA384_3072, .rsaSHA512_4096: return true
        default: return false
        }
    }

    var isEdDSA: Bool { self == .ed25519 || self == .ed25519ph }

    /// PKCS#1 v1.5 / X9.62 verifier algorithm for the certificate-backed
    /// types; nil for EdDSA, which is verified from the raw subject key.
    var secKeyAlgorithm: SecKeyAlgorithm? {
        switch self {
        case .rsaSHA256_2048: return .rsaSignatureMessagePKCS1v15SHA256
        case .rsaSHA384_3072: return .rsaSignatureMessagePKCS1v15SHA384
        case .rsaSHA512_4096: return .rsaSignatureMessagePKCS1v15SHA512
        case .ecdsaSHA256P256: return .ecdsaSignatureMessageX962SHA256
        case .ecdsaSHA384P384: return .ecdsaSignatureMessageX962SHA384
        case .ecdsaSHA512P521: return .ecdsaSignatureMessageX962SHA512
        case .ed25519, .ed25519ph: return nil
        }
    }

    /// The digest SU3File computes over the signed region for this type.
    func digest(_ region: Data) -> Data {
        switch self {
        case .rsaSHA256_2048, .ecdsaSHA256P256:
            return SHA256.hash(data: region).withUnsafeBytes { Data($0) }
        case .rsaSHA384_3072, .ecdsaSHA384P384:
            return SHA384.hash(data: region).withUnsafeBytes { Data($0) }
        default:
            return SHA512.hash(data: region).withUnsafeBytes { Data($0) }
        }
    }
}

// MARK: - Container

/// A parsed SU3 container: header fields, payload and the exact byte region
/// its signature covers.
struct I2PSU3Container {
    /// Size of the fixed SU3 header (SU3File.VERSION_OFFSET).
    static let headerLength = 40
    /// Sanity cap on the declared content length (i2pd caps at 128 MB).
    static let maxContentLength = 128 * 1024 * 1024

    let signatureType: I2PSU3SignatureType
    let fileType: UInt8
    let contentType: UInt8
    let version: String
    let signerID: String
    let content: Data
    let signature: Data
    /// Every byte the signature covers: header, version, signer ID, content.
    let signedRegion: Data

    static func parse(_ data: Data) throws -> I2PSU3Container {
        let bytes = [UInt8](data)
        guard bytes.count >= headerLength else {
            throw I2PSU3Error.invalidContainer(
                "truncated SU3 header (\(bytes.count) of \(headerLength) bytes)")
        }
        guard Array(bytes[0..<6]) == Array("I2Psu3".utf8) else {
            let head = bytes.prefix(8).map { String(format: "%02x", $0) }.joined()
            throw I2PSU3Error.invalidContainer("bad SU3 magic (payload begins \(head))")
        }
        guard bytes[6] == 0 else {
            throw I2PSU3Error.invalidContainer("SU3 header byte 6 is not zero")
        }
        guard bytes[7] == 0 else {
            throw I2PSU3Error.invalidContainer(
                "unsupported SU3 file format version \(bytes[7]) (this build reads version 0)")
        }

        let signatureCode = be16(bytes, 8)
        guard let signatureType = I2PSU3SignatureType(rawValue: signatureCode) else {
            throw I2PSU3Error.unsupportedSignatureType(signatureCode)
        }
        let declaredSignatureLength = Int(be16(bytes, 10))
        guard declaredSignatureLength == signatureType.signatureLength else {
            throw I2PSU3Error.invalidContainer(
                "SU3 signature length \(declaredSignatureLength) does not match \(signatureType.name) (\(signatureType.signatureLength) bytes)")
        }
        guard bytes[12] == 0, bytes[14] == 0, bytes[24] == 0, bytes[26] == 0 else {
            throw I2PSU3Error.invalidContainer("reserved SU3 header byte is not zero")
        }
        for index in 28..<headerLength where bytes[index] != 0 {
            throw I2PSU3Error.invalidContainer("reserved SU3 header byte \(index) is not zero")
        }

        let versionLength = Int(bytes[13])
        guard versionLength >= 16 else {
            throw I2PSU3Error.invalidContainer(
                "SU3 version string is \(versionLength) bytes (the format requires at least 16)")
        }
        let signerLength = Int(bytes[15])
        guard signerLength > 0 else {
            throw I2PSU3Error.invalidContainer("SU3 container carries no signer ID")
        }

        let contentLengthValue = be64(bytes, 16)
        guard contentLengthValue > 0 else {
            throw I2PSU3Error.invalidContainer("empty SU3 content")
        }
        guard contentLengthValue <= UInt64(maxContentLength) else {
            throw I2PSU3Error.invalidContainer(
                "SU3 content length \(contentLengthValue) exceeds the \(maxContentLength)-byte cap")
        }
        let contentLength = Int(contentLengthValue)

        let contentOffset = headerLength + versionLength + signerLength
        guard contentOffset <= bytes.count, contentLength <= bytes.count - contentOffset else {
            throw I2PSU3Error.invalidContainer(
                "SU3 content length \(contentLength) exceeds the file (received \(bytes.count) bytes — truncated transfer)")
        }
        let signatureOffset = contentOffset + contentLength
        guard bytes.count <= Int.max - declaredSignatureLength else {
            throw I2PSU3Error.invalidContainer("SU3 declared lengths overflow")
        }
        guard bytes.count >= signatureOffset + declaredSignatureLength else {
            throw I2PSU3Error.invalidContainer(
                "SU3 signature is cut short (received \(bytes.count - signatureOffset) of \(declaredSignatureLength) bytes — truncated transfer)")
        }
        guard bytes.count == signatureOffset + declaredSignatureLength else {
            throw I2PSU3Error.invalidContainer(
                "trailing data after the SU3 signature (\(bytes.count - signatureOffset - declaredSignatureLength) bytes)")
        }

        let versionBytes = Array(bytes[headerLength..<(headerLength + versionLength)])
        let terminator = versionBytes.firstIndex(of: 0) ?? versionBytes.count
        let version = String(decoding: versionBytes[..<terminator], as: UTF8.self)
        let signerBytes = bytes[(headerLength + versionLength)..<contentOffset]
        let signerID = String(decoding: signerBytes, as: UTF8.self)
        guard !signerID.isEmpty else {
            throw I2PSU3Error.invalidContainer("SU3 signer ID decodes to nothing")
        }

        return I2PSU3Container(
            signatureType: signatureType,
            fileType: bytes[25],
            contentType: bytes[27],
            version: version,
            signerID: signerID,
            content: Data(bytes[contentOffset..<signatureOffset]),
            signature: Data(bytes[signatureOffset..<bytes.count]),
            signedRegion: Data(bytes[0..<signatureOffset]))
    }

    /// Verifies the container signature against a trusted signer certificate.
    /// Throws on an unknown signer or a rejected signature — never returns a
    /// best-effort verdict.
    func verify(using trust: I2PSU3TrustStore) throws {
        guard let signer = trust.signer(id: signerID) else {
            throw I2PSU3Error.unknownSigner(signerID)
        }
        try I2PSU3SignerVerifier.verify(
            signature: signature, region: signedRegion,
            signatureType: signatureType, signer: signer)
    }
}

// MARK: - Trust store

/// A trusted SU3 signer: the header's signer ID plus the key material its
/// certificate carries.
struct I2PSU3Signer {
    enum KeyMaterial {
        /// DER X.509 certificate — RSA and ECDSA go through Security, Ed25519
        /// through the raw subject key extracted from it.
        case x509Certificate(Data)
        /// A bare 32-byte Ed25519 public key (synthetic signers, tests).
        case ed25519PublicKey(Data)
    }

    let id: String
    let keyMaterial: KeyMaterial
}

struct I2PSU3TrustStore {
    private let signers: [String: I2PSU3Signer]

    init(signers: [I2PSU3Signer]) {
        var table: [String: I2PSU3Signer] = [:]
        for signer in signers {
            table[Self.normalize(signer.id)] = signer
        }
        self.signers = table
    }

    /// Signer IDs are compared case-insensitively with the "@" of a mail-style
    /// name folded to the "_at_" form certificate files use: the same signer is
    /// published as `igor@novg.net` in the certificate CN and stored as
    /// `igor_at_novg.net.crt` by both reference routers.
    static func normalize(_ id: String) -> String {
        id.trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
            .replacingOccurrences(of: "@", with: "_at_")
    }

    func signer(id: String) -> I2PSU3Signer? {
        signers[Self.normalize(id)]
    }

    var signerIDs: [String] { signers.keys.sorted() }

    /// The reseed signers bundled with the app.
    static let bundled = I2PSU3TrustStore(signers: I2PSU3BundledReseedSigners.load())
}

/// The reseed signing certificates shipped with the app (Resources/reseed-certs),
/// the same public cert set Java I2P and i2pd ship for SU3 verification. The
/// file name is the signer ID: DirKeyRing looks the header's signer string up as
/// `certificates/reseed/<signer>.crt`.
enum I2PSU3BundledReseedSigners {
    static let directory = "reseed-certs"
    static let fileExtension = "crt"

    static func load(in bundle: Bundle = .main) -> [I2PSU3Signer] {
        var urls = bundle.urls(forResourcesWithExtension: fileExtension, subdirectory: directory) ?? []
        if urls.isEmpty {
            urls = bundle.urls(forResourcesWithExtension: fileExtension, subdirectory: nil) ?? []
        }
        if urls.isEmpty, let root = bundle.resourceURL,
           let enumerator = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil) {
            // A file-system synchronized group may copy the folder's contents
            // flat, preserve the folder, or nest it under Resources/ — walk the
            // bundle rather than depend on which.
            for case let url as URL in enumerator
            where url.pathExtension.lowercased() == fileExtension {
                urls.append(url)
            }
        }
        if urls.isEmpty,
           let override = ProcessInfo.processInfo.environment["I2P_RESEED_CERTS_DIR"] {
            // Off-device harnesses compile the sources with swiftc and have no
            // app bundle; they point at the certificate folder in the source
            // tree instead, so the same signer set is exercised.
            if let entries = try? FileManager.default.contentsOfDirectory(atPath: override) {
                let base = URL(fileURLWithPath: override, isDirectory: true)
                urls = entries
                    .filter { ($0 as NSString).pathExtension.lowercased() == fileExtension }
                    .sorted()
                    .map { base.appendingPathComponent($0) }
            }
        }

        var seen = Set<String>()
        var signers: [I2PSU3Signer] = []
        for url in urls {
            guard let data = try? Data(contentsOf: url),
                  let der = derBytes(from: data) else { continue }
            let id = url.deletingPathExtension().lastPathComponent
            guard !id.isEmpty, seen.insert(I2PSU3TrustStore.normalize(id)).inserted else { continue }
            signers.append(I2PSU3Signer(id: id, keyMaterial: .x509Certificate(der)))
        }
        return signers
    }

    /// Accepts a PEM certificate ("-----BEGIN CERTIFICATE-----") or raw DER.
    static func derBytes(from data: Data) -> Data? {
        if data.first == 0x30 { return data }
        guard let text = String(data: data, encoding: .utf8) else { return nil }
        let body = text.components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("-----") }
            .joined()
        guard !body.isEmpty,
              let der = Data(base64Encoded: body, options: [.ignoreUnknownCharacters]),
              !der.isEmpty else { return nil }
        return der
    }
}

// MARK: - Verification

enum I2PSU3SignerVerifier {
    static func verify(signature: Data, region: Data,
                       signatureType: I2PSU3SignatureType,
                       signer: I2PSU3Signer) throws {
        guard signature.count == signatureType.signatureLength else {
            throw I2PSU3Error.signatureRejected(
                "SU3 signature is \(signature.count) bytes; \(signatureType.name) requires \(signatureType.signatureLength)")
        }
        switch signer.keyMaterial {
        case .ed25519PublicKey(let publicKey):
            guard signatureType.isEdDSA else {
                throw I2PSU3Error.signatureRejected(
                    "signer \(signer.id) carries an Ed25519 key but the container declares \(signatureType.name)")
            }
            try verifyEdwards(signature: signature, region: region,
                              signatureType: signatureType,
                              publicKey: publicKey, signerID: signer.id)
        case .x509Certificate(let der):
            if signatureType.isEdDSA {
                guard let publicKey = ed25519PublicKey(fromCertificate: der) else {
                    throw I2PSU3Error.signatureRejected(
                        "certificate for \(signer.id) carries no Ed25519 subject key")
                }
                try verifyEdwards(signature: signature, region: region,
                                  signatureType: signatureType,
                                  publicKey: publicKey, signerID: signer.id)
            } else {
                try verifyWithSecurity(signature: signature, region: region,
                                       signatureType: signatureType,
                                       certificateDER: der, signerID: signer.id)
            }
        }
    }

    // MARK: Certificate-backed types (RSA, ECDSA)

    private static func verifyWithSecurity(signature: Data, region: Data,
                                           signatureType: I2PSU3SignatureType,
                                           certificateDER: Data, signerID: String) throws {
        guard let algorithm = signatureType.secKeyAlgorithm else {
            throw I2PSU3Error.unsupportedSignatureType(signatureType.rawValue)
        }
        guard let certificate = SecCertificateCreateWithData(nil, certificateDER as CFData) else {
            throw I2PSU3Error.signatureRejected(
                "certificate for \(signerID) is not a DER X.509 certificate")
        }
        guard let key = SecCertificateCopyKey(certificate) else {
            throw I2PSU3Error.signatureRejected(
                "certificate for \(signerID) carries no public key")
        }
        if SecKeyVerifySignature(key, algorithm, region as CFData, signature as CFData, nil) {
            return
        }
        // ECDSA: SU3File's Signature class writes the fixed-length r||s form,
        // not X9.62 DER. Re-wrap it and retry — a signature that verifies over
        // the same region is a valid signature either way.
        if signatureType.isECDSA,
           let der = derEncodedRawECDSA(signature),
           SecKeyVerifySignature(key, algorithm, region as CFData, der as CFData, nil) {
            return
        }
        // RSA: SU3File signs the bare container digest under PKCS#1 v1.5
        // padding, so the standard verifier above rejects every real reseed
        // file. Take the raw s^e mod n block and check the padding and digest
        // the format actually produces (the acceptance bar i2pd uses).
        if signatureType.isRSA,
           rawRSADigestMatches(key: key, signature: signature,
                               digest: signatureType.digest(region)) {
            return
        }
        throw I2PSU3Error.signatureRejected(
            "\(signatureType.name) signature by \(signerID) does not verify over the \(region.count)-byte container prefix")
    }

    /// Decrypts the signature with the public exponent (raw RSA) and validates
    /// the PKCS#1 v1.5 block the SU3 format signs: 00 01 FF..FF (at least 8) 00
    /// followed by the digest — bare, as Java I2P's RSA engine emits it, or
    /// wrapped in a DigestInfo, as a standard signer would emit it.
    private static func rawRSADigestMatches(key: SecKey, signature: Data, digest: Data) -> Bool {
        guard SecKeyIsAlgorithmSupported(key, .decrypt, .rsaEncryptionRaw) else { return false }
        var error: Unmanaged<CFError>?
        guard let encoded = SecKeyCreateDecryptedData(key, .rsaEncryptionRaw,
                                                      signature as CFData, &error) else {
            return false
        }
        let block = [UInt8](encoded as NSData as Data)
        guard block.count > digest.count + 2, block[0] == 0x00, block[1] == 0x01 else {
            return false
        }
        var index = 2
        var paddingBytes = 0
        while index < block.count, block[index] == 0xff {
            paddingBytes += 1
            index += 1
        }
        guard paddingBytes >= 8, index < block.count, block[index] == 0x00 else {
            return false
        }
        let payload = Data(block[(index + 1)...])
        return payload == digest || payload.suffix(digest.count) == digest
    }

    /// Wraps a fixed-length r||s ECDSA signature in the X9.62 SEQUENCE the
    /// Certificate-backed verifier expects.
    private static func derEncodedRawECDSA(_ signature: Data) -> Data? {
        guard signature.count % 2 == 0, signature.count >= 2 else { return nil }
        let half = signature.count / 2
        let r = derInteger(Data(signature.prefix(half)))
        let s = derInteger(Data(signature.suffix(half)))
        let body = r + s
        guard body.count < 0x80 else { return nil }
        return Data([0x30, UInt8(body.count)]) + body
    }

    private static func derInteger(_ value: Data) -> Data {
        var trimmed = value
        while trimmed.count > 1, trimmed.first == 0x00 {
            trimmed.removeFirst()
        }
        if let first = trimmed.first, first & 0x80 != 0 {
            trimmed = Data([0x00]) + trimmed
        }
        guard trimmed.count < 0x80 else { return Data() }
        return Data([0x02, UInt8(trimmed.count)]) + trimmed
    }

    // MARK: EdDSA

    private static func verifyEdwards(signature: Data, region: Data,
                                      signatureType: I2PSU3SignatureType,
                                      publicKey: Data, signerID: String) throws {
        guard publicKey.count == 32 else {
            throw I2PSU3Error.signatureRejected(
                "signer \(signerID) carries a \(publicKey.count)-byte Ed25519 key")
        }
        let digest = signatureType.digest(region)
        if signatureType == .ed25519ph {
            if I2PCrypto.ed25519phVerify(signature: signature, message: region, publicKey: publicKey) {
                return
            }
            if I2PCrypto.ed25519Verify(signature: signature, message: digest, publicKey: publicKey) {
                return
            }
        } else {
            // SU3File signs the container's SHA-512 digest, Ed25519 over that
            // digest being what its Signature(hash) path produces; the RFC 8032
            // form over the raw region is accepted as well.
            if I2PCrypto.ed25519Verify(signature: signature, message: digest, publicKey: publicKey) {
                return
            }
            if I2PCrypto.ed25519Verify(signature: signature, message: region, publicKey: publicKey) {
                return
            }
        }
        throw I2PSU3Error.signatureRejected(
            "\(signatureType.name) signature by \(signerID) does not verify over the \(region.count)-byte container prefix")
    }

    /// Pulls the raw Ed25519 key out of a certificate's SubjectPublicKeyInfo:
    /// the id-Ed25519 OID (06 03 2B 65 70) followed by a 32-byte BIT STRING.
    private static func ed25519PublicKey(fromCertificate der: Data) -> Data? {
        let bytes = [UInt8](der)
        let oid: [UInt8] = [0x06, 0x03, 0x2B, 0x65, 0x70]
        guard bytes.count > oid.count else { return nil }
        var index = 0
        while index + oid.count + 3 <= bytes.count {
            if Array(bytes[index..<(index + oid.count)]) == oid {
                let bitString = index + oid.count
                if bytes[bitString] == 0x03, bytes[bitString + 1] == 0x21,
                   bytes[bitString + 2] == 0x00,
                   bitString + 3 + 32 <= bytes.count {
                    return Data(bytes[(bitString + 3)..<(bitString + 35)])
                }
            }
            index += 1
        }
        return nil
    }
}

// MARK: - Big-endian header fields

private func be16(_ bytes: [UInt8], _ offset: Int) -> UInt16 {
    (UInt16(bytes[offset]) << 8) | UInt16(bytes[offset + 1])
}

private func be64(_ bytes: [UInt8], _ offset: Int) -> UInt64 {
    var value: UInt64 = 0
    for index in 0..<8 { value = (value << 8) | UInt64(bytes[offset + index]) }
    return value
}
