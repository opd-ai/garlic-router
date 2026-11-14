//
//  I2PLeaseSet2.swift
//  The LeaseSet2 family per proposal 123 and the common-structures spec:
//  plain LeaseSet2 (DatabaseStore type 3), EncryptedLeaseSet (type 5) and
//  MetaLeaseSet (type 7) for ECIES destinations.
//
//  Wire shape — the store type is NOT repeated in the payload, the
//  DatabaseStore type byte carries it, and the signature covers that byte
//  prepended to the body ("The signature is over the data above, PREPENDED
//  with the single byte containing the DatabaseStore type"):
//
//    LeaseSet2Header = destination (KeysAndCert, 387+ bytes), published
//      (4 bytes, seconds), expires (2 bytes, offset from published), flags
//      (2 bytes), then — when flags bit 0 is set — the offline delegation
//      block: expires (4), sigtype (2), transient key, signature (64).
//    plain (3):     options Mapping, numk, keys (type/len/key each), num,
//                   Lease2 × num
//    encrypted (5): sigtype (2), blinded signing key, published, expires,
//                   flags, [offline block], len (2), encrypted body
//                   — no destination and no options on this variant.
//    meta (7):      options Mapping, num, MetaLease × num, numr, revocations
//
//  followed by the 64-byte Ed25519/EdDSA signature. Lease2 is 40 bytes
//  (gateway hash + tunnel ID + 4-byte end date); it carries no cost field.
//
//  Every parse fails closed: the delegation block and the body signature must
//  verify, or the whole entry is rejected.
//

import Foundation
import CryptoKit

/// LeaseSet2 store types, keyed by their DatabaseStore type byte (the byte the
/// body signature is prepended with).
enum I2PLeaseSet2Type: UInt16 {
    case plain = 3        /// LeaseSet2: visible lease entries.
    case encrypted = 5    /// EncryptedLeaseSet: the inner body stays opaque without credentials.
    case meta = 7         /// MetaLeaseSet: a multi-homing list of entry hashes.

    /// The byte prepended to the signed contents.
    var signaturePrefix: UInt8 { UInt8(rawValue & 0xFF) }
}

/// A LeaseSet2 lease entry (Lease2): gateway hash + tunnel ID + end date.
/// 40 bytes on the wire; the 4-byte end date is what distinguishes it from the
/// classic 44-byte LeaseSet lease.
struct I2PLease2: Equatable {
    let gatewayHash: Data
    let tunnelId: UInt32
    let expiration: Date
}

/// One published encryption key of a plain LeaseSet2 (numk list): the key type,
/// its length and the key material, in the publisher's order of preference.
struct I2PLeaseSet2EncryptionKey: Equatable {
    let type: UInt16
    let key: Data
}

/// Offline/transient signing key block (flags bit 0x0001): the destination's
/// permanent Ed25519 key delegates to a short-lived transient key. The LS2 body
/// is then signed with the transient key, and this block's signature — made by
/// the permanent key over (expiration, sig type, transient key) — authenticates
/// the delegation.
struct I2PLeaseSet2OfflineSignature: Equatable {
    let sigType: I2PSigType
    let transientExpiration: Date
    let transientPublicKey: Data
    var signature: Data

    /// The exact bytes the permanent key signs, in wire order: expiration
    /// seconds (4) + sig type (2) + transient public key.
    var signedContents: Data {
        var w = I2PWriter()
        w.integer(UInt32(max(0, transientExpiration.timeIntervalSince1970.rounded())))
        w.short(sigType.rawValue)
        w.raw(transientPublicKey)
        return w.data
    }

    /// Signs the delegation block with the permanent signing seed.
    static func sign(sigType: I2PSigType, transientExpiration: Date,
                     transientPublicKey: Data, permanentSeed: Data) throws -> I2PLeaseSet2OfflineSignature {
        let base = I2PLeaseSet2OfflineSignature(
            sigType: sigType,
            transientExpiration: Date(timeIntervalSince1970:
                transientExpiration.timeIntervalSince1970.rounded()),
            transientPublicKey: transientPublicKey,
            signature: Data())
        var signed = base
        signed.signature = try I2PCrypto.ed25519Sign(base.signedContents, seed: permanentSeed)
        return signed
    }
}

/// One MetaLease (40 bytes): the hash of the gateway router — or of another
/// MetaLeaseSet — plus 3 flag bytes, a cost byte and a 4-byte end date.
/// Bits 3-0 of the flags carry the entry type (1 LeaseSet, 3 LeaseSet2,
/// 5 MetaLeaseSet; 0 unknown).
struct I2PMetaLease: Equatable {
    let gatewayHash: Data
    /// The 3 flag bytes as stored, big-endian.
    let flags: UInt32
    /// 0-255; a lower value is a higher priority.
    let cost: UInt8
    let expiration: Date

    init(gatewayHash: Data, flags: UInt32 = 0, cost: UInt8 = 0, expiration: Date) {
        self.gatewayHash = gatewayHash
        self.flags = flags & 0x00FF_FFFF
        self.cost = cost
        self.expiration = expiration
    }

    /// The entry type in flags bits 3-0.
    var entryTypeCode: UInt8 { UInt8(flags & 0x0F) }
}

/// LeaseSet2 family entry. `raw` is the complete wire payload — the body
/// followed by the 64-byte signature — exactly as a DatabaseStore carries it.
struct I2PLeaseSet2 {
    let storeType: I2PLeaseSet2Type
    let destination: I2PDestination
    /// 4 BE seconds since epoch (LS2 uses second-grained timestamps).
    let published: Date
    /// Expiration offset in seconds added to `published` (2 bytes on the wire).
    let expiresOffsetSeconds: UInt16
    /// LS2 flags: bit 0x0001 = offline signature (transient delegation block).
    let flags: UInt16
    let offlineSignature: I2PLeaseSet2OfflineSignature?
    /// Options Mapping (plain and meta variants; the encrypted form has none).
    let options: [String: String]
    /// Plain type-3 lease entries (empty for the encrypted/meta envelopes).
    let leases: [I2PLease2]
    /// Plain type-3 published encryption keys, in preference order.
    let encryptionKeys: [I2PLeaseSet2EncryptionKey]
    /// Type-5 encrypted inner body.
    let encryptedBody: Data
    /// Type-5 blinded signing public key (the wire's identity for the entry).
    let blindedSigningPublicKey: Data?
    /// Type-7 meta lease entries.
    let metaEntries: [I2PMetaLease]
    /// Type-7 revocation hashes.
    let revocations: [Data]
    /// The trailing Ed25519 signature.
    var signature: Data
    /// The complete wire payload (body + signature).
    var raw: Data

    var expiresAt: Date {
        published.addingTimeInterval(TimeInterval(expiresOffsetSeconds))
    }

    var hasOfflineSignature: Bool {
        flags & 0x0001 != 0
    }

    /// The key the body signature verifies with: the transient key when the
    /// offline flag is set, else the destination's own permanent signing key.
    var bodySigningPublicKey: Data {
        offlineSignature?.transientPublicKey ?? destination.signingPublicKey
    }

    /// The ECIES key delivery encrypts to: the entry's own published key list.
    /// Only a key whose type this router implements is usable — a destination
    /// that publishes solely a hybrid (ML-KEM) key yields none here, since the
    /// destination's crypto field is unused padding, never a real key.
    var preferredEncryptionKey: Data? {
        for key in encryptionKeys where key.key.count == 32 {
            if key.type == I2PEncType.x25519.rawValue || key.type == I2PEncType.eciesX25519.rawValue {
                return key.key
            }
        }
        return nil
    }

    /// The body: everything the signature covers, minus its type prefix.
    func bodyBytes() -> Data {
        raw.count > 64 ? Data(raw.prefix(raw.count - 64)) : Data()
    }

    /// Everything covered by the signature: the DatabaseStore type byte
    /// prepended to the body.
    func serializedSignedContents() -> Data {
        var w = I2PWriter()
        w.byte(storeType.signaturePrefix)
        w.raw(bodyBytes())
        return w.data
    }

    func verifySignature() -> Bool {
        I2PCrypto.ed25519Verify(signature: signature,
                                message: serializedSignedContents(),
                                publicKey: bodySigningPublicKey)
    }

    /// The delegation block's signature must verify under the permanent key.
    func verifyTransientBlockSignature() -> Bool {
        guard let offline = offlineSignature else { return true }
        return I2PCrypto.ed25519Verify(signature: offline.signature,
                                       message: offline.signedContents,
                                       publicKey: destination.signingPublicKey)
    }

    // MARK: Identity

    /// The canonical destination a blinded signing key maps to. An encrypted
    /// LeaseSet carries only the blinded signing key (no destination), so the
    /// netdb key of an encrypted entry is derived from that key alone — the
    /// same derivation on the publishing and the resolving side. A Destination's
    /// crypto field is unused padding, so it is pinned to zero here.
    static func blindedDestination(_ blindedSigningPublicKey: Data) -> I2PDestination {
        I2PKeysAndCert(encryptionPublicKey: Data(repeating: 0, count: 32),
                       signingPublicKey: blindedSigningPublicKey)
    }

    // MARK: Delivery helpers (netdb resolution → garlic delivery)

    /// Classic LeaseSet shape for the delivery paths. Only a plain LeaseSet2
    /// publishes usable leases: a meta LeaseSet2 points at other entries by
    /// hash (each one is a further lookup) and an encrypted one stays opaque
    /// without the b33 credentials.
    func resolvedLeaseSet() -> I2PLeaseSet? {
        guard storeType == .plain else { return nil }
        let converted = leases.map {
            I2PLease(gatewayHash: $0.gatewayHash, tunnelId: $0.tunnelId, expiration: $0.expiration)
        }
        guard !converted.isEmpty else { return nil }
        return I2PLeaseSet(destination: destination, published: published, leases: converted)
    }

    // MARK: Serialization

    func serialize() -> Data { raw }

    /// Re-seals the payload after a signature change (the b33 publisher signs
    /// the envelope with the blinded private key).
    mutating func replaceSignature(_ new: Data) {
        signature = new
        raw = bodyBytes() + new
    }

    /// The unsigned body, in spec field order.
    private func makeBody() -> Data {
        var w = I2PWriter()
        switch storeType {
        case .encrypted:
            // EncryptedLeaseSet: sigtype + blinded key replace the destination,
            // and this variant carries no options Mapping.
            w.short(I2PSigType.ed25519.rawValue)
            w.raw(blindedSigningPublicKey ?? destination.signingPublicKey)
            writeHeaderTail(&w)
            guard encryptedBody.count <= Int(UInt16.max) else { return w.data }
            w.short(UInt16(encryptedBody.count))
            w.raw(encryptedBody)
        case .plain, .meta:
            destination.serialize(into: &w)
            writeHeaderTail(&w)
            w.mapping(options)
            if storeType == .plain {
                // The destination's own crypto field is only a fallback key for
                // an identity that publishes none (it is unused — empty — for a
                // LeaseSet2-era destination), so an empty list stays empty.
                var keys = encryptionKeys
                if keys.isEmpty, destination.encryptionPublicKey.count == 32 {
                    keys = [I2PLeaseSet2EncryptionKey(type: I2PEncType.x25519.rawValue,
                                                      key: destination.encryptionPublicKey)]
                }
                w.byte(UInt8(min(keys.count, 255)))
                for key in keys.prefix(255) {
                    w.short(key.type)
                    w.short(UInt16(min(key.key.count, Int(UInt16.max))))
                    w.raw(key.key)
                }
                w.byte(UInt8(min(leases.count, 16)))
                for lease in leases.prefix(16) { Self.writeLease2(lease, into: &w) }
            } else {
                w.byte(UInt8(min(metaEntries.count, 255)))
                for entry in metaEntries.prefix(255) {
                    w.hash(entry.gatewayHash)
                    w.byte(UInt8((entry.flags >> 16) & 0xFF))
                    w.byte(UInt8((entry.flags >> 8) & 0xFF))
                    w.byte(UInt8(entry.flags & 0xFF))
                    w.byte(entry.cost)
                    w.integer(UInt32(max(0, entry.expiration.timeIntervalSince1970.rounded())))
                }
                w.byte(UInt8(min(revocations.count, 255)))
                for hash in revocations.prefix(255) { w.hash(hash) }
            }
        }
        return w.data
    }

    /// published (4 s) + expires (2 s) + flags (2) + the offline block.
    private func writeHeaderTail(_ w: inout I2PWriter) {
        w.integer(UInt32(max(0, published.timeIntervalSince1970.rounded())))
        w.short(expiresOffsetSeconds)
        w.short(flags)
        guard let offline = offlineSignature else { return }
        w.integer(UInt32(max(0, offline.transientExpiration.timeIntervalSince1970.rounded())))
        w.short(offline.sigType.rawValue)
        w.raw(offline.transientPublicKey)
        w.raw(offline.signature)
    }

    private static func writeLease2(_ lease: I2PLease2, into w: inout I2PWriter) {
        w.hash(lease.gatewayHash)
        w.integer(lease.tunnelId)
        w.integer(UInt32(max(0, lease.expiration.timeIntervalSince1970.rounded())))
    }

    private static func parseLease2(_ r: inout I2PReader) throws -> I2PLease2 {
        let gateway = try r.hash()
        let tunnelId = try r.integer()
        let end = try r.integer()
        return I2PLease2(gatewayHash: gateway, tunnelId: tunnelId,
                         expiration: Date(timeIntervalSince1970: TimeInterval(end)))
    }

    // MARK: Parsing (fail closed)

    /// Parses a complete LS2 store payload (body + 64-byte signature). The
    /// type is not in the payload — the DatabaseStore type byte supplies it, so
    /// `expectedType` selects the variant (plain when omitted).
    static func parse(_ data: Data, expectedType: I2PLeaseSet2Type? = .plain) throws -> I2PLeaseSet2 {
        let storeType = expectedType ?? .plain
        // The signature trails every variant: a payload that cannot even hold a
        // body plus one is not an entry. Field-level truncation is caught by the
        // readers below, which throw rather than read past the buffer.
        guard data.count > 64 + 4 else { throw I2PWireError.invalidFormat }
        let bytes = Array(data)
        let body = Data(bytes[0..<(bytes.count - 64)])
        let signature = Data(bytes[(bytes.count - 64)...])
        var r = I2PReader(body)

        let header: Header
        var options: [String: String] = [:]
        var blindedSigningPublicKey: Data?
        var leases: [I2PLease2] = []
        var encryptionKeys: [I2PLeaseSet2EncryptionKey] = []
        var encryptedBody = Data()
        var metaEntries: [I2PMetaLease] = []
        var revocations: [Data] = []

        switch storeType {
        case .encrypted:
            let sigTypeRaw = try r.short()
            guard let sigType = I2PSigType(rawValue: sigTypeRaw) else {
                throw I2PWireError.unsupportedAlgorithm
            }
            let blindedKey = try r.raw(sigType.publicKeyLength)
            guard blindedKey.count == 32 else { throw I2PWireError.unsupportedAlgorithm }
            blindedSigningPublicKey = blindedKey
            // The encrypted variant has no destination: the entry's identity is
            // the blinded signing key alone.
            header = try readHeaderTail(&r,
                                        destination: I2PLeaseSet2.blindedDestination(blindedKey))
            let bodyLength = Int(try r.short())
            guard bodyLength >= 1 else { throw I2PWireError.invalidFormat }
            encryptedBody = try r.raw(bodyLength)
        case .plain, .meta:
            let destination = try I2PKeysAndCert.parse(&r)
            header = try readHeaderTail(&r, destination: destination)
            if storeType == .plain {
                let parsed = try parseOptionsAndKeys(&r)
                options = parsed.options
                leases = parsed.leases
                encryptionKeys = parsed.keys
            } else {
                options = try r.mapping()
                let count = Int(try r.byte())
                guard count >= 1, count <= 16 else { throw I2PWireError.invalidFormat }
                for _ in 0..<count {
                    let gateway = try r.hash()
                    let f0 = try r.byte(), f1 = try r.byte(), f2 = try r.byte()
                    let flags = (UInt32(f0) << 16) | (UInt32(f1) << 8) | UInt32(f2)
                    let cost = try r.byte()
                    let end = try r.integer()
                    metaEntries.append(I2PMetaLease(
                        gatewayHash: gateway, flags: flags, cost: cost,
                        expiration: Date(timeIntervalSince1970: TimeInterval(end))))
                }
                let revocationCount = Int(try r.byte())
                for _ in 0..<revocationCount { revocations.append(try r.hash()) }
            }
        }
        guard r.remaining == 0 else { throw I2PWireError.trailingData }

        let leaseSet2 = I2PLeaseSet2(
            storeType: storeType,
            destination: header.destination,
            published: header.published,
            expiresOffsetSeconds: header.expiresOffsetSeconds,
            flags: header.flags,
            offlineSignature: header.offlineSignature,
            options: options,
            leases: leases,
            encryptionKeys: encryptionKeys,
            encryptedBody: encryptedBody,
            blindedSigningPublicKey: blindedSigningPublicKey,
            metaEntries: metaEntries,
            revocations: revocations,
            signature: signature,
            raw: data)
        // Fail closed: the delegation block and the body signature must verify.
        guard leaseSet2.verifyTransientBlockSignature() else { throw I2PWireError.invalidSignature }
        guard leaseSet2.verifySignature() else { throw I2PWireError.invalidSignature }
        return leaseSet2
    }

    private struct Header {
        let destination: I2PDestination
        let published: Date
        let expiresOffsetSeconds: UInt16
        let flags: UInt16
        let offlineSignature: I2PLeaseSet2OfflineSignature?
    }

    /// published (4 s) + expires (2) + flags (2) + the optional offline block.
    private static func readHeaderTail(_ r: inout I2PReader,
                                       destination: I2PDestination) throws -> Header {
        let publishedSeconds = try r.integer()
        let expiresOffset = try r.short()
        let flags = try r.short()
        var offline: I2PLeaseSet2OfflineSignature?
        if flags & 0x0001 != 0 {
            let expiration = try r.integer()
            let sigTypeRaw = try r.short()
            guard let sigType = I2PSigType(rawValue: sigTypeRaw) else {
                throw I2PWireError.unsupportedAlgorithm
            }
            let transientKey = try r.raw(sigType.publicKeyLength)
            let blockSignature = try r.raw(64)
            offline = I2PLeaseSet2OfflineSignature(
                sigType: sigType,
                transientExpiration: Date(timeIntervalSince1970: TimeInterval(expiration)),
                transientPublicKey: transientKey,
                signature: blockSignature)
        }
        return Header(destination: destination,
                      published: Date(timeIntervalSince1970: TimeInterval(publishedSeconds)),
                      expiresOffsetSeconds: expiresOffset,
                      flags: flags,
                      offlineSignature: offline)
    }

    /// options Mapping + numk encryption keys + leases (plain variant).
    ///
    /// `numk` has no minimum in the spec ("Number of key sections to follow
    /// (1 byte, max TBD)"): a destination that keeps the legacy ElGamal crypto
    /// field publishes none and still publishes leases. Requiring at least one
    /// key rejected every such entry whole.
    private static func parseOptionsAndKeys(_ r: inout I2PReader) throws
        -> (options: [String: String], keys: [I2PLeaseSet2EncryptionKey], leases: [I2PLease2]) {
        let options = try r.mapping()
        let keyCount = Int(try r.byte())
        guard keyCount <= 8 else { throw I2PWireError.invalidFormat }
        var keys: [I2PLeaseSet2EncryptionKey] = []
        for _ in 0..<keyCount {
            let keyType = try r.short()
            let keyLength = Int(try r.short())
            // The length rides each key precisely so an entry parses even when a
            // key type is not implemented here — including the large hybrid
            // keys — and selection only ever uses a key this router implements
            // (see preferredEncryptionKey). The bound is the largest public key
            // the specs define; the reader rejects a length the buffer cannot hold.
            guard keyLength >= 1, keyLength <= 1408 else { throw I2PWireError.unsupportedAlgorithm }
            keys.append(I2PLeaseSet2EncryptionKey(type: keyType, key: try r.raw(keyLength)))
        }
        let leaseCount = Int(try r.byte())
        guard leaseCount >= 1, leaseCount <= 16 else { throw I2PWireError.invalidFormat }
        var leases: [I2PLease2] = []
        for _ in 0..<leaseCount { leases.append(try parseLease2(&r)) }
        return (options, keys, leases)
    }

    /// Builds a signed entry (tests and publishers): assembles the structure,
    /// signs the type-prefixed body and returns the complete payload.
    ///
    /// Dates are normalized to the precision the wire carries before signing —
    /// `published` and the delegation block's expiration in whole seconds, lease
    /// ends in whole seconds too (4-byte Lease2 dates). Without that, a freshly
    /// built value would carry sub-second Date precision its own wire form can
    /// never reproduce, and comparing it against a parsed copy would differ.
    static func build(storeType: I2PLeaseSet2Type,
                      destination: I2PDestination,
                      published: Date,
                      expiresOffsetSeconds: UInt16,
                      flags: UInt16 = 0,
                      offlineSignature: I2PLeaseSet2OfflineSignature? = nil,
                      options: [String: String] = [:],
                      leases: [I2PLease2] = [],
                      encryptionKeys: [I2PLeaseSet2EncryptionKey] = [],
                      encryptedBody: Data = Data(),
                      metaEntries: [I2PMetaLease] = [],
                      revocations: [Data] = [],
                      signingSeed: Data?) throws -> I2PLeaseSet2 {
        let normalizedOffline = offlineSignature.map {
            I2PLeaseSet2OfflineSignature(
                sigType: $0.sigType,
                transientExpiration: Date(timeIntervalSince1970:
                    ($0.transientExpiration.timeIntervalSince1970).rounded()),
                transientPublicKey: $0.transientPublicKey,
                signature: $0.signature)
        }
        let base = I2PLeaseSet2(
            storeType: storeType,
            destination: storeType == .encrypted
                ? I2PLeaseSet2.blindedDestination(destination.signingPublicKey)
                : destination,
            published: Date(timeIntervalSince1970: published.timeIntervalSince1970.rounded()),
            expiresOffsetSeconds: expiresOffsetSeconds,
            flags: flags,
            offlineSignature: normalizedOffline,
            options: options,
            leases: leases.map {
                I2PLease2(gatewayHash: $0.gatewayHash,
                          tunnelId: $0.tunnelId,
                          expiration: Date(timeIntervalSince1970:
                              $0.expiration.timeIntervalSince1970.rounded()))
            },
            encryptionKeys: storeType == .plain
                ? (encryptionKeys.isEmpty && destination.encryptionPublicKey.count == 32
                    ? [I2PLeaseSet2EncryptionKey(type: I2PEncType.x25519.rawValue,
                                                 key: destination.encryptionPublicKey)]
                    : encryptionKeys)
                : [],
            encryptedBody: encryptedBody,
            blindedSigningPublicKey: storeType == .encrypted ? destination.signingPublicKey : nil,
            metaEntries: metaEntries,
            revocations: revocations,
            signature: Data(repeating: 0, count: 64),
            raw: Data())

        let body = base.makeBody()
        var unsigned = I2PWriter()
        unsigned.byte(storeType.signaturePrefix)
        unsigned.raw(body)
        let bodySignature = try I2PCrypto.ed25519Sign(
            unsigned.data, seed: signingSeed ?? I2PCrypto.generateEd25519Seed())
        var signed = base
        signed.signature = bodySignature
        signed.raw = body + bodySignature
        return signed
    }
}
