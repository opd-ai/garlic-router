//
//  I2PLeaseSet2.swift
//  LeaseSet2 per I2P proposal 123: store types 2 (plain), 3 (encrypted)
//  and 5 (meta) for ECIES destinations — destination identity with offline/
//  transient signing keys, lease entries (46-byte Lease2 with cost), and an
//  Ed25519 signature over the LS2 body (type + length + data). Every parse
//  fails closed: the delegation block and the body signature must verify or
//  the whole entry is rejected.
//
//  Wired into the netdb ingest and lookup paths so mainnet ECIES eepsite
//  destinations resolve through DatabaseLookup (see I2PNetDB.swift).
//
//  Encrypted LeaseSet2 (type 3): the envelope is parsed and signature-verified
//  exactly as a floodfill verifies a store — destination (carrying the real
//  X25519 ECIES key), published/expires, flags, transient delegation block,
//  encrypted-body length + opaque body, trailing signature. The inner leases
//  ride the encrypted body and only decrypt under the spec's b33 blinding /
//  authentication path (a client-side concern, not a netdb verify concern).
//
//  Meta LeaseSet2 (type 5): carries a list of complete inner LeaseSet2s
//  (plain or encrypted). Plain inner entries yield delivery-usable leases.
//

import Foundation
import CryptoKit

/// LeaseSet2 store types (proposal 123).
enum I2PLeaseSet2Type: UInt16 {
    case plain = 2        /// LeaseSet2: plaintext body with visible lease entries.
    case encrypted = 3    /// Encrypted LeaseSet2: the inner body is opaque without the blinding/auth decryption path.
    case meta = 5         /// Meta LeaseSet2: a list of complete inner LeaseSet2s (multi-homing).
}

/// A LeaseSet2 lease entry: gateway hash (32) + tunnel ID (4) +
/// end timestamp (8 BE ms) + cost (2 BE). The cost byte-pair is what
/// distinguishes the LS2 Lease2 from the classic 44-byte LeaseSet lease.
struct I2PLease2: Equatable {
    let gatewayHash: Data
    let tunnelId: UInt32
    let expiration: Date
    let cost: UInt16
}

/// Offline/transient signing key block (flags bit 0x0001): the destination's
/// permanent Ed25519 key delegates to a short-lived transient key. The LS2
/// body is then signed with the transient key, and this block's signature —
/// made by the permanent key over (sig type + expiration + transient key) —
/// authenticates the delegation.
struct I2PLeaseSet2OfflineSignature: Equatable {
    let sigType: I2PSigType
    let transientExpiration: Date
    let transientPublicKey: Data
    var signature: Data

    /// The exact bytes the permanent key signs: sig type (2) + expiration
    /// seconds (4) + transient public key.
    var signedContents: Data {
        var w = I2PWriter()
        w.short(sigType.rawValue)
        w.integer(UInt32(max(0, transientExpiration.timeIntervalSince1970.rounded())))
        w.raw(transientPublicKey)
        return w.data
    }

    /// Signs the delegation block with the permanent signing seed.
    static func sign(sigType: I2PSigType, transientExpiration: Date,
                     transientPublicKey: Data, permanentSeed: Data) throws -> I2PLeaseSet2OfflineSignature {
        let base = I2PLeaseSet2OfflineSignature(
            sigType: sigType,
            transientExpiration: transientExpiration,
            transientPublicKey: transientPublicKey,
            signature: Data())
        var signed = base
        signed.signature = try I2PCrypto.ed25519Sign(base.signedContents, seed: permanentSeed)
        return signed
    }
}

/// A meta LeaseSet2 (type 5) entry: a complete inner LeaseSet2 (plain or
/// encrypted) with its own one-byte entry flags.
struct I2PMetaLeaseSet2Entry {
    let flags: UInt8
    let inner: I2PLeaseSet2
}

/// LeaseSet2 (proposal 123). `raw` is the complete wire payload
/// (type + length + data + signature); `serializedSignedContents()` recovers
/// exactly the byte range the signature covers.
struct I2PLeaseSet2 {
    let storeType: I2PLeaseSet2Type
    let destination: I2PDestination
    /// 4 BE seconds since epoch — LS2 uses second-grained timestamps, not the LS1 8-byte Date.
    let published: Date
    /// Expiration offset in seconds added to `published` (the netdb entry expiry anchor).
    let expiresOffsetSeconds: UInt32
    /// LS2 flags: bit 0x0001 = offline signature (transient delegation block present).
    let flags: UInt16
    let offlineSignature: I2PLeaseSet2OfflineSignature?
    /// Plain type-2 lease entries (empty for encrypted/meta at envelope level).
    let leases: [I2PLease2]
    /// Type-3 encrypted inner body (opaque without the blinding/auth decryption path).
    let encryptedBody: Data
    /// Type-5 meta entries: each is a complete inner LeaseSet2 (plain or encrypted).
    let metaEntries: [I2PMetaLeaseSet2Entry]
    /// The trailing 64-byte Ed25519/Ed25519ph signature.
    var signature: Data
    /// The complete wire payload.
    var raw: Data

    var expiresAt: Date {
        published.addingTimeInterval(TimeInterval(expiresOffsetSeconds))
    }

    var hasOfflineSignature: Bool {
        flags & 0x0001 != 0
    }

    /// The data field: everything between the length header and the trailing signature.
    func dataBytes() -> Data {
        let length = Int((UInt16(raw[2]) << 8) | UInt16(raw[3]))
        return raw.subdata(in: 4..<(4 + length))
    }

    /// Everything covered by the signature: type (2) + length (2) + data.
    func serializedSignedContents() -> Data {
        var w = I2PWriter()
        w.short(storeType.rawValue)
        w.short(UInt16(dataBytes().count))
        w.raw(dataBytes())
        return w.data
    }

    /// The key the body signature verifies with: the transient key when the
    /// offline flag is set, else the destination's own permanent signing key.
    var bodySigningPublicKey: Data {
        offlineSignature?.transientPublicKey ?? destination.signingPublicKey
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

    // MARK: Delivery helpers (netdb resolution → garlic delivery)

    /// Classic LeaseSet shape for the delivery paths: the type-2 lease entries
    /// converted, plus plain entries recovered from a meta LS2 (a meta LS2
    /// multi-homes the destination across its inner LeaseSet2s).
    func resolvedLeaseSet() -> I2PLeaseSet? {
        var converted: [I2PLease] = []
        if storeType == .plain {
            converted.append(contentsOf: leases.map {
                I2PLease(gatewayHash: $0.gatewayHash, tunnelId: $0.tunnelId, expiration: $0.expiration)
            })
        }
        for entry in metaEntries where entry.inner.storeType == .plain {
            converted.append(contentsOf: entry.inner.leases.map {
                I2PLease(gatewayHash: $0.gatewayHash, tunnelId: $0.tunnelId, expiration: $0.expiration)
            })
        }
        guard !converted.isEmpty else { return nil }
        return I2PLeaseSet(destination: destination, published: published, leases: converted)
    }

    // MARK: Serialization

    func serialize() -> Data {
        var bw = I2PWriter()
        destination.serialize(into: &bw)
        bw.integer(UInt32(max(0, published.timeIntervalSince1970.rounded())))
        bw.integer(expiresOffsetSeconds)
        bw.short(flags)
        if let offline = offlineSignature {
            bw.short(offline.sigType.rawValue)
            bw.integer(UInt32(max(0, offline.transientExpiration.timeIntervalSince1970.rounded())))
            bw.raw(offline.transientPublicKey)
            bw.raw(offline.signature)
        }
        switch storeType {
        case .plain:
            bw.short(UInt16(leases.count))
            for lease in leases {
                bw.hash(lease.gatewayHash)
                bw.integer(lease.tunnelId)
                bw.date(lease.expiration)
                bw.short(lease.cost)
            }
        case .encrypted:
            bw.short(UInt16(encryptedBody.count))
            bw.raw(encryptedBody)
        case .meta:
            bw.short(UInt16(metaEntries.count))
            for entry in metaEntries {
                bw.byte(entry.flags)
                bw.short(entry.inner.storeType.rawValue)
                // The meta entry body is the inner LS2's data field plus its
                // trailing signature; type + length are re-framed from the header.
                bw.short(UInt16(entry.inner.dataBytes().count + entry.inner.signature.count))
                bw.raw(entry.inner.dataBytes() + entry.inner.signature)
            }
        }
        var w = I2PWriter()
        w.short(storeType.rawValue)
        w.short(UInt16(bw.data.count))
        w.raw(bw.data)
        w.raw(signature)
        return w.data
    }

    // MARK: Parsing (fail closed)

    /// Parses a complete LS2 store payload (type + length + data + signature).
    /// When `expectedType` is given (the DatabaseStore entry-type byte),
    /// a mismatching leading type is rejected.
    static func parse(_ data: Data, expectedType: UInt16? = nil) throws -> I2PLeaseSet2 {
        guard data.count >= 4 + 64 else { throw I2PWireError.invalidFormat }
        let typeRaw = (UInt16(data[0]) << 8) | UInt16(data[1])
        if let expectedType, typeRaw != expectedType {
            throw I2PWireError.invalidFormat
        }
        guard let storeType = I2PLeaseSet2Type(rawValue: typeRaw) else {
            throw I2PWireError.unsupportedAlgorithm
        }
        let length = Int((UInt16(data[2]) << 8) | UInt16(data[3]))
        guard data.count == 4 + length + 64 else { throw I2PWireError.invalidFormat }
        let dataBytes = data.subdata(in: 4..<(4 + length))
        let signature = data.subdata(in: (4 + length)..<(4 + length + 64))

        var b = I2PReader(dataBytes)
        let destination = try I2PKeysAndCert.parse(&b)
        let publishedSeconds = try b.integer()
        let expiresOffset = try b.integer()
        let flags = try b.short()
        var offlineSignature: I2PLeaseSet2OfflineSignature?
        if flags & 0x0001 != 0 {
            let sigTypeRaw = try b.short()
            guard let sigType = I2PSigType(rawValue: sigTypeRaw) else {
                throw I2PWireError.unsupportedAlgorithm
            }
            let transientExpiration = try b.integer()
            let transientKey = try b.raw(sigType.publicKeyLength)
            let blockSignature = try b.raw(64)
            offlineSignature = I2PLeaseSet2OfflineSignature(
                sigType: sigType,
                transientExpiration: Date(timeIntervalSince1970: TimeInterval(transientExpiration)),
                transientPublicKey: transientKey,
                signature: blockSignature)
        }
        var leases: [I2PLease2] = []
        var encryptedBody = Data()
        var metaEntries: [I2PMetaLeaseSet2Entry] = []
        switch storeType {
        case .plain:
            let count = Int(try b.short())
            guard count >= 1 else { throw I2PWireError.invalidFormat }
            for _ in 0..<count {
                let gateway = try b.hash()
                let tunnelId = try b.integer()
                let expiration = try b.date() ?? Date(timeIntervalSince1970: 0)
                let cost = try b.short()
                leases.append(I2PLease2(gatewayHash: gateway, tunnelId: tunnelId,
                                        expiration: expiration, cost: cost))
            }
        case .encrypted:
            let bodyLength = Int(try b.short())
            encryptedBody = try b.raw(bodyLength)
        case .meta:
            let count = Int(try b.short())
            for _ in 0..<count {
                let entryFlags = try b.byte()
                let entryTypeRaw = try b.short()
                guard let entryType = I2PLeaseSet2Type(rawValue: entryTypeRaw) else {
                    throw I2PWireError.unsupportedAlgorithm
                }
                let entryLength = Int(try b.short())
                let entryBody = try b.raw(entryLength)
                // Re-frame the inner LS2's full payload (type + length + body)
                // so it parses by the same rules it was written with.
                var innerPayload = I2PWriter()
                innerPayload.short(entryType.rawValue)
                innerPayload.short(UInt16(entryBody.count))
                innerPayload.raw(entryBody)
                let inner = try I2PLeaseSet2.parse(innerPayload.data)
                metaEntries.append(I2PMetaLeaseSet2Entry(flags: entryFlags, inner: inner))
            }
        }
        guard b.remaining == 0 else { throw I2PWireError.trailingData }

        let leaseSet2 = I2PLeaseSet2(
            storeType: storeType,
            destination: destination,
            published: Date(timeIntervalSince1970: TimeInterval(publishedSeconds)),
            expiresOffsetSeconds: expiresOffset,
            flags: flags,
            offlineSignature: offlineSignature,
            leases: leases,
            encryptedBody: encryptedBody,
            metaEntries: metaEntries,
            signature: signature,
            raw: data)
        // Fail closed: the delegation block and the body signature must verify.
        guard leaseSet2.verifyTransientBlockSignature() else { throw I2PWireError.invalidSignature }
        guard leaseSet2.verifySignature() else { throw I2PWireError.invalidSignature }
        return leaseSet2
    }

    /// Builds a signed LeaseSet2 (tests and publishers): assembles the
    /// structure with a zeroed signature, signs the serialized signed
    /// contents (type + length + data), and returns the complete payload.
    static func build(storeType: I2PLeaseSet2Type,
                      destination: I2PDestination,
                      published: Date,
                      expiresOffsetSeconds: UInt32,
                      flags: UInt16 = 0,
                      offlineSignature: I2PLeaseSet2OfflineSignature? = nil,
                      leases: [I2PLease2] = [],
                      encryptedBody: Data = Data(),
                      metaEntries: [I2PMetaLeaseSet2Entry] = [],
                      signingSeed: Data?) throws -> I2PLeaseSet2 {
        let base = I2PLeaseSet2(
            storeType: storeType,
            destination: destination,
            published: published,
            expiresOffsetSeconds: expiresOffsetSeconds,
            flags: flags,
            offlineSignature: offlineSignature,
            leases: leases,
            encryptedBody: encryptedBody,
            metaEntries: metaEntries,
            signature: Data(repeating: 0, count: 64),
            raw: Data())
        let unsigned = base.serialize()
        let signedContents = unsigned.prefix(unsigned.count - 64)
        let bodySignature = try I2PCrypto.ed25519Sign(Data(signedContents),
                                                      seed: signingSeed ?? I2PCrypto.generateEd25519Seed())
        var signed = base
        signed.signature = bodySignature
        signed.raw = Data(unsigned.prefix(unsigned.count - 64)) + bodySignature
        return signed
    }
}