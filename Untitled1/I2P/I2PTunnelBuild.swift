//
//  I2PTunnelBuild.swift
//  Tunnel establishment wire format: 528-byte VariableTunnelBuild request
//  records (I2NP type 21) and VariableTunnelBuildReply records (I2NP type 22),
//  layered so only the addressed hop can decrypt its record.
//
//  Spec notes: this router implements the modern cipher suite (EncType 4/5)
//  under the modern-only crypto policy: each record is ECIES-X25519 — an
//  ephemeral X25519 key agreement with the hop's encryption key, HKDF-SHA256
//  key derivation, and a ChaCha20-Poly1305 AEAD box. Reply records use the
//  per-hop reply key and reply IV carried in the request record. Tunnel data
//  layer encryption follows the tunnel spec (see I2PTunnelLayerCipher).
//

import Foundation
import CryptoKit

/// VariableTunnelBuild return codes (I2P spec: 0 = accepted, <30 transient
/// rejects, >=30 permanent rejects).
enum I2PTunnelBuildReturnCode: UInt8 {
    case accepted = 0
    case bandwidthExceeded = 1
    case tunnelIDInUse = 2
    case overload = 3
    case loop = 4
}

/// One hop's build request record in plaintext form (528 bytes on the wire
/// before the per-hop ECIES layer).
struct I2PTunnelBuildRequestRecord {
    let hopNumber: UInt8
    /// Tunnel ID this hop receives messages on.
    let receiveTunnelID: UInt32
    /// Next router in the message path (zeros = none, message-path end).
    let nextHopHash: Data
    /// The next hop's receive tunnel ID (0 = none).
    let nextTunnelID: UInt32
    /// Key for encrypting tunnel messages at this hop.
    let layerKey: Data
    /// Key for deriving per-message IVs/nonces at this hop.
    let ivKey: Data
    /// Key encrypting this hop's build reply record.
    let replyKey: Data
    /// IV for the reply encryption.
    let replyIV: Data
    /// Flag bit 0: this hop ends the build message path.
    let isMessagePathEnd: Bool
    /// Flag bit 1: the next hop is the tunnel creator (inbound gateway hop).
    let nextHopIsOriginator: Bool
    /// Flag: more records follow in the message path.
    let hasMoreRecords: Bool
    let padding: Data

    static let plaintextLength = 528
    static let headerLength = 156
    /// Wire record: 32-byte ephemeral X25519 key + AEAD(528) + 16-byte tag.
    static let wireLength = 32 + 528 + 16

    var flags: UInt8 {
        (isMessagePathEnd ? 0x01 : 0) | (nextHopIsOriginator ? 0x02 : 0)
    }

    func serialize() -> Data {
        var writer = I2PWriter()
        writer.byte(hopNumber)
        writer.integer(receiveTunnelID)
        writer.raw(Self.fixed(nextHopHash, 32))
        writer.integer(nextTunnelID)
        writer.raw(Self.fixed(layerKey, 32))
        writer.raw(Self.fixed(ivKey, 32))
        writer.raw(Self.fixed(replyKey, 32))
        writer.raw(Self.fixed(replyIV, 16))
        writer.byte(flags)
        writer.byte(hasMoreRecords ? 1 : 0)
        writer.byte(0) // reserved
        writer.raw(Self.fixed(padding, Self.plaintextLength - Self.headerLength))
        return writer.data
    }

    static func parse(_ data: Data) throws -> I2PTunnelBuildRequestRecord {
        guard data.count == plaintextLength else { throw I2PWireError.invalidFormat }
        var reader = I2PReader(data)
        let hop = try reader.byte()
        let receiveID = try reader.integer()
        let nextHash = try reader.raw(32)
        let nextID = try reader.integer()
        let layer = try reader.raw(32)
        let iv = try reader.raw(32)
        let replyKey = try reader.raw(32)
        let replyIV = try reader.raw(16)
        let flags = try reader.byte()
        let more = try reader.byte()
        let reserved = try reader.byte()
        let padding = try reader.raw(plaintextLength - headerLength)
        guard reader.remaining == 0 else { throw I2PWireError.trailingData }
        guard reserved == 0 else { throw I2PWireError.invalidFormat }
        return I2PTunnelBuildRequestRecord(
            hopNumber: hop,
            receiveTunnelID: receiveID,
            nextHopHash: nextHash,
            nextTunnelID: nextID,
            layerKey: layer,
            ivKey: iv,
            replyKey: replyKey,
            replyIV: replyIV,
            isMessagePathEnd: flags & 0x01 != 0,
            nextHopIsOriginator: flags & 0x02 != 0,
            hasMoreRecords: more == 1,
            padding: padding
        )
    }

    private static func fixed(_ data: Data, _ length: Int) -> Data {
        var out = data
        if out.count > length { out = Data(out.prefix(length)) }
        while out.count < length { out.append(0) }
        return out
    }
}
enum I2PTunnelBuildError: Error {
    case rejected(code: UInt8)
    case timeout
    case invalidConfiguration
}

/// Per-hop record/reply encryption.
enum I2PTunnelBuildCrypto {
    /// ECIES record key: HKDF-SHA256 over the ephemeral DH, salted with the
    /// ephemeral public key.
    static func recordKey(sharedIKM: Data, ephemeralPublicKey: Data) -> Data {
        I2PCrypto.hkdfSHA256(
            inputKeyMaterial: sharedIKM,
            salt: ephemeralPublicKey,
            info: Data("i2p-tunnel-build-record".utf8),
            outputLength: 32
        )
    }

    private static func recordNonce() -> ChaChaPoly.Nonce {
        (try? ChaChaPoly.Nonce(data: Data(repeating: 0, count: 12)))!
    }

    /// Encrypts a 528-byte plaintext record to a hop: ephemeral key (32) +
    /// ChaChaPoly(528 + 16). The record index is bound as associated data.
    static func encryptRecord(_ plaintext: Data, to peerEncryptionKey: Data, recordIndex: UInt8) throws -> Data {
        guard plaintext.count == I2PTunnelBuildRequestRecord.plaintextLength else {
            throw I2PWireError.invalidFormat
        }
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerEncryptionKey)
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: peer)
        let ikm = shared.withUnsafeBytes { Data($0) }
        let key = recordKey(sharedIKM: ikm, ephemeralPublicKey: ephemeral.publicKey.rawRepresentation)
        let box = try ChaChaPoly.seal(
            plaintext,
            using: SymmetricKey(data: key),
            nonce: recordNonce(),
            authenticating: Data([recordIndex])
        )
        return ephemeral.publicKey.rawRepresentation + box.combined
    }

    /// A hop decrypts its record by trying its own encryption key.
    static func decryptRecord(_ wire: Data, localEncryptionKey: Curve25519.KeyAgreement.PrivateKey, recordIndex: UInt8) throws -> Data {
        guard wire.count == I2PTunnelBuildRequestRecord.wireLength else { throw I2PWireError.invalidFormat }
        let ephemeral = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: wire.subdata(in: 0..<32))
        let shared = try localEncryptionKey.sharedSecretFromKeyAgreement(with: ephemeral)
        let ikm = shared.withUnsafeBytes { Data($0) }
        let key = recordKey(sharedIKM: ikm, ephemeralPublicKey: ephemeral.rawRepresentation)
        let box = try ChaChaPoly.SealedBox(combined: wire.subdata(in: 32..<wire.count))
        return try ChaChaPoly.open(box, using: SymmetricKey(data: key), authenticating: Data([recordIndex]))
    }

    /// Encrypts one hop's reply record ([tunnel ID][code]) with that hop's
    /// reply key; the reply IV provides the nonce and the message ID the AAD.
    static func encryptReplyRecord(_ record: I2PTunnelBuildReplyRecord, replyKey: Data, replyIV: Data, messageID: UInt32) throws -> Data {
        var plaintext = I2PWriter()
        plaintext.integer(record.receiveTunnelID)
        plaintext.byte(record.returnCode)
        let box = try ChaChaPoly.seal(
            plaintext.data,
            using: SymmetricKey(data: replyKey),
            nonce: ChaChaPoly.Nonce(data: Data(replyIV.prefix(12))),
            authenticating: Self.messageIDData(messageID)
        )
        return box.combined
    }

    static func decryptReplyRecord(_ wire: Data, replyKey: Data, replyIV: Data, messageID: UInt32) throws -> I2PTunnelBuildReplyRecord {
        guard wire.count == 21 else { throw I2PWireError.invalidFormat }
        let box = try ChaChaPoly.SealedBox(combined: wire)
        let plaintext = try ChaChaPoly.open(box, using: SymmetricKey(data: replyKey), authenticating: Self.messageIDData(messageID))
        var reader = I2PReader(plaintext)
        let tunnelID = try reader.integer()
        let code = try reader.byte()
        return I2PTunnelBuildReplyRecord(receiveTunnelID: tunnelID, returnCode: code)
    }

    static func messageIDData(_ messageID: UInt32) -> Data {
        var writer = I2PWriter()
        writer.integer(messageID)
        return writer.data
    }
}

/// VariableTunnelBuildMessage (I2NP type 21): clear message ID plus all
/// per-hop encrypted records; delivered hop by hop through the message path.
struct I2PTunnelBuildMessage {
    let messageID: UInt32
    let records: [Data]

    static let recordWireLength = I2PTunnelBuildRequestRecord.wireLength

    func serialize() -> Data {
        var writer = I2PWriter()
        writer.integer(messageID)
        writer.byte(UInt8(records.count))
        records.forEach { writer.raw($0) }
        return writer.data
    }

    static func parse(_ data: Data) throws -> I2PTunnelBuildMessage {
        var reader = I2PReader(data)
        let id = try reader.integer()
        let count = Int(try reader.byte())
        guard count >= 1 && count <= 8 else { throw I2PWireError.invalidFormat }
        var records: [Data] = []
        for _ in 0..<count {
            records.append(try reader.raw(recordWireLength))
        }
        guard reader.remaining == 0 else { throw I2PWireError.trailingData }
        return I2PTunnelBuildMessage(messageID: id, records: records)
    }
}

/// One decrypted build reply record.
struct I2PTunnelBuildReplyRecord {
    let receiveTunnelID: UInt32
    let returnCode: UInt8
}

/// VariableTunnelBuildReply (I2NP type 22): the reply travels back hop by
/// hop; every hop appends its own reply record, individually encrypted with
/// the reply key from its request record. The message ID stays in the clear.
struct I2PTunnelBuildReply {
    let messageID: UInt32
    /// 21-byte encrypted records (5-byte plaintext + 16-byte tag).
    let encryptedRecords: [Data]

    static let encryptedRecordLength = 21

    func serialize() -> Data {
        var writer = I2PWriter()
        writer.integer(messageID)
        writer.byte(UInt8(encryptedRecords.count))
        encryptedRecords.forEach { writer.raw($0) }
        return writer.data
    }

    static func parse(_ data: Data) throws -> I2PTunnelBuildReply {
        var reader = I2PReader(data)
        let id = try reader.integer()
        let count = Int(try reader.byte())
        guard count >= 1 && count <= 8 else { throw I2PWireError.invalidFormat }
        var records: [Data] = []
        for _ in 0..<count {
            records.append(try reader.raw(encryptedRecordLength))
        }
        guard reader.remaining == 0 else { throw I2PWireError.trailingData }
        return I2PTunnelBuildReply(messageID: id, encryptedRecords: records)
    }
}