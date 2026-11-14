//
//  I2PTunnelBuild.swift
//  Tunnel establishment wire format per the ECIES tunnel-creation spec:
//  218-byte ShortTunnelBuild records (16-byte hop hash prefix + 32-byte
//  ephemeral X25519 key + ChaCha20-Poly1305 over a 154-byte short request
//  record) and 218-byte short reply records, carried in ShortTunnelBuild
//  (I2NP type 25) and OutboundTunnelBuildReply (type 26) envelopes.
//
//  The per-hop key agreement is the spec's Noise_N_25519_ChaChaPoly_SHA256
//  handshake: h = SHA256(protocol name padded to 32), h = SHA256(h || hepk),
//  h = SHA256(h || hepk_ephemeral), a token-bucket-free HKDF over the X25519
//  secret with the handshake hash as salt, and the request sealed with n = 0
//  and ad = h. Reply keys come from the chain key with the spec's info strings
//  ("SMTunnelReplyKey", "SMTunnelLayerKey", "TunnelLayerIVKey" for the OBEP).
//

import Foundation
import CryptoKit

/// ShortTunnelBuild return codes (I2P spec: 0 = accepted; 30 = reject bandwidth).
enum I2PTunnelBuildReturnCode: UInt8 {
    case accepted = 0
    case bandwidthExceeded = 30
    case tunnelIDInUse = 1
    case overload = 2
    case loop = 3
}

/// One hop's ShortBuildRequestRecord in plaintext form (154 bytes on the wire
/// before the per-hop ECIES box).
struct I2PTunnelBuildRequestRecord {
    // Wire fields (big-endian), per the ECIES tunnel-creation spec.
    let receiveTunnelID: UInt32
    let nextTunnelID: UInt32
    let nextHopHash: Data
    let flags: UInt8
    let layerEncryptionType: UInt8
    let requestTimeMinutes: UInt32
    let requestExpirationSeconds: UInt32
    let nextMessageID: UInt32
    let options: [String: String]
    let padding: Data

    // Local bookkeeping (never on the wire): the forwarding decision the
    // creator made for this hop. It rides the spec's Mapping options so the
    // hop can make the same decision without out-of-band state.
    let hopNumber: UInt8
    let isMessagePathEnd: Bool
    let hasMoreRecords: Bool
    let nextHopIsOriginator: Bool
    /// Router that receives the decrypted inner TunnelGateway payload at the
    /// message path's end. It cannot ride the record's next-hop fields: the
    /// spec gives those to the build reply's address for an outbound endpoint
    /// (flags bit 6) and routes the payload by its own delivery instructions.
    /// An unknown Mapping option is ignored by every peer that does not read it.
    let payloadDeliveryHash: Data?

    static let plaintextLength = 154
    static let wireLength = 218

    static let flagInboundGateway: UInt8 = 0x80
    static let flagOutboundEndpoint: UInt8 = 0x40

    /// Build option carrying `payloadDeliveryHash` as lowercase hex.
    static let payloadDeliveryOption = "d"

    init(hopNumber: UInt8 = 0,
         receiveTunnelID: UInt32,
         nextHopHash: Data,
         nextTunnelID: UInt32,
         layerKey: Data = Data(),
         ivKey: Data = Data(),
         replyKey: Data = Data(),
         replyIV: Data = Data(),
         isMessagePathEnd: Bool = false,
         nextHopIsOriginator: Bool = false,
         hasMoreRecords: Bool = false,
         flags: UInt8 = 0,
         layerEncryptionType: UInt8 = 0,
         requestTimeMinutes: UInt32 = UInt32(Date().timeIntervalSince1970 / 60),
         requestExpirationSeconds: UInt32 = 600,
         nextMessageID: UInt32 = 0,
         options: [String: String] = [:],
         padding: Data = Data(),
         payloadDeliveryHash: Data? = nil) {
        self.hopNumber = hopNumber
        self.receiveTunnelID = receiveTunnelID
        self.nextHopHash = nextHopHash
        self.nextTunnelID = nextTunnelID
        self.flags = flags & 0xF0
        self.layerEncryptionType = layerEncryptionType
        self.requestTimeMinutes = requestTimeMinutes
        self.requestExpirationSeconds = requestExpirationSeconds
        self.nextMessageID = nextMessageID
        self.payloadDeliveryHash = payloadDeliveryHash
        var options = options
        if isMessagePathEnd { options["end"] = "1" }
        if let payloadDeliveryHash { options[Self.payloadDeliveryOption] = payloadDeliveryHash.hex }
        self.options = options
        self.isMessagePathEnd = isMessagePathEnd
        self.nextHopIsOriginator = nextHopIsOriginator
        self.hasMoreRecords = hasMoreRecords
        // Random padding is drawn once, at construction: serialize() must
        // produce the same bytes every time (round trips and signatures depend
        // on it), while each record still carries fresh random filler.
        var filler = padding
        if filler.isEmpty {
            var mappingWriter = I2PWriter()
            mappingWriter.mapping(options)
            let used = 4 + 4 + 32 + 1 + 2 + 1 + 4 + 4 + 4 + mappingWriter.data.count
            filler = I2PCrypto.randomBytes(max(0, Self.plaintextLength - used))
        }
        self.padding = filler
    }

    func serialize() -> Data {
        var writer = I2PWriter()
        writer.integer(receiveTunnelID)
        writer.integer(nextTunnelID)
        writer.raw(Self.fixed(nextHopHash, 32))
        writer.byte(flags & 0xF0) // bits 5-0 must be zero
        writer.byte(0)
        writer.byte(0)
        writer.byte(layerEncryptionType)
        writer.integer(requestTimeMinutes)
        writer.integer(requestExpirationSeconds)
        writer.integer(nextMessageID)
        writer.mapping(options)
        var out = writer.data
        guard out.count <= Self.plaintextLength else {
            return Data(out.prefix(Self.plaintextLength))
        }
        var filler = padding
        if filler.count > Self.plaintextLength - out.count {
            filler = Data(filler.prefix(Self.plaintextLength - out.count))
        }
        out.append(filler)
        while out.count < Self.plaintextLength {
            out.append(contentsOf: I2PCrypto.randomBytes(Self.plaintextLength - out.count))
        }
        return out
    }

    static func parse(_ data: Data) throws -> I2PTunnelBuildRequestRecord {
        guard data.count == plaintextLength else { throw I2PWireError.invalidFormat }
        var reader = I2PReader(data)
        let receiveID = try reader.integer()
        let nextID = try reader.integer()
        let nextHash = try reader.raw(32)
        let flags = try reader.byte()
        let reservedA = try reader.byte()
        let reservedB = try reader.byte()
        let layerType = try reader.byte()
        let requestTime = try reader.integer()
        let expiration = try reader.integer()
        let nextMessageID = try reader.integer()
        let options = try reader.mapping()
        let padding = try reader.raw(reader.remaining)
        guard reader.remaining == 0 else { throw I2PWireError.trailingData }
        guard reservedA == 0, reservedB == 0 else { throw I2PWireError.invalidFormat }
        guard flags & 0x3F == 0 else { throw I2PWireError.invalidFormat }
        guard layerType == 0 else { throw I2PWireError.unsupportedAlgorithm }
        let isEnd = options["end"] == "1"
        let delivery = options[Self.payloadDeliveryOption].flatMap { Self.hexBytes($0) }
        return I2PTunnelBuildRequestRecord(
            receiveTunnelID: receiveID,
            nextHopHash: nextHash,
            nextTunnelID: nextID,
            isMessagePathEnd: isEnd,
            flags: flags,
            layerEncryptionType: layerType,
            requestTimeMinutes: requestTime,
            requestExpirationSeconds: expiration,
            nextMessageID: nextMessageID,
            options: options.filter { $0.key != "end" && $0.key != Self.payloadDeliveryOption },
            padding: padding,
            payloadDeliveryHash: delivery
        )
    }

    /// Lowercase-hex option value → bytes (the Mapping carries text only).
    private static func hexBytes(_ string: String) -> Data? {
        let chars = Array(string.utf8)
        guard chars.count % 2 == 0 else { return nil }
        var out = Data()
        out.reserveCapacity(chars.count / 2)
        var index = 0
        while index < chars.count {
            guard let high = nibble(chars[index]), let low = nibble(chars[index + 1]) else { return nil }
            out.append(high << 4 | low)
            index += 2
        }
        return out
    }

    private static func nibble(_ character: UInt8) -> UInt8? {
        switch character {
        case 0x30...0x39: return character - 0x30  // 0-9
        case 0x61...0x66: return character - 0x57  // a-f
        case 0x41...0x46: return character - 0x37  // A-F
        default: return nil
        }
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

/// The per-hop reply/layer material derived from the build request's Noise
/// chain key: the keys both sides use for the tunnel layers and the build reply.
struct I2PTunnelBuildReplyMaterial {
    /// Noise handshake hash after the request ciphertext.
    let h: Data
    let replyKey: Data
    let layerKey: Data
    let ivKey: Data
    let isOutboundEndpoint: Bool
}

/// Per-hop record and reply encryption per the ECIES tunnel-creation spec.
enum I2PTunnelBuildCrypto {
    static let protocolName = Data("Noise_N_25519_ChaChaPoly_SHA256".utf8)
    static let zeroNonce = Data(repeating: 0, count: 12)
    static let replyPlaintextLength = 202

    /// h = protocol name padded to 32, ck = h, h = SHA256(h) || SHA256(h || hepk).
    private static func initialHash(hopStaticKey: Data) -> (h: Data, ck: Data) {
        var padded = protocolName
        if padded.count < 32 { padded.append(0) }
        let ck = padded
        var h = I2PCrypto.sha256(padded)
        h = I2PCrypto.sha256(h + hopStaticKey)
        return (h, ck)
    }

    /// One record's reply/layer key schedule from the Noise chain key.
    private static func replyMaterial(chainKey: Data,
                                      h: Data,
                                      isOutboundEndpoint: Bool) -> I2PTunnelBuildReplyMaterial {
        var ck = chainKey
        var keydata = I2PCrypto.hkdfSHA256(inputKeyMaterial: Data(), salt: ck,
                                           info: Data("SMTunnelReplyKey".utf8), outputLength: 64)
        let replyKey = Data(keydata.suffix(32))
        ck = Data(keydata.prefix(32))

        keydata = I2PCrypto.hkdfSHA256(inputKeyMaterial: Data(), salt: ck,
                                       info: Data("SMTunnelLayerKey".utf8), outputLength: 64)
        let layerKey = Data(keydata.suffix(32))
        var ivKey: Data
        if isOutboundEndpoint {
            ck = Data(keydata.prefix(32))
            keydata = I2PCrypto.hkdfSHA256(inputKeyMaterial: Data(), salt: ck,
                                           info: Data("TunnelLayerIVKey".utf8), outputLength: 64)
            ivKey = Data(keydata.suffix(32))
        } else {
            // Non-OBEP hops reuse the layer-key block's left half, per the spec.
            ivKey = Data(keydata.prefix(32))
        }
        return I2PTunnelBuildReplyMaterial(
            h: h,
            replyKey: replyKey,
            layerKey: layerKey,
            ivKey: ivKey,
            isOutboundEndpoint: isOutboundEndpoint
        )
    }

    /// Seals one 154-byte short request record to a hop, returning the 218-byte
    /// wire record and the reply/layer material the creator keeps for it.
    static func encryptRecordWithMaterial(_ plaintext: Data,
                                          to hopEncryptionKey: Data,
                                          hopHash: Data?,
                                          recordIndex: UInt8) throws -> (wire: Data, material: I2PTunnelBuildReplyMaterial) {
        guard plaintext.count == I2PTunnelBuildRequestRecord.plaintextLength else {
            throw I2PWireError.invalidFormat
        }
        let peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: hopEncryptionKey)
        var (h, ck) = initialHash(hopStaticKey: hopEncryptionKey)
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let sepk = ephemeral.publicKey.rawRepresentation
        h = I2PCrypto.sha256(h + sepk)
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: peer)
        let ikm = shared.withUnsafeBytes { Data($0) }
        let keydata = I2PCrypto.hkdfSHA256(inputKeyMaterial: ikm, salt: ck,
                                           info: Data(), outputLength: 64)
        ck = Data(keydata.prefix(32))
        let k = Data(keydata.suffix(32))
        let ciphertext = try I2PCrypto.chacha20Poly1305Seal(
            key: k, nonce: zeroNonce, plaintext: plaintext, aad: h
        )
        h = I2PCrypto.sha256(h + ciphertext)
        let isOBEP = plaintext.count > 40 && (plaintext[plaintext.startIndex + 40] & 0x40) != 0
        let material = replyMaterial(chainKey: ck, h: h, isOutboundEndpoint: isOBEP)
        let prefix = hopHash.map { Data($0.prefix(16)) }
            ?? Data(I2PCrypto.sha256(hopEncryptionKey).prefix(16))
        return (prefix + sepk + ciphertext, material)
    }

    /// Compatibility wrapper: the creator's side of one record.
    static func encryptRecord(_ plaintext: Data,
                              to peerEncryptionKey: Data,
                              recordIndex: UInt8) throws -> Data {
        try encryptRecordWithMaterial(plaintext, to: peerEncryptionKey,
                                      hopHash: nil, recordIndex: recordIndex).wire
    }

    /// Opens one 218-byte short record addressed to this hop and returns the
    /// plaintext plus the reply/layer material the hop derives from it.
    static func decryptRecordWithMaterial(_ wire: Data,
                                          localEncryptionKey: Curve25519.KeyAgreement.PrivateKey,
                                          localRouterHash: Data? = nil,
                                          recordIndex: UInt8) throws -> (plaintext: Data, material: I2PTunnelBuildReplyMaterial) {
        guard wire.count == I2PTunnelBuildRequestRecord.wireLength else {
            throw I2PWireError.invalidFormat
        }
        let bytes = Array(wire)
        if let localRouterHash {
            let expected = Array(localRouterHash.prefix(16))
            guard Array(bytes[0..<16]) == expected else { throw I2PWireError.invalidFormat }
        }
        let sepk = Data(bytes[16..<48])
        let ciphertext = Data(bytes[48..<218])
        let ephemeral = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: sepk)
        var (h, ck) = initialHash(hopStaticKey: localEncryptionKey.publicKey.rawRepresentation)
        h = I2PCrypto.sha256(h + sepk)
        let shared = try localEncryptionKey.sharedSecretFromKeyAgreement(with: ephemeral)
        let ikm = shared.withUnsafeBytes { Data($0) }
        let keydata = I2PCrypto.hkdfSHA256(inputKeyMaterial: ikm, salt: ck,
                                           info: Data(), outputLength: 64)
        ck = Data(keydata.prefix(32))
        let k = Data(keydata.suffix(32))
        let plaintext = try I2PCrypto.chacha20Poly1305Open(
            key: k, nonce: zeroNonce, ciphertextAndTag: ciphertext, aad: h
        )
        guard plaintext.count == I2PTunnelBuildRequestRecord.plaintextLength else {
            throw I2PWireError.invalidFormat
        }
        h = I2PCrypto.sha256(h + ciphertext)
        let isOBEP = plaintext.count > 40 && (plaintext[plaintext.startIndex + 40] & 0x40) != 0
        let material = replyMaterial(chainKey: ck, h: h, isOutboundEndpoint: isOBEP)
        return (plaintext, material)
    }

    /// Compatibility wrapper: the hop's side of one record.
    static func decryptRecord(_ wire: Data,
                              localEncryptionKey: Curve25519.KeyAgreement.PrivateKey,
                              recordIndex: UInt8) throws -> Data {
        try decryptRecordWithMaterial(wire, localEncryptionKey: localEncryptionKey,
                                      recordIndex: recordIndex).plaintext
    }

    // MARK: Build replies

    /// A 202-byte short reply record: Mapping options, random padding, the reply
    /// byte last.
    static func replyPlaintext(returnCode: UInt8, options: [String: String] = [:]) -> Data {
        var writer = I2PWriter()
        writer.mapping(options)
        var body = writer.data
        guard body.count <= 201 else {
            return Data([0, 0] + [UInt8](repeating: 0, count: 199) + [returnCode])
        }
        body.append(contentsOf: I2PCrypto.randomBytes(201 - body.count))
        body.append(returnCode)
        return body
    }

    /// The 12-byte nonce for a reply record: the record's position in the message.
    static func replyNonce(recordIndex: UInt8) -> Data {
        var nonce = Data(repeating: 0, count: 12)
        nonce[4] = recordIndex
        return nonce
    }

    /// Seals this hop's own reply record (Poly1305) at its index.
    static func encryptReplyRecord(_ record: I2PTunnelBuildReplyRecord,
                                   material: I2PTunnelBuildReplyMaterial,
                                   recordIndex: UInt8) throws -> Data {
        try I2PCrypto.chacha20Poly1305Seal(
            key: material.replyKey,
            nonce: replyNonce(recordIndex: recordIndex),
            plaintext: replyPlaintext(returnCode: record.returnCode),
            aad: material.h
        )
    }

    /// Re-encrypts another hop's reply record symmetrically with plain ChaCha20
    /// (no Poly1305), per the spec.
    static func reencryptReplyRecord(_ wire: Data,
                                     material: I2PTunnelBuildReplyMaterial,
                                     recordIndex: UInt8) -> Data {
        guard wire.count == I2PTunnelBuildReplyRecord.wireLength,
              let output = I2PChaCha20.apply(key: material.replyKey,
                                             nonce: replyNonce(recordIndex: recordIndex),
                                             data: wire) else {
            return wire
        }
        return output
    }

    /// Opens this hop's own reply record.
    static func decryptReplyRecord(_ wire: Data,
                                   material: I2PTunnelBuildReplyMaterial,
                                   recordIndex: UInt8) throws -> I2PTunnelBuildReplyRecord {
        let plaintext = try I2PCrypto.chacha20Poly1305Open(
            key: material.replyKey,
            nonce: replyNonce(recordIndex: recordIndex),
            ciphertextAndTag: wire,
            aad: material.h
        )
        guard plaintext.count == replyPlaintextLength else { throw I2PWireError.invalidFormat }
        let code = Array(plaintext)[201]
        return I2PTunnelBuildReplyRecord(receiveTunnelID: 0, returnCode: code)
    }
}

/// One decrypted build reply record.
struct I2PTunnelBuildReplyRecord {
    let receiveTunnelID: UInt32
    let returnCode: UInt8

    static let wireLength = I2PTunnelBuildRequestRecord.wireLength
}

/// ShortTunnelBuild (I2NP type 25): record count plus 218-byte short records.
/// The message ID rides the I2NP header, not the body.
struct I2PTunnelBuildMessage {
    let messageID: UInt32
    let records: [Data]

    static let recordWireLength = I2PTunnelBuildRequestRecord.wireLength

    init(messageID: UInt32 = 0, records: [Data]) {
        self.messageID = messageID
        self.records = records
    }

    func serialize() -> Data {
        var writer = I2PWriter()
        writer.byte(UInt8(min(records.count, 255)))
        records.forEach { writer.raw($0) }
        return writer.data
    }

    static func parse(_ data: Data) throws -> I2PTunnelBuildMessage {
        var reader = I2PReader(data)
        let count = Int(try reader.byte())
        guard count >= 1 && count <= 8 else { throw I2PWireError.invalidFormat }
        var records: [Data] = []
        for _ in 0..<count {
            records.append(try reader.raw(recordWireLength))
        }
        guard reader.remaining == 0 else { throw I2PWireError.trailingData }
        return I2PTunnelBuildMessage(records: records)
    }
}

/// OutboundTunnelBuildReply (I2NP type 26): every hop re-encrypts the other
/// records with plain ChaCha20 and replaces its own with its Poly1305 reply.
struct I2PTunnelBuildReply {
    let messageID: UInt32
    let encryptedRecords: [Data]

    static let encryptedRecordLength = I2PTunnelBuildRequestRecord.wireLength

    init(messageID: UInt32 = 0, encryptedRecords: [Data]) {
        self.messageID = messageID
        self.encryptedRecords = encryptedRecords
    }

    func serialize() -> Data {
        var writer = I2PWriter()
        writer.byte(UInt8(min(encryptedRecords.count, 255)))
        encryptedRecords.forEach { writer.raw($0) }
        return writer.data
    }

    static func parse(_ data: Data) throws -> I2PTunnelBuildReply {
        var reader = I2PReader(data)
        let count = Int(try reader.byte())
        guard count >= 1 && count <= 8 else { throw I2PWireError.invalidFormat }
        var records: [Data] = []
        for _ in 0..<count {
            records.append(try reader.raw(encryptedRecordLength))
        }
        guard reader.remaining == 0 else { throw I2PWireError.trailingData }
        return I2PTunnelBuildReply(encryptedRecords: records)
    }
}

// MARK: - ChaCha20 (plain stream cipher for reply re-encryption)

/// The RFC 8439 ChaCha20 block function and XOR stream, needed because the
/// short build reply re-encrypts other hops' records without Poly1305.
enum I2PChaCha20 {
    static func apply(key: Data, nonce: Data, data: Data) -> Data? {
        guard key.count == 32, nonce.count == 12 else { return nil }
        let keyWords = words(key)
        let nonceWords = words(nonce)
        var output = [UInt8]()
        output.reserveCapacity(data.count)
        var counter: UInt32 = 0
        var offset = 0
        let input = Array(data)
        while offset < input.count {
            let block = block(keyWords: keyWords, counter: counter, nonceWords: nonceWords)
            for word in block {
                for byteIndex in 0..<4 {
                    let stream = UInt8((word >> (8 * UInt32(byteIndex))) & 0xff)
                    if offset < input.count {
                        output.append(input[offset] ^ stream)
                        offset += 1
                    }
                }
            }
            counter &+= 1
        }
        return Data(output)
    }

    private static func words(_ data: Data) -> [UInt32] {
        var result: [UInt32] = []
        let bytes = Array(data)
        for index in stride(from: 0, to: bytes.count, by: 4) {
            result.append(UInt32(bytes[index])
                          | (UInt32(bytes[index + 1]) << 8)
                          | (UInt32(bytes[index + 2]) << 16)
                          | (UInt32(bytes[index + 3]) << 24))
        }
        return result
    }

    private static func rotate(_ value: UInt32, _ count: UInt32) -> UInt32 {
        (value << count) | (value >> (32 - count))
    }

    private static func block(keyWords: [UInt32], counter: UInt32, nonceWords: [UInt32]) -> [UInt32] {
        let state: [UInt32] = [
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
            keyWords[0], keyWords[1], keyWords[2], keyWords[3],
            keyWords[4], keyWords[5], keyWords[6], keyWords[7],
            counter, nonceWords[0], nonceWords[1], nonceWords[2]
        ]
        var working = state
        func quarter(_ a: Int, _ b: Int, _ c: Int, _ d: Int) {
            working[a] = working[a] &+ working[b]
            working[d] = rotate(working[d] ^ working[a], 16)
            working[c] = working[c] &+ working[d]
            working[b] = rotate(working[b] ^ working[c], 12)
            working[a] = working[a] &+ working[b]
            working[d] = rotate(working[d] ^ working[a], 8)
            working[c] = working[c] &+ working[d]
            working[b] = rotate(working[b] ^ working[c], 7)
        }
        for _ in 0..<10 {
            quarter(0, 4, 8, 12)
            quarter(1, 5, 9, 13)
            quarter(2, 6, 10, 14)
            quarter(3, 7, 11, 15)
            quarter(0, 5, 10, 15)
            quarter(1, 6, 11, 12)
            quarter(2, 7, 8, 13)
            quarter(3, 4, 9, 14)
        }
        for index in 0..<16 {
            working[index] = working[index] &+ state[index]
        }
        return working
    }
}
