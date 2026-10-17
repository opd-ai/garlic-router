//
//  I2PNTCP2Crypto.swift
//  I2P
//
//  NTCP2 cryptographic core: Noise_XK_25519_ChaChaPoly_SHA256 chaining state,
//  the spec's AES-256-CBC ephemeral-key obfuscation (proposal 111 KDF),
//  SipHash-2-4 length obfuscation with the spec data-phase KDF, and the
//  NTCP2 payload block codec.
//

import Foundation
import CryptoKit
import CommonCrypto

enum NTCP2Error: Error {
    case needMoreData
    case handshakeFailed(String)
    case decryptFailed
    case invalidFrame
    case invalidBlock
    case notEstablished
    case noSession(forHash: Data)
}

/// Noise_XK chaining state. `h` starts as HASH(protocol_name); the responder's
/// static key is folded in as the Noise pre-message. `MixKey` rekeys via HKDF and
/// resets the handshake AEAD nonce; `MixHash` folds wire material into `h`.
struct NTCP2NoiseChain {
    static let protocolName = "Noise_XK_25519_ChaChaPoly_SHA256"

    /// The ephemeral-key obfuscation KDF binds to this initial chaining key
    /// (the protocol name verbatim), not to any advanced handshake state, so
    /// both sides derive the obfuscation key and IV before any handshake
    /// processing.
    static var initialChainingKey: Data { NTCP2NoiseChain().chainingKey }

    private(set) var chainingKey: Data
    private(set) var hash: Data
    private(set) var key: Data?
    private(set) var nonce: UInt64 = 0

    init() {
        // Noise §5: protocol names of at most HASHLEN bytes are used verbatim
        // (zero-padded to HASHLEN) as both chaining key and hash; longer names
        // are SHA-256 hashed first. The NTCP2 protocol name is exactly 32
        // bytes, so it rides unhashed — matching every mainnet NTCP2 peer.
        let nameBytes = Data(Self.protocolName.utf8)
        if nameBytes.count <= 32 {
            var padded = nameBytes
            padded.append(contentsOf: [UInt8](repeating: 0, count: 32 - nameBytes.count))
            chainingKey = padded
            hash = padded
        } else {
            let nameHash = Data(SHA256.hash(data: nameBytes))
            chainingKey = nameHash
            hash = nameHash
        }
    }

    mutating func mixHash(_ data: Data) {
        hash = Data(SHA256.hash(data: hash + data))
    }

    mutating func mixKey(_ ikm: Data) {
        let derived = Self.hkdf(chainingKey, ikm, outputs: 2)
        chainingKey = derived[0]
        key = derived[1]
        nonce = 0
    }

    /// Noise EncryptWithAd: AEAD under the current key with `h` as associated
    /// data, then MixHash of the ciphertext. Nonce resets on every MixKey.
    mutating func encrypt(_ plaintext: Data) throws -> Data {
        guard let key else { throw NTCP2Error.handshakeFailed("EncryptWithAd without a key") }
        let box = try ChaChaPoly.seal(plaintext,
                                      using: SymmetricKey(data: key),
                                      nonce: Self.nonce96(nonce),
                                      authenticating: hash)
        nonce += 1
        let ciphertext = box.combined
        mixHash(ciphertext)
        return ciphertext
    }

    /// Noise DecryptWithAd.
    mutating func decrypt(_ ciphertext: Data) throws -> Data {
        guard let key else { throw NTCP2Error.handshakeFailed("DecryptWithAd without a key") }
        let box: ChaChaPoly.SealedBox
        do { box = try ChaChaPoly.SealedBox(combined: ciphertext) }
        catch { throw NTCP2Error.decryptFailed }
        guard let plaintext = try? ChaChaPoly.open(box, using: SymmetricKey(data: key), authenticating: hash) else {
            throw NTCP2Error.decryptFailed
        }
        nonce += 1
        mixHash(ciphertext)
        return plaintext
    }

    /// Noise Split(): temp_key = HMAC-SHA256(chaining_key, zerolen);
    /// k_ab = HMAC-SHA256(temp_key, chaining_key || byte(0x01));
    /// k_ba = HMAC-SHA256(temp_key, chaining_key || byte(0x02)).
    /// The SipHash length-obfuscation keys come from the NTCP2 spec's
    /// data-phase KDF (dataPhaseSipKey), not from the split output directly.
    func split() -> (ab: NTCP2DirectionKeys, ba: NTCP2DirectionKeys) {
        let temp = Self.hmac(Data(), key: chainingKey)
        let k_ab = Self.hmac(chainingKey + Data([0x01]), key: temp)
        let k_ba = Self.hmac(chainingKey + Data([0x02]), key: temp)
        return (NTCP2DirectionKeys(aeadKey: k_ab, sipKey: Self.dataPhaseSipKey(k_ab)),
                NTCP2DirectionKeys(aeadKey: k_ba, sipKey: Self.dataPhaseSipKey(k_ba)))
    }

    /// NTCP2 spec data-phase KDF for one direction's SipHash length-obfuscation key:
    /// temp_key = HMAC-SHA256(k_direction, zerolen);
    /// sipkey = first 16 bytes of HMAC-SHA256(temp_key, zerolen).
    static func dataPhaseSipKey(_ directionKey: Data) -> Data {
        Data(hmac(Data(), key: hmac(Data(), key: directionKey)).prefix(16))
    }

    private static func hmac(_ message: Data, key: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key)))
    }

    /// Noise HKDF: HMAC(chain, ikm), then chained HMAC(temp, previous || counter).
    static func hkdf(_ chainingKey: Data, _ ikm: Data, outputs: Int) -> [Data] {
        let temp = Data(HMAC<SHA256>.authenticationCode(for: ikm, using: SymmetricKey(data: chainingKey)))
        var out: [Data] = []
        var previous = Data()
        for index in 1...max(1, outputs) {
            let code = Data(HMAC<SHA256>.authenticationCode(for: previous + Data([UInt8(index)]),
                                                            using: SymmetricKey(data: temp)))
            out.append(code)
            previous = code
        }
        return out
    }

    /// Noise 96-bit nonce: 32 zero bits, then the 64-bit big-endian counter.
    static func nonce96(_ counter: UInt64) -> ChaChaPoly.Nonce {
        var bytes = [UInt8](repeating: 0, count: 12)
        var value = counter.bigEndian
        withUnsafeBytes(of: &value) { raw in
            for (index, byte) in raw.enumerated() { bytes[4 + index] = byte }
        }
        return (try? ChaChaPoly.Nonce(data: Data(bytes)))!
    }

    static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }
}

struct NTCP2DirectionKeys: Equatable {
    let aeadKey: Data
    let sipKey: Data
}

struct NTCP2SessionKeys {
    let sendKeys: NTCP2DirectionKeys
    let recvKeys: NTCP2DirectionKeys
}

/// NTCP2 spec ephemeral-key obfuscation (proposal 111): the 32-byte ephemeral
/// keys in messages 1 and 2 are AES-256-CBC-encrypted with a key and IV derived
/// by the spec KDF — temp_key = HMAC-SHA256(chaining_key, remote_material), then
/// the HKDF chain expansion of temp_key yields the 32-byte AES key and the
/// 16-byte IV. `remote_material` is the responder's static public key for
/// message 1 and the initiator's deobfuscated ephemeral key for message 2; both
/// bind to the initial chaining key (protocol name verbatim) so both sides can
/// derive them before any handshake state advances. Deterministic: the same
/// inputs always produce the same wire bytes.
enum NTCP2KeyObfuscation {
    static func keyAndIV(material: Data, chainingKey: Data) -> (key: Data, iv: Data) {
        let temp = hmac(material, key: chainingKey)
        let blocks = NTCP2NoiseChain.hkdf(temp, Data(), outputs: 2)
        return (blocks[0], Data(blocks[1].prefix(16)))
    }

    static func encrypt(_ key32: Data, chainingKey: Data, material: Data) throws -> Data {
        let (k, iv) = keyAndIV(material: material, chainingKey: chainingKey)
        return I2PAESCBC.encrypt(key32, key: k, iv: iv)
    }

    static func decrypt(_ key32: Data, chainingKey: Data, material: Data) throws -> Data {
        let (k, iv) = keyAndIV(material: material, chainingKey: chainingKey)
        return I2PAESCBC.decrypt(key32, key: k, iv: iv)
    }

    private static func hmac(_ message: Data, key: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key)))
    }
}

/// AES-256-CBC without padding (CommonCrypto), as required by the NTCP2 spec's
/// ephemeral-key obfuscation (block-aligned 32-byte input, 32-byte output).
enum I2PAESCBC {
    static func encrypt(_ data: Data, key: Data, iv: Data) -> Data {
        crypt(data, key: key, iv: iv, operation: CCOperation(kCCEncrypt))
    }

    static func decrypt(_ data: Data, key: Data, iv: Data) -> Data {
        crypt(data, key: key, iv: iv, operation: CCOperation(kCCDecrypt))
    }

    private static func crypt(_ data: Data, key: Data, iv: Data, operation: CCOperation) -> Data {
        precondition(key.count == Int(kCCKeySizeAES256), "AES-256 key required")
        precondition(iv.count == Int(kCCBlockSizeAES128), "16-byte IV required")
        precondition(data.count % Int(kCCBlockSizeAES128) == 0, "AES-CBC input must be block-aligned")
        var output = Data(repeating: 0, count: data.count)
        var moved = 0
        let status = output.withUnsafeMutableBytes { outputBuffer -> CCCryptorStatus in
            key.withUnsafeBytes { keyBuffer -> CCCryptorStatus in
                iv.withUnsafeBytes { ivBuffer -> CCCryptorStatus in
                    data.withUnsafeBytes { dataBuffer -> CCCryptorStatus in
                        CCCrypt(operation, CCAlgorithm(kCCAlgorithmAES), CCOptions(0),
                                keyBuffer.baseAddress, key.count,
                                ivBuffer.baseAddress,
                                dataBuffer.baseAddress, data.count,
                                outputBuffer.baseAddress, outputBuffer.count, &moved)
                    }
                }
            }
        }
        precondition(status == kCCSuccess, "AES-CBC failed with status \(status)")
        return output
    }
}

/// SipHash-2-4, used to obfuscate data-phase frame length fields.
enum SipHash24 {
    static func hash(key: Data, message: Data) -> UInt64 {
        precondition(key.count == 16)
        func le64(_ data: [UInt8], _ offset: Int) -> UInt64 {
            var value: UInt64 = 0
            for index in stride(from: offset + 7, through: offset, by: -1) {
                value = (value << 8) | UInt64(data[index])
            }
            return value
        }
        let keyBytes = Array(key)
        let messageBytes = Array(message)
        let k0 = le64(keyBytes, 0)
        let k1 = le64(keyBytes, 8)
        var v0 = 0x736f_6d65_7073_6575 ^ k0
        var v1 = 0x646f_7261_6e64_6f6d ^ k1
        var v2 = 0x6c79_6765_6e65_7261 ^ k0
        var v3 = 0x7465_6462_7974_6573 ^ k1
        func sipRound() {
            v0 &+= v1; v1 = (v1 << 13) | (v1 >> 51); v1 ^= v0; v0 = (v0 << 32) | (v0 >> 32)
            v2 &+= v3; v3 = (v3 << 16) | (v3 >> 48); v3 ^= v2
            v0 &+= v3; v3 = (v3 << 21) | (v3 >> 43); v3 ^= v0
            v2 &+= v1; v1 = (v1 << 17) | (v1 >> 47); v1 ^= v2; v2 = (v2 << 32) | (v2 >> 32)
        }
        var index = 0
        while index + 8 <= messageBytes.count {
            let m = le64(messageBytes, index)
            v3 ^= m
            sipRound(); sipRound()
            v0 ^= m
            index += 8
        }
        var tail: UInt64 = UInt64(messageBytes.count - index) << 56
        var shift: UInt64 = 0
        while index < messageBytes.count {
            tail |= UInt64(messageBytes[index]) << shift
            shift += 8
            index += 1
        }
        v3 ^= tail
        sipRound(); sipRound()
        v0 ^= tail
        v2 ^= 0xff
        sipRound(); sipRound(); sipRound()
        return v0 ^ v1 ^ v2 ^ v3
    }
}

/// Big-endian millisecond timestamps used in NTCP2 blocks.
enum NTCP2Time {
    static func milliseconds(_ date: Date) -> Data {
        let ms = UInt64(max(0, date.timeIntervalSince1970 * 1000).rounded())
        var value = ms.bigEndian
        return withUnsafeBytes(of: &value) { Data($0) }
    }

    static func date(_ data: Data) -> Date {
        var ms: UInt64 = 0
        for byte in data { ms = (ms << 8) | UInt64(byte) }
        return Date(timeIntervalSince1970: Double(ms) / 1000)
    }
}

/// NTCP2 payload blocks: [1-byte type][2-byte big-endian length][contents].
enum NTCP2BlockType: UInt8 {
    case padding = 0
    case options = 1
    case routerInfo = 2
    case data = 3
    case termination = 4
    case time = 5
}

enum NTCP2Block {
    case padding(Int)
    case options([String: String])
    case routerInfo(Data)
    case data(Data)
    case termination(reason: UInt8, validTime: Date)
    case time(Date)

    static func encode(_ blocks: [NTCP2Block]) throws -> Data {
        var writer = I2PWriter()
        func write(_ type: NTCP2BlockType, _ content: Data) {
            writer.byte(type.rawValue)
            writer.short(UInt16(content.count))
            writer.raw(content)
        }
        for block in blocks {
            switch block {
            case .padding(let count):
                write(.padding, Data(repeating: 0, count: count))
            case .options(let mapping):
                var mappingWriter = I2PWriter()
                mappingWriter.mapping(mapping)
                write(.options, mappingWriter.data)
            case .routerInfo(let routerInfo):
                write(.routerInfo, routerInfo)
            case .data(let payload):
                write(.data, payload)
            case .termination(let reason, let validTime):
                var content = Data([reason])
                content += NTCP2Time.milliseconds(validTime)
                write(.termination, content)
            case .time(let date):
                write(.time, NTCP2Time.milliseconds(date))
            }
        }
        return writer.data
    }

    static func decode(_ payload: Data) throws -> [NTCP2Block] {
        var reader = I2PReader(payload)
        var blocks: [NTCP2Block] = []
        while reader.remaining > 0 {
            guard let type = NTCP2BlockType(rawValue: try reader.byte()) else {
                throw NTCP2Error.invalidBlock
            }
            let length = Int(try reader.short())
            let content = try reader.raw(length)
            switch type {
            case .padding:
                blocks.append(.padding(length))
            case .options:
                var contentReader = I2PReader(content)
                blocks.append(.options(try contentReader.mapping()))
            case .routerInfo:
                blocks.append(.routerInfo(content))
            case .data:
                blocks.append(.data(content))
            case .termination:
                guard content.count >= 9 else { throw NTCP2Error.invalidBlock }
                blocks.append(.termination(reason: content[0], validTime: NTCP2Time.date(Data(content.dropFirst(1)))))
            case .time:
                guard content.count == 8 else { throw NTCP2Error.invalidBlock }
                blocks.append(.time(NTCP2Time.date(content)))
            }
        }
        return blocks
    }

    /// NTCP2 payloads are padded so their total length is a multiple of 16.
    static func aligned(_ payload: Data) -> Data {
        let remainder = payload.count % 16
        guard remainder != 0 else { return payload }
        let pad = (16 - ((payload.count + 3) % 16)) % 16
        var out = payload
        out.append(NTCP2BlockType.padding.rawValue)
        out.append(UInt8((pad >> 8) & 0xff))
        out.append(UInt8(pad & 0xff))
        out.append(contentsOf: [UInt8](repeating: 0, count: pad))
        return out
    }
}

/// Data-phase framing: [2-byte SipHash-obfuscated length][AEAD payload + 16-byte MAC].
/// A class so sessions share one mutable codec per direction.
final class NTCP2FrameCodec {
    private let aeadKey: Data
    private let sipKey: Data
    private(set) var counter: UInt64 = 0

    init(directionKeys: NTCP2DirectionKeys) {
        aeadKey = directionKeys.aeadKey
        sipKey = directionKeys.sipKey
    }

    func frame(_ payload: Data) throws -> Data {
        let box = try ChaChaPoly.seal(payload,
                                      using: SymmetricKey(data: aeadKey),
                                      nonce: NTCP2NoiseChain.nonce96(counter))
        let ciphertext = box.combined
        let mask = lengthMask(counter)
        let obfuscated = UInt16(ciphertext.count) ^ mask
        counter += 1
        var out = Data()
        out.append(UInt8((obfuscated >> 8) & 0xff))
        out.append(UInt8(obfuscated & 0xff))
        out.append(ciphertext)
        return out
    }

    /// Returns nil when more bytes are needed; throws on authentication failure.
    func unframe(_ buffer: Data) throws -> (payload: Data, consumed: Int)? {
        let bytes = Array(buffer)
        guard bytes.count >= 2 else { return nil }
        let obfuscated = (UInt16(bytes[0]) << 8) | UInt16(bytes[1])
        let length = obfuscated ^ lengthMask(counter)
        guard length >= 16 else { throw NTCP2Error.invalidFrame }
        let total = 2 + Int(length)
        guard bytes.count >= total else { return nil }
        let box = try ChaChaPoly.SealedBox(combined: Data(bytes[2..<total]))
        guard let payload = try? ChaChaPoly.open(box, using: SymmetricKey(data: aeadKey), authenticating: Data()) else {
            throw NTCP2Error.decryptFailed
        }
        counter += 1
        return (payload, total)
    }

    private func lengthMask(_ frameCounter: UInt64) -> UInt16 {
        var input = frameCounter.bigEndian
        let message = withUnsafeBytes(of: &input) { Data($0) }
        return UInt16(truncatingIfNeeded: SipHash24.hash(key: sipKey, message: message))
    }
}