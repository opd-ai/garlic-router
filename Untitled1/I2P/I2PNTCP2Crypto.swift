//
//  I2PNTCP2Crypto.swift
//  I2P
//
//  NTCP2 cryptographic core: the Noise XK chaining state for the
//  Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256 protocol, the spec's
//  AES-256-CBC ephemeral-key obfuscation, SipHash-2-4 length obfuscation with
//  the spec data-phase KDF, and the NTCP2 payload block codec.
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

/// Constant handshake fields of the NTCP2 protocol.
enum NTCP2Handshake {
    /// Network ID (spec §SessionRequest options block: "currently 2, except for
    /// test networks"). A peer advertising another ID is on a different network.
    static let networkID: UInt8 = 2
    /// NTCP2 protocol version this implementation speaks.
    static let version: UInt8 = 2
}

/// Noise_XK chaining state over NTCP2's protocol name. `h` and `ck` start at
/// SHA256(protocol_name); the null prologue and the responder's static key are
/// folded in as the Noise pre-messages. `MixKey` rekeys via HKDF and resets the
/// handshake AEAD nonce; `MixHash` folds wire material into `h`.
struct NTCP2NoiseChain {
    /// The spec's `protocol_name`: 48 bytes of US-ASCII, no NULL terminator.
    /// The shorthand "Noise_XK_25519_ChaChaPoly_SHA256" names the base pattern
    /// but is not the identifier that seeds the KDF, so it can never interop.
    static let protocolName = "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256"

    private(set) var chainingKey: Data
    private(set) var hash: Data
    private(set) var key: Data?
    private(set) var nonce: UInt64 = 0

    init() {
        // Spec KDF: h = SHA256(protocol_name); ck = h; then MixHash(null
        // prologue), h = SHA256(h). Both sides precalculate this before any
        // connection-specific material arrives.
        let nameHash = Self.sha256(Data(Self.protocolName.utf8))
        chainingKey = nameHash
        hash = nameHash
        mixHash(Data())
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
    /// The wire format is ciphertext || tag (the nonce rides implicitly in the
    /// counter, never on the wire).
    mutating func encrypt(_ plaintext: Data) throws -> Data {
        guard let key else { throw NTCP2Error.handshakeFailed("EncryptWithAd without a key") }
        let box = try ChaChaPoly.seal(plaintext,
                                      using: SymmetricKey(data: key),
                                      nonce: Self.nonce96(nonce),
                                      authenticating: hash)
        nonce += 1
        // CryptoKit's ciphertext is a slice with a non-zero index base; copy it
        // into a fresh buffer so the wire blob is safe to index from zero.
        var wire = Data()
        wire.append(contentsOf: box.ciphertext)
        wire.append(contentsOf: box.tag)
        mixHash(wire)
        return wire
    }

    /// Noise DecryptWithAd over a ciphertext || tag wire blob.
    mutating func decrypt(_ ciphertext: Data) throws -> Data {
        guard let key else { throw NTCP2Error.handshakeFailed("DecryptWithAd without a key") }
        guard ciphertext.count > 16 else { throw NTCP2Error.decryptFailed }
        // dropLast/suffix split — never subdata(in:) with absolute ranges:
        // Data carries its own index base (a slice of another Data can start
        // at any offset), and subdata(in: 0..<n) traps with SIGTRAP when the
        // receiver's indices are not zero-based. dropLast/suffix are immune.
        let box = try ChaChaPoly.SealedBox(
            nonce: Self.nonce96(nonce),
            ciphertext: Data(ciphertext.dropLast(16)),
            tag: Data(ciphertext.suffix(16)))
        guard let plaintext = try? ChaChaPoly.open(box, using: SymmetricKey(data: key), authenticating: hash) else {
            throw NTCP2Error.decryptFailed
        }
        nonce += 1
        mixHash(ciphertext)
        return plaintext
    }

    /// The spec's data-phase KDF. It needs the final handshake hash as well as
    /// the chaining key, because the SipHash labels are seeded with `h`.
    ///
    /// temp_key = HMAC-SHA256(ck, zerolen); k_ab = HMAC(temp_key, 0x01);
    /// k_ba = HMAC(temp_key, k_ab || 0x02); ask_master = HMAC(temp_key,
    /// "ask" || 0x01); temp_key = HMAC(ask_master, h || "siphash");
    /// sip_master = HMAC(temp_key, 0x01); temp_key = HMAC(sip_master, zerolen);
    /// sipkeys_ab = HMAC(temp_key, 0x01),
    /// sipkeys_ba = HMAC(temp_key, sipkeys_ab || 0x02).
    func split() -> (ab: NTCP2DirectionKeys, ba: NTCP2DirectionKeys) {
        let tempKey = Self.hmac(Data(), key: chainingKey)
        let kAB = Self.hmac(Data([0x01]), key: tempKey)
        let kBA = Self.hmac(kAB + Data([0x02]), key: tempKey)

        let askMaster = Self.hmac(Data("ask".utf8) + Data([0x01]), key: tempKey)
        let sipTempKey = Self.hmac(hash + Data("siphash".utf8), key: askMaster)
        let sipMaster = Self.hmac(Data([0x01]), key: sipTempKey)
        let sipExpand = Self.hmac(Data(), key: sipMaster)
        let sipAB = Self.hmac(Data([0x01]), key: sipExpand)
        let sipBA = Self.hmac(sipAB + Data([0x02]), key: sipExpand)

        // Each direction gets 24 bytes: two 8-byte SipHash keys and the 8-byte
        // initial IV, in the order the spec's KDF emits them.
        return (NTCP2DirectionKeys(aeadKey: kAB, sipKeys: Data(sipAB.prefix(24))),
                NTCP2DirectionKeys(aeadKey: kBA, sipKeys: Data(sipBA.prefix(24))))
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

    /// Noise 96-bit nonce: 32 zero bits, then the 64-bit **little-endian**
    /// counter, as the Noise spec (and NTCP2 §Authenticated Encryption) require.
    static func nonce96(_ counter: UInt64) -> ChaChaPoly.Nonce {
        var bytes = [UInt8](repeating: 0, count: 12)
        for index in 0..<8 {
            bytes[4 + index] = UInt8((counter >> (8 * UInt64(index))) & 0xff)
        }
        return (try? ChaChaPoly.Nonce(data: Data(bytes)))!
    }

    static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }
}

/// One direction of the established session: the ChaChaPoly data key plus the
/// 24 bytes of SipHash key material (k1 ‖ k2 ‖ iv) the data-phase KDF emits.
struct NTCP2DirectionKeys: Equatable {
    let aeadKey: Data
    let sipKeys: Data
}

struct NTCP2SessionKeys {
    let sendKeys: NTCP2DirectionKeys
    let recvKeys: NTCP2DirectionKeys
}

/// NTCP2 §SessionRequest: the 32-byte X25519 ephemeral key is AES-256-CBC
/// encrypted under the responder's router hash with the IV the responder
/// publishes in its RouterInfo `i` option. Message 2 continues the same CBC
/// chain ("iv: Using AES state from message 1"), so one instance carries the
/// whole exchange: the initiator encrypts X then decrypts Y, the responder
/// decrypts X then encrypts Y.
struct NTCP2HandshakeObfuscator {
    private let key: Data
    private var iv: Data

    init(routerHash: Data, iv: Data) throws {
        guard routerHash.count == 32 else {
            throw NTCP2Error.handshakeFailed("NTCP2 obfuscation key must be the 32-byte router hash")
        }
        guard iv.count == 16 else {
            throw NTCP2Error.handshakeFailed("NTCP2 obfuscation IV must be the 16-byte published 'i' option")
        }
        self.key = routerHash
        self.iv = iv
    }

    mutating func encrypt(_ ephemeralKey: Data) throws -> Data {
        guard ephemeralKey.count == 32 else {
            throw NTCP2Error.handshakeFailed("NTCP2 ephemeral key must be 32 bytes")
        }
        let ciphertext = I2PAESCBC.encrypt(ephemeralKey, key: key, iv: iv)
        iv = Data(ciphertext.suffix(16))
        return ciphertext
    }

    mutating func decrypt(_ wire: Data) throws -> Data {
        guard wire.count == 32 else {
            throw NTCP2Error.handshakeFailed("obfuscated NTCP2 ephemeral key must be 32 bytes")
        }
        let plaintext = I2PAESCBC.decrypt(wire, key: key, iv: iv)
        iv = Data(wire.suffix(16))
        return plaintext
    }
}

/// AES-CBC without padding (CommonCrypto), as required by the NTCP2 spec's
/// ephemeral-key obfuscation (block-aligned 32-byte input, 32-byte output) and
/// by the tunnel layer cipher's IV transform (AES-128-ECB over one block).
enum I2PAESCBC {
    static func encrypt(_ data: Data, key: Data, iv: Data) -> Data {
        crypt(data, key: key, iv: iv, operation: CCOperation(kCCEncrypt))
    }

    static func decrypt(_ data: Data, key: Data, iv: Data) -> Data {
        crypt(data, key: key, iv: iv, operation: CCOperation(kCCDecrypt))
    }

    private static func crypt(_ data: Data, key: Data, iv: Data, operation: CCOperation) -> Data {
        // AES-256 (32-byte key) is what NTCP2's obfuscation uses; the tunnel IV
        // transform keys AES-128 with the spec's 16-byte IV key. Both ride the
        // same CommonCrypto path, so the key length decides the AES variant.
        precondition(key.count == Int(kCCKeySizeAES128) || key.count == Int(kCCKeySizeAES192)
                     || key.count == Int(kCCKeySizeAES256),
                     "AES key must be 16, 24 or 32 bytes")
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
    /// The two 64-bit keys are loaded **little-endian** from the 16-byte key
    /// material. The spec's "two 8-byte keys (big endian)" line describes the
    /// integer-to-wire order of the mask, not the key load: reference routers
    /// read the KDF bytes with a little-endian 64-bit load (Java I2P's
    /// `fromLong8LE` in NTCPConnection), and reading them big-endian here makes
    /// every length mask differ from the peer's.
    static func hash(key: Data, message: Data) -> UInt64 {
        precondition(key.count == 16)
        let bytes = Array(key)
        var k0: UInt64 = 0
        var k1: UInt64 = 0
        for index in 0..<8 {
            k0 |= UInt64(bytes[index]) << (8 * UInt64(index))
            k1 |= UInt64(bytes[8 + index]) << (8 * UInt64(index))
        }
        return hash(k0: k0, k1: k1, message: message)
    }

    static func hash(k0: UInt64, k1: UInt64, message: Data) -> UInt64 {
        // SipHash reads each 64-bit message word little-endian (the reference
        // `U8TO64_LE`); loading it big-endian produces a digest no reference
        // implementation agrees with, so every NTCP2 frame length mask would
        // differ from the peer's and the peer would read a bogus frame length
        // and drop the session right after the first data frame.
        func le64(_ data: [UInt8], _ offset: Int) -> UInt64 {
            var value: UInt64 = 0
            for index in 0..<8 {
                value |= UInt64(data[offset + index]) << (8 * UInt64(index))
            }
            return value
        }
        let messageBytes = Array(message)
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
        // The tail word's high byte carries the TOTAL message length (the
        // reference's `b = inlen << 56`), not the leftover byte count: using the
        // remainder matches the published vectors for messages shorter than 8
        // bytes and silently diverges for every longer one, which would corrupt
        // every NTCP2 frame length mask once a session sends a full block.
        var tail: UInt64 = UInt64(messageBytes.count) << 56
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
        // SipHash-**2-4**: two compression rounds per block, four finalization
        // rounds. Three final rounds (the previous code) produces a digest no
        // reference implementation agrees with, so every frame length mask
        // differed from the peer's.
        sipRound(); sipRound(); sipRound(); sipRound()
        return v0 ^ v1 ^ v2 ^ v3
    }
}

/// 4-byte big-endian Unix timestamps in seconds, the only timestamp form NTCP2
/// puts on the wire (handshake options blocks and datetime blocks).
enum NTCP2Time {
    static func seconds(_ date: Date) -> Data {
        let value = UInt32(truncatingIfNeeded: UInt64(max(0, date.timeIntervalSince1970)))
        var bytes = [UInt8](repeating: 0, count: 4)
        for index in 0..<4 {
            let shift = UInt32(8 * (3 - index))
            bytes[index] = UInt8((value >> shift) & 0xff)
        }
        return Data(bytes)
    }

    static func date(_ data: Data) -> Date {
        var value: UInt32 = 0
        for byte in data.prefix(4) { value = (value << 8) | UInt32(byte) }
        return Date(timeIntervalSince1970: TimeInterval(value))
    }
}

/// The data-phase options block (type 1): the padding negotiation record. Each
/// ratio is a 4.4 fixed-point value (0x10 = 100% padding); the dummy and delay
/// fields are 16-bit big-endian byte- and millisecond-per-second averages.
struct NTCP2Options: Equatable {
    var transmitMin: UInt8 = 0
    var transmitMax: UInt8 = 0
    var receiveMin: UInt8 = 0
    var receiveMax: UInt8 = 0
    var transmitDummy: UInt16 = 0
    var receiveDummy: UInt16 = 0
    var transmitDelay: UInt16 = 0
    var receiveDelay: UInt16 = 0

    /// The spec's minimum record; later revisions append `more_options`.
    static let wireLength = 12

    func encode() -> Data {
        var writer = I2PWriter()
        writer.byte(transmitMin)
        writer.byte(transmitMax)
        writer.byte(receiveMin)
        writer.byte(receiveMax)
        writer.short(transmitDummy)
        writer.short(receiveDummy)
        writer.short(transmitDelay)
        writer.short(receiveDelay)
        return writer.data
    }

    static func decode(_ data: Data) -> NTCP2Options? {
        guard data.count >= wireLength else { return nil }
        var reader = I2PReader(Data(data.prefix(wireLength)))
        guard let transmitMin = try? reader.byte(),
              let transmitMax = try? reader.byte(),
              let receiveMin = try? reader.byte(),
              let receiveMax = try? reader.byte(),
              let transmitDummy = try? reader.short(),
              let receiveDummy = try? reader.short(),
              let transmitDelay = try? reader.short(),
              let receiveDelay = try? reader.short() else {
            return nil
        }
        return NTCP2Options(transmitMin: transmitMin,
                            transmitMax: transmitMax,
                            receiveMin: receiveMin,
                            receiveMax: receiveMax,
                            transmitDummy: transmitDummy,
                            receiveDummy: receiveDummy,
                            transmitDelay: transmitDelay,
                            receiveDelay: receiveDelay)
    }
}

/// NTCP2 payload blocks: [1-byte type][2-byte big-endian length][contents].
/// The type codes are the spec's: 0 datetime, 1 options, 2 RouterInfo,
/// 3 I2NP message, 4 termination, 254 padding.
enum NTCP2BlockType: UInt8 {
    case time = 0
    case options = 1
    case routerInfo = 2
    case data = 3
    case termination = 4
    case padding = 254
}

enum NTCP2Block {
    /// Type 0: a 4-byte Unix-seconds timestamp (rounded to the second).
    case time(Date)
    /// Type 1: the padding negotiation record.
    case options(NTCP2Options)
    /// Type 2: a RouterInfo preceded by a 1-byte flags field (bit 0 = flood
    /// request). The enum carries the RouterInfo itself, flag stripped. The
    /// RouterInfo is NOT gzipped here, unlike in a DatabaseStore message.
    case routerInfo(Data)
    /// Type 3: one I2NP message in the 9-byte short header (type, message ID,
    /// 4-byte seconds-level expiry, body).
    case data(Data)
    /// Type 4: the number of valid AEAD data frames received, then the reason
    /// code; this must be the last non-padding block of the frame.
    case termination(reason: UInt8, validFrames: UInt64)
    /// Type 254: opaque padding, last block of the frame when present.
    case padding(Int)

    static func encode(_ blocks: [NTCP2Block]) throws -> Data {
        var writer = I2PWriter()
        func write(_ type: NTCP2BlockType, _ content: Data) throws {
            guard content.count <= 0xFFFE else { throw NTCP2Error.invalidBlock }
            writer.byte(type.rawValue)
            writer.short(UInt16(content.count))
            writer.raw(content)
        }
        for block in blocks {
            switch block {
            case .time(let date):
                try write(.time, NTCP2Time.seconds(date))
            case .options(let options):
                try write(.options, options.encode())
            case .routerInfo(let routerInfo):
                try write(.routerInfo, Data([0]) + routerInfo)
            case .data(let payload):
                try write(.data, payload)
            case .termination(let reason, let validFrames):
                var content = Data()
                var count = validFrames.bigEndian
                withUnsafeBytes(of: &count) { content.append(contentsOf: $0) }
                content.append(reason)
                try write(.termination, content)
            case .padding(let count):
                try write(.padding, Data(repeating: 0, count: max(0, count)))
            }
        }
        return writer.data
    }

    static func decode(_ payload: Data) throws -> [NTCP2Block] {
        var reader = I2PReader(payload)
        var blocks: [NTCP2Block] = []
        while reader.remaining > 0 {
            let rawType = try reader.byte()
            let length = Int(try reader.short())
            let content = try reader.raw(length)
            guard let type = NTCP2BlockType(rawValue: rawType) else {
                // Spec: unknown block identifiers are ignored, as if padding.
                blocks.append(.padding(length))
                continue
            }
            switch type {
            case .time:
                guard content.count >= 4 else { throw NTCP2Error.invalidBlock }
                blocks.append(.time(NTCP2Time.date(content)))
            case .options:
                guard let options = NTCP2Options.decode(content) else { throw NTCP2Error.invalidBlock }
                blocks.append(.options(options))
            case .routerInfo:
                guard content.count >= 1 else { throw NTCP2Error.invalidBlock }
                blocks.append(.routerInfo(Data(content.dropFirst(1))))
            case .data:
                blocks.append(.data(content))
            case .termination:
                guard content.count >= 9 else { throw NTCP2Error.invalidBlock }
                var frames: UInt64 = 0
                for index in 0..<8 { frames = (frames << 8) | UInt64(content[index]) }
                blocks.append(.termination(reason: content[8], validFrames: frames))
            case .padding:
                blocks.append(.padding(length))
            }
        }
        return blocks
    }

    /// NTCP2 payloads are padded so their total length is a multiple of 16.
    static func aligned(_ payload: Data) -> Data {
        guard payload.count % 16 != 0 else { return payload }
        let pad = (16 - ((payload.count + 3) % 16)) % 16
        var out = payload
        out.append(NTCP2BlockType.padding.rawValue)
        out.append(0)
        out.append(UInt8(pad))
        out.append(contentsOf: [UInt8](repeating: 0, count: pad))
        return out
    }
}

/// Data-phase framing: [2-byte SipHash-obfuscated length][AEAD payload + 16-byte MAC].
/// A class so sessions share one mutable codec per direction.
final class NTCP2FrameCodec {
    private let aeadKey: Data
    private let sipKey1: UInt64
    private let sipKey2: UInt64
    private var sipIV: Data
    private(set) var counter: UInt64 = 0

    init(directionKeys: NTCP2DirectionKeys) {
        precondition(directionKeys.sipKeys.count >= 24, "24-byte SipHash key material required")
        aeadKey = directionKeys.aeadKey
        let keys = Array(directionKeys.sipKeys)
        // Key material layout from the data-phase KDF: two 8-byte SipHash keys
        // then the 8-byte IV. Reference routers load each 64-bit key
        // little-endian (Java I2P `fromLong8LE`) — using the same load is what
        // makes our mask chain identical to the peer's.
        sipKey1 = keys[0..<8].enumerated().reduce(UInt64(0)) { $0 | (UInt64($1.element) << (8 * UInt64($1.offset))) }
        sipKey2 = keys[8..<16].enumerated().reduce(UInt64(0)) { $0 | (UInt64($1.element) << (8 * UInt64($1.offset))) }
        sipIV = Data(keys[16..<24])
    }

    func frame(_ payload: Data) throws -> Data {
        let box = try ChaChaPoly.seal(payload,
                                      using: SymmetricKey(data: aeadKey),
                                      nonce: NTCP2NoiseChain.nonce96(counter))
        // Normalize the CryptoKit slice into a zero-based buffer before the
        // caller prepends the obfuscated length.
        var ciphertext = Data()
        ciphertext.append(contentsOf: box.ciphertext)
        ciphertext.append(contentsOf: box.tag)
        guard ciphertext.count <= 0xFFFF else { throw NTCP2Error.invalidFrame }
        let mask = deriveMask()
        let length = UInt16(ciphertext.count)
        sipIV = mask.iv
        counter += 1
        var out = Data()
        out.append(UInt8((length >> 8) & 0xff) ^ mask.high)
        out.append(UInt8(length & 0xff) ^ mask.low)
        out.append(ciphertext)
        return out
    }

    /// Returns nil when more bytes are needed; throws on authentication failure.
    func unframe(_ buffer: Data) throws -> (payload: Data, consumed: Int)? {
        let bytes = Array(buffer)
        guard bytes.count >= 2 else { return nil }
        let mask = deriveMask()
        let length = (UInt16(bytes[0] ^ mask.high) << 8) | UInt16(bytes[1] ^ mask.low)
        guard length >= 16 else { throw NTCP2Error.invalidFrame }
        let total = 2 + Int(length)
        guard bytes.count >= total else { return nil }
        let body = Data(bytes[2..<total])
        // Same slice-safe split as NoiseChain.decrypt (see note there).
        let box = try ChaChaPoly.SealedBox(
            nonce: NTCP2NoiseChain.nonce96(counter),
            ciphertext: Data(body.dropLast(16)),
            tag: Data(body.suffix(16)))
        guard let payload = try? ChaChaPoly.open(box, using: SymmetricKey(data: aeadKey), authenticating: Data()) else {
            throw NTCP2Error.decryptFailed
        }
        sipIV = mask.iv
        counter += 1
        return (payload, total)
    }

    /// The mask the next frame's big-endian length field is XORed with. Deriving
    /// it does not commit the chained IV, so a partial read can be retried with
    /// the same state; both directions derive identical masks from the KDF.
    func nextLengthMask() -> UInt16 {
        let mask = deriveMask()
        return (UInt16(mask.high) << 8) | UInt16(mask.low)
    }

    /// NTCP2 §SipHash obfuscated length: IV[n] = SipHash-2-4(k1, k2, IV[n-1]);
    /// Mask[n] = first two bytes of IV[n], obfuscatedLength = length ^ Mask[n],
    /// with the first length XORed against IV[1]. The digest is carried into the
    /// next round as a **little-endian** 64-bit value, and the mask is the least
    /// significant two bytes of the digest XORed onto the big-endian length —
    /// the high length byte against the digest's second byte and the low byte
    /// against its first (Java I2P: `enc[0] ^= sipIV >> 8`, `enc[1] ^= sipIV`).
    private func deriveMask() -> (high: UInt8, low: UInt8, iv: Data) {
        let digest = SipHash24.hash(k0: sipKey1, k1: sipKey2, message: sipIV)
        var next = [UInt8](repeating: 0, count: 8)
        for index in 0..<8 {
            next[index] = UInt8((digest >> (8 * UInt64(index))) & 0xff)
        }
        return (next[1], next[0], Data(next))
    }
}
