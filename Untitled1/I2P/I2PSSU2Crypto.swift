//
//  I2PSSU2Crypto.swift
//  I2P
//
//  SSU2 cryptographic core: long/short packet headers with immutable connection
//  IDs and per-direction packet numbers, the seven DPI-resistant header
//  protection phases (ChaCha20 XOR masking keyed off the RouterInfo intro key
//  or session-derived keys), the full-ephemeral-region obfuscation of Session
//  Request/Created packets, the Noise_XK_25519_ChaChaPoly_SHA256 handshake
//  chaining state, and the data-phase ciphers with replay protection.
//

import Foundation
import CryptoKit

enum SSU2Error: Error {
    case invalidHeader
    case unsupportedVersion
    case unsupportedNetworkID
    case handshakeFailed(String)
    case decryptFailed
    case replayedPacket
    case invalidPacket
    case invalidToken
    case rateLimited
    case notEstablished
    case fragmentTimeout
    case noSession
    case testFailed(String)
}

// MARK: - Message types

/// SSU2 packet types carried in the header type byte (long headers unless noted).
enum SSU2MessageType: UInt8 {
    case sessionRequest = 0    // long header, initiates the handshake
    case sessionCreated = 1    // long header, Noise response
    case sessionConfirmed = 2  // SHORT header, authentication confirmation (fragmentable)
    case data = 6              // SHORT header, encrypted I2NP payloads
    case peerTest = 7          // long header, reachability testing
    case retry = 9             // long header, address-validation challenge with a fresh token
    case tokenRequest = 10     // long header, obtain a token without a full handshake
    case holePunch = 11        // long header, coordinate symmetric NAT traversal
}

// MARK: - ChaCha20 keystream (RFC 8439 block function, raw XOR without Poly1305)

/// Raw ChaCha20 keystream XOR, as used for SSU2 header protection masking.
/// CryptoKit exposes ChaChaPoly (AEAD) only, so the stream cipher is implemented
/// per RFC 8439: 20 quarter-rounds over the 4x4 state, output summed with the
/// initial state, little-endian serialization.
enum ChaCha20Stream {
    private static func quarterRound(_ s: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
        s[a] &+= s[b]; s[d] ^= s[a]; s[d] = (s[d] << 16) | (s[d] >> 16)
        s[c] &+= s[d]; s[b] ^= s[c]; s[b] = (s[b] << 12) | (s[b] >> 20)
        s[a] &+= s[b]; s[d] ^= s[a]; s[d] = (s[d] << 8) | (s[d] >> 24)
        s[c] &+= s[d]; s[b] ^= s[c]; s[b] = (s[b] << 7) | (s[b] >> 25)
    }

    private static func words(_ data: Data) -> [UInt32] {
        let bytes = Array(data)
        var out: [UInt32] = []
        var index = 0
        while index + 4 <= bytes.count {
            let value = UInt32(bytes[index])
                | (UInt32(bytes[index + 1]) << 8)
                | (UInt32(bytes[index + 2]) << 16)
                | (UInt32(bytes[index + 3]) << 24)
            out.append(value)
            index += 4
        }
        return out
    }

    private static func block(key: Data, counter: UInt32, nonce: Data) -> [UInt8] {
        var state: [UInt32] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]
        state += words(key)
        state.append(counter)
        state += words(nonce)
        var working = state
        for _ in 0..<10 {
            quarterRound(&working, 0, 4, 8, 12)
            quarterRound(&working, 1, 5, 9, 13)
            quarterRound(&working, 2, 6, 10, 14)
            quarterRound(&working, 3, 7, 11, 15)
            quarterRound(&working, 0, 5, 10, 15)
            quarterRound(&working, 1, 6, 11, 12)
            quarterRound(&working, 2, 7, 8, 13)
            quarterRound(&working, 3, 4, 9, 14)
        }
        var out: [UInt8] = []
        for index in 0..<16 {
            var value = (working[index] &+ state[index]).littleEndian
            withUnsafeBytes(of: &value) { out.append(contentsOf: $0) }
        }
        return out
    }

    /// Generates `length` keystream bytes starting at block `counter`.
    static func keystream(key: Data, nonce: Data, counter: UInt32 = 0, length: Int) -> Data {
        precondition(key.count == 32, "ChaCha20 requires a 32-byte key")
        precondition(nonce.count == 12, "ChaCha20 requires a 12-byte nonce")
        var out = Data()
        var blockCounter = counter
        while out.count < length {
            out.append(contentsOf: block(key: key, counter: blockCounter, nonce: nonce))
            blockCounter &+= 1
        }
        return out.prefix(length)
    }

    /// XORs `data` with the keystream (self-inverse, used for masking).
    static func xor(_ data: Data, key: Data, nonce: Data, counter: UInt32 = 0) -> Data {
        let stream = keystream(key: key, nonce: nonce, counter: counter, length: data.count)
        return Data(zip(Array(data), Array(stream)).map { $0 ^ $1 })
    }
}

// MARK: - Packet headers

/// SSU2 packet headers. Long headers are 32 bytes (handshake and auxiliary
/// packets), short headers 16 bytes (SessionConfirmed fragments and data).
/// Connection IDs are randomly generated, immutable for the session's life,
/// and src/dst are never identical.
struct SSU2PacketHeader {
    static let longLength = 32
    static let shortLength = 16
    static let version: UInt8 = 2
    static let networkID: UInt8 = 2

    let isLong: Bool
    /// Long-header handshake version: 2 = classical Noise_XK, 3 = ML-KEM-512
    /// hybrid, 4 = ML-KEM-768 hybrid (short headers do not carry a version).
    let version: UInt8
    let destinationConnectionID: Data // 8 bytes
    let packetNumber: UInt32
    let type: SSU2MessageType
    let flags: UInt8
    /// Long headers only: source connection ID (8 bytes) and token (8 bytes).
    let sourceConnectionID: Data?
    let token: Data?
    /// Short headers only: fragment info (high nibble = fragment index,
    /// low nibble = total fragments - 1) and two reserved additional-flag bytes.
    let fragmentIndex: Int
    let totalFragments: Int

    /// A long header with all fields explicit. `sourceConnectionID` and
    /// `token` must both be 8 bytes. `version` defaults to the classical
    /// handshake; hybrid offers pass the ML-KEM long-header variant here.
    init(destinationConnectionID: Data, packetNumber: UInt32, type: SSU2MessageType,
         flags: UInt8 = 0, sourceConnectionID: Data? = nil, token: Data? = nil,
         version: UInt8 = SSU2PacketHeader.version) {
        precondition(destinationConnectionID.count == 8, "connection IDs are 8 bytes")
        if let sourceConnectionID { precondition(sourceConnectionID.count == 8, "connection IDs are 8 bytes") }
        if let token { precondition(token.count == 8, "tokens are 8 bytes") }
        isLong = true
        self.version = version
        self.destinationConnectionID = destinationConnectionID
        self.packetNumber = packetNumber
        self.type = type
        self.flags = flags
        self.sourceConnectionID = sourceConnectionID
        self.token = token
        fragmentIndex = 0
        totalFragments = 1
    }

    /// A short header for a SessionConfirmed fragment or a data packet.
    init(shortDestinationConnectionID: Data, packetNumber: UInt32, type: SSU2MessageType,
         fragmentIndex: Int = 0, totalFragments: Int = 1, additionalFlags: UInt16 = 0) {
        precondition(shortDestinationConnectionID.count == 8, "connection IDs are 8 bytes")
        precondition(type == .sessionConfirmed || type == .data, "short headers carry sessionConfirmed/data only")
        precondition(totalFragments >= 1 && totalFragments <= 15, "up to 15 fragments")
        precondition(fragmentIndex >= 0 && fragmentIndex < totalFragments, "fragment index out of range")
        isLong = false
        version = SSU2PacketHeader.version
        destinationConnectionID = shortDestinationConnectionID
        self.packetNumber = packetNumber
        self.type = type
        flags = UInt8((fragmentIndex << 4) | (totalFragments - 1))
        sourceConnectionID = nil
        token = nil
        self.fragmentIndex = fragmentIndex
        self.totalFragments = totalFragments
    }

    /// Random connection ID, guaranteed distinct from `other` when given.
    static func randomConnectionID(distinctFrom other: Data? = nil) -> Data {
        var id = I2PCrypto.randomBytes(8)
        while let other, id == other {
            id = I2PCrypto.randomBytes(8)
        }
        return id
    }

    /// Connection IDs must never be identical across a session.
    static func validatePair(_ local: Data, _ remote: Data) throws {
        guard local != remote else { throw SSU2Error.invalidHeader }
    }

    func serialize() -> Data {
        var w = I2PWriter()
        w.raw(destinationConnectionID)
        var pn = packetNumber.bigEndian
        w.raw(withUnsafeBytes(of: &pn) { Data($0) })
        w.byte(type.rawValue)
        if isLong {
            w.byte(version)
            w.byte(SSU2PacketHeader.networkID)
            w.byte(flags)
            w.raw(sourceConnectionID ?? Data(repeating: 0, count: 8))
            w.raw(token ?? Data(repeating: 0, count: 8))
        } else {
            w.byte(flags) // fragment info byte
            let extra = UInt16(0) // additional flags, reserved
            w.short(extra)
        }
        return w.data
    }

    /// Parses a header from the head of `packet` (which must be the full
    /// datagram so tail-derived masking IVs are available to the caller).
    /// Validates version and network ID on long headers.
    static func parse(_ packet: Data) throws -> SSU2PacketHeader {
        let bytes = Array(Data(packet))
        guard bytes.count >= shortLength else { throw SSU2Error.invalidHeader }
        func be32(_ offset: Int) -> UInt32 {
            (UInt32(bytes[offset]) << 24) | (UInt32(bytes[offset + 1]) << 16)
                | (UInt32(bytes[offset + 2]) << 8) | UInt32(bytes[offset + 3])
        }
        let dst = Data(bytes[0..<8])
        let pn = be32(8)
        let rawType = bytes[12]
        guard let type = SSU2MessageType(rawValue: rawType) else { throw SSU2Error.invalidHeader }
        if type == .sessionConfirmed || type == .data {
            // Short header.
            let fragmentByte = bytes[13]
            let header = SSU2PacketHeader(
                shortDestinationConnectionID: dst, packetNumber: pn, type: type,
                fragmentIndex: Int(fragmentByte >> 4), totalFragments: Int(fragmentByte & 0x0f) + 1)
            return header
        }
        // Long header. Versions 2 (classical Noise_XK) and 3/4 (the ML-KEM
        // hybrid variants) are accepted; anything else fails closed.
        guard bytes.count >= longLength else { throw SSU2Error.invalidHeader }
        guard bytes[13] == 2 || bytes[13] == 3 || bytes[13] == 4 else {
            throw SSU2Error.unsupportedVersion
        }
        guard bytes[14] == SSU2PacketHeader.networkID else { throw SSU2Error.unsupportedNetworkID }
        let header = SSU2PacketHeader(
            destinationConnectionID: dst, packetNumber: pn, type: type,
            flags: bytes[15],
            sourceConnectionID: Data(bytes[16..<24]),
            token: Data(bytes[24..<32]),
            version: bytes[13])
        return header
    }

    /// The ML-KEM hybrid leg bound to this long header
    /// (nil for the classical version-2 handshake).
    var pqVersion: I2PSSU2PQVersion? {
        I2PSSU2PQVersion(rawValue: version)
    }
}

// MARK: - Header protection (DPI resistance)

/// The seven header-protection phases. Pre-handshake packets (session request,
/// session created, retry, peer test, hole punch — token requests share the
/// session-request key) mask with keys derived from the RouterInfo intro key;
/// session-established phases (session confirmed, data) mask with keys derived
/// from the split direction keys. Masking is ChaCha20 XOR: the first 8 bytes
/// use the packet tail bytes [len-24, len-12) as IV, bytes 8-16 use the last
/// 12 bytes of the packet as a separate IV, so every packet masks differently.
enum SSU2HeaderPhase: String, CaseIterable {
    case sessionRequest
    case sessionCreated
    case retry
    case sessionConfirmed
    case data
    case peerTest
    case holePunch

    var info: Data {
        Data(("SSU2 header protection/" + rawValue).utf8)
    }

    /// Phases masked with intro-key-derived keys (session confirmed and data
    /// use session-derived keys instead).
    static var introKeyPhases: [SSU2HeaderPhase] {
        [.sessionRequest, .sessionCreated, .retry, .peerTest, .holePunch]
    }
}

enum SSU2HeaderProtection {
    /// HKDF-SHA256 key for a phase: intro-key phases derive from the RouterInfo
    /// intro key; session phases derive from the split direction key.
    static func key(phase: SSU2HeaderPhase, introKey: Data, sessionKey: Data? = nil) -> Data {
        if let sessionKey {
            return I2PCrypto.hkdfSHA256(inputKeyMaterial: sessionKey,
                                        salt: Data("SSU2 header protection".utf8),
                                        info: phase.info, outputLength: 32)
        }
        return I2PCrypto.hkdfSHA256(inputKeyMaterial: introKey,
                                    salt: Data("SSU2 header protection".utf8),
                                    info: phase.info, outputLength: 32)
    }

    /// XOR-masks (or unmasks — the operation is an involution) the first 16
    /// bytes of `packet` in two 8-byte ChaCha20 blocks keyed by the phase key,
    /// with IVs taken from the packet tail (last 24 bytes). The packet must be
    /// fully assembled (at least 40 bytes including the MAC) before masking.
    static func maskHeader(_ packet: inout Data, phase: SSU2HeaderPhase,
                           introKey: Data, sessionKey: Data? = nil) throws {
        guard packet.count >= 40 else { throw SSU2Error.invalidPacket }
        let key = Self.key(phase: phase, introKey: introKey, sessionKey: sessionKey)
        let tail = packet.subdata(in: (packet.count - 24)..<packet.count)
        let iv1 = tail.subdata(in: 0..<12)
        let iv2 = tail.subdata(in: 12..<24)
        let first = ChaCha20Stream.xor(packet.subdata(in: 0..<8), key: key, nonce: iv1)
        packet.replaceSubrange(0..<8, with: first)
        let second = ChaCha20Stream.xor(packet.subdata(in: 8..<16), key: key, nonce: iv2)
        packet.replaceSubrange(8..<16, with: second)
    }

    /// Masking is an involution over XOR; unmask re-applies it.
    static func unmaskHeader(_ packet: inout Data, phase: SSU2HeaderPhase,
                             introKey: Data, sessionKey: Data? = nil) throws {
        try maskHeader(&packet, phase: phase, introKey: introKey, sessionKey: sessionKey)
    }

    /// Receiver-side phase detection for pre-handshake packets: the header is
    /// masked with an unknown phase key, so each intro-key phase is tried and
    /// accepted when the unmasked destination connection ID matches the
    /// expected value (a wrong key yields a random-looking ID).
    static func detectPhase(_ packet: Data, introKey: Data,
                            expectedDestinationConnectionID: Data) -> SSU2HeaderPhase? {
        for phase in SSU2HeaderPhase.introKeyPhases {
            var candidate = Data(packet)
            do { try unmaskHeader(&candidate, phase: phase, introKey: introKey) } catch { continue }
            if candidate.subdata(in: 0..<8) == expectedDestinationConnectionID {
                return phase
            }
        }
        return nil
    }

    /// Key for the 48-byte ephemeral region of SessionRequest/SessionCreated
    /// packets (bytes 16..64: source connection ID, token and the 32-byte
    /// ephemeral public key). Derives from the intro key and the responder's
    /// static public key — material both sides hold before any handshake state
    /// advances — and is applied as a ChaCha20 XOR with a zero IV.
    static func ephemeralRegionKey(introKey: Data, responderStaticKey: Data) -> Data {
        I2PCrypto.hkdfSHA256(inputKeyMaterial: introKey,
                             salt: responderStaticKey,
                             info: Data("SSU2 ephemeral region".utf8),
                             outputLength: 32)
    }

    /// Obfuscates (or deobfuscates) bytes 16..64 of a SessionRequest/Created
    /// packet with the ephemeral-region key, zero IV.
    static func obfuscateEphemeralRegion(_ packet: inout Data, introKey: Data,
                                         responderStaticKey: Data) throws {
        guard packet.count >= 64 else { throw SSU2Error.invalidPacket }
        let key = ephemeralRegionKey(introKey: introKey, responderStaticKey: responderStaticKey)
        let region = packet.subdata(in: 16..<64)
        let masked = ChaCha20Stream.xor(region, key: key, nonce: Data(repeating: 0, count: 12))
        packet.replaceSubrange(16..<64, with: masked)
    }
}

// MARK: - Noise chaining and session keys

/// SSU2 uses the same Noise_XK_25519_ChaChaPoly_SHA256 chaining state as
/// NTCP2 (protocol name rides verbatim as the 32-byte chaining key/hash).
/// SSU2-specific KDF scheduling lives in the handshake engines; the chain
/// itself is shared, so derived keys are byte-identical machinery.
typealias SSU2NoiseChain = NTCP2NoiseChain

struct SSU2DirectionKeys: Equatable {
    let aeadKey: Data
    /// Header-protection key for this direction's established traffic.
    let headerKey: Data
}

struct SSU2SessionKeys {
    let send: SSU2DirectionKeys
    let recv: SSU2DirectionKeys
}

/// Noise Split() for SSU2: temp_key = HMAC-SHA256(chaining_key, zerolen);
/// k_ab = HMAC-SHA256(temp_key, chaining_key || 0x01);
/// k_ba = HMAC-SHA256(temp_key, chaining_key || 0x02). Each direction key also
/// yields its header-protection key by HKDF.
enum SSU2KeySchedule {
    static func split(chainingKey: Data, initiatorSendsWithAB: Bool = true) -> SSU2SessionKeys {
        let temp = Data(HMAC<SHA256>.authenticationCode(for: Data(), using: SymmetricKey(data: chainingKey)))
        let k_ab = Data(HMAC<SHA256>.authenticationCode(for: chainingKey + Data([0x01]), using: SymmetricKey(data: temp)))
        let k_ba = Data(HMAC<SHA256>.authenticationCode(for: chainingKey + Data([0x02]), using: SymmetricKey(data: temp)))
        let ab = SSU2DirectionKeys(aeadKey: k_ab,
                                   headerKey: SSU2HeaderProtection.key(phase: .data, introKey: Data(), sessionKey: k_ab))
        let ba = SSU2DirectionKeys(aeadKey: k_ba,
                                   headerKey: SSU2HeaderProtection.key(phase: .data, introKey: Data(), sessionKey: k_ba))
        return initiatorSendsWithAB ? SSU2SessionKeys(send: ab, recv: ba)
                                    : SSU2SessionKeys(send: ba, recv: ab)
    }
}

// MARK: - Data phase

/// The 12-byte AEAD nonce: 32 zero bits then the 64-bit big-endian packet
/// number (nonce96, same layout as the transport AEAD nonces).
enum SSU2Nonce {
    static func nonce96(_ packetNumber: UInt32) -> ChaChaPoly.Nonce {
        var bytes = [UInt8](repeating: 0, count: 12)
        var value = UInt64(packetNumber).bigEndian
        withUnsafeBytes(of: &value) { raw in
            for (index, byte) in raw.enumerated() { bytes[4 + index] = byte }
        }
        return (try? ChaChaPoly.Nonce(data: Data(bytes)))!
    }
}

/// Replay protection over per-direction packet numbers: duplicates and packets
/// older than the 64-packet window are rejected; in-window out-of-order
/// delivery is accepted.
final class SSU2ReplayWindow {
    private let lock = NSLock()
    private var received: Set<UInt32> = []
    private var highest: UInt32?

    static let windowSize: UInt32 = 64

    /// Returns false when the packet number was already seen or fell out of
    /// the acceptance window.
    func checkAndInsert(_ packetNumber: UInt32) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if let highest {
            guard packetNumber &+ SSU2ReplayWindow.windowSize > highest else { return false }
        }
        guard !received.contains(packetNumber) else { return false }
        received.insert(packetNumber)
        if highest == nil || packetNumber > highest! {
            highest = packetNumber
        }
        // Bound memory: drop entries that fell out of the window.
        if let highest {
            received = received.filter { $0 &+ SSU2ReplayWindow.windowSize > highest }
        }
        return true
    }

    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return received.count
    }
}

/// One direction of the established data phase: ChaCha20-Poly1305 with the
/// direction key, the 12-byte counter nonce, and the short header as
/// associated data. Every authenticated payload carries a 16-byte MAC.
final class SSU2DataCipher {
    let key: Data

    init(key: Data) {
        precondition(key.count == 32)
        self.key = key
    }

    /// Sizes: minimum message 40 bytes (16 header + 8 payload + 16 MAC),
    /// maximum 1472 bytes (IPv4 datagram budget).
    static let minimumMessageLength = 40
    static let maximumMessageLength = 1472

    /// Seals `payload` under `header` (the 16-byte short header as associated
    /// data) with the nonce96 of `packetNumber`, returning header || ciphertext
    /// || MAC. The session owns the per-direction packet-number sequence, so
    /// the nonce comes from the header number itself.
    func seal(_ payload: Data, header: Data, packetNumber: UInt32) throws -> Data {
        guard payload.count >= 8 else { throw SSU2Error.invalidPacket }
        let messageLength = header.count + payload.count + 16
        guard messageLength <= SSU2DataCipher.maximumMessageLength else {
            throw SSU2Error.invalidPacket
        }
        let box = try ChaChaPoly.seal(payload,
                                      using: SymmetricKey(data: key),
                                      nonce: SSU2Nonce.nonce96(packetNumber),
                                      authenticating: header)
        var out = header
        out.append(box.ciphertext)
        out.append(box.tag)
        return out
    }

    /// Opens header || ciphertext || MAC; the 16-byte tag authenticates both
    /// the payload and the header. Returns the plaintext payload.
    func open(_ packet: Data, headerLength: Int = SSU2PacketHeader.shortLength) throws -> Data {
        guard packet.count >= SSU2DataCipher.minimumMessageLength else { throw SSU2Error.invalidPacket }
        let parsedHeader = try SSU2PacketHeader.parse(packet)
        let header = packet.subdata(in: 0..<headerLength)
        let body = packet.subdata(in: headerLength..<packet.count)
        guard body.count >= 16 else { throw SSU2Error.invalidPacket }
        let box = try ChaChaPoly.SealedBox(nonce: SSU2Nonce.nonce96(parsedHeader.packetNumber),
                                           ciphertext: body.subdata(in: 0..<(body.count - 16)),
                                           tag: body.subdata(in: (body.count - 16)..<body.count))
        guard let payload = try? ChaChaPoly.open(box, using: SymmetricKey(data: key), authenticating: header) else {
            throw SSU2Error.decryptFailed
        }
        return payload
    }
}

// MARK: - SSU2 payload blocks

/// Established-session payload blocks: [1-byte type][2-byte BE length][body].
enum SSU2BlockType: UInt8 {
    case data = 0
    case termination = 1
    case padding = 2
    case time = 3
    case pathChallenge = 4
    case pathResponse = 5
}

enum SSU2Block {
    /// One fragment of a possibly-fragmented I2NP message:
    /// [messageID (4 BE)][fragment byte: index << 4 | total - 1][payload].
    case dataFragment(messageID: UInt32, fragmentIndex: Int, totalFragments: Int, payload: Data)
    case termination(reason: UInt8, detail: String)
    case padding(Int)
    case time(Date)
    case pathChallenge(value: Data)
    case pathResponse(value: Data)

    static func encode(_ blocks: [SSU2Block]) throws -> Data {
        var w = I2PWriter()
        func write(_ type: SSU2BlockType, _ content: Data) {
            w.byte(type.rawValue)
            w.short(UInt16(content.count))
            w.raw(content)
        }
        for block in blocks {
            switch block {
            case .dataFragment(let messageID, let index, let total, let payload):
                guard total >= 1 && total <= 15, index >= 0, index < total else {
                    throw SSU2Error.invalidPacket
                }
                var content = Data()
                var id = messageID.bigEndian
                content.append(contentsOf: withUnsafeBytes(of: &id) { Data($0) })
                content.append(UInt8((index << 4) | (total - 1)))
                content.append(payload)
                write(.data, content)
            case .termination(let reason, let detail):
                var content = Data([reason])
                content.append(contentsOf: Data(detail.utf8))
                write(.termination, content)
            case .padding(let count):
                write(.padding, I2PCrypto.randomBytes(count))
            case .time(let date):
                let ms = UInt64(max(0, date.timeIntervalSince1970 * 1000).rounded())
                var value = ms.bigEndian
                write(.time, withUnsafeBytes(of: &value) { Data($0) })
            case .pathChallenge(let value):
                write(.pathChallenge, value)
            case .pathResponse(let value):
                write(.pathResponse, value)
            }
        }
        return w.data
    }

    static func decode(_ payload: Data) throws -> [SSU2Block] {
        var r = I2PReader(Data(payload))
        var blocks: [SSU2Block] = []
        while r.remaining > 0 {
            guard let type = SSU2BlockType(rawValue: try r.byte()) else {
                throw SSU2Error.invalidPacket
            }
            let length = Int(try r.short())
            let content = try r.raw(length)
            switch type {
            case .data:
                guard content.count >= 5 else { throw SSU2Error.invalidPacket }
                var cr = I2PReader(content)
                let messageID = try cr.integer()
                let fragmentByte = try cr.byte()
                let total = Int(fragmentByte & 0x0f) + 1
                let index = Int(fragmentByte >> 4)
                guard index < total else { throw SSU2Error.invalidPacket }
                blocks.append(.dataFragment(messageID: messageID,
                                            fragmentIndex: index,
                                            totalFragments: total,
                                            payload: content.subdata(in: 5..<content.count)))
            case .termination:
                guard !content.isEmpty else { throw SSU2Error.invalidPacket }
                blocks.append(.termination(reason: content[0],
                                           detail: String(decoding: content.dropFirst(), as: UTF8.self)))
            case .padding:
                blocks.append(.padding(length))
            case .time:
                guard content.count == 8 else { throw SSU2Error.invalidPacket }
                var ms: UInt64 = 0
                for byte in content { ms = (ms << 8) | UInt64(byte) }
                blocks.append(.time(Date(timeIntervalSince1970: Double(ms) / 1000)))
            case .pathChallenge:
                blocks.append(.pathChallenge(value: content))
            case .pathResponse:
                blocks.append(.pathResponse(value: content))
            }
        }
        return blocks
    }
}