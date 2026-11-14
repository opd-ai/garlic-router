//
//  I2NPMessages.swift
//  I2NP message layer: header format, typed payloads and delivery instructions.
//

import Foundation

enum I2NPError: Error {
    case unsupportedType
    case invalidPayload
    case invalidConfiguration
    case unknownTunnel
    case expired
}

/// I2NP message type codes on the wire per the I2P common message spec:
/// DatabaseStore 1, DatabaseLookup 2, DatabaseSearchReply 3, DeliveryStatus 10,
/// Garlic 11, TunnelData 18, TunnelGateway 19, Data 20, and the short tunnel
/// build pair 25/26. Earlier revisions of this router used 4/5/6/7/8 for the
/// middle five, which reference routers drop as unknown types.
///
/// The spec defines no "Options" I2NP message (and Java I2P has no
/// OptionsMessage class): router options and status ride RouterInfo options and
/// the NTCP2 handshake Options block, so no non-spec type slot exists here.
enum I2NPMessageType: UInt8, CaseIterable {
    case databaseStore = 1
    case databaseLookup = 2
    case databaseSearchReply = 3
    case deliveryStatus = 10
    case garlic = 11
    case tunnelData = 18
    case tunnelGateway = 19
    case dataMessage = 20
    case tunnelBuild = 25
    case tunnelBuildReply = 26
}

/// I2NP wire header per the spec's full-header layout: type byte, message ID,
/// expiry (8-byte ms), big-endian payload size (2 bytes) and the checksum byte
/// — the first byte of SHA-256(payload). Tunnel hops verify that byte to catch
/// AES-CBC malleability before touching the payload, so it is part of the
/// contract, not decoration.
struct I2NPMessageHeader {
    let type: I2NPMessageType
    let messageID: UInt32
    let expiration: Date
    let size: Int
    let checksum: UInt8

    static let length = 16

    func serialize() -> Data {
        var w = I2PWriter()
        w.byte(type.rawValue)
        w.integer(messageID)
        w.long(UInt64((expiration.timeIntervalSince1970 * 1000).rounded()))
        w.short(UInt16(clamping: size)) // the spec caps I2NP payloads at 64 KiB
        w.byte(checksum)
        return w.data
    }

    static func parse(_ data: Data) throws -> I2NPMessageHeader {
        var r = I2PReader(data)
        guard r.remaining >= I2NPMessageHeader.length else { throw I2PWireError.truncated }
        guard let type = I2NPMessageType(rawValue: try r.byte()) else { throw I2NPError.unsupportedType }
        let messageID = try r.integer()
        let ms = try r.long()
        let size = Int(try r.short())
        let checksum = try r.byte()
        return I2NPMessageHeader(
            type: type,
            messageID: messageID,
            expiration: Date(timeIntervalSince1970: Double(ms) / 1000),
            size: size,
            checksum: checksum
        )
    }
}
/// A complete I2NP message: header plus typed payload.
struct I2NPMessage {
    let type: I2NPMessageType
    let messageID: UInt32
    let expiration: Date
    let payload: Data

    static let headerLength = I2NPMessageHeader.length

    init(type: I2NPMessageType, messageID: UInt32? = nil,
         expiration: Date? = nil, payload: Data = Data()) {
        self.type = type
        self.messageID = messageID ?? UInt32.random(in: 1...UInt32.max)
        // Spec note: implementations may reject expirations too far in the
        // future; the recommended maximum is 60 s.
        self.expiration = expiration ?? Date().addingTimeInterval(60)
        self.payload = payload
    }

    func serialize() -> Data {
        var w = I2PWriter()
        w.byte(type.rawValue)
        w.integer(messageID)
        w.long(UInt64((expiration.timeIntervalSince1970 * 1000).rounded()))
        w.short(UInt16(clamping: payload.count))
        w.byte(I2PCrypto.sha256(payload)[0])
        w.raw(payload)
        return w.data
    }

    static func parse(_ data: Data) throws -> I2NPMessage {
        var r = I2PReader(data)
        guard let type = I2NPMessageType(rawValue: try r.byte()) else { throw I2NPError.unsupportedType }
        let messageID = try r.integer()
        let ms = try r.long()
        let size = Int(try r.short())
        let checksum = try r.byte()
        let payload = try r.raw(size)
        guard r.remaining == 0 else { throw I2PWireError.trailingData }
        // Parse-time verification per the spec's full-header contract: the
        // checksum byte must equal the first byte of SHA-256(payload). A
        // tampered or corrupt payload is rejected whole, before any
        // interpretation rides on it.
        guard checksum == I2PCrypto.sha256(payload)[0] else { throw I2PWireError.invalidFormat }
        let message = I2NPMessage(
            type: type,
            messageID: messageID,
            expiration: Date(timeIntervalSince1970: Double(ms) / 1000),
            payload: payload
        )
        // Spec expiry enforcement: an expired message is never processed.
        guard !message.isExpired() else { throw I2NPError.expired }
        return message
    }

    static func parseHeader(_ data: Data) throws -> I2NPMessageHeader {
        try I2NPMessageHeader.parse(data)
    }

    /// Expiry enforcement: stale messages are dropped on receipt.
    func isExpired(now: Date = Date()) -> Bool {
        expiration.timeIntervalSince(now) <= 0
    }

    /// The spec's 9-byte short header used by NTCP2/SSU2 data-phase framing:
    /// type (1) + message ID (4 BE) + expiration (4 BE seconds). Size and
    /// checksum are provided by the transport frame. The message ID rides the
    /// wire so ID-based correlation (delivery status, reply tokens) works
    /// across transports, exactly as real routers frame it.
    func serializeShort() -> Data {
        var w = I2PWriter()
        w.byte(type.rawValue)
        w.integer(messageID)
        w.integer(UInt32(max(0, (expiration.timeIntervalSince1970).rounded())))
        w.raw(payload)
        return w.data
    }

    /// Parses one short-header I2NP message:
    /// [type (1)][message ID (4 BE)][expiration (4 BE s)][payload].
    /// Real mainnet short-header messages carry the message ID — parsing it
    /// back (rather than regenerating one) is what makes inbound traffic from
    /// Java I2P / i2pd peers readable at all.
    static func parseShort(_ data: Data) throws -> I2NPMessage {
        guard data.count >= 9, let type = I2NPMessageType(rawValue: data[0]) else {
            throw I2NPError.unsupportedType
        }
        let messageID = (UInt32(data[1]) << 24) | (UInt32(data[2]) << 16)
                        | (UInt32(data[3]) << 8) | UInt32(data[4])
        let seconds = (UInt32(data[5]) << 24) | (UInt32(data[6]) << 16)
                      | (UInt32(data[7]) << 8) | UInt32(data[8])
        return I2NPMessage(
            type: type,
            messageID: messageID,
            expiration: Date(timeIntervalSince1970: TimeInterval(seconds)),
            payload: data.subdata(in: 9..<data.count)
        )
    }

    /// True when `data` begins with a valid short header (a known type code and
    /// the full 9-byte header). Transport receivers use this to distinguish
    /// mainnet short-header messages from raw non-I2NP payloads.
    static func looksLikeShortHeaderMessage(_ data: Data) -> Bool {
        data.count >= 9 && I2NPMessageType(rawValue: data[0]) != nil
    }

    /// Typed payload parsing for every standard message type.
    func parseBody() throws -> I2NPBody {
        switch type {
        case .databaseStore:
            return .databaseStore(try I2PDatabaseStore.parse(payload))
        case .databaseLookup:
            return .databaseLookup(try I2PDatabaseLookup.parse(payload))
        case .databaseSearchReply:
            return .databaseSearchReply(try I2PDatabaseSearchReply.parse(payload))
        case .deliveryStatus:
            var r = I2PReader(payload)
            guard payload.count >= 12 else { throw I2NPError.invalidPayload }
            let id = try r.integer()
            let ms = try r.long()
            return .deliveryStatus(messageID: id, timestamp: Date(timeIntervalSince1970: Double(ms) / 1000))
        case .dataMessage:
            return .dataMessage(payload)
        case .garlic:
            return .garlic(payload)
        case .tunnelData:
            return .tunnelData(try I2PTunnelDataPayload.parse(payload))
        case .tunnelGateway:
            let parsed = try I2PTunnelGatewayPayload.parse(payload)
            return .tunnelGateway(gatewayID: parsed.gatewayID, message: parsed.message)
        case .tunnelBuild:
            return .tunnelBuild(try I2PTunnelBuildMessage.parse(payload))
        case .tunnelBuildReply:
            return .tunnelBuildReply(try I2PTunnelBuildReply.parse(payload))
        }
    }
}

enum I2NPBody {
    case databaseStore(I2PDatabaseStore)
    case databaseLookup(I2PDatabaseLookup)
    case databaseSearchReply(I2PDatabaseSearchReply)
    case deliveryStatus(messageID: UInt32, timestamp: Date)
    case dataMessage(Data)
    case garlic(Data)
    case tunnelData(I2PTunnelDataPayload)
    case tunnelGateway(gatewayID: UInt32, message: Data)
    case tunnelBuild(I2PTunnelBuildMessage)
    case tunnelBuildReply(I2PTunnelBuildReply)
}
/// TunnelData payload per the tunnel spec: one encrypted hop layer with its
/// routing header.
struct I2PTunnelDataPayload {
    /// Fixed-size encrypted tunnel message body (mainnet uses 1008 bytes).
    static let bodySize = 1008
    /// Total wire size: 4-byte tunnel ID + 16-byte IV + 1008-byte body.
    static let payloadSize = 4 + 16 + bodySize

    let tunnelID: UInt32
    /// 16-byte tunnel IV. The hop derives its CBC IV from this field through
    /// its IV key (IV_used = AES-256-ECB(IV_key, IV) XOR IV).
    let iv: Data
    /// 1008-byte AES-256-CBC body (no authentication tag, per the spec).
    let body: Data

    init(tunnelID: UInt32, iv: Data, body: Data) {
        precondition(iv.count == 16, "tunnel data IV must be 16 bytes")
        precondition(body.count == I2PTunnelDataPayload.bodySize,
                     "tunnel data body must be \(I2PTunnelDataPayload.bodySize) bytes")
        self.tunnelID = tunnelID
        self.iv = iv
        self.body = body
    }

    func serialize() -> Data {
        var w = I2PWriter()
        w.integer(tunnelID)
        w.raw(iv)
        w.raw(body)
        return w.data
    }

    static func parse(_ data: Data) throws -> I2PTunnelDataPayload {
        guard data.count == payloadSize else { throw I2NPError.invalidPayload }
        var r = I2PReader(data)
        let id = try r.integer()
        let iv = try r.raw(16)
        let body = try r.raw(bodySize)
        guard r.remaining == 0 else { throw I2PWireError.trailingData }
        return I2PTunnelDataPayload(tunnelID: id, iv: iv, body: body)
    }
}

/// TunnelGateway payload: a tunnel ID plus the I2NP message it delivers.
struct I2PTunnelGatewayPayload {
    let gatewayID: UInt32
    let message: Data

    func serialize() -> Data {
        var w = I2PWriter()
        w.integer(gatewayID)
        w.raw(message)
        return w.data
    }

    static func parse(_ data: Data) throws -> (gatewayID: UInt32, message: Data) {
        var r = I2PReader(data)
        let id = try r.integer()
        let message = try r.raw(r.remaining)
        return (id, message)
    }
}

/// Garlic clove delivery instructions, per I2NP §"GarlicCloveDeliveryInstructions":
/// one flag byte (bit 7 encrypted — never set; bits 6-5 delivery type:
/// 0 LOCAL, 1 DESTINATION, 2 ROUTER, 3 TUNNEL; bit 4 delay — never present;
/// bits 3-0 reserved zero), then the 32-byte "to" hash for
/// DESTINATION/ROUTER/TUNNEL, then the 4-byte tunnel ID for TUNNEL. Wire
/// lengths are therefore exactly 1, 33 or 37 bytes.
enum I2PDeliveryMode: UInt8 {
    case local = 0
    case destination = 1
    case router = 2
    case tunnel = 3
}

struct I2PDeliveryInstructions {
    let mode: I2PDeliveryMode
    let tunnelID: UInt32?
    /// Destination hash, router hash, or tunnel gateway hash depending on mode.
    let routerHash: Data?

    init(mode: I2PDeliveryMode, tunnelID: UInt32? = nil,
         routerHash: Data? = nil) {
        switch mode {
        case .local:
            precondition(tunnelID == nil && routerHash == nil)
        case .destination, .router:
            precondition(tunnelID == nil && routerHash?.count == 32)
        case .tunnel:
            precondition(tunnelID != nil && tunnelID != 0 && routerHash?.count == 32)
        }
        self.mode = mode
        self.tunnelID = tunnelID
        self.routerHash = routerHash
    }

    var flag: UInt8 {
        UInt8(mode.rawValue & 0x03) << 5
    }

    func serialize() -> Data {
        var w = I2PWriter()
        w.byte(flag)
        switch mode {
        case .local:
            break
        case .destination, .router:
            w.hash(routerHash!)
        case .tunnel:
            // Hash precedes the tunnel ID, per the spec.
            w.hash(routerHash!)
            w.integer(tunnelID!)
        }
        return w.data
    }

    static func parse(_ data: Data) throws -> (instructions: I2PDeliveryInstructions, consumed: Int) {
        var r = I2PReader(data)
        let flag = try r.byte()
        // Bit 7 would introduce a 32-byte session key; the spec never emits it
        // (1/33/37-byte forms only), so reject rather than misparse.
        guard flag & 0x80 == 0 else { throw I2NPError.invalidPayload }
        let type = (flag >> 5) & 0x03
        guard let mode = I2PDeliveryMode(rawValue: type) else {
            throw I2NPError.invalidPayload
        }
        // Bits 4-0 (delay/reserved) are never present on the wire.
        var tunnelID: UInt32?
        var routerHash: Data?
        switch mode {
        case .local:
            break
        case .destination, .router:
            routerHash = try r.raw(32)
        case .tunnel:
            routerHash = try r.raw(32)
            tunnelID = try r.integer()
            guard tunnelID != 0 else { throw I2NPError.invalidPayload }
        }
        let consumed = data.count - r.remaining
        let instructions = I2PDeliveryInstructions(mode: mode, tunnelID: tunnelID,
                                                   routerHash: routerHash)
        return (instructions, consumed)
    }
}