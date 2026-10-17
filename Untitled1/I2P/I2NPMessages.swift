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
}

/// I2NP message type codes carried in the type byte.
/// Codes assigned in this router's I2NP specification; the mainnet wire
/// codes are noted where they differ (reconciliation happens at interop).
enum I2NPMessageType: UInt8, CaseIterable {
    case databaseStore = 67
    case databaseLookup = 98
    case databaseSearchReply = 2
    case deliveryStatus = 3
    case options = 6
    case garlic = 94
    case tunnelData = 18
    case tunnelGateway = 15
    case dataMessage = 9
    case tunnelBuild = 10
    case tunnelBuildReply = 11
}

/// I2NP wire header: type byte, message ID, expiry and big-endian size.
struct I2NPMessageHeader {
    let type: I2NPMessageType
    let messageID: UInt32
    let expiration: Date
    let size: Int

    static let length = 17

    func serialize() -> Data {
        var w = I2PWriter()
        w.byte(type.rawValue)
        w.integer(messageID)
        w.long(UInt64((expiration.timeIntervalSince1970 * 1000).rounded()))
        w.integer(UInt32(size))
        return w.data
    }

    static func parse(_ data: Data) throws -> I2NPMessageHeader {
        var r = I2PReader(data)
        guard r.remaining >= I2NPMessageHeader.length else { throw I2PWireError.truncated }
        guard let type = I2NPMessageType(rawValue: try r.byte()) else { throw I2NPError.unsupportedType }
        let messageID = try r.integer()
        let ms = try r.long()
        let size = Int(try r.integer())
        return I2NPMessageHeader(
            type: type,
            messageID: messageID,
            expiration: Date(timeIntervalSince1970: Double(ms) / 1000),
            size: size
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
        self.expiration = expiration ?? Date().addingTimeInterval(120)
        self.payload = payload
    }

    func serialize() -> Data {
        var w = I2PWriter()
        w.byte(type.rawValue)
        w.integer(messageID)
        w.long(UInt64((expiration.timeIntervalSince1970 * 1000).rounded()))
        w.integer(UInt32(payload.count))
        w.raw(payload)
        return w.data
    }

    static func parse(_ data: Data) throws -> I2NPMessage {
        var r = I2PReader(data)
        guard let type = I2NPMessageType(rawValue: try r.byte()) else { throw I2NPError.unsupportedType }
        let messageID = try r.integer()
        let ms = try r.long()
        let size = Int(try r.integer())
        let payload = try r.raw(size)
        guard r.remaining == 0 else { throw I2PWireError.trailingData }
        return I2NPMessage(
            type: type,
            messageID: messageID,
            expiration: Date(timeIntervalSince1970: Double(ms) / 1000),
            payload: payload
        )
    }

    static func parseHeader(_ data: Data) throws -> I2NPMessageHeader {
        try I2NPMessageHeader.parse(data)
    }

    /// Expiry enforcement: stale messages are dropped on receipt.
    func isExpired(now: Date = Date()) -> Bool {
        expiration.timeIntervalSince(now) <= 0
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
        case .options:
            var r = I2PReader(payload)
            return .options(try r.mapping())
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
    case options([String: String])
    case dataMessage(Data)
    case garlic(Data)
    case tunnelData(I2PTunnelDataPayload)
    case tunnelGateway(gatewayID: UInt32, message: Data)
    case tunnelBuild(I2PTunnelBuildMessage)
    case tunnelBuildReply(I2PTunnelBuildReply)
}
/// TunnelData payload: one encrypted hop layer plus its routing header.
struct I2PTunnelDataPayload {
    /// Fixed-size encrypted tunnel message body (mainnet uses 1008 bytes).
    static let dataSize = 1008
    /// 16-byte Poly1305 tag rides with the ciphertext.
    static let ciphertextLength = dataSize + 16

    let tunnelID: UInt32
    /// Per-message IV (12 bytes) used as the layer cipher's nonce.
    let iv: Data
    let ciphertext: Data

    init(tunnelID: UInt32, iv: Data, ciphertext: Data) {
        precondition(iv.count == 12, "tunnel data IV must be 12 bytes")
        precondition(ciphertext.count == I2PTunnelDataPayload.ciphertextLength,
                     "tunnel data ciphertext must be \(I2PTunnelDataPayload.ciphertextLength) bytes")
        self.tunnelID = tunnelID
        self.iv = iv
        self.ciphertext = ciphertext
    }

    func serialize() -> Data {
        var w = I2PWriter()
        w.integer(tunnelID)
        w.raw(iv)
        w.raw(ciphertext)
        return w.data
    }

    static func parse(_ data: Data) throws -> I2PTunnelDataPayload {
        guard data.count == 4 + 12 + ciphertextLength else { throw I2NPError.invalidPayload }
        var r = I2PReader(data)
        let id = try r.integer()
        let iv = try r.raw(12)
        let ct = try r.raw(ciphertextLength)
        guard r.remaining == 0 else { throw I2PWireError.trailingData }
        return I2PTunnelDataPayload(tunnelID: id, iv: iv, ciphertext: ct)
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

/// Delivery instructions: local, tunnel and router delivery with an optional
/// delay. Serialized as [mode][flags][mode-specific][delay?]; the byte count
/// consumed is returned on parse so larger structures can embed instructions.
enum I2PDeliveryMode: UInt8 {
    case local = 0
    case tunnel = 1
    case router = 2
}

struct I2PDeliveryInstructions {
    let mode: I2PDeliveryMode
    let tunnelID: UInt32?
    let routerHash: Data?
    let delayMilliseconds: UInt32?

    init(mode: I2PDeliveryMode, tunnelID: UInt32? = nil,
         routerHash: Data? = nil, delayMilliseconds: UInt32? = nil) {
        switch mode {
        case .local:
            precondition(tunnelID == nil && routerHash == nil)
        case .tunnel:
            // Tunnel delivery names both the tunnel and its gateway router
            // (real I2P format: [1][tunnelID][routerHash]).
            precondition(tunnelID != nil && routerHash?.count == 32)
        case .router:
            precondition(tunnelID == nil && routerHash?.count == 32)
        }
        self.mode = mode
        self.tunnelID = tunnelID
        self.routerHash = routerHash
        self.delayMilliseconds = delayMilliseconds
    }

    func serialize() -> Data {
        var w = I2PWriter()
        w.byte(mode.rawValue)
        var flags: UInt8 = 0
        if delayMilliseconds != nil { flags |= 0x01 }
        w.byte(flags)
        switch mode {
        case .local:
            break
        case .tunnel:
            w.integer(tunnelID!)
            w.raw(routerHash!)
        case .router:
            w.raw(routerHash!)
        }
        if let delay = delayMilliseconds { w.integer(delay) }
        return w.data
    }

    static func parse(_ data: Data) throws -> (instructions: I2PDeliveryInstructions, consumed: Int) {
        var r = I2PReader(data)
        guard let mode = I2PDeliveryMode(rawValue: try r.byte()) else { throw I2NPError.invalidPayload }
        let flags = try r.byte()
        var tunnelID: UInt32?
        var routerHash: Data?
        switch mode {
        case .local:
            break
        case .tunnel:
            tunnelID = try r.integer()
            routerHash = try r.raw(32)
        case .router:
            routerHash = try r.raw(32)
        }
        var delay: UInt32?
        if flags & 0x01 != 0 { delay = try r.integer() }
        let consumed = data.count - r.remaining
        let instructions = I2PDeliveryInstructions(
            mode: mode, tunnelID: tunnelID, routerHash: routerHash, delayMilliseconds: delay
        )
        return (instructions, consumed)
    }
}