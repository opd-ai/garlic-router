//
//  I2PNetDBMessages.swift
//  Network Database messages per the I2P I2NP specification:
//  DatabaseStore (type 0), DatabaseLookup (type 1) and DatabaseSearchReply (type 2).
//  These payloads are wrapped by the I2NP layer (later milestone); the serialization
//  here covers each message's spec-defined body.
//

import Foundation

/// Database entry types carried in DatabaseStore messages.
enum I2PDatabaseEntryType: UInt8 {
    case routerInfo = 0
    case leaseSet = 1
}

/// I2NP DatabaseStore message: publish a RouterInfo/LeaseSet, reply to a lookup,
/// or acknowledge a store (nonzero reply token).
struct I2PDatabaseStore {
    /// 32-byte hash the entry is stored under (router identity hash / destination hash).
    let key: Data
    let entryType: I2PDatabaseEntryType
    /// Nonzero requests an acknowledgment and identifies the exchange.
    let replyToken: UInt32
    /// Reply destination (meaningful when replyToken > 0).
    let replyTunnelId: UInt32
    let replyGateway: Data
    /// Serialized RouterInfo or LeaseSet (uncompressed).
    let payload: Data

    init(key: Data, entryType: I2PDatabaseEntryType, replyToken: UInt32,
         replyTunnelId: UInt32 = 0, replyGateway: Data = Data(), payload: Data) {
        precondition(key.count == 32, "DatabaseStore key must be a 32-byte hash")
        if replyToken > 0 {
            precondition(replyGateway.count == 32, "reply gateway must be a 32-byte hash")
        }
        self.key = key
        self.entryType = entryType
        self.replyToken = replyToken
        self.replyTunnelId = replyTunnelId
        self.replyGateway = replyGateway
        self.payload = payload
    }

    func serialize() -> Data {
        var w = I2PWriter()
        w.hash(key)
        w.byte(entryType.rawValue)
        w.integer(replyToken)
        if replyToken > 0 {
            w.integer(replyTunnelId)
            w.hash(replyGateway)
        }
        w.short(UInt16(payload.count))
        w.raw(payload)
        return w.data
    }

    static func parse(_ data: Data) throws -> I2PDatabaseStore {
        var r = I2PReader(data)
        let key = try r.hash()
        guard let entryType = I2PDatabaseEntryType(rawValue: try r.byte()) else {
            throw I2PWireError.unsupportedAlgorithm
        }
        let replyToken = try r.integer()
        var replyTunnelId: UInt32 = 0
        var replyGateway = Data()
        if replyToken > 0 {
            replyTunnelId = try r.integer()
            replyGateway = try r.hash()
        }
        let size = Int(try r.short())
        let payload = try r.raw(size)
        guard r.remaining == 0 else { throw I2PWireError.trailingData }
        return I2PDatabaseStore(key: key, entryType: entryType, replyToken: replyToken,
                                replyTunnelId: replyTunnelId, replyGateway: replyGateway, payload: payload)
    }
}

/// I2NP DatabaseLookup message: query the netdb for a key.
struct I2PDatabaseLookup {
    let queryKey: Data
    /// Requesting router's hash.
    let fromHash: Data
    /// Floodfills to exclude from search replies (spec caps this at 3).
    let excludedPeers: [Data]
    /// Reply tunnels for LeaseSet-style replies (flag 0x01).
    let replyTunnels: [(gateway: Data, tunnelId: UInt32)]
    /// Nonzero requests a direct reply to replyGateway.
    let replyToken: UInt32
    let replyTunnelId: UInt32
    let replyGateway: Data

    init(queryKey: Data, fromHash: Data, excludedPeers: [Data] = [],
         replyTunnels: [(gateway: Data, tunnelId: UInt32)] = [],
         replyToken: UInt32, replyTunnelId: UInt32 = 0, replyGateway: Data = Data()) {
        precondition(queryKey.count == 32 && fromHash.count == 32)
        if replyToken > 0 {
            precondition(replyGateway.count == 32, "reply gateway must be a 32-byte hash")
        }
        self.queryKey = queryKey
        self.fromHash = fromHash
        self.excludedPeers = excludedPeers
        self.replyTunnels = replyTunnels
        self.replyToken = replyToken
        self.replyTunnelId = replyTunnelId
        self.replyGateway = replyGateway
    }

    func serialize() -> Data {
        var w = I2PWriter()
        w.hash(queryKey)
        w.hash(fromHash)
        let excluded = Array(excludedPeers.prefix(3))
        w.byte(UInt8(excluded.count))
        excluded.forEach { w.hash($0) }
        var flags: UInt8 = 0
        if !replyTunnels.isEmpty { flags |= 0x01 }
        w.byte(flags)
        if !replyTunnels.isEmpty {
            w.byte(UInt8(replyTunnels.count))
            for tunnel in replyTunnels {
                w.hash(tunnel.gateway)
                w.integer(tunnel.tunnelId)
            }
        }
        w.integer(replyToken)
        if replyToken > 0 {
            w.integer(replyTunnelId)
            w.hash(replyGateway)
        }
        return w.data
    }

    static func parse(_ data: Data) throws -> I2PDatabaseLookup {
        var r = I2PReader(data)
        let queryKey = try r.hash()
        let fromHash = try r.hash()
        let excludedCount = Int(try r.byte())
        var excludedPeers: [Data] = []
        for _ in 0..<excludedCount {
            excludedPeers.append(try r.hash())
        }
        let flags = try r.byte()
        var replyTunnels: [(gateway: Data, tunnelId: UInt32)] = []
        if flags & 0x01 != 0 {
            let tunnelCount = Int(try r.byte())
            for _ in 0..<tunnelCount {
                let gateway = try r.hash()
                let tunnelId = try r.integer()
                replyTunnels.append((gateway, tunnelId))
            }
        }
        let replyToken = try r.integer()
        var replyTunnelId: UInt32 = 0
        var replyGateway = Data()
        if replyToken > 0 {
            replyTunnelId = try r.integer()
            replyGateway = try r.hash()
        }
        guard r.remaining == 0 else { throw I2PWireError.trailingData }
        return I2PDatabaseLookup(queryKey: queryKey, fromHash: fromHash, excludedPeers: excludedPeers,
                                 replyTunnels: replyTunnels, replyToken: replyToken,
                                 replyTunnelId: replyTunnelId, replyGateway: replyGateway)
    }
}

/// I2NP DatabaseSearchReply message: a floodfill's answer when it does not hold the key,
/// listing the closest known peers for iterative querying.
struct I2PDatabaseSearchReply {
    let queryKey: Data
    /// Responding floodfill's hash.
    let fromHash: Data
    let peerHashes: [Data]

    init(queryKey: Data, fromHash: Data, peerHashes: [Data]) {
        precondition(queryKey.count == 32 && fromHash.count == 32)
        peerHashes.forEach { precondition($0.count == 32) }
        self.queryKey = queryKey
        self.fromHash = fromHash
        self.peerHashes = peerHashes
    }

    func serialize() -> Data {
        var w = I2PWriter()
        w.hash(queryKey)
        w.hash(fromHash)
        let peers = Array(peerHashes.prefix(255))
        w.byte(UInt8(peers.count))
        peers.forEach { w.hash($0) }
        return w.data
    }

    static func parse(_ data: Data) throws -> I2PDatabaseSearchReply {
        var r = I2PReader(data)
        let queryKey = try r.hash()
        let fromHash = try r.hash()
        let count = Int(try r.byte())
        var peerHashes: [Data] = []
        for _ in 0..<count {
            peerHashes.append(try r.hash())
        }
        guard r.remaining == 0 else { throw I2PWireError.trailingData }
        return I2PDatabaseSearchReply(queryKey: queryKey, fromHash: fromHash, peerHashes: peerHashes)
    }
}

/// A netdb message ready to be carried by the I2NP layer.
enum I2PNetDBMessage {
    case store(I2PDatabaseStore)
    case lookup(I2PDatabaseLookup)
    case searchReply(I2PDatabaseSearchReply)

    /// I2NP message type code for this payload.
    var i2npType: UInt8 {
        switch self {
        case .store: return 0
        case .lookup: return 1
        case .searchReply: return 2
        }
    }

    func serialize() -> Data {
        switch self {
        case .store(let s): return s.serialize()
        case .lookup(let l): return l.serialize()
        case .searchReply(let r): return r.serialize()
        }
    }

    static func parse(_ data: Data, i2npType: UInt8) throws -> I2PNetDBMessage {
        switch i2npType {
        case 0: return .store(try I2PDatabaseStore.parse(data))
        case 1: return .lookup(try I2PDatabaseLookup.parse(data))
        case 2: return .searchReply(try I2PDatabaseSearchReply.parse(data))
        default: throw I2PWireError.unsupportedAlgorithm
        }
    }
}