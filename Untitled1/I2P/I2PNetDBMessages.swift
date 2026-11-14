//
//  I2PNetDBMessages.swift
//  Network Database messages per the I2P I2NP specification:
//  DatabaseStore (I2NP type 1), DatabaseLookup (I2NP type 2) and
//  DatabaseSearchReply (I2NP type 3). These payloads are wrapped by the I2NP
//  layer; the serialization here covers each message's spec-defined body.
//

import Foundation

/// Database entry types carried in DatabaseStore messages, per the I2NP spec:
/// type 0 RouterInfo (gzip), 1 LeaseSet, 3 LeaseSet2, 5 EncryptedLeaseSet,
/// 7 MetaLeaseSet. The whole byte's low nibble is the type.
enum I2PDatabaseEntryType: UInt8 {
    case routerInfo = 0
    case leaseSet = 1
    case leaseSet2 = 3
    case encryptedLeaseSet2 = 5
    case metaLeaseSet2 = 7
}

/// I2NP DatabaseStore message: publish a RouterInfo/LeaseSet, reply to a lookup,
/// or acknowledge a store (nonzero reply token).
struct I2PDatabaseStore {
    /// 32-byte hash the entry is stored under (router identity hash / destination hash).
    let key: Data
    let entryType: I2PDatabaseEntryType
    /// Nonzero requests a DeliveryStatus acknowledgment and identifies the exchange.
    let replyToken: UInt32
    /// Reply destination (meaningful when replyToken > 0).
    let replyTunnelId: UInt32
    let replyGateway: Data
    /// Serialized RouterInfo or LeaseSet (uncompressed in memory; a type-0
    /// RouterInfo is gzip-compressed on the wire).
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
        if entryType == .routerInfo {
            // Spec: a type-0 entry is a 2-byte compressed size followed by the
            // gzip-compressed RouterInfo. Reference routers do not sniff or
            // fall back to plain bytes.
            let compressed = I2PGzip.compress(payload)
            guard compressed.count <= Int(UInt16.max) else {
                return w.data // unreachable for a spec-sized RouterInfo
            }
            w.short(UInt16(compressed.count))
            w.raw(compressed)
        } else {
            w.raw(payload)
        }
        return w.data
    }

    static func parse(_ data: Data) throws -> I2PDatabaseStore {
        var r = I2PReader(data)
        let key = try r.hash()
        // Reference routers mask the type byte to its low nibble.
        let typeByte = try r.byte() & 0x0F
        guard let entryType = I2PDatabaseEntryType(rawValue: typeByte) else {
            throw I2PWireError.unsupportedAlgorithm
        }
        let replyToken = try r.integer()
        var replyTunnelId: UInt32 = 0
        var replyGateway = Data()
        if replyToken > 0 {
            replyTunnelId = try r.integer()
            replyGateway = try r.hash()
        }
        let payload: Data
        if entryType == .routerInfo {
            let size = Int(try r.short())
            let compressed = try r.raw(size)
            payload = try I2PGzip.decompress(compressed)
        } else {
            payload = try r.raw(r.remaining)
        }
        guard r.remaining == 0 else { throw I2PWireError.trailingData }
        return I2PDatabaseStore(key: key, entryType: entryType, replyToken: replyToken,
                                replyTunnelId: replyTunnelId, replyGateway: replyGateway, payload: payload)
    }
}

/// DatabaseLookup lookup-type flags (flag bits 3-2). The spec deprecates `any`
/// as of 0.9.16: a lookup states whether it wants a LeaseSet, a RouterInfo, or
/// a list of non-floodfill peers (exploration), and reference floodfills use it
/// to decide what to answer.
enum I2PLookupKind: UInt8 {
    case any = 0
    case leaseSet = 1
    case routerInfo = 2
    case exploration = 3
}

/// I2NP DatabaseLookup message: query the netdb for a key.
///
/// Wire layout per the spec: key (32) + from (32) + flags (1) +
/// [replyTunnelId (4) when deliveryFlag] + size (2) + excluded hashes +
/// [reply key/tags when encryption is requested]. There is no reply token in a
/// DatabaseLookup; `replyToken` is kept only as a local correlation handle.
struct I2PDatabaseLookup {
    let queryKey: Data
    /// Requesting router's hash (or reply-tunnel gateway when deliveryFlag is set).
    let fromHash: Data
    /// Floodfills to exclude from search replies (spec caps this at 512).
    let excludedPeers: [Data]
    /// Reply tunnels for LeaseSet-style replies (flag 0x01). Only the first is
    /// serialized, per the spec's single replyTunnelId.
    let replyTunnels: [(gateway: Data, tunnelId: UInt32)]
    /// Local-only correlation handle; never serialized.
    let replyToken: UInt32
    let replyTunnelId: UInt32
    let replyGateway: Data
    /// True when the requester asked for an encrypted reply (flags bits 1/4).
    let encryptedReplyRequested: Bool
    let lookupType: I2PLookupKind

    init(queryKey: Data, fromHash: Data, excludedPeers: [Data] = [],
         replyTunnels: [(gateway: Data, tunnelId: UInt32)] = [],
         replyToken: UInt32 = 0, replyTunnelId: UInt32 = 0, replyGateway: Data = Data(),
         encryptedReplyRequested: Bool = false, lookupType: I2PLookupKind = .any) {
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
        self.encryptedReplyRequested = encryptedReplyRequested
        self.lookupType = lookupType
    }

    func serialize() -> Data {
        var w = I2PWriter()
        w.hash(queryKey)
        let tunnel = replyTunnels.first
        w.hash(tunnel?.gateway ?? fromHash)
        var flags: UInt8 = (lookupType.rawValue & 0x03) << 2
        if tunnel != nil { flags |= 0x01 }
        w.byte(flags)
        if let tunnel {
            w.integer(tunnel.tunnelId)
        }
        let excluded = Array(excludedPeers.prefix(512))
        w.short(UInt16(excluded.count))
        excluded.forEach { w.hash($0) }
        return w.data
    }

    static func parse(_ data: Data) throws -> I2PDatabaseLookup {
        var r = I2PReader(data)
        let queryKey = try r.hash()
        let fromHash = try r.hash()
        let flags = try r.byte()
        var replyTunnelId: UInt32 = 0
        if flags & 0x01 != 0 {
            replyTunnelId = try r.integer()
        }
        let excludedCount = Int(try r.short())
        guard excludedCount <= 512 else { throw I2PWireError.invalidFormat }
        var excludedPeers: [Data] = []
        for _ in 0..<excludedCount {
            excludedPeers.append(try r.hash())
        }
        // Remaining bytes are the encrypted-reply key/tags when requested; we do
        // not decrypt replies, so they are validated only by the flag.
        let encrypted = flags & 0x12 != 0
        let tunnels: [(gateway: Data, tunnelId: UInt32)] = replyTunnelId != 0
            ? [(fromHash, replyTunnelId)] : []
        return I2PDatabaseLookup(queryKey: queryKey,
                                 fromHash: fromHash,
                                 excludedPeers: excludedPeers,
                                 replyTunnels: tunnels,
                                 replyToken: 0,
                                 replyTunnelId: replyTunnelId,
                                 replyGateway: fromHash,
                                 encryptedReplyRequested: encrypted,
                                 lookupType: I2PLookupKind(rawValue: (flags >> 2) & 0x03) ?? .any)
    }
}

/// I2NP DatabaseSearchReply message: a floodfill's answer when it does not hold the key,
/// listing the closest known peers for iterative querying.
///
/// Wire layout per the spec: query key (32) + count (1) + peer hashes (count × 32)
/// + the responding router's hash (32, at the END). The `from` hash trailing the
/// peer list is easy to place second by intuition, and doing so made every real
/// search reply unparseable — which is why mainnet lookups never saw an answer.
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
        let peers = Array(peerHashes.prefix(255))
        w.byte(UInt8(peers.count))
        for peer in peers { w.hash(peer) }
        w.hash(fromHash)
        return w.data
    }

    static func parse(_ data: Data) throws -> I2PDatabaseSearchReply {
        var r = I2PReader(data)
        let queryKey = try r.hash()
        let count = Int(try r.byte())
        var peerHashes: [Data] = []
        peerHashes.reserveCapacity(count)
        for _ in 0..<count {
            peerHashes.append(try r.hash())
        }
        let fromHash = try r.hash()
        guard r.remaining == 0 else { throw I2PWireError.trailingData }
        return I2PDatabaseSearchReply(queryKey: queryKey, fromHash: fromHash, peerHashes: peerHashes)
    }
}

/// A netdb message ready to be carried by the I2NP layer.
enum I2PNetDBMessage {
    case store(I2PDatabaseStore)
    case lookup(I2PDatabaseLookup)
    case searchReply(I2PDatabaseSearchReply)
    /// DeliveryStatus acknowledgment: message ID = the store's reply token.
    case deliveryStatus(messageID: UInt32, timestamp: Date)

    /// I2NP message type code for this payload, per the spec.
    var i2npType: UInt8 {
        switch self {
        case .store: return 1
        case .lookup: return 2
        case .searchReply: return 3
        case .deliveryStatus: return 10
        }
    }

    func serialize() -> Data {
        switch self {
        case .store(let s): return s.serialize()
        case .lookup(let l): return l.serialize()
        case .searchReply(let r): return r.serialize()
        case .deliveryStatus(let id, let timestamp):
            var w = I2PWriter()
            w.integer(id)
            w.long(UInt64((timestamp.timeIntervalSince1970 * 1000).rounded()))
            return w.data
        }
    }

    static func parse(_ data: Data, i2npType: UInt8) throws -> I2PNetDBMessage {
        switch i2npType {
        case 1: return .store(try I2PDatabaseStore.parse(data))
        case 2: return .lookup(try I2PDatabaseLookup.parse(data))
        case 3: return .searchReply(try I2PDatabaseSearchReply.parse(data))
        case 10:
            var r = I2PReader(data)
            let id = try r.integer()
            let ms = try r.long()
            guard r.remaining == 0 else { throw I2PWireError.trailingData }
            return .deliveryStatus(messageID: id,
                                   timestamp: Date(timeIntervalSince1970: Double(ms) / 1000))
        default: throw I2PWireError.unsupportedAlgorithm
        }
    }
}