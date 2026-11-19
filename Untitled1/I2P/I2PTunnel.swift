//
//  I2PTunnel.swift
//  Tunnel model, hop participation, and the originator-side builder.
//

import Foundation
import CryptoKit

/// One hop of a built tunnel, in tunnel data-path order.
struct I2PTunnelHop {
    let routerHash: Data
    /// Tunnel ID messages arrive on at this hop.
    let receiveTunnelID: UInt32
    /// The receive tunnel ID of the next hop in the data path (0 = tunnel end;
    /// for an inbound tunnel the final entry is the originator's local ID).
    let nextTunnelID: UInt32
    /// True when the next hop is the tunnel end (originator for inbound,
    /// final router for outbound).
    let isTunnelEndpoint: Bool
}

/// A built unidirectional tunnel with a 10-30 minute lifetime.
final class I2PTunnel {
    enum Direction: String {
        case outbound
        case inbound
    }

    let direction: Direction
    /// Hops in tunnel data-path order.
    let hops: [I2PTunnelHop]
    /// First hop's receive tunnel ID (the gateway the outside world sends to).
    let gatewayTunnelID: UInt32
    /// Final receive tunnel ID (a remote router for outbound, the originator
    /// for inbound).
    let endpointTunnelID: UInt32
    /// Per-hop layer keys, in data-path order (carried to hops via build
    /// records and kept here for the message pipeline).
    let layerKeys: [Data]
    let ivKeys: [Data]
    let createdAt: Date
    let expiresAt: Date
    /// Measured build round-trip latency; used for selection.
    let buildLatency: TimeInterval?

    init(direction: I2PTunnel.Direction,
         hops: [I2PTunnelHop],
         gatewayTunnelID: UInt32,
         endpointTunnelID: UInt32,
         layerKeys: [Data],
         ivKeys: [Data],
         createdAt: Date = Date(),
         expiresAt: Date,
         buildLatency: TimeInterval?) {
        self.direction = direction
        self.hops = hops
        self.gatewayTunnelID = gatewayTunnelID
        self.endpointTunnelID = endpointTunnelID
        self.layerKeys = layerKeys
        self.ivKeys = ivKeys
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.buildLatency = buildLatency
    }

    func remainingLifetime(now: Date = Date()) -> TimeInterval {
        expiresAt.timeIntervalSince(now)
    }

    func isExpired(now: Date = Date()) -> Bool {
        now >= expiresAt
    }

    var hopCount: Int { hops.count }
}

/// A candidate router for a tunnel hop: router hash + X25519 encryption key.
struct I2PTunnelPeer {
    let routerHash: Data
    let encryptionPublicKey: Data
}

/// Supplies candidate hops for tunnel builds.
protocol I2PTunnelPeerProvider: AnyObject {
    func peers(count: Int, excluding: Set<Data>) -> [I2PTunnelPeer]

    /// Asks the provider to refresh its candidate set; returns true when at
    /// least one hop candidate is available afterwards. Default: no-op.
    func refreshPeers() async -> Bool

    /// Reports the outcome of a build attempt so the provider can keep a
    /// profile per hop (failures bench a hop with exponential backoff).
    /// Default: no-op.
    func recordBuildOutcome(_ outcome: I2PTunnelPeerBuildOutcome)
}

extension I2PTunnelPeerProvider {
    func refreshPeers() async -> Bool { false }
    func recordBuildOutcome(_ outcome: I2PTunnelPeerBuildOutcome) {}
}

/// Carries tunnel build traffic between routers. The NTCP2 transport layer
/// implements this; tests use the loopback hub.
protocol I2PTunnelBuildTransport: AnyObject {
    func sendBuild(_ message: I2PTunnelBuildMessage, to routerHash: Data)
    func sendBuildReply(_ body: Data, to routerHash: Data)

    /// Delivers a build reply to the end of the creator's reply tunnel: the
    /// tunnel-creation spec's "Reply through existing inbound D-E-F", where an
    /// outbound endpoint cannot dial a creator behind NAT and therefore answers
    /// the reply route the creator named in its record (flags bit 6).
    func sendBuildReply(_ body: Data, throughTunnel tunnelID: UInt32, to gatewayRouterHash: Data)

    /// Whether a reply addressed to a tunnel ID really reaches that tunnel's
    /// endpoint. Default false: a transport that cannot carry tunnel traffic
    /// (the loopback hub) must never be handed a tunnel reply route, because the
    /// reply would be lost inside a tunnel nothing forwards.
    var supportsTunnelBuildReplies: Bool { get }
}

extension I2PTunnelBuildTransport {
    var supportsTunnelBuildReplies: Bool { false }

    /// A transport without tunnel delivery falls back to the direct send, which
    /// is what its reply route means in that case (the caller checks
    /// `supportsTunnelBuildReplies` before choosing a tunnel route).
    func sendBuildReply(_ body: Data, throughTunnel tunnelID: UInt32, to gatewayRouterHash: Data) {
        sendBuildReply(body, to: gatewayRouterHash)
    }
}

/// Test/development message bus connecting participants directly.
final class I2PTunnelBuildHub {
    private let lock = NSLock()
    private var participants: [Data: I2PTunnelParticipant] = [:]

    func register(_ participant: I2PTunnelParticipant) {
        lock.lock()
        participants[participant.localRouterHash] = participant
        lock.unlock()
    }

    func deliverBuild(_ message: I2PTunnelBuildMessage, from source: Data, to target: Data) {
        lock.lock()
        let participant = participants[target]
        lock.unlock()
        guard let participant else { return }
        Task { participant.handleBuild(message, from: source) }
    }

    func deliverBuildReply(_ body: Data, from source: Data, to target: Data) {
        lock.lock()
        let participant = participants[target]
        lock.unlock()
        guard let participant else { return }
        Task { participant.handleBuildReply(body, from: source) }
    }
}

final class I2PTunnelLoopbackTransport: I2PTunnelBuildTransport {
    private weak var hub: I2PTunnelBuildHub?
    private let localRouterHash: Data

    init(hub: I2PTunnelBuildHub, localRouterHash: Data) {
        self.hub = hub
        self.localRouterHash = localRouterHash
    }

    func sendBuild(_ message: I2PTunnelBuildMessage, to routerHash: Data) {
        hub?.deliverBuild(message, from: localRouterHash, to: routerHash)
    }

    func sendBuildReply(_ body: Data, to routerHash: Data) {
        hub?.deliverBuildReply(body, from: localRouterHash, to: routerHash)
    }
}
/// State a router keeps when it participates in a tunnel as a hop.
struct I2PTunnelHopState {
    let receiveTunnelID: UInt32
    /// The record's next-hop router. Transit hops forward to it, and an
    /// outbound endpoint answers the build to it (flags bit 6).
    let nextHopHash: Data
    let nextTunnelID: UInt32
    /// True for the last hop in the build message path: after decrypting its
    /// layer it delivers the inner TunnelGateway payload (outbound: to the
    /// router the creator designated, inbound: to the originator).
    let isMessagePathEnd: Bool
    let layerKey: Data
    let ivKey: Data
    let registeredAt: Date
    /// Where the decrypted inner TunnelGateway payload goes at the end of the
    /// message path. Separate from `nextHopHash` because those are two
    /// different addresses: the spec gives the next-hop fields to the build
    /// reply (an outbound endpoint answers there) and routes the payload by its
    /// own delivery instructions. Defaults to the next hop, which is the right
    /// answer for every hop that is not an outbound endpoint.
    let payloadDeliveryHash: Data

    init(receiveTunnelID: UInt32, nextHopHash: Data, nextTunnelID: UInt32,
         isMessagePathEnd: Bool, layerKey: Data, ivKey: Data, registeredAt: Date,
         payloadDeliveryHash: Data? = nil) {
        self.receiveTunnelID = receiveTunnelID
        self.nextHopHash = nextHopHash
        self.nextTunnelID = nextTunnelID
        self.isMessagePathEnd = isMessagePathEnd
        self.layerKey = layerKey
        self.ivKey = ivKey
        self.registeredAt = registeredAt
        self.payloadDeliveryHash = payloadDeliveryHash ?? nextHopHash
    }

    /// Hop participation state expires with the tunnel (~30 min upper bound).
    static let participationTTL: TimeInterval = 1800

    func isExpired(now: Date = Date()) -> Bool {
        now.timeIntervalSince(registeredAt) > Self.participationTTL
    }
}

/// A router acting as a tunnel hop: decrypts its own request record from a
/// VariableTunnelBuild, registers participation state (or rejects), and both
/// forwards the build and accumulates the hop-by-hop build reply.
final class I2PTunnelParticipant {
    let localRouterHash: Data
    let localEncryptionKey: Curve25519.KeyAgreement.PrivateKey
    private let transport: I2PTunnelBuildTransport
    private let lock = NSLock()

    /// Test/policy hook: force every build request to be rejected with this
    /// return code (nil = normal acceptance logic).
    var forcedRejectCode: UInt8?

    /// Ceiling on concurrently participating tunnels (nil = unlimited).
    /// The participation screen derives it from the tunnel-share ratio: 0 turns
    /// transit participation off entirely, 100% admits the full quota.
    private var transitBudget: Int?

    /// The number of participating tunnels the share ratio allows: 0% none,
    /// 100% the 32-tunnel transit budget, proportional in between.
    static func transitTunnelBudget(forSharePercent share: Int) -> Int {
        guard share > 0 else { return 0 }
        return max(1, Int((Double(min(share, 100)) / 100) * 32))
    }

    /// Applies the tunnel-share ratio as the participating-tunnel ceiling.
    func setTransitBudget(_ budget: Int?) {
        lock.lock()
        transitBudget = budget
        lock.unlock()
    }

    /// Live (non-expired) hop states, i.e. tunnels we currently carry for
    /// other participants.
    var activeHopStateCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return hopStates.values.filter { !$0.isExpired() }.count
    }

    /// Builds we forwarded: message ID → the peer we received it from, plus
    /// the material needed to append our reply record on the way back.
    private struct PendingBuild {
        let source: Data
        /// The hop this build was forwarded to; its reply comes back from it.
        let nextHopHash: Data
        let recordIndex: UInt8
        let recordCount: Int
        let material: I2PTunnelBuildReplyMaterial
        let deadline: Date
    }

    private var pendingBuilds: [PendingBuild] = []
    private var hopStates: [UInt32: I2PTunnelHopState] = [:]
    /// Reply consumers registered by originators (builders) on this router.
    private var replyConsumers: [(I2PTunnelBuildReply) -> Void] = []

    private static let pendingReplyTTL: TimeInterval = 60

    init(localRouterHash: Data,
         localEncryptionKey: Curve25519.KeyAgreement.PrivateKey,
         transport: I2PTunnelBuildTransport) {
        self.localRouterHash = localRouterHash
        self.localEncryptionKey = localEncryptionKey
        self.transport = transport
    }

    /// Registers a consumer for build replies that are not build relays
    /// (i.e. replies addressed to this router as the tunnel creator).
    func addReplyConsumer(_ consumer: @escaping (I2PTunnelBuildReply) -> Void) {
        lock.lock()
        replyConsumers.append(consumer)
        lock.unlock()
    }

    func handleBuild(_ message: I2PTunnelBuildMessage, from source: Data) {
        var found: (record: I2PTunnelBuildRequestRecord,
                    material: I2PTunnelBuildReplyMaterial,
                    index: Int)?
        for (index, wire) in message.records.enumerated() {
            if let (plaintext, material) = try? I2PTunnelBuildCrypto.decryptRecordWithMaterial(
                    wire,
                    localEncryptionKey: localEncryptionKey,
                    localRouterHash: localRouterHash,
                    recordIndex: UInt8(index)),
               let parsed = try? I2PTunnelBuildRequestRecord.parse(plaintext) {
                found = (parsed, material, index)
                break
            }
        }
        guard let match = found else { return } // no record for us; drop
        let record = match.record
        let isMessagePathEnd = record.isMessagePathEnd
            || record.nextHopHash.allSatisfy { $0 == 0 }

        let code = acceptanceCode(for: record)
        if code != I2PTunnelBuildReturnCode.accepted.rawValue {
            // Reject: reply immediately with our record; do not forward. The
            // rejection travels the same route an acceptance would, so a creator
            // behind NAT learns why its build failed.
            initiateReply(recordCount: message.records.count,
                          recordIndex: UInt8(match.index),
                          material: match.material,
                          code: code,
                          route: replyRoute(for: record, source: source))
            return
        }

        let state = I2PTunnelHopState(
            receiveTunnelID: record.receiveTunnelID,
            nextHopHash: record.nextHopHash,
            nextTunnelID: record.nextTunnelID,
            isMessagePathEnd: isMessagePathEnd,
            layerKey: match.material.layerKey,
            ivKey: match.material.ivKey,
            registeredAt: Date(),
            payloadDeliveryHash: record.payloadDeliveryHash
        )
        lock.lock()
        hopStates[record.receiveTunnelID] = state
        if !isMessagePathEnd {
            pendingBuilds.append(PendingBuild(
                source: source,
                nextHopHash: record.nextHopHash,
                recordIndex: UInt8(match.index),
                recordCount: message.records.count,
                material: match.material,
                deadline: Date().addingTimeInterval(Self.pendingReplyTTL)
            ))
        }
        pruneHopStatesLocked()
        lock.unlock()

        if isMessagePathEnd {
            // Message-path end (outbound endpoint or inbound gateway hop).
            initiateReply(recordCount: message.records.count,
                          recordIndex: UInt8(match.index),
                          material: match.material,
                          code: I2PTunnelBuildReturnCode.accepted.rawValue,
                          route: replyRoute(for: record, source: source))
        } else {
            transport.sendBuild(message, to: record.nextHopHash)
        }
    }

    /// Where this hop's build reply goes.
    ///
    /// A transit hop and an inbound gateway answer the router the build came
    /// from, so the reply walks back along the message path and every hop adds
    /// its own record. An outbound endpoint does not: flags bit 6 means "send
    /// the reply to the specified next hop in a Tunnel Build Reply Message", and
    /// that next hop is the creator's reply route — normally one of its inbound
    /// tunnels — because an outbound endpoint cannot dial a creator behind NAT.
    /// Answering the previous hop instead left the creator waiting for a reply
    /// that the reply tunnel never carried, so every tunnel another router built
    /// through this one looked rejected to its creator.
    private func replyRoute(for record: I2PTunnelBuildRequestRecord,
                            source: Data) -> (gateway: Data, tunnelID: UInt32) {
        guard record.flags & I2PTunnelBuildRequestRecord.flagOutboundEndpoint != 0,
              !record.nextHopHash.allSatisfy({ $0 == 0 }) else {
            return (gateway: source, tunnelID: 0)
        }
        return (gateway: record.nextHopHash, tunnelID: record.nextTunnelID)
    }

    /// Receives a reply body on the build's way back: re-encrypts the other
    /// records, installs our Poly1305 reply at our index, and forwards to the
    /// router we received the request from; otherwise hands the reply to a
    /// registered originator consumer.
    func handleBuildReply(_ body: Data, from source: Data) {
        guard let reply = try? I2PTunnelBuildReply.parse(body) else { return }
        lock.lock()
        let match = pendingBuilds.first { pending in
            guard Date() < pending.deadline,
                  pending.nextHopHash == source,
                  pending.recordCount == reply.encryptedRecords.count,
                  Int(pending.recordIndex) < reply.encryptedRecords.count else { return false }
            return true
        }
        if let match {
            pendingBuilds.removeAll { $0.recordIndex == match.recordIndex && $0.source == match.source }
        }
        lock.unlock()
        guard let match else {
            let consumers = replyConsumers
            consumers.forEach { $0(reply) }
            return
        }
        guard let own = try? I2PTunnelBuildCrypto.encryptReplyRecord(
            I2PTunnelBuildReplyRecord(receiveTunnelID: 0,
                                      returnCode: I2PTunnelBuildReturnCode.accepted.rawValue),
            material: match.material,
            recordIndex: match.recordIndex) else { return }
        var records = reply.encryptedRecords.enumerated().map { index, wire -> Data in
            if index == Int(match.recordIndex) { return own }
            return I2PTunnelBuildCrypto.reencryptReplyRecord(
                wire, material: match.material, recordIndex: UInt8(index))
        }
        if records.count > Int(match.recordIndex) { records[Int(match.recordIndex)] = own }
        let updated = I2PTunnelBuildReply(encryptedRecords: records)
        transport.sendBuildReply(updated.serialize(), to: match.source)
    }

    func hasHopState(receiveTunnelID: UInt32) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return hopStates[receiveTunnelID] != nil
    }

    func hopState(receiveTunnelID: UInt32) -> I2PTunnelHopState? {
        lock.lock()
        defer { lock.unlock() }
        return hopStates[receiveTunnelID]
    }

    var hopStateCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return hopStates.count
    }

    func pruneHopStates(now: Date = Date()) -> Int {
        lock.lock()
        defer { lock.unlock() }
        return pruneHopStatesLocked(now: now)
    }

    /// Test hook: registers a hop state directly (bypasses the build flow).
    func testInjectHopState(_ state: I2PTunnelHopState) {
        lock.lock()
        hopStates[state.receiveTunnelID] = state
        lock.unlock()
    }

    @discardableResult
    private func pruneHopStatesLocked(now: Date = Date()) -> Int {
        let before = hopStates.count
        hopStates = hopStates.filter { !$0.value.isExpired(now: now) }
        pendingBuilds = pendingBuilds.filter { $0.deadline > now }
        return before - hopStates.count
    }

    private func acceptanceCode(for record: I2PTunnelBuildRequestRecord) -> UInt8 {
        if let forced = forcedRejectCode { return forced }
        // A self-addressed next hop is only a loop when this hop must forward
        // onward; message-path end records may target ourselves (single-hop
        // tunnels deliver their gateway payload locally).
        if !record.isMessagePathEnd && record.nextHopHash == localRouterHash && !record.nextHopIsOriginator {
            return I2PTunnelBuildReturnCode.loop.rawValue
        }
        lock.lock()
        let inUse = hopStates[record.receiveTunnelID] != nil
        let liveCount = hopStates.values.filter { !$0.isExpired() }.count
        let budget = transitBudget
        lock.unlock()
        if inUse { return I2PTunnelBuildReturnCode.tunnelIDInUse.rawValue }
        // The tunnel-share ratio caps how many tunnels we carry for others:
        // 0% refuses transit builds outright, a full budget reports overload.
        if let budget, liveCount >= budget {
            return budget == 0
                ? I2PTunnelBuildReturnCode.bandwidthExceeded.rawValue
                : I2PTunnelBuildReturnCode.overload.rawValue
        }
        return I2PTunnelBuildReturnCode.accepted.rawValue
    }

    private func initiateReply(recordCount: Int,
                               recordIndex: UInt8,
                               material: I2PTunnelBuildReplyMaterial,
                               code: UInt8,
                               route: (gateway: Data, tunnelID: UInt32)) {
        guard let own = try? I2PTunnelBuildCrypto.encryptReplyRecord(
            I2PTunnelBuildReplyRecord(receiveTunnelID: 0, returnCode: code),
            material: material,
            recordIndex: recordIndex) else { return }
        var records = (0..<max(1, recordCount)).map { _ in
            I2PCrypto.randomBytes(I2PTunnelBuildReply.encryptedRecordLength)
        }
        if records.count > Int(recordIndex) { records[Int(recordIndex)] = own }
        let reply = I2PTunnelBuildReply(encryptedRecords: records)
        let body = reply.serialize()
        // A reply route with a tunnel ID is the creator's inbound tunnel: the
        // reply has to be carried through it, not addressed to the gateway as a
        // standalone message.
        if route.tunnelID != 0, transport.supportsTunnelBuildReplies {
            transport.sendBuildReply(body, throughTunnel: route.tunnelID, to: route.gateway)
        } else {
            transport.sendBuildReply(body, to: route.gateway)
        }
    }
}

/// What a tunnel hop does with a TunnelData payload after decrypting its layer.
enum I2PTunnelHopAction {
    /// Reveal the next hop's (already-encrypted) TunnelData payload and
    /// forward it over the transport to the next hop's router.
    case forward(nextHopHash: Data, tunnelData: I2PTunnelDataPayload)
    /// Message-path end: hand the inner TunnelGateway payload to the tunnel's
    /// gateway router (outbound) or the originator (inbound).
    case deliverGateway(toRouterHash: Data, gatewayPayload: Data)
}

extension I2PTunnelParticipant {
    /// The I2NP tunnel message pipeline per the tunnel spec: decrypt the hop's
    /// AES-256-CBC layer (the full 1008-byte body, CBC IV chained through the
    /// hop's IV key), then either forward the revealed next-hop TunnelData
    /// message — carrying its ciphertext region byte-for-byte and re-randomizing
    /// the region this hop's key never covered — or, at the message path's end,
    /// deliver the inner TunnelGateway payload to the tunnel's gateway router
    /// (outbound) or the originator (inbound).
    func processTunnelData(_ payload: I2PTunnelDataPayload) throws -> I2PTunnelHopAction {
        let state: I2PTunnelHopState? = {
            lock.lock()
            defer { lock.unlock() }
            return hopStates[payload.tunnelID]
        }()
        guard let state, !state.isExpired() else { throw I2NPError.unknownTunnel }
        let content = try I2PTunnelLayerCipher.unwrap(
            body: payload.body,
            layerKey: state.layerKey,
            ivField: payload.iv,
            ivKey: state.ivKey
        )
        if state.isMessagePathEnd {
            // Innermost content is the TunnelGateway payload: [gatewayID][I2NP].
            guard content.count >= 4 else { throw I2NPError.invalidPayload }
            return .deliverGateway(toRouterHash: state.payloadDeliveryHash, gatewayPayload: content)
        }
        // Transit hop: [nextTunnelID (4)][nextIV (16)][next ciphertext region].
        guard content.count >= 20 else { throw I2NPError.invalidPayload }
        let bytes = Array(content)
        let nextTunnelID = (UInt32(bytes[0]) << 24) | (UInt32(bytes[1]) << 16)
                         | (UInt32(bytes[2]) << 8) | UInt32(bytes[3])
        let nextIV = Data(bytes[4..<20])
        let nextBody = Data(bytes[20..<bytes.count])
        let filler = I2PTunnelDataPayload.bodySize - nextBody.count
        guard filler >= 0 else { throw I2NPError.invalidPayload }
        var body = nextBody
        body.append(contentsOf: I2PCrypto.randomBytes(filler))
        let inner = I2PTunnelDataPayload(tunnelID: nextTunnelID, iv: nextIV, body: body)
        guard inner.tunnelID == state.nextTunnelID else { throw I2NPError.invalidPayload }
        return .forward(nextHopHash: state.nextHopHash, tunnelData: inner)
    }
}
/// Builds tunnels from the originator's side: generates per-hop material,
/// encrypts VariableTunnelBuild records to each hop's X25519 identity key,
/// sends the build through the message path, and assembles the tunnel from
/// the accumulated BuildReply.
final class I2PTunnelBuilder {
    private struct BuildContext {
        let direction: I2PTunnel.Direction
        let peerHashes: [Data]
        let receiveIDs: [UInt32]
        let layerKeys: [Data]
        let ivKeys: [Data]
        /// Per-hop reply material in hop order: the originator's side of the
        /// short-build record KDF, and the key order a walk-back reply peels in.
        let hopReplyMaterials: [I2PTunnelBuildReplyMaterial]
        /// Per-slot reply material in wire order; nil for a fake record.
        let replyMaterials: [I2PTunnelBuildReplyMaterial?]
        /// The wire slot each hop's record was placed in, in hop order.
        let positions: [Int]
        /// The slot holding the message-path end's record (the outbound
        /// endpoint, or the inbound build's hop nearest the originator).
        let endpointSlot: Int
        let originatorEndpointID: UInt32
        let sentAt: Date
        let lifetime: TimeInterval
    }

    /// Where each hop's record sits in a build message.
    struct BuildLayout: Equatable {
        /// Records the message carries: the real hops plus the spec's fake
        /// records, and never fewer than four.
        let slotCount: Int
        /// The wire slot of each hop's record, in hop order.
        let positions: [Int]
        /// The free slot given to an inbound build's originator decoy.
        let originatorSlot: Int?
    }

    /// The tunnel-creation spec's build-record layout: "Build record order must
    /// be randomized", "the recommended minimum number of build records is 4",
    /// and for an inbound build "there must always be one 'fake' record for the
    /// originating router". Real records land on random slots and the rest are
    /// filler, so a hop can infer neither its own position nor the hop count.
    static func buildLayout(hopCount: Int, direction: I2PTunnel.Direction) -> BuildLayout {
        let required = hopCount + (direction == .inbound ? 1 : 0)
        let slotCount = min(8, max(4, required))
        var free = Array(0..<slotCount).shuffled()
        let positions = [Int](free.prefix(hopCount))
        free.removeFirst(positions.count)
        return BuildLayout(slotCount: slotCount,
                           positions: positions,
                           originatorSlot: direction == .inbound ? free.first : nil)
    }

    /// The inbound build's mandatory decoy record: an X25519 ephemeral public key
    /// under this router's own truncated identity hash, so the hop nearest the
    /// originator cannot tell that the tunnel's endpoint is right beside it. The
    /// remainder is filler no hop can open.
    static func originatorDecoyRecord(localRouterHash: Data) -> Data {
        var record = Data(localRouterHash.prefix(16))
        record.append(Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation)
        record.append(I2PCrypto.randomBytes(I2PTunnelBuildRequestRecord.wireLength - record.count))
        return record
    }

    enum BuildResult {
        case success(I2PTunnel)
        case failed(code: UInt8)
    }

    private let localRouterHash: Data
    private let participant: I2PTunnelParticipant
    private let transport: I2PTunnelBuildTransport
    private let lock = NSLock()
    private var contexts: [UInt32: BuildContext] = [:]
    private var results: [UInt32: BuildResult] = [:]

    init(localRouterHash: Data, participant: I2PTunnelParticipant, transport: I2PTunnelBuildTransport) {
        self.localRouterHash = localRouterHash
        self.participant = participant
        self.transport = transport
        participant.addReplyConsumer { [weak self] reply in
            self?.consume(reply)
        }
    }

    /// Builds a unidirectional tunnel through the given peers, listed in
    /// tunnel data-path order: the first hop is the tunnel's gateway; for an
    /// inbound tunnel the last hop is the one nearest the originator. The
    /// records' *contents* follow this order, but their positions on the wire do
    /// not: each record is placed in a random slot of a message padded to the
    /// spec's minimum four records, so no hop learns its place in the path.
    ///
    /// `replyRoute` is where an outbound build's endpoint sends its build reply:
    /// per the spec's message flow, "Reply through existing inbound D-E-F" — an
    /// existing inbound tunnel of the creator, because an outbound endpoint
    /// cannot dial a creator behind NAT. Without one, pass the creator's own
    /// router hash plus a local endpoint ID the router hands back to the
    /// participant.
    func buildTunnel(direction: I2PTunnel.Direction,
                     hops: [I2PTunnelPeer],
                     lifetime: TimeInterval,
                     timeout: TimeInterval = 15,
                     replyRoute: (gateway: Data, tunnelID: UInt32)? = nil) async throws -> I2PTunnel {
        guard hops.count >= 1 && hops.count <= 4 else {
            throw I2PTunnelBuildError.invalidConfiguration
        }
        let messageID = UInt32.random(in: 1...UInt32.max)
        let receiveIDs = hops.map { _ in UInt32.random(in: 1...UInt32.max) }
        let originatorEndpointID = UInt32.random(in: 1...UInt32.max)
        // Slots are chosen up front so each record is sealed with the reply index
        // its hop will answer at.
        let layout = Self.buildLayout(hopCount: hops.count, direction: direction)

        var records: [Data] = []
        var materials: [I2PTunnelBuildReplyMaterial] = []
        for (index, peer) in hops.enumerated() {
            let isLast = index == hops.count - 1
            var nextHopHash = Data(repeating: 0, count: 32)
            var nextTunnelID: UInt32 = 0
            var isEnd = false
            var nextIsOriginator = false
            var flags: UInt8 = 0
            var payloadDelivery: Data?
            if direction == .inbound && index == 0 {
                // The build's first recipient is the inbound gateway.
                flags |= I2PTunnelBuildRequestRecord.flagInboundGateway
            }
            if isLast {
                if direction == .outbound {
                    // Flags bit 6 (tunnel-creation-ecies): an outbound endpoint
                    // "send[s] the reply to the specified next hop in a Tunnel
                    // Build Reply Message". Those next-hop fields are the reply's
                    // address — an existing inbound tunnel of the creator, or the
                    // creator's router plus a local endpoint. Pointing them at our
                    // own gateway framed the reply as a loop back into the tunnel
                    // we were building, so a real hop had no reply address and
                    // dropped the build: the live row timed out with every record
                    // encrypted correctly.
                    let reply = replyRoute ?? (gateway: localRouterHash, tunnelID: 0)
                    flags |= I2PTunnelBuildRequestRecord.flagOutboundEndpoint
                    nextHopHash = reply.gateway
                    nextTunnelID = reply.tunnelID
                    isEnd = true
                    nextIsOriginator = true
                    // The payload's own route is a different address and rides a
                    // build option, so it survives the reply re-pointing above.
                    payloadDelivery = hops[0].routerHash
                } else {
                    nextHopHash = localRouterHash
                    nextTunnelID = originatorEndpointID
                    isEnd = true
                    nextIsOriginator = true
                }
            } else {
                nextHopHash = hops[index + 1].routerHash
                nextTunnelID = receiveIDs[index + 1]
            }
            let record = I2PTunnelBuildRequestRecord(
                hopNumber: UInt8(index),
                receiveTunnelID: receiveIDs[index],
                nextHopHash: nextHopHash,
                nextTunnelID: nextTunnelID,
                isMessagePathEnd: isEnd,
                nextHopIsOriginator: nextIsOriginator,
                hasMoreRecords: !isLast,
                flags: flags,
                nextMessageID: messageID,
                payloadDeliveryHash: payloadDelivery
            )
            let encrypted = try I2PTunnelBuildCrypto.encryptRecordWithMaterial(
                record.serialize(),
                to: peer.encryptionPublicKey,
                hopHash: peer.routerHash,
                recordIndex: UInt8(layout.positions[index])
            )
            records.append(encrypted.wire)
            materials.append(encrypted.material)
        }

        // Place the real records at their randomized slots and fill the rest with
        // fake records: that is what hides the tunnel's hop count and each hop's
        // position from its neighbours.
        var wireRecords = (0..<layout.slotCount).map { _ in
            I2PCrypto.randomBytes(I2PTunnelBuildRequestRecord.wireLength)
        }
        var wireMaterials = [I2PTunnelBuildReplyMaterial?](repeating: nil,
                                                          count: layout.slotCount)
        for (index, slot) in layout.positions.enumerated() {
            wireRecords[slot] = records[index]
            wireMaterials[slot] = materials[index]
        }
        if let decoySlot = layout.originatorSlot {
            wireRecords[decoySlot] = Self.originatorDecoyRecord(localRouterHash: localRouterHash)
        }

        let context = BuildContext(
            direction: direction,
            peerHashes: hops.map(\.routerHash),
            receiveIDs: receiveIDs,
            layerKeys: materials.map(\.layerKey),
            ivKeys: materials.map(\.ivKey),
            hopReplyMaterials: materials,
            replyMaterials: wireMaterials,
            positions: layout.positions,
            endpointSlot: layout.positions[hops.count - 1],
            originatorEndpointID: originatorEndpointID,
            sentAt: Date(),
            lifetime: lifetime
        )
        lock.lock()
        contexts[messageID] = context
        lock.unlock()

        transport.sendBuild(I2PTunnelBuildMessage(messageID: messageID, records: wireRecords),
                            to: hops[0].routerHash)

        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if let result = takeResult(messageID) {
                // The context is done either way. Leaving it behind made every
                // later reply scan every build this router had ever started.
                lock.lock()
                contexts[messageID] = nil
                lock.unlock()
                switch result {
                case .success(let tunnel):
                    return tunnel
                case .failed(let code):
                    throw I2PTunnelBuildError.rejected(code: code)
                }
            }
            try? await Task.sleep(for: .milliseconds(25))
        }
        lock.lock()
        contexts[messageID] = nil
        lock.unlock()
        throw I2PTunnelBuildError.timeout
    }

    func takeResult(_ messageID: UInt32) -> BuildResult? {
        lock.lock()
        defer { lock.unlock() }
        let result = results[messageID]
        results[messageID] = nil
        return result
    }
    /// Opens one reply slot in either shape a reply can arrive in.
    ///
    /// A rejection walks back along the build path, so every hop before the
    /// reporting one has already XORed its ChaCha20 keystream over the later
    /// slots; undoing those layers recovers the record (XOR is commutative, so
    /// the order the hops applied them in does not matter). An acceptance that
    /// came through the creator's reply tunnel has no such layers — only the
    /// endpoint wrote a record — and opens as it arrived.
    private static func openReplySlot(_ records: [Data],
                                      slot: Int,
                                      context: BuildContext) -> I2PTunnelBuildReplyRecord? {
        guard slot < records.count, slot < context.replyMaterials.count,
              let material = context.replyMaterials[slot] else { return nil }
        let recordIndex = UInt8(slot)
        if let record = try? I2PTunnelBuildCrypto.decryptReplyRecord(
            records[slot], material: material, recordIndex: recordIndex) {
            return record
        }
        // A rejection walks back along the *build path*: the hops before this
        // one in that path have already laid their keystreams over this record.
        guard let hop = context.positions.firstIndex(of: slot) else { return nil }
        var peeled = records[slot]
        for earlier in 0..<hop {
            peeled = I2PTunnelBuildCrypto.reencryptReplyRecord(
                peeled, material: context.hopReplyMaterials[earlier],
                recordIndex: recordIndex)
        }
        return try? I2PTunnelBuildCrypto.decryptReplyRecord(
            peeled, material: material, recordIndex: recordIndex)
    }

    /// Peels the reply and maps per-hop accept/reject codes.
    ///
    /// Two reply shapes reach the creator and both must be readable:
    ///  * a rejection comes back along the *build* path, so every hop up to the
    ///    one that refused has re-encrypted the later slots with its own reply
    ///    key and installed its own record — the creator unwraps slot n+1... with
    ///    hop n's key before opening slot n;
    ///  * an acceptance comes back through the creator's reply tunnel (the spec's
    ///    "Reply through existing inbound D-E-F"), so only the outbound endpoint's
    ///    record was ever written and the remaining slots are the random filler it
    ///    sent. Treating an unfilled slot as corruption rejected every build whose
    ///    reply took a tunnel — the only route a creator behind NAT can offer.
    ///
    /// The endpoint's record is what success requires: a reply whose last slot
    /// does not open never authenticated the build. A record that opens and
    /// refuses fails the build whatever the other slots hold.
    private func consume(_ reply: I2PTunnelBuildReply) {
        lock.lock()
        var matched: (id: UInt32, context: BuildContext)?
        for (id, context) in contexts
        where context.replyMaterials.count == reply.encryptedRecords.count {
            // Any slot can carry this context's record: the reply's author is the
            // endpoint on an acceptance and the refusing hop on a rejection, and
            // only the AEAD decides which slot belongs to us.
            for slot in 0..<context.replyMaterials.count {
                if Self.openReplySlot(reply.encryptedRecords, slot: slot,
                                      context: context) != nil {
                    matched = (id, context)
                    break
                }
            }
            if matched != nil { break }
        }
        guard let matched else {
            lock.unlock()
            return
        }
        contexts[matched.id] = nil
        lock.unlock()

        var rejection: UInt8?
        var endpointAccepted = false
        let endpointSlot = matched.context.endpointSlot
        for slot in 0..<matched.context.replyMaterials.count {
            guard let record = Self.openReplySlot(reply.encryptedRecords,
                                                  slot: slot,
                                                  context: matched.context) else {
                continue // filler: this hop never wrote a reply into the slot
            }
            if record.returnCode != I2PTunnelBuildReturnCode.accepted.rawValue {
                rejection = record.returnCode
                break
            }
            if slot == endpointSlot { endpointAccepted = true }
        }
        if let rejection {
            storeResult(matched.id, .failed(code: rejection))
            return
        }
        guard endpointAccepted else {
            // No endpoint record: nothing authenticated this build's acceptance.
            storeResult(matched.id, .failed(code: 255))
            return
        }
        let completedAt = Date()
        let tunnel = makeTunnel(matched.context, completedAt: completedAt)
        storeResult(matched.id, .success(tunnel))
    }

    private func storeResult(_ messageID: UInt32, _ result: BuildResult) {
        lock.lock()
        results[messageID] = result
        lock.unlock()
    }

    /// Assembles the tunnel in data-path order for both directions: the first
    /// hop is the gateway and the last is the message-path end (the outbound
    /// endpoint, or the hop nearest the originator on an inbound build). The
    /// build message travels that same order — the ECIES tunnel-creation spec's
    /// message-flow diagram sends an inbound build to the IBGW first and along
    /// the new tunnel's path from there — so no reversal is applied here.
    private func makeTunnel(_ context: BuildContext, completedAt: Date) -> I2PTunnel {
        let count = context.peerHashes.count
        var hops: [I2PTunnelHop] = []
        var layerKeys: [Data]
        var ivKeys: [Data]

        if context.direction == .outbound {
            for index in 0..<count {
                hops.append(I2PTunnelHop(
                    routerHash: context.peerHashes[index],
                    receiveTunnelID: context.receiveIDs[index],
                    nextTunnelID: index + 1 < count ? context.receiveIDs[index + 1] : 0,
                    isTunnelEndpoint: index == count - 1
                ))
            }
            layerKeys = context.layerKeys
            ivKeys = context.ivKeys
            return I2PTunnel(
                direction: .outbound,
                hops: hops,
                gatewayTunnelID: context.receiveIDs[0],
                endpointTunnelID: context.receiveIDs[count - 1],
                layerKeys: layerKeys,
                ivKeys: ivKeys,
                createdAt: completedAt,
                expiresAt: completedAt.addingTimeInterval(context.lifetime),
                buildLatency: completedAt.timeIntervalSince(context.sentAt)
            )
        }

        // Inbound tunnels list hops in data-path order too: the inbound
        // gateway first, the hop nearest the originator last. The final
        // entry's next tunnel ID is the originator's local endpoint ID.
        for index in 0..<count {
            hops.append(I2PTunnelHop(
                routerHash: context.peerHashes[index],
                receiveTunnelID: context.receiveIDs[index],
                nextTunnelID: index + 1 < count ? context.receiveIDs[index + 1] : context.originatorEndpointID,
                isTunnelEndpoint: index == count - 1
            ))
        }
        layerKeys = context.layerKeys
        ivKeys = context.ivKeys
        return I2PTunnel(
            direction: .inbound,
            hops: hops,
            gatewayTunnelID: context.receiveIDs[0],
            endpointTunnelID: context.originatorEndpointID,
            layerKeys: layerKeys,
            ivKeys: ivKeys,
            createdAt: completedAt,
            expiresAt: completedAt.addingTimeInterval(context.lifetime),
            buildLatency: completedAt.timeIntervalSince(context.sentAt)
        )
    }
}