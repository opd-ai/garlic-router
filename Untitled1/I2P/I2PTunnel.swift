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

/// Supplies random candidate hops for tunnel builds.
protocol I2PTunnelPeerProvider: AnyObject {
    func peers(count: Int, excluding: Set<Data>) -> [I2PTunnelPeer]
}

/// Carries tunnel build traffic between routers. The NTCP2 transport layer
/// implements this; tests use the loopback hub.
protocol I2PTunnelBuildTransport: AnyObject {
    func sendBuild(_ message: I2PTunnelBuildMessage, to routerHash: Data)
    func sendBuildReply(_ body: Data, to routerHash: Data)
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
    let nextHopHash: Data
    let nextTunnelID: UInt32
    /// True for the last hop in the build message path: after decrypting its
    /// layer it delivers the inner TunnelGateway payload to nextHopHash
    /// (the tunnel's gateway router for outbound, the originator for inbound).
    let isMessagePathEnd: Bool
    let layerKey: Data
    let ivKey: Data
    let registeredAt: Date

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

    /// Builds we forwarded: message ID → the peer we received it from, plus
    /// the material needed to append our reply record on the way back.
    private struct PendingBuild {
        let source: Data
        let receiveTunnelID: UInt32
        let replyKey: Data
        let replyIV: Data
        let deadline: Date
    }

    private var pendingBuilds: [UInt32: PendingBuild] = [:]
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
        var found: (record: I2PTunnelBuildRequestRecord, index: Int)?
        for (index, wire) in message.records.enumerated() {
            if let plaintext = try? I2PTunnelBuildCrypto.decryptRecord(
                    wire,
                    localEncryptionKey: localEncryptionKey,
                    recordIndex: UInt8(index)),
               let parsed = try? I2PTunnelBuildRequestRecord.parse(plaintext) {
                found = (parsed, index)
                break
            }
        }
        guard let match = found else { return } // no record for us; drop
        let record = match.record

        let code = acceptanceCode(for: record)
        if code != I2PTunnelBuildReturnCode.accepted.rawValue {
            // Reject: reply immediately with our record; do not forward.
            initiateReply(messageID: message.messageID, record: record, code: code, to: source)
            return
        }

        let state = I2PTunnelHopState(
            receiveTunnelID: record.receiveTunnelID,
            nextHopHash: record.nextHopHash,
            nextTunnelID: record.nextTunnelID,
            isMessagePathEnd: record.isMessagePathEnd,
            layerKey: record.layerKey,
            ivKey: record.ivKey,
            registeredAt: Date()
        )
        lock.lock()
        hopStates[record.receiveTunnelID] = state
        if !record.isMessagePathEnd {
            pendingBuilds[message.messageID] = PendingBuild(
                source: source,
                receiveTunnelID: record.receiveTunnelID,
                replyKey: record.replyKey,
                replyIV: record.replyIV,
                deadline: Date().addingTimeInterval(Self.pendingReplyTTL)
            )
        }
        pruneHopStatesLocked()
        lock.unlock()

        if record.isMessagePathEnd {
            // Message-path end (outbound endpoint or inbound gateway hop).
            initiateReply(
                messageID: message.messageID,
                record: record,
                code: I2PTunnelBuildReturnCode.accepted.rawValue,
                to: source
            )
        } else {
            transport.sendBuild(message, to: record.nextHopHash)
        }
    }

    /// Receives a reply body on the build's way back: appends our encrypted
    /// reply record and forwards to the router we received the request from,
    /// or hands the reply to a registered originator consumer.
    func handleBuildReply(_ body: Data, from source: Data) {
        guard let reply = try? I2PTunnelBuildReply.parse(body) else { return }
        lock.lock()
        if var pending = pendingBuilds[reply.messageID], Date() < pending.deadline {
            pendingBuilds[reply.messageID] = nil
            lock.unlock()
            var records = reply.encryptedRecords
            if let ours = try? I2PTunnelBuildCrypto.encryptReplyRecord(
                    I2PTunnelBuildReplyRecord(
                        receiveTunnelID: pending.receiveTunnelID,
                        returnCode: I2PTunnelBuildReturnCode.accepted.rawValue
                    ),
                    replyKey: pending.replyKey,
                    replyIV: pending.replyIV,
                    messageID: reply.messageID) {
                records.append(ours)
            }
            let updated = I2PTunnelBuildReply(messageID: reply.messageID, encryptedRecords: records)
            transport.sendBuildReply(updated.serialize(), to: pending.source)
            return
        }
        let consumers = replyConsumers
        lock.unlock()
        consumers.forEach { $0(reply) }
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
        pendingBuilds = pendingBuilds.filter { $0.value.deadline > now }
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
        lock.unlock()
        if inUse { return I2PTunnelBuildReturnCode.tunnelIDInUse.rawValue }
        return I2PTunnelBuildReturnCode.accepted.rawValue
    }

    private func initiateReply(messageID: UInt32, record: I2PTunnelBuildRequestRecord, code: UInt8, to target: Data) {
        guard let encrypted = try? I2PTunnelBuildCrypto.encryptReplyRecord(
                I2PTunnelBuildReplyRecord(receiveTunnelID: record.receiveTunnelID, returnCode: code),
                replyKey: record.replyKey,
                replyIV: record.replyIV,
                messageID: messageID) else { return }
        let reply = I2PTunnelBuildReply(messageID: messageID, encryptedRecords: [encrypted])
        transport.sendBuildReply(reply.serialize(), to: target)
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
    /// The I2NP tunnel message pipeline: decrypt one layer of a TunnelData
    /// payload with this hop's layer key and IV, then either forward the
    /// revealed next-hop payload or deliver the inner TunnelGateway message.
    func processTunnelData(_ payload: I2PTunnelDataPayload) throws -> I2PTunnelHopAction {
        let state: I2PTunnelHopState? = {
            lock.lock()
            defer { lock.unlock() }
            return hopStates[payload.tunnelID]
        }()
        guard let state, !state.isExpired() else { throw I2NPError.unknownTunnel }
        let content = try I2PTunnelLayerCipher.unwrap(
            ciphertext: payload.ciphertext,
            layerKey: state.layerKey,
            iv: payload.iv,
            tunnelID: payload.tunnelID
        )
        if state.isMessagePathEnd {
            // Innermost content is a TunnelGateway payload: [gatewayID][I2NP].
            guard content.count >= 4 else { throw I2NPError.invalidPayload }
            return .deliverGateway(toRouterHash: state.nextHopHash, gatewayPayload: content)
        }
        let inner = try I2PTunnelDataPayload.parse(content)
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
        let replyKeys: [Data]
        let replyIVs: [Data]
        let originatorEndpointID: UInt32
        let sentAt: Date
        let lifetime: TimeInterval
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
    /// build message follows this same order, so each hop's state, layer key
    /// and next-hop info describe the data path it will actually process.
    func buildTunnel(direction: I2PTunnel.Direction,
                     hops: [I2PTunnelPeer],
                     lifetime: TimeInterval,
                     timeout: TimeInterval = 15) async throws -> I2PTunnel {
        guard hops.count >= 1 && hops.count <= 4 else {
            throw I2PTunnelBuildError.invalidConfiguration
        }
        let messageID = UInt32.random(in: 1...UInt32.max)
        let receiveIDs = hops.map { _ in UInt32.random(in: 1...UInt32.max) }
        let layerKeys = hops.map { _ in I2PCrypto.randomBytes(32) }
        let ivKeys = hops.map { _ in I2PCrypto.randomBytes(32) }
        let replyKeys = hops.map { _ in I2PCrypto.randomBytes(32) }
        let replyIVs = hops.map { _ in I2PCrypto.randomBytes(16) }
        let originatorEndpointID = UInt32.random(in: 1...UInt32.max)

        var records: [Data] = []
        for (index, peer) in hops.enumerated() {
            let isLast = index == hops.count - 1
            var nextHopHash = Data(repeating: 0, count: 32)
            var nextTunnelID: UInt32 = 0
            var isEnd = false
            var nextIsOriginator = false
            if isLast {
                if direction == .outbound {
                    // The endpoint learns the tunnel's gateway so it can
                    // deliver the inner TunnelGateway payload there.
                    nextHopHash = hops[0].routerHash
                    nextTunnelID = receiveIDs[0]
                    isEnd = true
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
                layerKey: layerKeys[index],
                ivKey: ivKeys[index],
                replyKey: replyKeys[index],
                replyIV: replyIVs[index],
                isMessagePathEnd: isEnd,
                nextHopIsOriginator: nextIsOriginator,
                hasMoreRecords: !isLast,
                padding: I2PCrypto.randomBytes(I2PTunnelBuildRequestRecord.plaintextLength - I2PTunnelBuildRequestRecord.headerLength)
            )
            records.append(try I2PTunnelBuildCrypto.encryptRecord(
                record.serialize(),
                to: peer.encryptionPublicKey,
                recordIndex: UInt8(index)
            ))
        }

        let context = BuildContext(
            direction: direction,
            peerHashes: hops.map(\.routerHash),
            receiveIDs: receiveIDs,
            layerKeys: layerKeys,
            ivKeys: ivKeys,
            replyKeys: replyKeys,
            replyIVs: replyIVs,
            originatorEndpointID: originatorEndpointID,
            sentAt: Date(),
            lifetime: lifetime
        )
        lock.lock()
        contexts[messageID] = context
        lock.unlock()

        transport.sendBuild(I2PTunnelBuildMessage(messageID: messageID, records: records), to: hops[0].routerHash)

        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if let result = takeResult(messageID) {
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
/// Decrypts every reply record with the originator-held reply keys, maps
    /// per-hop accept/reject codes, and assembles the tunnel on success.
    private func consume(_ reply: I2PTunnelBuildReply) {
        lock.lock()
        guard let context = contexts[reply.messageID] else {
            lock.unlock()
            return
        }
        contexts[reply.messageID] = nil
        lock.unlock()

        var codesByTunnelID: [UInt32: UInt8] = [:]
        for wire in reply.encryptedRecords {
            for (index, replyKey) in context.replyKeys.enumerated() {
                if let record = try? I2PTunnelBuildCrypto.decryptReplyRecord(
                        wire,
                        replyKey: replyKey,
                        replyIV: context.replyIVs[index],
                        messageID: reply.messageID) {
                    codesByTunnelID[record.receiveTunnelID] = record.returnCode
                    break
                }
            }
        }
        let orderedCodes = context.receiveIDs.compactMap { codesByTunnelID[$0] }
        guard orderedCodes.count == context.receiveIDs.count else {
            storeResult(reply.messageID, .failed(code: 255))
            return
        }
        if let bad = orderedCodes.first(where: { $0 != I2PTunnelBuildReturnCode.accepted.rawValue }) {
            storeResult(reply.messageID, .failed(code: bad))
            return
        }

        let completedAt = Date()
        let tunnel = makeTunnel(context, completedAt: completedAt)
        storeResult(reply.messageID, .success(tunnel))
    }

    private func storeResult(_ messageID: UInt32, _ result: BuildResult) {
        lock.lock()
        results[messageID] = result
        lock.unlock()
    }

    /// Assembles the tunnel in data-path order. Outbound: message path equals
    /// data path. Inbound: the data path is the reversed build message path
    /// (the gateway is the last hop in the message path).
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