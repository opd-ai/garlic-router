//
//  I2NPPipeline.swift
//  Tunnel data pipeline: hop layer cipher, originator pre-processing,
//  the I2NP router's type dispatch and loopback delivery for tests.
//

import Foundation
import CryptoKit

/// Per-hop tunnel layer encryption per the I2P tunnel spec (data phase).
///
/// Each hop's layer is AES-256-CBC over the 1008-byte TunnelData body with the
/// hop's 32-byte layer key (from its build record). The CBC IV derives from the
/// message's 16-byte IV field through the hop's IV key:
///
///     IV_used = AES-256-ECB(IV_key, IV_field) XOR IV_field
///
/// The ECB-keyed IV transform prevents IV tampering: an adversary flipping bits
/// in the IV field cannot predict the CBC IV the hop actually uses, defeating
/// CBC's first-block malleability. The IV field itself is rewritten at every
/// hop — each forwarding hop carries the next hop's IV in the header.
enum I2PTunnelLayerCipher {
    static func tunnelIDBytes(_ tunnelID: UInt32) -> Data {
        var value = tunnelID.bigEndian
        return withUnsafeBytes(of: &value) { Data($0) }
    }

    /// AES-256-ECB encryption of one 16-byte block (CBC of a single block with
    /// a zero IV), used for the spec's IV-key transform.
    static func ecbBlock(_ block: Data, key: Data) -> Data {
        precondition(block.count == 16 && key.count == 32,
                     "ECB block requires a 16-byte block and a 32-byte key")
        return I2PAESCBC.encrypt(block, key: key, iv: Data(repeating: 0, count: 16))
    }

    /// IV_used = AES-256-ECB(IV_key, IV_field) XOR IV_field.
    static func deriveCBCIV(ivField: Data, ivKey: Data) -> Data {
        let transformed = ecbBlock(ivField, key: ivKey)
        return Data(zip(transformed, ivField).map { $0 ^ $1 })
    }

    /// [BE16 content length][content][zero padding] to the fixed body size.
    static func padded(_ content: Data) throws -> Data {
        guard content.count <= I2PTunnelDataPayload.bodySize - 2 else { throw I2NPError.invalidPayload }
        var out = Data()
        out.append(UInt8((content.count >> 8) & 0xff))
        out.append(UInt8(content.count & 0xff))
        out.append(content)
        while out.count < I2PTunnelDataPayload.bodySize { out.append(0) }
        return out
    }

    static func unpad(_ padded: Data) throws -> Data {
        let bytes = Array(padded)
        guard bytes.count >= 2 else { throw I2NPError.invalidPayload }
        let length = (Int(bytes[0]) << 8) | Int(bytes[1])
        guard 2 + length <= bytes.count else { throw I2NPError.invalidPayload }
        return Data(bytes[2..<(2 + length)])
    }

    /// Encrypts one hop's layer: AES-256-CBC over the padded 1008-byte body
    /// with the layer key and the IV-key-derived CBC IV.
    static func wrap(content: Data, layerKey: Data, ivField: Data, ivKey: Data) throws -> Data {
        I2PAESCBC.encrypt(try padded(content),
                          key: layerKey,
                          iv: deriveCBCIV(ivField: ivField, ivKey: ivKey))
    }

    /// Decrypts one hop's layer: AES-256-CBC over the full 1008-byte body with
    /// the layer key and the IV-key-derived CBC IV, then unpads. CBC prefix
    /// decryption is exact for the region the layer key covered; bytes beyond
    /// it are forwarding filler and decode to garbage the framer ignores.
    static func unwrap(body: Data, layerKey: Data, ivField: Data, ivKey: Data) throws -> Data {
        guard body.count == I2PTunnelDataPayload.bodySize else { throw I2NPError.invalidPayload }
        let plain = I2PAESCBC.decrypt(body,
                                      key: layerKey,
                                      iv: deriveCBCIV(ivField: ivField, ivKey: ivKey))
        return try unpad(plain)
    }
}

/// Originator-side preprocessing per the tunnel spec: wraps an I2NP message in
/// a TunnelGateway payload addressed to the tunnel's gateway and applies every
/// hop's AES-256-CBC layer (innermost first), producing the TunnelData payload
/// addressed to the tunnel's gateway hop.
///
/// Layer nesting follows the spec's fixed-size messages: each transit hop's
/// decrypted body frames the next hop's message as
/// [BE16 length][nextTunnelID (4)][nextIV (16)][next ciphertext region], so the
/// encrypted region shrinks by 32 bytes per hop (block-aligned room for the
/// tunnel ID + IV prefix and the length field). The region a hop's key never
/// covered is re-randomized by the forwarding hop; here it stays zero padding.
enum I2PTunnelDataProcessor {
    /// Encrypted region length per hop in data-path order: the outermost layer
    /// covers the full 1008-byte body, each deeper layer's region shrinks.
    static func layerLengths(hopCount: Int) -> [Int] {
        (0..<max(hopCount, 0)).map { index in
            max(I2PTunnelDataPayload.bodySize - 32 * index, 16)
        }
    }

    static func preprocess(_ i2npMessage: Data,
                           via tunnel: I2PTunnel,
                           gatewayID: UInt32? = nil,
                           ivProvider: (() -> Data)? = nil) throws -> I2PTunnelDataPayload {
        guard !tunnel.hops.isEmpty else { throw I2NPError.invalidConfiguration }
        let gateway = gatewayID ?? (tunnel.direction == .outbound
            ? tunnel.gatewayTunnelID
            : tunnel.endpointTunnelID)
        let lengths = layerLengths(hopCount: tunnel.hops.count)

        // Innermost (message-path end) content: the padded TunnelGateway
        // payload frame. Its budget is the innermost layer's covered region
        // minus the length field.
        let gatewayPayload = I2PTunnelGatewayPayload(gatewayID: gateway, message: i2npMessage).serialize()
        let innerBudget = lengths[lengths.count - 1] - 2
        guard gatewayPayload.count <= innerBudget else { throw I2NPError.invalidPayload }
        var plaintext = try I2PTunnelLayerCipher.padded(gatewayPayload)

        var ciphertext = Data()
        var nextTunnelID: UInt32 = 0
        var nextIV = Data()
        for index in stride(from: tunnel.hops.count - 1, through: 0, by: -1) {
            let hop = tunnel.hops[index]
            if index < tunnel.hops.count - 1 {
                // Frame the next hop's message for this hop's layer:
                // [BE16 length][nextTunnelID (4)][nextIV (16)][next region].
                let regionLength = lengths[index + 1]
                let innerLength = 20 + regionLength
                guard innerLength <= I2PTunnelDataPayload.bodySize - 2 else {
                    throw I2NPError.invalidConfiguration
                }
                var frame = Data()
                frame.append(UInt8((innerLength >> 8) & 0xff))
                frame.append(UInt8(innerLength & 0xff))
                frame.append(contentsOf: I2PTunnelLayerCipher.tunnelIDBytes(nextTunnelID))
                frame.append(contentsOf: nextIV)
                frame.append(contentsOf: ciphertext)
                while frame.count < I2PTunnelDataPayload.bodySize { frame.append(0) }
                plaintext = frame
            }
            let iv = ivProvider?() ?? I2PCrypto.randomBytes(16)
            let full = try I2PTunnelLayerCipher.wrap(
                content: plaintext,
                layerKey: tunnel.layerKeys[index],
                ivField: iv,
                ivKey: tunnel.ivKeys[index]
            )
            // Only the covered region rides onward; the forwarding hop pads
            // the remainder with fresh random bytes.
            ciphertext = Data(full.prefix(lengths[index]))
            nextTunnelID = hop.receiveTunnelID
            nextIV = iv
        }
        return I2PTunnelDataPayload(tunnelID: nextTunnelID, iv: nextIV, body: ciphertext)
    }
}
/// Delivers serialized I2NP messages to routers identified by their hashes.
/// NTCP2 implements this in production; the loopback hub serves tests.
protocol I2PDeliveryTransport: AnyObject {
    func deliver(_ i2npBytes: Data, to routerHash: Data) async throws
}

/// Router-level I2NP dispatch: expiry enforcement, typed payload parsing,
/// tunnel-data hop processing with forwarding, gateway delivery and
/// registration points for netdb/garlic/status consumers.
final class I2NPMessageRouter {
    let localRouterHash: Data
    weak var deliveryTransport: I2PDeliveryTransport?
    private let lock = NSLock()
    private var participants: [I2PTunnelParticipant] = []
    private var gatewayHandlers: [UInt32: (I2NPMessage, Data) -> Void] = [:]
    private var bodyHandlers: [(I2NPMessage, Data) -> Void] = []

    init(localRouterHash: Data) {
        self.localRouterHash = localRouterHash
    }

    func addTunnelParticipant(_ participant: I2PTunnelParticipant) {
        lock.lock()
        participants.append(participant)
        lock.unlock()
    }

    /// Registers a handler for TunnelGateway messages addressed to a tunnel
    /// ID we operate as gateway or endpoint (reply path / IBGW delivery).
    func registerGateway(tunnelID: UInt32, handler: @escaping (I2NPMessage, Data) -> Void) {
        lock.lock()
        gatewayHandlers[tunnelID] = handler
        lock.unlock()
    }

    /// Registers a consumer for every other routed body (netdb, garlic,
    /// status, options, data messages, tunnel builds).
    func addBodyHandler(_ handler: @escaping (I2NPMessage, Data) -> Void) {
        lock.lock()
        bodyHandlers.append(handler)
        lock.unlock()
    }

    /// Observation hook invoked for every routed inbound message, before
    /// dispatch (used by the status engine for throughput counting).
    var onMessageRouted: ((I2NPMessage, Data) -> Void)?

    /// Routes an inbound I2NP message from the given source router.
    func handleIncoming(_ message: I2NPMessage, from source: Data) async {
        onMessageRouted?(message, source)
        guard !message.isExpired() else { return } // expiry enforcement
        guard let body = try? message.parseBody() else { return }
        let participants = self.participantsSnapshot()
        switch body {
        case .tunnelData(let payload):
            for participant in participants {
                guard let action = try? participant.processTunnelData(payload) else { continue }
                await perform(action)
                return
            }
            // No participation state for this tunnel ID: drop.
        case .tunnelGateway(let gatewayID, let innerBytes):
            guard let innerMessage = try? I2NPMessage.parse(innerBytes) else { return }
            let handler: ((I2NPMessage, Data) -> Void)? = {
                lock.lock()
                defer { lock.unlock() }
                return gatewayHandlers[gatewayID]
            }()
            if let handler {
                handler(innerMessage, source)
            } else {
                notifyBodyHandlers(innerMessage, source)
            }
        case .tunnelBuild(let buildMessage):
            notifyBodyHandlers(message, source)
            // Tunnel participants attempt to decrypt their own record from the
            // build (the same dispatch the local build hub performs for loopback
            // traffic). This completes organic inbound tunnel participation —
            // real hops build through us over live sessions — and routes build
            // replies back to our originators.
            for participant in participants {
                participant.handleBuild(buildMessage, from: source)
            }
        case .tunnelBuildReply(let reply):
            notifyBodyHandlers(message, source)
            let body = reply.serialize()
            for participant in participants {
                participant.handleBuildReply(body, from: source)
            }
        case .deliveryStatus, .options, .dataMessage, .garlic,
             .databaseStore, .databaseLookup, .databaseSearchReply:
            notifyBodyHandlers(message, source)
        }
    }

    private func participantsSnapshot() -> [I2PTunnelParticipant] {
        lock.lock()
        defer { lock.unlock() }
        return participants
    }

    private func perform(_ action: I2PTunnelHopAction) async {
        switch action {
        case .forward(let nextHopHash, let tunnelData):
            do {
                let envelope = I2NPMessage(type: .tunnelData, payload: tunnelData.serialize())
                try await deliveryTransport?.deliver(envelope.serialize(), to: nextHopHash)
            } catch { /* drop on framing failure */ }
        case .deliverGateway(let toRouterHash, let gatewayPayload):
            do {
                let envelope = I2NPMessage(type: .tunnelGateway, payload: gatewayPayload)
                try await deliveryTransport?.deliver(envelope.serialize(), to: toRouterHash)
            } catch { /* drop on framing failure */ }
        }
    }

    private func notifyBodyHandlers(_ message: I2NPMessage, _ source: Data) {
        let snapshot: [(I2NPMessage, Data) -> Void] = {
            lock.lock()
            defer { lock.unlock() }
            return bodyHandlers
        }()
        snapshot.forEach { $0(message, source) }
    }
}
/// Test/development delivery bus routing I2NP messages between routers.
final class I2NPLoopbackDeliveryHub {
    private let lock = NSLock()
    private var routers: [Data: I2NPMessageRouter] = [:]

    func attach(_ router: I2NPMessageRouter) {
        lock.lock()
        routers[router.localRouterHash] = router
        lock.unlock()
    }

    func deliver(from source: Data, _ i2npBytes: Data, to target: Data) async {
        let router: I2NPMessageRouter? = {
            lock.lock()
            defer { lock.unlock() }
            return routers[target]
        }()
        guard let router, let message = try? I2NPMessage.parse(i2npBytes) else { return }
        await router.handleIncoming(message, from: source)
    }
}

final class I2NPLoopbackDeliveryTransport: I2PDeliveryTransport {
    private weak var hub: I2NPLoopbackDeliveryHub?
    private let localRouterHash: Data

    init(hub: I2NPLoopbackDeliveryHub, localRouterHash: Data) {
        self.hub = hub
        self.localRouterHash = localRouterHash
    }

    func deliver(_ i2npBytes: Data, to routerHash: Data) async throws {
        await hub?.deliver(from: localRouterHash, i2npBytes, to: routerHash)
    }
}