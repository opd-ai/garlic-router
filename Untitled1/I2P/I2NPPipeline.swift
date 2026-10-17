//
//  I2NPPipeline.swift
//  Tunnel data pipeline: hop layer cipher, originator pre-processing,
//  the I2NP router's type dispatch and loopback delivery for tests.
//

import Foundation
import CryptoKit

/// Per-hop tunnel layer encryption. Each hop's layer key (from its build
/// record) seals a fixed-size padded plaintext with ChaCha20-Poly1305; the
/// nonce is the per-message IV carried in the TunnelData header and the
/// hop's tunnel ID is bound as additional authenticated data.
enum I2PTunnelLayerCipher {
    static func tunnelIDBytes(_ tunnelID: UInt32) -> Data {
        var value = tunnelID.bigEndian
        return withUnsafeBytes(of: &value) { Data($0) }
    }

    /// [BE16 content length][content][zero padding] to the fixed body size.
    static func padded(_ content: Data) throws -> Data {
        guard content.count <= I2PTunnelDataPayload.dataSize - 2 else { throw I2NPError.invalidPayload }
        var out = Data()
        out.append(UInt8((content.count >> 8) & 0xff))
        out.append(UInt8(content.count & 0xff))
        out.append(content)
        while out.count < I2PTunnelDataPayload.dataSize { out.append(0) }
        return out
    }

    static func unpad(_ padded: Data) throws -> Data {
        let bytes = Array(padded)
        guard bytes.count >= 2 else { throw I2NPError.invalidPayload }
        let length = (Int(bytes[0]) << 8) | Int(bytes[1])
        guard 2 + length <= bytes.count else { throw I2NPError.invalidPayload }
        return Data(bytes[2..<(2 + length)])
    }

    static func wrap(content: Data, layerKey: Data, iv: Data, tunnelID: UInt32) throws -> Data {
        let box = try ChaChaPoly.seal(
            try padded(content),
            using: SymmetricKey(data: layerKey),
            nonce: ChaChaPoly.Nonce(data: iv),
            authenticating: tunnelIDBytes(tunnelID)
        )
        return box.combined
    }

    static func unwrap(ciphertext: Data, layerKey: Data, iv: Data, tunnelID: UInt32) throws -> Data {
        guard ciphertext.count == I2PTunnelDataPayload.ciphertextLength else { throw I2NPError.invalidPayload }
        let box = try ChaChaPoly.SealedBox(combined: ciphertext)
        let plain = try ChaChaPoly.open(
            box,
            using: SymmetricKey(data: layerKey),
            authenticating: tunnelIDBytes(tunnelID)
        )
        return try unpad(plain)
    }
}

/// Originator-side preprocessing: wraps an I2NP message in a TunnelGateway
/// payload addressed to the tunnel's gateway and applies every hop's
/// encryption layer (innermost first), producing the TunnelData payload
/// addressed to the tunnel's gateway hop.
enum I2PTunnelDataProcessor {
    static func preprocess(_ i2npMessage: Data,
                           via tunnel: I2PTunnel,
                           gatewayID: UInt32? = nil,
                           ivProvider: (() -> Data)? = nil) throws -> I2PTunnelDataPayload {
        guard !tunnel.hops.isEmpty else { throw I2NPError.invalidConfiguration }
        let gateway = gatewayID ?? (tunnel.direction == .outbound
            ? tunnel.gatewayTunnelID
            : tunnel.endpointTunnelID)
        var content = I2PTunnelGatewayPayload(gatewayID: gateway, message: i2npMessage).serialize()
        var payload: I2PTunnelDataPayload!
        for index in stride(from: tunnel.hops.count - 1, through: 0, by: -1) {
            let hop = tunnel.hops[index]
            let iv = ivProvider?() ?? I2PCrypto.randomBytes(12)
            let ciphertext = try I2PTunnelLayerCipher.wrap(
                content: content,
                layerKey: tunnel.layerKeys[index],
                iv: iv,
                tunnelID: hop.receiveTunnelID
            )
            let layer = I2PTunnelDataPayload(tunnelID: hop.receiveTunnelID, iv: iv, ciphertext: ciphertext)
            if index == 0 {
                payload = layer
            } else {
                content = layer.serialize()
            }
        }
        return payload
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

    /// Routes an inbound I2NP message from the given source router.
    func handleIncoming(_ message: I2NPMessage, from source: Data) async {
        guard !message.isExpired() else { return } // expiry enforcement
        guard let body = try? message.parseBody() else { return }
        switch body {
        case .tunnelData(let payload):
            let snapshot: [I2PTunnelParticipant] = {
                lock.lock()
                defer { lock.unlock() }
                return participants
            }()
            for participant in snapshot {
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
        case .deliveryStatus, .options, .dataMessage, .garlic,
             .databaseStore, .databaseLookup, .databaseSearchReply,
             .tunnelBuild, .tunnelBuildReply:
            notifyBodyHandlers(message, source)
        }
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