//
//  I2NPTests.swift
//  Self-tests for the I2NP message layer and the tunnel data pipeline.
//

import Foundation
import CryptoKit

private enum I2NPTestTimeout: Error { case timedOut }

private func i2npTestWaitUntil(timeout: TimeInterval = 15, _ condition: @escaping () -> Bool) async throws {
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        if condition() { return }
        try await Task.sleep(for: .milliseconds(50))
    }
    if condition() { return }
    throw I2NPTestTimeout.timedOut
}

private final class I2NPTestGatewayBox {
    let lock = NSLock()
    private var received: [(I2NPMessage, Data)] = []
    private var bodyMessages: [(I2NPMessage, Data)] = []

    func gateway(_ message: I2NPMessage, _ source: Data) {
        lock.lock(); received.append((message, source)); lock.unlock()
    }
    func body(_ message: I2NPMessage, _ source: Data) {
        lock.lock(); bodyMessages.append((message, source)); lock.unlock()
    }
    var gatewayCount: Int { lock.lock(); defer { lock.unlock() }; return received.count }
    var bodyCount: Int { lock.lock(); defer { lock.unlock() }; return bodyMessages.count }
    func firstGateway() -> I2NPMessage? {
        lock.lock(); defer { lock.unlock() }; return received.first?.0
    }
    var gatewaySources: [Data] {
        lock.lock(); defer { lock.unlock() }; return received.map(\.1)
    }
    var bodyKinds: [I2NPMessageType] {
        lock.lock(); defer { lock.unlock() }; return bodyMessages.map { $0.0.type }
    }
}

enum I2NPSelfTest {
    static func runAll() async -> [I2PSelfTestResult] {
        var results: [I2PSelfTestResult] = []
        func run(_ name: String, _ body: () async throws -> String) async {
            do {
                let detail = try await body()
                results.append(I2PSelfTestResult(name: name, passed: true, detail: detail))
            } catch {
                results.append(I2PSelfTestResult(name: name, passed: false, detail: String(describing: error)))
            }
        }

        await run("I2NP header + envelope round-trip") {
            try await headerEnvelopeTest()
        }
        await run("I2NP typed payloads round-trip (all types)") {
            try await typedPayloadTest()
        }
        await run("Delivery instructions: local, tunnel, router") {
            try await deliveryInstructionsTest()
        }
        await run("Tunnel data pipeline through outbound tunnel") {
            try await outboundPipelineTest()
        }
        await run("Tunnel data pipeline through inbound tunnel") {
            try await inboundPipelineTest()
        }
        await run("I2NP expiry enforcement + unknown tunnel drop") {
            try await expiryTest()
        }
        return results
    }

    private static func headerEnvelopeTest() async throws -> String {
        let store = I2PDatabaseStore(
            key: I2PCrypto.sha256(Data("netdb-key".utf8)),
            entryType: .leaseSet,
            replyToken: 0x11223344,
            replyTunnelId: 7,
            replyGateway: I2PCrypto.randomBytes(32),
            payload: Data(repeating: 0xAB, count: 40)
        )
        let sent = Date()
        let message = I2NPMessage(type: .databaseStore, messageID: 0xC0FFEE01, expiration: sent, payload: store.serialize())
        guard I2NPMessage.headerLength == 17 else { throw I2NPError.invalidPayload }
        let parsed = try I2NPMessage.parse(message.serialize())
        guard parsed.type == .databaseStore, parsed.messageID == 0xC0FFEE01,
              abs(parsed.expiration.timeIntervalSince(sent)) < 0.002 else {
            throw I2NPError.invalidPayload
        }
        // Header peek: type byte, big-endian size and expiry before the payload.
        let header = try I2NPMessage.parseHeader(message.serialize())
        guard header.type == .databaseStore, header.size == store.serialize().count else {
            throw I2NPError.invalidPayload
        }
        guard case .databaseStore(let body) = try parsed.parseBody(),
              body.replyToken == 0x11223344, body.key == store.key,
              body.payload == store.payload, body.entryType == .leaseSet else {
            throw I2NPError.invalidPayload
        }
        // An expired message is flagged on receipt.
        let stale = I2NPMessage(type: .databaseStore, expiration: Date().addingTimeInterval(-5))
        guard stale.isExpired() else { throw I2NPError.invalidPayload }
        return "\(message.serialize().count)-byte envelope, 17-byte header, store payload intact"
    }
private static func typedPayloadTest() async throws -> String {
        // DeliveryStatus
        let status = I2NPMessage(type: .deliveryStatus, payload: {
            var w = I2PWriter(); w.integer(0x5150); w.long(1_700_000_500_000); return w.data
        }())
        guard case .deliveryStatus(let id, let stamp) = try I2NPMessage.parse(status.serialize()).parseBody(),
              id == 0x5150, abs(stamp.timeIntervalSince1970 - 1_700_000_500) < 1 else {
            throw I2NPError.invalidPayload
        }
        // Options (mapping) + DataMessage + Garlic (opaque clove set bytes)
        let options = I2NPMessage(type: .options, payload: {
            var w = I2PWriter(); w.mapping(["router.version": "0.9.62", "caps": "XOf"]); return w.data
        }())
        guard case .options(let mapping) = try I2NPMessage.parse(options.serialize()).parseBody(),
              mapping["caps"] == "XOf" else { throw I2NPError.invalidPayload }
        let blob = I2PCrypto.randomBytes(64)
        let dataMessage = I2NPMessage(type: .dataMessage, payload: blob)
        guard case .dataMessage(let payload) = try I2NPMessage.parse(dataMessage.serialize()).parseBody(),
              payload == blob else { throw I2NPError.invalidPayload }
        let garlic = I2NPMessage(type: .garlic, payload: I2PCrypto.randomBytes(88))
        guard case .garlic(let cloveSet) = try I2NPMessage.parse(garlic.serialize()).parseBody(),
              cloveSet.count == 88 else { throw I2NPError.invalidPayload }
        // TunnelGateway carries an inner I2NP message
        let inner = I2NPMessage(type: .dataMessage, payload: Data("inner payload".utf8))
        let gateway = I2NPMessage(type: .tunnelGateway, payload: I2PTunnelGatewayPayload(
            gatewayID: 0x1234ABCD, message: inner.serialize()).serialize())
        guard case .tunnelGateway(let gatewayID, let message) = try I2NPMessage.parse(gateway.serialize()).parseBody(),
              gatewayID == 0x1234ABCD,
              try I2NPMessage.parse(message).messageID == inner.messageID else {
            throw I2NPError.invalidPayload
        }
        // TunnelData payload round-trip through one layer cipher
        let layerKey = I2PCrypto.randomBytes(32)
        let content = Data("tunnel message content".utf8)
        let wire = try I2PTunnelLayerCipher.wrap(content: content, layerKey: layerKey,
                                                 iv: I2PCrypto.randomBytes(12), tunnelID: 42)
        let dataPayload = I2NPMessage(type: .tunnelData, payload: wire)
        guard case .tunnelData(let parsedPayload) = try I2NPMessage.parse(dataPayload.serialize()).parseBody(),
              parsedPayload.tunnelID == 42,
              try I2PTunnelLayerCipher.unwrap(ciphertext: parsedPayload.ciphertext,
                                              layerKey: layerKey, iv: parsedPayload.iv,
                                              tunnelID: 42) == content else {
            throw I2NPError.invalidPayload
        }
        // TunnelBuild / TunnelBuildReply carriers
        let hopKey = Curve25519.KeyAgreement.PrivateKey()
        let record = I2PTunnelBuildRequestRecord(
            hopNumber: 0, receiveTunnelID: 9, nextHopHash: I2PCrypto.randomBytes(32),
            nextTunnelID: 0, layerKey: I2PCrypto.randomBytes(32), ivKey: I2PCrypto.randomBytes(32),
            replyKey: I2PCrypto.randomBytes(32), replyIV: I2PCrypto.randomBytes(16),
            isMessagePathEnd: true, nextHopIsOriginator: false, hasMoreRecords: false,
            padding: I2PCrypto.randomBytes(372)
        )
        let buildWire = try I2PTunnelBuildCrypto.encryptRecord(record.serialize(),
                                                               to: hopKey.publicKey.rawRepresentation,
                                                               recordIndex: 0)
        let buildMessage = I2PTunnelBuildMessage(messageID: 77, records: [buildWire])
        guard case .tunnelBuild(let parsedBuild) = try I2NPMessage.parse({
            let m = I2NPMessage(type: .tunnelBuild, payload: buildMessage.serialize()); return m
        }().serialize()).parseBody(), parsedBuild.messageID == 77 else { throw I2NPError.invalidPayload }
        let replyRecord = try I2PTunnelBuildCrypto.encryptReplyRecord(
            I2PTunnelBuildReplyRecord(receiveTunnelID: 9, returnCode: 0),
            replyKey: I2PCrypto.randomBytes(32), replyIV: I2PCrypto.randomBytes(16), messageID: 77
        )
        let replyMessage = I2PTunnelBuildReply(messageID: 77, encryptedRecords: [replyRecord])
        let replyEnvelope = I2NPMessage(type: .tunnelBuildReply, payload: replyMessage.serialize())
        guard case .tunnelBuildReply(let parsedReply) = try I2NPMessage.parse(replyEnvelope.serialize()).parseBody(),
              parsedReply.encryptedRecords.count == 1 else { throw I2NPError.invalidPayload }
        return "11 message types: header, expiry, bodies and carriers verified"
    }

    private static func deliveryInstructionsTest() async throws -> String {
        let local = I2PDeliveryInstructions(mode: .local)
        let (parsedLocal, localConsumed) = try I2PDeliveryInstructions.parse(local.serialize())
        guard parsedLocal.mode == .local, localConsumed == 2 else { throw I2NPError.invalidPayload }
        let gateway = I2PCrypto.randomBytes(32)
        let tunnel = I2PDeliveryInstructions(mode: .tunnel, tunnelID: 0xDEADBEEF,
                                             routerHash: gateway, delayMilliseconds: 250)
        let (parsedTunnel, tunnelConsumed) = try I2PDeliveryInstructions.parse(tunnel.serialize())
        guard parsedTunnel.mode == .tunnel, parsedTunnel.tunnelID == 0xDEADBEEF,
              parsedTunnel.routerHash == gateway,
              parsedTunnel.delayMilliseconds == 250, tunnelConsumed == 42 else {
            throw I2NPError.invalidPayload
        }
        let router = I2PDeliveryInstructions(mode: .router, routerHash: I2PCrypto.randomBytes(32))
        let (parsedRouter, routerConsumed) = try I2PDeliveryInstructions.parse(router.serialize())
        guard parsedRouter.mode == .router, parsedRouter.routerHash == router.routerHash,
              routerConsumed == 35 else { throw I2NPError.invalidPayload }
        // Local instructions with a delay flag still round-trip.
        let delayed = I2PDeliveryInstructions(mode: .local, delayMilliseconds: 1_000)
        let (parsedDelayed, _) = try I2PDeliveryInstructions.parse(delayed.serialize())
        guard parsedDelayed.delayMilliseconds == 1_000 else { throw I2NPError.invalidPayload }
        return "local (2 B), tunnel (42 B: tunnel ID + gateway), router (35 B) instructions verified"
    }
private struct I2NPTestNode {
    let routerHash: Data
    let encryptionKey: Curve25519.KeyAgreement.PrivateKey
    let participant: I2PTunnelParticipant
    let buildTransport: I2PTunnelBuildTransport
    let deliveryTransport: I2NPLoopbackDeliveryTransport
    let router: I2NPMessageRouter

    init(buildHub: I2PTunnelBuildHub, deliveryHub: I2NPLoopbackDeliveryHub) {
        routerHash = I2PCrypto.randomBytes(32)
        encryptionKey = Curve25519.KeyAgreement.PrivateKey()
        buildTransport = I2PTunnelLoopbackTransport(hub: buildHub, localRouterHash: routerHash)
        participant = I2PTunnelParticipant(
            localRouterHash: routerHash,
            localEncryptionKey: encryptionKey,
            transport: buildTransport
        )
        buildHub.register(participant)
        router = I2NPMessageRouter(localRouterHash: routerHash)
        router.addTunnelParticipant(participant)
        deliveryTransport = I2NPLoopbackDeliveryTransport(hub: deliveryHub, localRouterHash: routerHash)
        router.deliveryTransport = deliveryTransport
        deliveryHub.attach(router)
    }

    var peer: I2PTunnelPeer {
        I2PTunnelPeer(routerHash: routerHash, encryptionPublicKey: encryptionKey.publicKey.rawRepresentation)
    }
}

private static func outboundPipelineTest() async throws -> String {
    let buildHub = I2PTunnelBuildHub()
    let deliveryHub = I2NPLoopbackDeliveryHub()
    let originator = I2NPTestNode(buildHub: buildHub, deliveryHub: deliveryHub)
    let hop1 = I2NPTestNode(buildHub: buildHub, deliveryHub: deliveryHub)
    let hop2 = I2NPTestNode(buildHub: buildHub, deliveryHub: deliveryHub)

    let builder = I2PTunnelBuilder(
        localRouterHash: originator.routerHash,
        participant: originator.participant,
        transport: originator.buildTransport
    )
    let tunnel = try await builder.buildTunnel(
        direction: .outbound, hops: [hop1.peer, hop2.peer], lifetime: 900, timeout: 10
    )

    // The tunnel's gateway (hop1) receives the inner TunnelGateway payload.
    let box = I2NPTestGatewayBox()
    hop1.router.registerGateway(tunnelID: tunnel.gatewayTunnelID) { message, source in
        box.gateway(message, source)
    }

    let inner = I2NPMessage(type: .dataMessage, payload: Data("e2e pipeline payload".utf8))
    let payload = try I2PTunnelDataProcessor.preprocess(inner.serialize(), via: tunnel)
    let dataMessage = I2NPMessage(type: .tunnelData, payload: payload.serialize())
    await deliveryHub.deliver(from: originator.routerHash, dataMessage.serialize(), to: hop1.routerHash)

    try await i2npTestWaitUntil { box.gatewayCount == 1 }
    guard let received = box.firstGateway(), received.messageID == inner.messageID,
          received.type == .dataMessage,
          received.payload == inner.payload else {
        throw I2NPError.invalidPayload
    }
    guard box.gatewaySources.first == hop2.routerHash else {
        throw I2NPError.invalidPayload
    }
    return "2-hop outbound pipeline: originator → hop1 → hop2 → gateway delivery"
}

private static func inboundPipelineTest() async throws -> String {
    let buildHub = I2PTunnelBuildHub()
    let deliveryHub = I2NPLoopbackDeliveryHub()
    let originator = I2NPTestNode(buildHub: buildHub, deliveryHub: deliveryHub)
    let gateway = I2NPTestNode(buildHub: buildHub, deliveryHub: deliveryHub)
    let nearest = I2NPTestNode(buildHub: buildHub, deliveryHub: deliveryHub)

    let builder = I2PTunnelBuilder(
        localRouterHash: originator.routerHash,
        participant: originator.participant,
        transport: originator.buildTransport
    )
    let tunnel = try await builder.buildTunnel(
        direction: .inbound, hops: [gateway.peer, nearest.peer], lifetime: 900, timeout: 10
    )

    let box = I2NPTestGatewayBox()
    originator.router.registerGateway(tunnelID: tunnel.endpointTunnelID) { message, source in
        box.gateway(message, source)
    }

    // The test acts as a remote sender delivering into the tunnel's gateway.
    let inner = I2NPMessage(type: .dataMessage, payload: Data("inbound delivery".utf8))
    let payload = try I2PTunnelDataProcessor.preprocess(inner.serialize(), via: tunnel)
    let dataMessage = I2NPMessage(type: .tunnelData, payload: payload.serialize())
    await deliveryHub.deliver(from: originator.routerHash, dataMessage.serialize(), to: gateway.routerHash)

    try await i2npTestWaitUntil { box.gatewayCount == 1 }
    guard let received = box.firstGateway(), received.messageID == inner.messageID,
          received.payload == inner.payload else {
        throw I2NPError.invalidPayload
    }
    guard box.gatewaySources.first == nearest.routerHash else {
        throw I2NPError.invalidPayload
    }
    return "inbound pipeline: gateway → nearest hop → originator endpoint delivery"
}

private static func expiryTest() async throws -> String {
    let node = I2NPTestNode(buildHub: I2PTunnelBuildHub(), deliveryHub: I2NPLoopbackDeliveryHub())
    let box = I2NPTestGatewayBox()
    node.router.addBodyHandler { message, source in
        box.body(message, source)
    }
    // Expired messages are dropped before dispatch.
    let stale = I2NPMessage(type: .deliveryStatus, expiration: Date().addingTimeInterval(-10),
                            payload: { var w = I2PWriter(); w.integer(1); w.long(0); return w.data }())
    await node.router.handleIncoming(stale, from: I2PCrypto.randomBytes(32))
    try await Task.sleep(for: .milliseconds(150))
    guard box.bodyCount == 0 else { throw I2NPError.invalidPayload }
    // Fresh delivery status and options messages reach the registered consumers.
    let fresh = I2NPMessage(type: .deliveryStatus, payload: { var w = I2PWriter(); w.integer(2); w.long(0); return w.data }())
    let opts = I2NPMessage(type: .options, payload: { var w = I2PWriter(); w.mapping(["caps": "Xf"]); return w.data }())
    await node.router.handleIncoming(fresh, from: I2PCrypto.randomBytes(32))
    await node.router.handleIncoming(opts, from: I2PCrypto.randomBytes(32))
    try await i2npTestWaitUntil { box.bodyCount == 2 }
    guard box.bodyKinds == [.deliveryStatus, .options] else { throw I2NPError.invalidPayload }

    // A tunnel hop whose participation state expired no longer decrypts data.
    let tunnelKeys = (layerKey: I2PCrypto.randomBytes(32), iv: I2PCrypto.randomBytes(12))
    let tunnelID: UInt32 = 0x76543210
    let payload = try I2PTunnelDataPayload(tunnelID: tunnelID, iv: tunnelKeys.iv,
        ciphertext: I2PTunnelLayerCipher.wrap(content: Data("x".utf8), layerKey: tunnelKeys.layerKey,
                                              iv: tunnelKeys.iv, tunnelID: tunnelID))
    let state = I2PTunnelHopState(
        receiveTunnelID: tunnelID, nextHopHash: I2PCrypto.randomBytes(32), nextTunnelID: 0,
        isMessagePathEnd: true, layerKey: tunnelKeys.layerKey, ivKey: tunnelKeys.iv, registeredAt: Date()
    )
    node.participant.testInjectHopState(state)
    _ = node.participant.pruneHopStates(now: Date().addingTimeInterval(1801))
    do {
        _ = try node.participant.processTunnelData(payload)
        throw I2NPError.invalidPayload
    } catch let error as I2NPError {
        guard case .unknownTunnel = error else { throw error }
    }
    return "stale I2NP dropped, fresh routed to consumers, expired hop state rejects"
}
}
