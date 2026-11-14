//
//  I2PSSU2.swift
//  I2P
//
//  SSU2 protocol layer: token request/retry management, the SessionRequest →
//  SessionCreated → SessionConfirmed Noise_XK handshake engines, the session
//  state machine with retransmission/backoff, data-phase delivery with replay
//  protection and out-of-order handling, SessionConfirmed and I2NP message
//  fragmentation/reassembly, the peer-test reachability protocol, relay/hole-
//  punch coordination, connection migration with path validation, termination
//  with terminal-packet retransmission and idle teardown, and the UDP
//  transport over the Network framework with a per-peer session pool.
//

import Foundation
import Network
import CryptoKit

// MARK: - Endpoints

struct SSU2Endpoint: Equatable, CustomStringConvertible {
    let host: String
    let port: UInt16

    var description: String { "\(host):\(port)" }

    func serialize() -> Data {
        var w = I2PWriter()
        let hostBytes = Array(Data(host.utf8))
        w.byte(UInt8(hostBytes.count))
        w.raw(Data(hostBytes))
        w.short(port)
        return w.data
    }

    static func parse(_ data: Data) throws -> SSU2Endpoint {
        var r = I2PReader(Data(data))
        let hostLength = Int(try r.byte())
        let host = String(decoding: try r.raw(hostLength), as: UTF8.self)
        let port = try r.short()
        return SSU2Endpoint(host: host, port: port)
    }
}

private func ssu2Timestamp(_ date: Date) -> Data {
    let seconds = UInt32(max(0, date.timeIntervalSince1970).rounded())
    var value = seconds.bigEndian
    return withUnsafeBytes(of: &value) { Data($0) }
}

// MARK: - Session state machine states

/// UNKNOWN → INITIAL (token obtained) → REQUESTED (SessionRequest sent) →
/// CREATED (SessionCreated processed) → CONFIRMED (SessionConfirmed sent) →
/// ESTABLISHED → TERMINATING → CLOSED.
enum SSU2SessionState: Equatable {
    case unknown
    case initial
    case requested
    case created
    case confirmed
    case established
    case terminating
    case closed
}

// MARK: - Token management

/// Server-side token service: opaque 8-byte tokens bound to the requester's
/// source connection ID, single expiry, and rate limiting per requester.
final class SSU2TokenManager {
    private struct Entry {
        let ownerConnectionID: Data
        let expiresAt: Date
    }

    private let lock = NSLock()
    private var tokens: [Data: Entry] = [:]
    private var requests: [Data: [Date]] = [:]

    let tokenLifetime: TimeInterval
    let maxRequestsPerWindow: Int
    let requestWindow: TimeInterval

    init(tokenLifetime: TimeInterval = 600,
         maxRequestsPerWindow: Int = 5,
         requestWindow: TimeInterval = 60) {
        self.tokenLifetime = tokenLifetime
        self.maxRequestsPerWindow = maxRequestsPerWindow
        self.requestWindow = requestWindow
    }

    /// Issues a token for a requester, or nil when the requester exceeded the
    /// request rate for the current window.
    func issue(for requesterConnectionID: Data, now: Date = Date()) -> Data? {
        lock.lock()
        defer { lock.unlock() }
        pruneLocked(now: now)
        var list = requests[requesterConnectionID] ?? []
        list = list.filter { now.timeIntervalSince($0) < requestWindow }
        guard list.count < maxRequestsPerWindow else { return nil }
        list.append(now)
        requests[requesterConnectionID] = list
        let token = I2PCrypto.randomBytes(8)
        tokens[token] = Entry(ownerConnectionID: requesterConnectionID,
                              expiresAt: now.addingTimeInterval(tokenLifetime))
        return token
    }

    /// Validates a token presented in a SessionRequest header: it must exist,
    /// belong to the requesting connection ID, and not be expired.
    func validate(_ token: Data, for requesterConnectionID: Data, now: Date = Date()) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        pruneLocked(now: now)
        guard let entry = tokens[token] else { return false }
        return entry.ownerConnectionID == requesterConnectionID && entry.expiresAt > now
    }

    private func pruneLocked(now: Date) {
        tokens = tokens.filter { $0.value.expiresAt > now }
        requests = requests.mapValues { $0.filter { now.timeIntervalSince($0) < requestWindow } }
        requests = requests.filter { !$0.value.isEmpty }
    }

    func prune(now: Date = Date()) {
        lock.lock()
        defer { lock.unlock() }
        pruneLocked(now: now)
    }

    var activeTokenCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return tokens.count
    }
}

/// Initiator-side token cache: tokens learned from Retry packets, keyed by the
/// responder's static key, with expiry.
final class SSU2TokenCache {
    private struct Entry {
        let token: Data
        let expiresAt: Date
    }

    private let lock = NSLock()
    private var byRemote: [Data: Entry] = [:]

    func store(token: Data, for remoteStaticKey: Data, lifetime: TimeInterval = 600, now: Date = Date()) {
        lock.lock()
        defer { lock.unlock() }
        byRemote[remoteStaticKey] = Entry(token: token, expiresAt: now.addingTimeInterval(lifetime))
    }

    func token(for remoteStaticKey: Data, now: Date = Date()) -> Data? {
        lock.lock()
        defer { lock.unlock() }
        guard let entry = byRemote[remoteStaticKey], entry.expiresAt > now else { return nil }
        return entry.token
    }

    func prune(now: Date = Date()) {
        lock.lock()
        defer { lock.unlock() }
        byRemote = byRemote.filter { $0.value.expiresAt > now }
    }
}

// MARK: - Noise XK handshake engines

/// The initiator engine: knows the responder's static key (pattern XK).
/// SessionRequest carries the ephemeral key (region-obfuscated), the encrypted
/// initiator static key, and the encrypted options payload; SessionConfirmed
/// rides in the data phase.
final class SSU2InitiatorHandshake {
    enum Stage { case idle, awaitingRetryOrCreated, awaitingCreated, confirmed }

    private(set) var stage: Stage = .idle
    private(set) var remoteConnectionID: Data?
    /// The offered ML-KEM hybrid leg (nil = classical handshake in progress).
    private(set) var pqLeg: I2PSSU2PQVersion?
    private let remoteMLKEMKey: I2PMLKEMPublicKey?
    private var pendingEncapsulation: I2PMLKEMEncapsulation?

    private var chain = NTCP2NoiseChain()
    private let localStaticKey: Curve25519.KeyAgreement.PrivateKey
    private let remoteStaticKey: Data
    private let introKey: Data
    private let ephemeral = Curve25519.KeyAgreement.PrivateKey()
    private var aliceHeader: Data?
    private var localConnectionID: Data?
    /// The responder's RouterInfo, recovered from the SessionCreated payload.
    private(set) var remoteRouterInfoData: Data?

    /// The responder's demultiplex connection ID, derived from its static key
    /// so inbound handshake packets land without prior state.
    static func responderConnectionID(for remoteStaticKey: Data) -> Data {
        Data(I2PCrypto.sha256(remoteStaticKey + Data("SSU2 dst conn".utf8)).prefix(8))
    }

    init(localStaticKey: Curve25519.KeyAgreement.PrivateKey,
         remoteStaticKey: Data, introKey: Data,
         remoteMLKEMKey: I2PMLKEMPublicKey? = nil) {
        precondition(remoteStaticKey.count == 32 && introKey.count == 32)
        self.localStaticKey = localStaticKey
        self.remoteStaticKey = remoteStaticKey
        self.introKey = introKey
        // The PQ leg is offered only when the peer advertises an ML-KEM
        // encapsulation key; the long-header version byte binds the offer.
        self.remoteMLKEMKey = remoteMLKEMKey
        self.pqLeg = remoteMLKEMKey?.version
    }

    /// TokenRequest (type 10): a long-header packet addressed to the responder's
    /// derived connection ID, asking for a Retry with a fresh token. The header
    /// is masked with the session-request phase key (token requests share it).
    func makeTokenRequest(localConnectionID: Data) throws -> Data {
        self.localConnectionID = localConnectionID
        let header = SSU2PacketHeader(
            destinationConnectionID: SSU2InitiatorHandshake.responderConnectionID(for: remoteStaticKey),
            packetNumber: 0, type: .tokenRequest,
            sourceConnectionID: localConnectionID,
            token: Data(repeating: 0, count: 8))
        var packet = header.serialize()
        packet.append(ssu2Timestamp(Date()))
        if packet.count < 40 {
            // Header masking derives its IVs from the packet tail; the minimum
            // datagram is 40 bytes (16 header + 24 tail). Pad up to it.
            packet.append(I2PCrypto.randomBytes(40 - packet.count))
        }
        try SSU2HeaderProtection.maskHeader(&packet, phase: .sessionRequest, introKey: introKey)
        stage = .awaitingRetryOrCreated
        return packet
    }

    /// SessionRequest (type 0): fresh Noise chain (each attempt starts clean),
    /// header MixHash binding, ephemeral key in the obfuscated region, encrypted
    /// static section (48 bytes), encrypted options payload.
    func makeSessionRequest(localConnectionID: Data, token: Data) throws -> Data {
        self.localConnectionID = localConnectionID
        chain = NTCP2NoiseChain()
        let header = SSU2PacketHeader(
            destinationConnectionID: SSU2InitiatorHandshake.responderConnectionID(for: remoteStaticKey),
            packetNumber: 0, type: .sessionRequest,
            sourceConnectionID: localConnectionID, token: token,
            version: pqLeg?.rawValue ?? SSU2PacketHeader.version)
        aliceHeader = header.serialize()
        chain.mixHash(aliceHeader!)
        var packet = aliceHeader! + ephemeral.publicKey.rawRepresentation

        let responderStatic = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: remoteStaticKey)
        let es = try ephemeral.sharedSecretFromKeyAgreement(with: responderStatic)
        chain.mixKey(es.withUnsafeBytes { Data($0) })
        // The encrypted static-key section is exactly 48 bytes on the wire
        // (32-byte ciphertext + 16-byte tag of the key alone, per the spec
        // SessionRequest layout the receiver slices at 64..<112).
        let staticPlain = localStaticKey.publicKey.rawRepresentation
        packet.append(try chain.encrypt(staticPlain))
        let ss = try localStaticKey.sharedSecretFromKeyAgreement(with: responderStatic)
        chain.mixKey(ss.withUnsafeBytes { Data($0) })
        var payload = ssu2Timestamp(Date())
        payload.append(contentsOf: Data("SSU2".utf8))
        packet.append(try chain.encrypt(payload))
        if let pqLeg, let remoteMLKEMKey {
            // Hybrid offer: the FIPS 203 ENCAPS ciphertext rides after the
            // options section, and the version byte binds the peer to this
            // ciphertext shape (768 bytes for ML-KEM-512, 1088 for ML-KEM-768).
            let encapsulation = try remoteMLKEMKey.encapsulate()
            try I2PPQHybrid.validateVersionBinding(versionRawValue: pqLeg.rawValue,
                                                   encapsulation: encapsulation)
            packet.append(encapsulation.ciphertext)
            pendingEncapsulation = encapsulation
        }

        try SSU2HeaderProtection.obfuscateEphemeralRegion(&packet, introKey: introKey,
                                                          responderStaticKey: remoteStaticKey)
        try SSU2HeaderProtection.maskHeader(&packet, phase: .sessionRequest, introKey: introKey)
        stage = .awaitingCreated
        return packet
    }

    /// Retry (type 9): unmasked with the retry phase key; the fresh token rides
    /// in the header token field. Returns the token for the token cache. A Retry
    /// doubles as the responder's no-PQ signal when a hybrid offer is outstanding.
    func processRetry(_ packet: Data) throws -> Data {
        guard stage == .awaitingRetryOrCreated || stage == .awaitingCreated else {
            throw SSU2Error.handshakeFailed("Retry outside the request stages")
        }
        var masked = Data(packet)
        try SSU2HeaderProtection.unmaskHeader(&masked, phase: .retry, introKey: introKey)
        let header = try SSU2PacketHeader.parse(masked)
        guard header.type == .retry, header.isLong, let token = header.token else {
            throw SSU2Error.invalidPacket
        }
        guard let localConnectionID,
              header.destinationConnectionID == localConnectionID else {
            throw SSU2Error.invalidPacket
        }
        return token
    }

    /// SessionCreated (type 1): unmask the header, deobfuscate the ephemeral
    /// region, run ee/se key agreement over the responder's static section, then
    /// the payload section. The chaining key at this point splits into the two
    /// data-phase directions.
    func processSessionCreated(_ packet: Data) throws {
        guard stage == .awaitingCreated else {
            throw SSU2Error.handshakeFailed("SessionCreated outside the request stage")
        }
        var masked = Data(packet)
        try SSU2HeaderProtection.unmaskHeader(&masked, phase: .sessionCreated, introKey: introKey)
        try SSU2HeaderProtection.obfuscateEphemeralRegion(&masked, introKey: introKey,
                                                          responderStaticKey: remoteStaticKey)
        let header = try SSU2PacketHeader.parse(masked)
        guard header.type == .sessionCreated, header.isLong,
              let bobSource = header.sourceConnectionID else {
            throw SSU2Error.invalidPacket
        }
        // The PQ negotiation is bound to the version byte: a hybrid offer is
        // only satisfied by a hybrid SessionCreated of the same shape.
        if let pqLeg {
            guard header.pqVersion == pqLeg, let pendingEncapsulation else {
                throw SSU2Error.handshakeFailed("hybrid SessionCreated missing the offered PQ leg")
            }
        } else if header.pqVersion != nil {
            throw SSU2Error.handshakeFailed("unoffered PQ version in SessionCreated")
        }
        guard header.destinationConnectionID == aliceHeader?.subdata(in: 16..<24) else {
            throw SSU2Error.handshakeFailed("SessionCreated not addressed to this initiator")
        }
        remoteConnectionID = bobSource
        chain.mixHash(header.serialize())

        let bobEphemeral = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: masked.subdata(in: 32..<64))
        let ee = try ephemeral.sharedSecretFromKeyAgreement(with: bobEphemeral)
        chain.mixKey(ee.withUnsafeBytes { Data($0) })
        let staticSection = masked.subdata(in: 64..<112)
        let staticPlain = try chain.decrypt(staticSection)
        guard staticPlain.prefix(32) == remoteStaticKey else {
            throw SSU2Error.handshakeFailed("responder static key mismatch")
        }
        let se = try localStaticKey.sharedSecretFromKeyAgreement(with: bobEphemeral)
        chain.mixKey(se.withUnsafeBytes { Data($0) })
        let payloadBytes = Array(try chain.decrypt(masked.subdata(in: 112..<masked.count)))
        // The responder's payload carries timestamp (4) + "SSU2" (4) and, when
        // present, its RouterInfo as [length (2 BE)][RouterInfo].
        if payloadBytes.count > 8 {
            let body = Data(payloadBytes.dropFirst(8))
            if body.count >= 2 {
                let length = (Int(body[body.startIndex]) << 8) | Int(body[body.index(after: body.startIndex)])
                if length > 0, body.count >= 2 + length {
                    remoteRouterInfoData = body.subdata(in: 2..<(2 + length))
                }
            }
        }
        if let encapsulation = pendingEncapsulation {
            // Dual-leg binding: mix the ML-KEM encapsulation output into the
            // session KDF before the split, so the split rides both legs.
            I2PSSU2PQKDF.mix(&chain, encapsulation: encapsulation)
        }
        stage = .confirmed
    }

    /// Down-negotiation: the peer signaled no PQ support (a Retry while a
    /// hybrid offer was outstanding), so the handshake continues classically.
    func downgradeToClassical() {
        pqLeg = nil
        pendingEncapsulation = nil
    }

    /// Noise Split() after the last handshake message was processed.
    func complete() throws -> SSU2SessionKeys {
        guard stage == .confirmed else {
            throw SSU2Error.handshakeFailed("handshake not confirmed")
        }
        return SSU2KeySchedule.split(chainingKey: chain.chainingKey)
    }
}

/// The responder engine: accepts TokenRequests (stateless token service),
/// validates SessionRequest tokens (issuing a Retry on failure), and splits the
/// session keys after the SessionConfirmed channel is prepared.
final class SSU2ResponderHandshake {
    enum Stage { case awaitingRequest, awaitingConfirmed, established }

    private(set) var stage: Stage = .awaitingRequest
    private(set) var remoteStaticKey: Data?
    private(set) var requesterConnectionID: Data?
    private(set) var validatedToken: Data?
    /// The accepted ML-KEM hybrid leg (nil = classical handshake in progress).
    private(set) var negotiatedPQ: I2PSSU2PQVersion?
    private let localMLKEMSecretKey: I2PMLKEMSecretKey?
    private var acceptedEncapsulation: I2PMLKEMEncapsulation?
    private var aliceEphemeralPub: Data?
    private var aliceStaticPub: Data?

    private var chain = NTCP2NoiseChain()
    private let localStaticKey: Curve25519.KeyAgreement.PrivateKey
    private let introKey: Data
    private let localConnectionID: Data
    private let tokenManager: SSU2TokenManager
    /// Our serialized RouterInfo, carried to the initiator in the SessionCreated
    /// payload (the initiator's own RI rides the SessionConfirmed), so both
    /// parties learn each other's identity during the handshake.
    private let localRouterInfoData: Data

    init(localStaticKey: Curve25519.KeyAgreement.PrivateKey, localConnectionID: Data,
         introKey: Data, tokenManager: SSU2TokenManager,
         localMLKEMSecretKey: I2PMLKEMSecretKey? = nil,
         localRouterInfoData: Data = Data()) {
        self.localStaticKey = localStaticKey
        self.localConnectionID = localConnectionID
        self.introKey = introKey
        self.tokenManager = tokenManager
        self.localMLKEMSecretKey = localMLKEMSecretKey
        self.localRouterInfoData = localRouterInfoData
    }

    /// Retry (type 9) carrying a fresh token in the header token field.
    func makeRetry(for requesterConnectionID: Data, token: Data) throws -> Data {
        let header = SSU2PacketHeader(
            destinationConnectionID: requesterConnectionID, packetNumber: 0,
            type: .retry, sourceConnectionID: localConnectionID, token: token)
        var packet = header.serialize()
        packet.append(ssu2Timestamp(Date()))
        if packet.count < 40 {
            // Masking needs the 40-byte minimum; pad to it (padding is ignored
            // by the receiver, which reads the header and timestamp only).
            packet.append(I2PCrypto.randomBytes(40 - packet.count))
        }
        try SSU2HeaderProtection.maskHeader(&packet, phase: .retry, introKey: introKey)
        return packet
    }

    /// TokenRequest (type 10): rate-limited token issuance bound to the
    /// requester's source connection ID. Returns the Retry datagram, or nil
    /// when the requester is rate-limited (silent drop).
    func processTokenRequest(_ packet: Data) throws -> Data? {
        var masked = Data(packet)
        try SSU2HeaderProtection.unmaskHeader(&masked, phase: .sessionRequest, introKey: introKey)
        let header = try SSU2PacketHeader.parse(masked)
        guard header.type == .tokenRequest, header.isLong,
              let source = header.sourceConnectionID else {
            throw SSU2Error.invalidPacket
        }
        guard let token = tokenManager.issue(for: source) else { return nil }
        return try makeRetry(for: source, token: token)
    }

    /// SessionRequest (type 0): token validation (a Retry is issued on failure),
    /// es/ss agreement, encrypted initiator static verification, then the
    /// SessionCreated construction. The chaining key splits after this.
    func processSessionRequest(_ packet: Data) throws -> Data {
        guard stage == .awaitingRequest else {
            throw SSU2Error.handshakeFailed("unexpected SessionRequest")
        }
        var masked = Data(packet)
        try SSU2HeaderProtection.unmaskHeader(&masked, phase: .sessionRequest, introKey: introKey)
        try SSU2HeaderProtection.obfuscateEphemeralRegion(&masked, introKey: introKey,
                                                          responderStaticKey: localStaticKey.publicKey.rawRepresentation)
        let header = try SSU2PacketHeader.parse(masked)
        guard header.type == .sessionRequest, header.isLong,
              let source = header.sourceConnectionID, let token = header.token else {
            throw SSU2Error.invalidPacket
        }
        guard header.destinationConnectionID == localConnectionID else {
            throw SSU2Error.invalidPacket
        }
        // Hybrid offer gate: when the peer offered the ML-KEM leg (version 3/4)
        // but this responder holds no matching ML-KEM key, a Retry signals the
        // classical handshake — the initiator down-negotiates and retries.
        let offeredPQ = header.pqVersion
        if let offeredPQ, localMLKEMSecretKey?.version != offeredPQ {
            guard let fresh = tokenManager.issue(for: source) else { return Data() }
            return try makeRetry(for: source, token: fresh)
        }
        guard tokenManager.validate(token, for: source) else {
            guard let fresh = tokenManager.issue(for: source) else { return Data() }
            return try makeRetry(for: source, token: fresh)
        }
        requesterConnectionID = source
        validatedToken = token
        chain.mixHash(header.serialize())

        let aliceEphemeralPub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: masked.subdata(in: 32..<64))
        self.aliceEphemeralPub = aliceEphemeralPub.rawRepresentation
        let es = try localStaticKey.sharedSecretFromKeyAgreement(with: aliceEphemeralPub)
        chain.mixKey(es.withUnsafeBytes { Data($0) })
        // Hybrid offers append the FIPS 203 ciphertext after the options
        // section; its length is bound to the version byte, so the options
        // section ends where the ML-KEM ciphertext begins.
        let optionsEnd = masked.count - (offeredPQ?.mlKemCiphertextLength ?? 0)
        guard optionsEnd >= 112 else { throw SSU2Error.invalidPacket }
        let staticPlain = try chain.decrypt(masked.subdata(in: 64..<112))
        remoteStaticKey = staticPlain.prefix(32)
        self.aliceStaticPub = remoteStaticKey
        let aliceStatic = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: remoteStaticKey!)
        let ss = try localStaticKey.sharedSecretFromKeyAgreement(with: aliceStatic)
        chain.mixKey(ss.withUnsafeBytes { Data($0) })
        _ = try chain.decrypt(masked.subdata(in: 112..<optionsEnd))
        if let offeredPQ, let localMLKEMSecretKey {
            // Hybrid accept: decapsulate the FIPS 203 ciphertext and bind the
            // ciphertext shape to the long-header version byte. The shared
            // secret mixes into the session KDF before the split (dual-leg
            // binding), so a classical-only peer derives different material.
            let ciphertext = masked.subdata(in: optionsEnd..<masked.count)
            let secret = try localMLKEMSecretKey.decapsulate(ciphertext)
            let encapsulation = try I2PMLKEMEncapsulation(ciphertext: ciphertext, sharedSecret: secret)
            try I2PPQHybrid.validateVersionBinding(versionRawValue: offeredPQ.rawValue,
                                                   encapsulation: encapsulation)
            acceptedEncapsulation = encapsulation
        }
        negotiatedPQ = offeredPQ
        let response = try makeSessionCreated()
        // `complete()` is called by the owning session immediately after the
        // response is constructed. Advance only after construction succeeds so
        // failed handshakes cannot expose split keys from a partial exchange.
        stage = .awaitingConfirmed
        return response
    }

    /// SessionCreated (type 1): the ephemeral region carries the responder's
    /// fresh ephemeral key, the encrypted static section (48 bytes, tag inside)
    /// carries the responder's static key, and the encrypted options payload
    /// completes the XK exchange. The chain advances identically on both sides,
    /// so the split after this construction matches the initiator's split.
    private func makeSessionCreated() throws -> Data {
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let header = SSU2PacketHeader(
            destinationConnectionID: requesterConnectionID!, packetNumber: 0,
            type: .sessionCreated, sourceConnectionID: localConnectionID,
            version: negotiatedPQ?.rawValue ?? SSU2PacketHeader.version)
        chain.mixHash(header.serialize())
        var packet = header.serialize() + ephemeral.publicKey.rawRepresentation

        let aliceEphemeral = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: aliceEphemeralPub!)
        let ee = try ephemeral.sharedSecretFromKeyAgreement(with: aliceEphemeral)
        chain.mixKey(ee.withUnsafeBytes { Data($0) })
        // 48-byte encrypted static-key section: 32-byte ciphertext + tag.
        let staticPlain = localStaticKey.publicKey.rawRepresentation
        packet.append(try chain.encrypt(staticPlain))

        let aliceStatic = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: aliceStaticPub!)
        let se = try ephemeral.sharedSecretFromKeyAgreement(with: aliceStatic)
        chain.mixKey(se.withUnsafeBytes { Data($0) })
        var payload = ssu2Timestamp(Date())
        payload.append(contentsOf: Data("SSU2".utf8))
        // Our RouterInfo follows the timestamp/version header as a 2-byte
        // length-prefixed section, so the initiator learns who it is talking to
        // in the same handshake (its own RI arrives in the SessionConfirmed).
        if !localRouterInfoData.isEmpty, localRouterInfoData.count <= 0xFFFF {
            payload.append(UInt8((localRouterInfoData.count >> 8) & 0xff))
            payload.append(UInt8(localRouterInfoData.count & 0xff))
            payload.append(localRouterInfoData)
        }
        packet.append(try chain.encrypt(payload))
        if let encapsulation = acceptedEncapsulation {
            // The initiator mixes at the same chain point after decrypting this
            // payload; mixing here keeps both sides' split states aligned.
            I2PSSU2PQKDF.mix(&chain, encapsulation: encapsulation)
        }

        try SSU2HeaderProtection.obfuscateEphemeralRegion(&packet, introKey: introKey,
                                                          responderStaticKey: localStaticKey.publicKey.rawRepresentation)
        try SSU2HeaderProtection.maskHeader(&packet, phase: .sessionCreated, introKey: introKey)
        return packet
    }

    func complete() throws -> SSU2SessionKeys {
        guard stage == .awaitingConfirmed else {
            throw SSU2Error.handshakeFailed("SessionRequest not processed")
        }
        // The responder sends the Noise `ba` key and receives with `ab`; the
        // initiator uses the opposite direction mapping.
        return SSU2KeySchedule.split(chainingKey: chain.chainingKey,
                                     initiatorSendsWithAB: false)
    }
}

// MARK: - SessionConfirmed fragmentation and reassembly

/// Splits the SessionConfirmed payload into up to 15 fragments, each small
/// enough for one datagram (payload budget = 1472 - 16 header - 16 MAC).
enum SSU2ConfirmedFragmenter {
    static func split(_ payload: Data, maximumFragmentPayload: Int) throws -> [Data] {
        guard maximumFragmentPayload > 0 else { throw SSU2Error.invalidPacket }
        let count = max(1, Int((Double(payload.count) / Double(maximumFragmentPayload)).rounded(.up)))
        guard count <= 15 else { throw SSU2Error.invalidPacket }
        var fragments: [Data] = []
        var offset = 0
        while offset < payload.count {
            let end = min(offset + maximumFragmentPayload, payload.count)
            fragments.append(payload.subdata(in: offset..<end))
            offset = end
        }
        return fragments.isEmpty ? [Data()] : fragments
    }
}

/// Reassembles SessionConfirmed fragments (up to 15) with a completion timeout.
final class SSU2ConfirmedReassembler {
    private let lock = NSLock()
    private var fragments: [Int: Data] = [:]
    private var totalFragments: Int = 0
    private(set) var startedAt: Date?

    /// Adds one fragment; returns the complete payload when all fragments have
    /// arrived, otherwise nil. `now` bounds the reassembly window.
    func add(fragmentIndex: Int, totalFragments: Int, payload: Data,
             timeout: TimeInterval, now: Date = Date()) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        if let started = startedAt, now.timeIntervalSince(started) > timeout {
            throw SSU2Error.fragmentTimeout
        }
        guard totalFragments >= 1 && totalFragments <= 15 else { throw SSU2Error.invalidPacket }
        guard fragmentIndex >= 0 && fragmentIndex < totalFragments else { throw SSU2Error.invalidPacket }
        if fragments.isEmpty { startedAt = now }
        self.totalFragments = totalFragments
        fragments[fragmentIndex] = payload
        guard fragments.count == totalFragments else { return nil }
        var out = Data()
        for index in 0..<totalFragments {
            guard let chunk = fragments[index] else { throw SSU2Error.invalidPacket }
            out.append(chunk)
        }
        return out
    }

    var isComplete: Bool {
        lock.lock()
        defer { lock.unlock() }
        return totalFragments > 0 && fragments.count == totalFragments
    }
}

// MARK: - I2NP fragmentation within Data packets

/// Splits an oversized I2NP message into up to 15 data-block fragments, each
/// carrying [messageID (4 BE)][fragment byte][chunk] inside one data packet.
enum SSU2MessageFragmenter {
    static func split(_ message: Data, messageID: UInt32,
                      maximumFragmentPayload: Int) throws -> [SSU2Block] {
        let budget = maximumFragmentPayload - 5 // messageID + fragment byte
        guard budget > 0 else { throw SSU2Error.invalidPacket }
        let count = max(1, Int((Double(message.count) / Double(budget)).rounded(.up)))
        guard count <= 15 else { throw SSU2Error.invalidPacket }
        var blocks: [SSU2Block] = []
        var offset = 0
        while offset < message.count {
            let end = min(offset + budget, message.count)
            let index = blocks.count
            blocks.append(.dataFragment(messageID: messageID, fragmentIndex: index,
                                        totalFragments: count,
                                        payload: message.subdata(in: offset..<end)))
            offset = end
        }
        return blocks
    }
}

/// Reassembles fragmented I2NP messages by message ID with a completion timeout.
final class SSU2MessageReassembler {
    private let lock = NSLock()
    private var fragments: [Int: Data] = [:]
    private var totalFragments = 0
    private(set) var startedAt: Date?

    func add(fragmentIndex: Int, totalFragments: Int, payload: Data,
             timeout: TimeInterval, now: Date = Date()) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        if let started = startedAt, now.timeIntervalSince(started) > timeout {
            throw SSU2Error.fragmentTimeout
        }
        guard totalFragments >= 1 && totalFragments <= 15, fragmentIndex >= 0, fragmentIndex < totalFragments else {
            throw SSU2Error.invalidPacket
        }
        if fragments.isEmpty { startedAt = now }
        self.totalFragments = totalFragments
        fragments[fragmentIndex] = payload
        guard fragments.count == totalFragments else { return nil }
        var out = Data()
        for index in 0..<totalFragments {
            guard let chunk = fragments[index] else { throw SSU2Error.invalidPacket }
            out.append(chunk)
        }
        return out
    }
}

// MARK: - Peer test protocol

enum SSU2Reachability: String, Codable {
    case direct
    case portMapped
    case symmetricNAT
    case unreachable
}

/// Peer-test message bodies ride in type-7 long-header packets. The request
/// body is [nonce (4 BE)][timestamp (4 BE)]; the response body is
/// [nonce (4 BE)][observed endpoint] where the observed endpoint is the
/// requester's IP:port as seen by the tester.
enum SSU2PeerTestMessage {
    static func requestBody(nonce: UInt32, now: Date = Date()) -> Data {
        var w = Data()
        var value = nonce.bigEndian
        w.append(contentsOf: withUnsafeBytes(of: &value) { Data($0) })
        w.append(ssu2Timestamp(now))
        return w
    }

    static func responseBody(nonce: UInt32, observed: SSU2Endpoint, now: Date = Date()) -> Data {
        var w = Data()
        var value = nonce.bigEndian
        w.append(contentsOf: withUnsafeBytes(of: &value) { Data($0) })
        w.append(ssu2Timestamp(now))
        w.append(observed.serialize())
        return w
    }

    static func parse(_ body: Data) throws -> (nonce: UInt32, observed: SSU2Endpoint?) {
        let bytes = Array(Data(body))
        guard bytes.count >= 8 else { throw SSU2Error.invalidPacket }
        let nonce = (UInt32(bytes[0]) << 24) | (UInt32(bytes[1]) << 16)
            | (UInt32(bytes[2]) << 8) | UInt32(bytes[3])
        var observed: SSU2Endpoint?
        if bytes.count > 8 {
            observed = try SSU2Endpoint.parse(Data(bytes[8..<bytes.count]))
        }
        return (nonce, observed)
    }
}

/// Peer-test coordination: nonce correlation, endpoint classification and a
/// result cache with configurable expiration (default 1 hour).
final class SSU2PeerTestCoordinator {
    struct Result {
        let nonce: UInt32
        let observed: SSU2Endpoint?
        let classification: SSU2Reachability
        let recordedAt: Date
        let expiresAt: Date
    }

    private let lock = NSLock()
    private var results: [UInt32: Result] = [:]
    private var awaiting: [UInt32: Date] = [:]

    func begin(nonce: UInt32, now: Date = Date()) {
        lock.lock()
        defer { lock.unlock() }
        awaiting[nonce] = now
    }

    /// Reachability classification per the peer-test spec: the observed address
    /// equals the published address (direct), shares its IP but differs in port
    /// (port-mapped), differs in IP (symmetric NAT), or nothing arrived
    /// (unreachable).
    static func classify(observed: SSU2Endpoint?, published: SSU2Endpoint?) -> SSU2Reachability {
        guard let observed, let published else { return .unreachable }
        if observed == published { return .direct }
        if observed.host == published.host { return .portMapped }
        return .symmetricNAT
    }

    /// Records the observed endpoint for a nonce and classifies reachability.
    func record(nonce: UInt32, observed: SSU2Endpoint?, published: SSU2Endpoint?,
                lifetime: TimeInterval = 3600, now: Date = Date()) -> Result {
        lock.lock()
        defer { lock.unlock() }
        awaiting[nonce] = nil
        let result = Result(nonce: nonce, observed: observed,
                            classification: SSU2PeerTestCoordinator.classify(observed: observed, published: published),
                            recordedAt: now, expiresAt: now.addingTimeInterval(lifetime))
        results[nonce] = result
        return result
    }

    func result(for nonce: UInt32, now: Date = Date()) -> Result? {
        lock.lock()
        defer { lock.unlock() }
        guard let result = results[nonce], result.expiresAt > now else { return nil }
        return result
    }

    func isAwaiting(_ nonce: UInt32, now: Date = Date()) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return awaiting[nonce] != nil
    }

    func expire(now: Date = Date()) {
        lock.lock()
        defer { lock.unlock() }
        results = results.filter { $0.value.expiresAt > now }
        awaiting = awaiting.filter { now.timeIntervalSince($0.value) < 60 }
    }

    var resultCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return results.count
    }
}

// MARK: - Relay protocol

/// A relay (introducer) entry from a RouterInfo SSU2 address.
struct SSU2RelayEntry {
    let introductionKey: Data // 32 bytes
    let host: String
    let port: UInt16
    let sessionID: UInt32
    let supportsPeerTest: Bool
    let supportsHolePunch: Bool
}

/// Relay request/response payloads and the hole-punch coordination.
enum SSU2RelayMessage {
    /// RelayRequest to the introducer: [nonce (4 BE)][target hash (32)][target port (2 BE)].
    static func request(nonce: UInt32, targetHash: Data, targetPort: UInt16) -> Data {
        precondition(targetHash.count == 32)
        var w = Data()
        var value = nonce.bigEndian
        w.append(contentsOf: withUnsafeBytes(of: &value) { Data($0) })
        w.append(targetHash)
        var port = targetPort.bigEndian
        w.append(contentsOf: withUnsafeBytes(of: &port) { Data($0) })
        return w
    }

    /// RelayResponse: [nonce (4 BE)][status (1)] — status 0 = relay accepted.
    static func response(nonce: UInt32, status: UInt8) -> Data {
        var w = Data()
        var value = nonce.bigEndian
        w.append(contentsOf: withUnsafeBytes(of: &value) { Data($0) })
        w.append(Data([status]))
        return w
    }

    static func parseResponse(_ body: Data) throws -> (nonce: UInt32, status: UInt8) {
        let bytes = Array(Data(body))
        guard bytes.count >= 5 else { throw SSU2Error.invalidPacket }
        let nonce = (UInt32(bytes[0]) << 24) | (UInt32(bytes[1]) << 16)
            | (UInt32(bytes[2]) << 8) | UInt32(bytes[3])
        return (nonce, bytes[4])
    }

    static func parseRequest(_ body: Data) throws -> (nonce: UInt32, targetHash: Data, targetPort: UInt16) {
        let bytes = Array(Data(body))
        guard bytes.count >= 38 else { throw SSU2Error.invalidPacket }
        let nonce = (UInt32(bytes[0]) << 24) | (UInt32(bytes[1]) << 16)
            | (UInt32(bytes[2]) << 8) | UInt32(bytes[3])
        return (nonce, Data(bytes[4..<36]),
                UInt16(bytes[36]) << 8 | UInt16(bytes[37]))
    }
}

/// Relay coordination: RelayRequest to the introducer, RelayResponse handling,
/// and the HolePunch (type-11 long-header) packet toward the target.
final class SSU2RelayCoordinator {
    enum Phase { case idle, requested, relayAccepted, holePunchSent, completed, failed }

    private(set) var phase: Phase = .idle
    private(set) var lastStatus: UInt8 = 0

    func begin() { phase = .requested }

    /// Builds the RelayRequest payload addressed to the introducer.
    func buildRelayRequest(nonce: UInt32, targetHash: Data, targetPort: UInt16) -> Data {
        phase = .requested
        return SSU2RelayMessage.request(nonce: nonce, targetHash: targetHash, targetPort: targetPort)
    }

    /// Processes a RelayResponse body; returns true when the relay accepted.
    func handleRelayResponse(_ body: Data) throws -> Bool {
        let (_, status) = try SSU2RelayMessage.parseResponse(body)
        lastStatus = status
        guard status == 0 else {
            phase = .failed
            return false
        }
        phase = .relayAccepted
        return true
    }

    /// Builds the HolePunch (type-11) datagram toward the target address.
    func buildHolePunch(nonce: UInt32, packetNumber: UInt32, destinationConnectionID: Data,
                        sourceConnectionID: Data, introKey: Data) throws -> Data {
        let header = SSU2PacketHeader(
            destinationConnectionID: destinationConnectionID, packetNumber: packetNumber,
            type: .holePunch, sourceConnectionID: sourceConnectionID)
        var packet = header.serialize()
        var value = nonce.bigEndian
        packet.append(contentsOf: withUnsafeBytes(of: &value) { Data($0) })
        if packet.count < 40 {
            packet.append(I2PCrypto.randomBytes(40 - packet.count))
        }
        try SSU2HeaderProtection.maskHeader(&packet, phase: .holePunch, introKey: introKey)
        phase = .holePunchSent
        return packet
    }

    /// Receives a HolePunch (type-11) datagram: returns the nonce so the target
    /// can open a return path to the puncher's endpoint.
    func handleHolePunch(_ packet: Data, introKey: Data) throws -> UInt32 {
        var masked = Data(packet)
        try SSU2HeaderProtection.unmaskHeader(&masked, phase: .holePunch, introKey: introKey)
        let header = try SSU2PacketHeader.parse(masked)
        guard header.type == .holePunch, header.isLong else { throw SSU2Error.invalidPacket }
        let body = masked.subdata(in: 32..<masked.count)
        guard body.count >= 4 else { throw SSU2Error.invalidPacket }
        let nonce = (UInt32(body[0]) << 24) | (UInt32(body[1]) << 16)
            | (UInt32(body[2]) << 8) | UInt32(body[3])
        phase = .completed
        return nonce
    }
}
// MARK: - Session

protocol SSU2SessionDelegate: AnyObject {
    func session(_ session: SSU2Session, didEstablish remoteRouterInfo: I2PRouterInfo?)
    func session(_ session: SSU2Session, didReceiveData data: Data)
    func session(_ session: SSU2Session, didClose error: Error?)
}

/// One SSU2 session: full state machine (token request → retry → handshake →
/// confirmed → established → terminating → closed), data-phase delivery with
/// replay protection and I2NP reassembly, peer tests, relay coordination,
/// connection migration with path validation, termination with terminal-packet
/// retransmission, and idle teardown. Outbound datagrams flow through the
/// `outboundHandler` (transport socket or loopback wiring in tests).
final class SSU2Session {
    enum Role { case initiator, responder }

    typealias OutboundHandler = ((Data, SSU2Endpoint?) -> Void)

    let role: Role
    let localConnectionID: Data
    private(set) var state: SSU2SessionState = .unknown
    private(set) var remoteConnectionID: Data?
    private(set) var remoteEndpoint: SSU2Endpoint?
    private(set) var remoteRouterInfo: I2PRouterInfo?
    private(set) var lastError: Error?
    private(set) var replayDrops = 0
    private(set) var terminationRetransmissions = 0
    private(set) var peerTest = SSU2PeerTestCoordinator()
    private(set) var relay = SSU2RelayCoordinator()
    var publishedEndpoint: SSU2Endpoint?

    var outboundHandler: OutboundHandler?
    weak var delegate: SSU2SessionDelegate?

    private let localStaticKey: Curve25519.KeyAgreement.PrivateKey
    private let remoteStaticKey: Data?
    private let introKey: Data
    /// Our ML-KEM capability for accepting hybrid sessions (responder side).
    private let localMLKEMSecretKey: I2PMLKEMSecretKey?
    /// The peer's advertised ML-KEM encapsulation key (initiator side; nil =
    /// the peer does not advertise PQ support, so the handshake stays classical).
    private let remoteMLKEMKey: I2PMLKEMPublicKey?
    private let localRouterInfoData: Data
    var tokenCache = SSU2TokenCache()
    private var tokenManager: SSU2TokenManager
    private var initiator: SSU2InitiatorHandshake?
    private var responder: SSU2ResponderHandshake?
    private var sendCipher: SSU2DataCipher?
    private var recvCipher: SSU2DataCipher?
    private var sendHeaderKey: Data?
    private var recvHeaderKey: Data?
    private var outboundPacketNumber: UInt32 = 0
    private var recvReplayWindow = SSU2ReplayWindow()
    private var confirmedReassembler: SSU2ConfirmedReassembler?
    private var messageReassemblers: [UInt32: SSU2MessageReassembler] = [:]
    private var nextMessageID: UInt32 = UInt32.random(in: 1...UInt32.max)
    private var pendingChallenge: (value: Data, newEndpoint: SSU2Endpoint)?
    private var lastActivity = Date()
    private var terminationPacket: Data?
    private(set) var establishedAt: Date?
    private(set) var outbox: [(data: Data, endpoint: SSU2Endpoint?)] = []

    var isEstablished: Bool { state == .established }

    /// The negotiated hybrid leg for this session
    /// (nil = the handshake completed classically).
    var negotiatedPQVersion: I2PSSU2PQVersion? {
        role == .initiator ? initiator?.pqLeg : responder?.negotiatedPQ
    }

    init(role: Role,
         localStaticKey: Curve25519.KeyAgreement.PrivateKey,
         remoteStaticKey: Data?,
         remoteIntroKey: Data,
         localRouterInfo: I2PRouterInfo,
         tokenManager: SSU2TokenManager = SSU2TokenManager(),
         publishedEndpoint: SSU2Endpoint? = nil,
         mlKemSecretKey: I2PMLKEMSecretKey? = nil,
         remoteMLKEMKeyData: Data? = nil) {
        self.role = role
        self.localStaticKey = localStaticKey
        self.remoteStaticKey = remoteStaticKey
        self.introKey = remoteIntroKey
        self.localMLKEMSecretKey = mlKemSecretKey
        self.remoteMLKEMKey = try? I2PMLKEMPublicKey(keyData: remoteMLKEMKeyData ?? Data())
        self.localRouterInfoData = localRouterInfo.serialize()
        self.tokenManager = tokenManager
        self.publishedEndpoint = publishedEndpoint
        if role == .responder {
            // The responder's local connection ID derives from its own static
            // key so inbound handshake packets demultiplex without prior state.
            localConnectionID = SSU2InitiatorHandshake.responderConnectionID(
                for: localStaticKey.publicKey.rawRepresentation)
        } else {
            localConnectionID = SSU2PacketHeader.randomConnectionID()
        }
    }

    // MARK: Key introspection (loopback key-verification in tests)

    /// The initiator-side split keys, available once the handshake confirmed.
    var initiatorEngineKeys: SSU2SessionKeys? {
        guard let initiator else { return nil }
        return try? initiator.complete()
    }

    /// The responder-side split keys, available once the SessionRequest processed.
    var responderEngineKeys: SSU2SessionKeys? {
        guard let responder else { return nil }
        return try? responder.complete()
    }

    // MARK: Handshake start

    /// Starts the handshake. Establishment sequences per spec:
    /// fast path — a cached token rides straight into the SessionRequest;
    /// token-request path — a TokenRequest solicits a Retry with a fresh token;
    /// retry path — a SessionRequest with an invalid token earns a Retry.
    func startHandshake(useCachedToken: Bool = true, forceInvalidToken: Bool = false) throws {
        guard role == .initiator else { throw SSU2Error.handshakeFailed("startHandshake on responder") }
        guard state == .unknown || state == .initial else { return }
        guard let remoteStaticKey else {
            throw SSU2Error.handshakeFailed("initiator without remote static key")
        }
        let engine = SSU2InitiatorHandshake(localStaticKey: localStaticKey,
                                            remoteStaticKey: remoteStaticKey, introKey: introKey,
                                            remoteMLKEMKey: remoteMLKEMKey)
        initiator = engine
        let token: Data?
        if forceInvalidToken {
            token = Data(repeating: 0, count: 8)
        } else if useCachedToken {
            token = tokenCache.token(for: remoteStaticKey)
        } else {
            token = nil
        }
        if let token {
            let request = try engine.makeSessionRequest(localConnectionID: localConnectionID, token: token)
            // Advance the state before the datagram is flushed: a peer wired
            // directly to the outbound handler (loopback) answers inside the
            // flush, so setting `.requested` afterwards overwrote the
            // `.established` state the nested handshake had just reached.
            state = .requested
            try enqueue(request)
        } else {
            let request = try engine.makeTokenRequest(localConnectionID: localConnectionID)
            state = .initial
            try enqueue(request)
        }
    }

    // MARK: Receive path

    func handleDatagram(_ datagram: Data, from endpoint: SSU2Endpoint) {
        lastActivity = Date()
        if remoteEndpoint == nil { remoteEndpoint = endpoint }
        // Connection migration: traffic arriving from a new address on an
        // established session is challenged before the path switches, and the
        // connection IDs stay immutable across the migration.
        if state == .established,
           let current = remoteEndpoint, endpoint != current,
           let remote = remoteConnectionID, pendingChallenge == nil {
            pendingChallenge = (I2PCrypto.randomBytes(8), endpoint)
            let reply = try? SSU2Block.encode([.pathChallenge(value: pendingChallenge!.value)])
            if let reply, let cipher = sendCipher {
                let pn = nextOutboundPacketNumber()
                let header = SSU2PacketHeader(shortDestinationConnectionID: remote,
                                              packetNumber: pn, type: .data)
                if var packet = try? cipher.seal(reply, header: header.serialize(), packetNumber: pn) {
                    try? SSU2HeaderProtection.maskHeader(&packet, phase: .data,
                                                         introKey: Data(), sessionKey: sendHeaderKey)
                    outbox.append((packet, endpoint)) // the challenge targets the new path
                }
            }
            flushOutbox()
            return // traffic on the unvalidated path is held until it validates
        }
        do {
            switch state {
            case .unknown, .initial, .requested:
                try handleHandshakeTraffic(Data(datagram), from: endpoint)
            case .created, .confirmed, .established:
                try handleEstablishedTraffic(Data(datagram), from: endpoint)
            case .terminating, .closed:
                break
            }
        } catch {
            // Malformed or unauthenticated datagrams drop silently; the error
            // is recorded for diagnostics and tests.
            lastError = error
            if state == .terminating {
                state = .closed
                delegate?.session(self, didClose: error)
            }
        }
    }

    private func handleHandshakeTraffic(_ datagram: Data, from endpoint: SSU2Endpoint) throws {
        switch role {
        case .initiator:
            guard let engine = initiator else { throw SSU2Error.handshakeFailed("no engine") }
            // Probe SessionCreated first, then Retry; both checks also verify
            // the destination connection ID so a wrong-phase unmask cannot
            // produce a false match.
            var created = Data(datagram)
            try? SSU2HeaderProtection.unmaskHeader(&created, phase: .sessionCreated, introKey: introKey)
            if let header = try? SSU2PacketHeader.parse(created),
               header.type == .sessionCreated, header.isLong,
               header.destinationConnectionID == localConnectionID {
                // The handshake engine owns header unmasking. Pass the original
                // datagram; `created` is only a temporary copy for phase/type
                // detection and is already unmasked here.
                try engine.processSessionCreated(Data(datagram))
                try establishAsInitiator()
                return
            }
            var retry = Data(datagram)
            try? SSU2HeaderProtection.unmaskHeader(&retry, phase: .retry, introKey: introKey)
            if let header = try? SSU2PacketHeader.parse(retry),
               header.type == .retry, header.isLong,
               header.destinationConnectionID == localConnectionID {
                // `retry` was unmasked above only to identify the packet. The
                // engine must receive the original wire bytes and unmask once.
                let token = try engine.processRetry(Data(datagram))
                if let remoteStaticKey {
                    tokenCache.store(token: token, for: remoteStaticKey)
                }
                if engine.pqLeg != nil, engine.stage == .awaitingCreated {
                    // A Retry while a hybrid SessionRequest is outstanding is
                    // the responder's no-PQ signal: the handshake falls back to
                    // the classical long-header variant. A Retry that answers a
                    // TokenRequest (stage .awaitingRetryOrCreated) carries no
                    // such meaning and must leave the offer intact.
                    engine.downgradeToClassical()
                }
                let request = try engine.makeSessionRequest(localConnectionID: localConnectionID, token: token)
                // Set the state before flushing (see startHandshake): the peer's
                // answer can arrive synchronously inside the enqueue.
                state = .requested
                try enqueue(request)
                return
            }
            throw SSU2Error.invalidPacket

        case .responder:
            // Established-phase probes first once the keys exist (the
            // SessionConfirmed fragments and data arrive on session-derived keys).
            if recvHeaderKey != nil, state == .created || state == .confirmed || state == .established {
                if try handleEstablishedTraffic(Data(datagram), from: endpoint) { return }
            }
            // Pre-handshake traffic: detect the masking phase among the intro
            // key phases by matching the destination connection ID.
            guard let phase = SSU2HeaderProtection.detectPhase(
                datagram, introKey: introKey, expectedDestinationConnectionID: localConnectionID) else {
                throw SSU2Error.invalidPacket
            }
            var unmasked = Data(datagram)
            try SSU2HeaderProtection.unmaskHeader(&unmasked, phase: phase, introKey: introKey)
            let header = try SSU2PacketHeader.parse(unmasked)
            if responder == nil {
                responder = SSU2ResponderHandshake(localStaticKey: localStaticKey,
                                                   localConnectionID: localConnectionID,
                                                   introKey: introKey, tokenManager: tokenManager,
                                                   localMLKEMSecretKey: localMLKEMSecretKey,
                                                   localRouterInfoData: localRouterInfoData)
            }
            switch header.type {
            case .tokenRequest:
                // `unmasked` is for dispatch only; processTokenRequest applies
                // its own phase unmask to the original datagram.
                guard let retry = try responder!.processTokenRequest(Data(datagram)) else { return }
                try enqueue(retry)
            case .sessionRequest:
                // Avoid feeding an already-unmasked header into the handshake
                // engine, which performs its own unmask before Noise processing.
                let created = try responder!.processSessionRequest(Data(datagram))
                guard !created.isEmpty else { return } // rate-limited, silent drop
                guard let requesterID = responder!.requesterConnectionID else {
                    // A no-PQ downgrade Retry: no handshake state advanced, so
                    // deliver the Retry and wait for the classical request.
                    try enqueue(created)
                    return
                }
                remoteConnectionID = requesterID
                try SSU2PacketHeader.validatePair(localConnectionID, remoteConnectionID!)
                // Split after the SessionCreated construction so the chaining
                // key state matches the initiator's split point exactly.
                let keys = try responder!.complete()
                sendCipher = SSU2DataCipher(key: keys.send.aeadKey)
                recvCipher = SSU2DataCipher(key: keys.recv.aeadKey)
                sendHeaderKey = keys.send.headerKey
                recvHeaderKey = keys.recv.headerKey
                confirmedReassembler = SSU2ConfirmedReassembler()
                // State first for the same re-entrancy reason: the initiator's
                // SessionConfirmed can be processed inside the flush below.
                state = .created
                try enqueue(created)
            case .peerTest, .holePunch, .retry, .sessionCreated, .sessionConfirmed, .data:
                throw SSU2Error.invalidPacket
            }
        }
    }

    /// Established-phase traffic: data packets, SessionConfirmed fragments and
    /// peer-test packets. Returns false when the datagram is not established-
    /// phase traffic (the caller falls back to handshake handling).
    @discardableResult
    private func handleEstablishedTraffic(_ datagram: Data, from endpoint: SSU2Endpoint) throws -> Bool {
        guard let recvHeaderKey else { return false }
        // Data phase first (most common), then SessionConfirmed, then peer test.
        var data = Data(datagram)
        try? SSU2HeaderProtection.unmaskHeader(&data, phase: .data, introKey: Data(), sessionKey: recvHeaderKey)
        if let header = try? SSU2PacketHeader.parse(data),
           header.type == .data, header.destinationConnectionID == localConnectionID {
            try handleDataPacket(data, header: header, from: endpoint)
            return true
        }
        var confirmed = Data(datagram)
        try? SSU2HeaderProtection.unmaskHeader(&confirmed, phase: .sessionConfirmed, introKey: Data(),
                                               sessionKey: recvHeaderKey)
        if let header = try? SSU2PacketHeader.parse(confirmed),
           header.type == .sessionConfirmed,
           header.destinationConnectionID == localConnectionID {
            try handleConfirmedFragment(confirmed, header: header)
            return true
        }
        var peerTestPacket = Data(datagram)
        try? SSU2HeaderProtection.unmaskHeader(&peerTestPacket, phase: .peerTest, introKey: Data(),
                                               sessionKey: recvHeaderKey)
        if let header = try? SSU2PacketHeader.parse(peerTestPacket),
           header.type == .peerTest, header.isLong,
           header.destinationConnectionID == localConnectionID {
            try handlePeerTestPacket(peerTestPacket, from: endpoint)
            return true
        }
        if state == .created || state == .confirmed {
            return false // fall back to handshake handling
        }
        throw SSU2Error.invalidPacket
    }

    private func establishAsInitiator() throws {
        guard let engine = initiator else { throw SSU2Error.handshakeFailed("no engine") }
        let keys = try engine.complete()
        remoteConnectionID = engine.remoteConnectionID
        try SSU2PacketHeader.validatePair(localConnectionID, remoteConnectionID!)
        sendCipher = SSU2DataCipher(key: keys.send.aeadKey)
        recvCipher = SSU2DataCipher(key: keys.recv.aeadKey)
        sendHeaderKey = keys.send.headerKey
        recvHeaderKey = keys.recv.headerKey
        establishedAt = Date()
        state = .established
        // The responder's RouterInfo arrived in the SessionCreated payload.
        if let data = engine.remoteRouterInfoData {
            remoteRouterInfo = try? I2PRouterInfo.parse(data)
        }
        sendSessionConfirmed()
        delegate?.session(self, didEstablish: remoteRouterInfo)
    }

    private func sendSessionConfirmed() {
        guard let cipher = sendCipher, let remote = remoteConnectionID else { return }
        let payload = (try? SSU2Block.encode([
            .dataFragment(messageID: nextMessageIdentifier(), fragmentIndex: 0,
                          totalFragments: 1, payload: localRouterInfoData),
        ])) ?? Data()
        let chunks = (try? SSU2ConfirmedFragmenter.split(payload, maximumFragmentPayload: 1000)) ?? [payload]
        for (index, chunk) in chunks.enumerated() {
            let pn = nextOutboundPacketNumber()
            let header = SSU2PacketHeader(shortDestinationConnectionID: remote, packetNumber: pn,
                                          type: .sessionConfirmed,
                                          fragmentIndex: index, totalFragments: chunks.count)
            guard var packet = try? cipher.seal(chunk, header: header.serialize(), packetNumber: pn) else { continue }
            try? SSU2HeaderProtection.maskHeader(&packet, phase: .sessionConfirmed,
                                                 introKey: Data(), sessionKey: sendHeaderKey)
            outbox.append((packet, nil))
        }
    }

    private func handleConfirmedFragment(_ packet: Data, header: SSU2PacketHeader) throws {
        guard let cipher = recvCipher, let reassembler = confirmedReassembler else {
            throw SSU2Error.notEstablished
        }
        guard recvReplayWindow.checkAndInsert(header.packetNumber) else {
            replayDrops += 1
            return
        }
        let payload = try cipher.open(packet)
        if let complete = try reassembler.add(fragmentIndex: header.fragmentIndex,
                                              totalFragments: header.totalFragments,
                                              payload: payload, timeout: 30) {
            deliverConfirmedPayload(complete)
        }
    }

    private func deliverConfirmedPayload(_ payload: Data) {
        guard let blocks = try? SSU2Block.decode(payload) else { return }
        for block in blocks {
            switch block {
            case .dataFragment(_, _, _, let routerInfoData):
                if let parsed = try? I2PRouterInfo.parse(routerInfoData) {
                    remoteRouterInfo = parsed
                }
                state = .established
                establishedAt = establishedAt ?? Date()
                delegate?.session(self, didEstablish: remoteRouterInfo)
            case .padding, .time, .termination, .pathChallenge, .pathResponse:
                break
            }
        }
    }

    private func handleDataPacket(_ packet: Data, header: SSU2PacketHeader, from endpoint: SSU2Endpoint) throws {
        guard let cipher = recvCipher else { throw SSU2Error.notEstablished }
        guard recvReplayWindow.checkAndInsert(header.packetNumber) else {
            replayDrops += 1
            return
        }
        let payload = try cipher.open(packet)
        let blocks = try SSU2Block.decode(payload)
        for block in blocks {
            switch block {
            case .dataFragment(let messageID, let fragmentIndex, let totalFragments, let fragment):
                if totalFragments == 1 {
                    delegate?.session(self, didReceiveData: fragment)
                    continue
                }
                let reassembler = messageReassemblers[messageID] ?? SSU2MessageReassembler()
                messageReassemblers[messageID] = reassembler
                if let complete = try reassembler.add(fragmentIndex: fragmentIndex,
                                                      totalFragments: totalFragments,
                                                      payload: fragment, timeout: 30) {
                    messageReassemblers[messageID] = nil
                    delegate?.session(self, didReceiveData: complete)
                }
            case .termination(let reason, let detail):
                state = .terminating
                let error = SSU2Error.handshakeFailed("peer termination \(reason): \(detail)")
                state = .closed
                delegate?.session(self, didClose: error)
                return
            case .pathChallenge(let value):
                let reply = try SSU2Block.encode([.pathResponse(value: value)])
                enqueueDataBlocks(reply)
            case .pathResponse(let value):
                if let pending = pendingChallenge, pending.value == value {
                    remoteEndpoint = pending.newEndpoint
                    pendingChallenge = nil
                }
            case .padding, .time:
                break
            }
        }
    }

    private func handlePeerTestPacket(_ packet: Data, from endpoint: SSU2Endpoint) throws {
        let body = packet.subdata(in: 32..<packet.count)
        let (nonce, observed) = try SSU2PeerTestMessage.parse(body)
        if peerTest.isAwaiting(nonce) {
            // The response to our own test: the tester echoes our observed
            // endpoint back inside the body.
            let observedEndpoint = observed ?? endpoint
            _ = peerTest.record(nonce: nonce, observed: observedEndpoint,
                                published: publishedEndpoint)
        } else {
            // A test request aimed at us: echo the nonce back, reporting the
            // requester's endpoint as we observed it.
            let pn = nextOutboundPacketNumber()
            let header = SSU2PacketHeader(destinationConnectionID: remoteConnectionID ?? localConnectionID,
                                          packetNumber: pn, type: .peerTest,
                                          sourceConnectionID: localConnectionID)
            var reply = header.serialize()
            reply.append(SSU2PeerTestMessage.responseBody(nonce: nonce, observed: endpoint))
            try SSU2HeaderProtection.maskHeader(&reply, phase: .peerTest,
                                                introKey: Data(), sessionKey: sendHeaderKey)
            outbox.append((reply, nil))
        }
    }

    // MARK: Data phase send

    /// Sends an I2NP message, fragmenting it across data packets when needed.
    func sendData(_ i2np: Data) throws {
        guard state == .established, let cipher = sendCipher, let remote = remoteConnectionID else {
            throw SSU2Error.notEstablished
        }
        nextMessageID = nextMessageID &+ 1
        let fragments = try SSU2MessageFragmenter.split(i2np, messageID: nextMessageID,
                                                        maximumFragmentPayload: 1200)
        for fragment in fragments {
            enqueueDataBlocks(try SSU2Block.encode([fragment]), cipher: cipher, remote: remote)
        }
        flushOutbox()
    }

    private func enqueueDataBlocks(_ payload: Data,
                                   cipher: SSU2DataCipher? = nil,
                                   remote: Data? = nil,
                                   endpointOverride: SSU2Endpoint? = nil) {
        guard let cipher = cipher ?? sendCipher, let remote = remote ?? remoteConnectionID else { return }
        let pn = nextOutboundPacketNumber()
        let header = SSU2PacketHeader(shortDestinationConnectionID: remote, packetNumber: pn, type: .data)
        guard var packet = try? cipher.seal(payload, header: header.serialize(), packetNumber: pn) else { return }
        try? SSU2HeaderProtection.maskHeader(&packet, phase: .data,
                                             introKey: Data(), sessionKey: sendHeaderKey)
        outbox.append((packet, endpointOverride))
    }

    // MARK: Peer test

    /// Starts a reachability test toward the session peer.
    func startPeerTest(nonce: UInt32? = nil) throws {
        guard state == .established, let remote = remoteConnectionID else {
            throw SSU2Error.notEstablished
        }
        let value = nonce ?? UInt32.random(in: 1...UInt32.max)
        peerTest.begin(nonce: value)
        let pn = nextOutboundPacketNumber()
        let header = SSU2PacketHeader(destinationConnectionID: remote, packetNumber: pn,
                                      type: .peerTest, sourceConnectionID: localConnectionID)
        var packet = header.serialize()
        packet.append(SSU2PeerTestMessage.requestBody(nonce: value))
        try SSU2HeaderProtection.maskHeader(&packet, phase: .peerTest,
                                            introKey: Data(), sessionKey: sendHeaderKey)
        outbox.append((packet, nil))
        flushOutbox()
    }

    // MARK: Termination and lifecycle

    /// Graceful termination: an encrypted termination block, retained for
    /// whole-packet retransmission.
    func close(reason: UInt8 = 0, detail: String = "") throws {
        guard state == .established, let cipher = sendCipher, let remote = remoteConnectionID else {
            state = .closed
            delegate?.session(self, didClose: nil)
            return
        }
        state = .terminating
        var payload = try SSU2Block.encode([.termination(reason: reason, detail: detail)])
        // The data phase's minimum authenticated message is 40 bytes (16-byte
        // header + 8-byte payload + 16-byte tag). A short termination block
        // ("bye" → 7 bytes) falls under it, so pad it out with an empty padding
        // block rather than failing the close of an otherwise healthy session.
        let minimumPayload = SSU2DataCipher.minimumMessageLength - SSU2PacketHeader.shortLength - 16
        if payload.count < minimumPayload {
            payload.append(try SSU2Block.encode([.padding(0)]))
        }
        let pn = nextOutboundPacketNumber()
        let header = SSU2PacketHeader(shortDestinationConnectionID: remote, packetNumber: pn, type: .data)
        var packet = try cipher.seal(payload, header: header.serialize(), packetNumber: pn)
        try SSU2HeaderProtection.maskHeader(&packet, phase: .data,
                                            introKey: Data(), sessionKey: sendHeaderKey)
        terminationPacket = packet
        outbox.append((packet, nil))
        flushOutbox()
    }

    /// Retransmits the terminal packet (bounded to 3 retransmissions).
    func retransmitTermination() throws {
        guard state == .terminating, let packet = terminationPacket else {
            throw SSU2Error.notEstablished
        }
        guard terminationRetransmissions < 3 else { throw SSU2Error.notEstablished }
        terminationRetransmissions += 1
        outbox.append((packet, nil))
    }

    /// Idle teardown: returns true when the session exceeded the idle timeout.
    @discardableResult
    func checkIdle(timeout: TimeInterval, now: Date = Date()) -> Bool {
        guard state == .established else { return false }
        guard now.timeIntervalSince(lastActivity) > timeout else { return false }
        state = .terminating
        state = .closed
        delegate?.session(self, didClose: SSU2Error.handshakeFailed("idle timeout"))
        return true
    }

    func abort() {
        state = .closed
        delegate?.session(self, didClose: nil)
    }

    // MARK: Plumbing

    /// Drains the outbound queue (transport socket send or loopback wiring).
    func drainOutbox() -> [(data: Data, endpoint: SSU2Endpoint?)] {
        let pending = outbox
        outbox = []
        return pending
    }

    private func enqueue(_ datagram: Data) throws {
        outbox.append((datagram, nil))
        flushOutbox()
    }

    /// Flushes queued datagrams through the outbound handler (loopback wiring
    /// performs its own delivery; the transport pumps with its socket).
    func flushOutbox() {
        guard let handler = outboundHandler, !outbox.isEmpty else { return }
        let pending = outbox
        outbox = []
        for (data, endpoint) in pending {
            handler(data, endpoint)
        }
    }

    private func nextOutboundPacketNumber() -> UInt32 {
        let pn = outboundPacketNumber
        outboundPacketNumber &+= 1
        return pn
    }

    private func nextMessageIdentifier() -> UInt32 {
        let id = nextMessageID
        nextMessageID = nextMessageID &+ 1
        return id
    }
}

// MARK: - UDP transport

protocol SSU2TransportDelegate: AnyObject {
    func transport(_ transport: SSU2Transport, sessionEstablished session: SSU2Session)
    func transport(_ transport: SSU2Transport, session: SSU2Session, didReceiveData data: Data)
    func transport(_ transport: SSU2Transport, sessionDidClose session: SSU2Session)
}

/// SSU2 UDP transport over the Network framework: a datagram listener with a
/// session pool keyed by remote endpoint, and connected UDP flows for outbound
/// sessions. Inbound handshake packets demultiplex by the responder connection
/// ID (derived from the local static key) and spawn responder sessions.
final class SSU2Transport {
    weak var delegate: SSU2TransportDelegate?

    private let localStaticKey: Curve25519.KeyAgreement.PrivateKey
    private let introKey: Data
    private let localRouterInfo: I2PRouterInfo
    private let publishedEndpoint: SSU2Endpoint?
    /// Our ML-KEM capability for hybrid sessions; spawned responder sessions
    /// accept hybrid offers, and initiator sessions carry it for symmetry.
    private let mlKemSecretKey: I2PMLKEMSecretKey?
    private let queue = DispatchQueue(label: "i2p.ssu2.transport")
    private let lock = NSLock()
    private var listener: NWListener?
    private var flows: [String: NWConnection] = [:]
    private var sessionsByEndpoint: [String: SSU2Session] = [:]
    private(set) var listenerPort: UInt16?
    private var tokenManager = SSU2TokenManager()

    init(localStaticKey: Curve25519.KeyAgreement.PrivateKey, introKey: Data,
         localRouterInfo: I2PRouterInfo, publishedEndpoint: SSU2Endpoint? = nil,
         mlKemSecretKey: I2PMLKEMSecretKey? = nil) {
        self.localStaticKey = localStaticKey
        self.introKey = introKey
        self.localRouterInfo = localRouterInfo
        self.publishedEndpoint = publishedEndpoint
        self.mlKemSecretKey = mlKemSecretKey
    }

    /// Starts the UDP listener; port 0 binds an ephemeral port.
    @discardableResult
    func startListener(port: UInt16 = 0) throws -> UInt16 {
        lock.lock()
        defer { lock.unlock() }
        guard listener == nil else { return listenerPort ?? port }
        let nwListener = try NWListener(using: NWParameters.udp,
                                        on: NWEndpoint.Port(rawValue: port) ?? .any)
        // The ephemeral binding completes asynchronously (notably slower on
        // device): publish the assigned port once the listener reaches ready.
        nwListener.stateUpdateHandler = { [weak self, weak nwListener] state in
            guard state == .ready, let self, let nwListener else { return }
            self.lock.lock()
            self.listenerPort = nwListener.port?.rawValue ?? self.listenerPort
            self.lock.unlock()
        }
        nwListener.newConnectionHandler = { [weak self] connection in
            guard let self else { return }
            self.registerFlow(connection)
            connection.start(queue: self.queue)
            // Accepted flows must be read or inbound datagrams never arrive.
            self.receiveOn(connection)
        }
        nwListener.start(queue: queue)
        listener = nwListener
        listenerPort = nwListener.port?.rawValue ?? port
        return listenerPort ?? port
    }

    /// Opens an outbound session toward a peer; the token-request path runs
    /// automatically and the session reports establishment via the delegate.
    @discardableResult
    func connect(host: String, port: UInt16, remoteStaticKey: Data, remoteIntroKey: Data,
                 remoteMLKEMKey: Data? = nil,
                 sessionDelegate: SSU2SessionDelegate? = nil) throws -> SSU2Session {
        let endpoint = SSU2Endpoint(host: host, port: port)
        let session = SSU2Session(role: .initiator, localStaticKey: localStaticKey,
                                  remoteStaticKey: remoteStaticKey, remoteIntroKey: remoteIntroKey,
                                  localRouterInfo: localRouterInfo, publishedEndpoint: publishedEndpoint,
                                  mlKemSecretKey: mlKemSecretKey, remoteMLKEMKeyData: remoteMLKEMKey)
        // Install the observer before starting traffic: loopback peers can
        // complete the handshake before `connect` returns.
        session.delegate = sessionDelegate ?? self
        let connection = NWConnection(host: NWEndpoint.Host(host),
                                      port: NWEndpoint.Port(rawValue: port) ?? .any,
                                      using: .udp)
        registerFlow(connection)
        connection.start(queue: queue)
        session.outboundHandler = { [weak connection] datagram, _ in
            connection?.send(content: datagram, completion: .contentProcessed { _ in })
        }
        lock.lock()
        sessionsByEndpoint[endpoint.description] = session
        lock.unlock()
        receiveOn(connection)
        try session.startHandshake()
        return session
    }

    func sessionCount() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return sessionsByEndpoint.count
    }

    func hasSession(for endpoint: SSU2Endpoint) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return sessionsByEndpoint[endpoint.description] != nil
    }

    func shutdown() {
        lock.lock()
        let all = Array(sessionsByEndpoint.values)
        sessionsByEndpoint.removeAll()
        flows.values.forEach { $0.cancel() }
        flows.removeAll()
        listener?.cancel()
        listener = nil
        lock.unlock()
        all.forEach { $0.abort() }
    }

    // MARK: Plumbing

    private func flowKey(_ endpoint: NWEndpoint) -> String {
        switch endpoint {
        case .hostPort(let host, let port):
            return "\(host):\(port.rawValue)"
        default:
            return "\(endpoint)"
        }
    }

    private func registerFlow(_ connection: NWConnection) {
        let key = flowKey(connection.endpoint)
        lock.lock()
        flows[key] = connection
        lock.unlock()
    }

    private func receiveOn(_ connection: NWConnection) {
        connection.receiveMessage { [weak self, weak connection] data, _, _, error in
            guard let self, let connection else { return }
            if let data, !data.isEmpty {
                self.route(Data(data), on: connection)
            }
            if error == nil {
                self.receiveOn(connection)
            }
        }
    }

    private func route(_ datagram: Data, on connection: NWConnection) {
        let key = flowKey(connection.endpoint)
        lock.lock()
        let existing = sessionsByEndpoint[key]
        lock.unlock()
        if let existing {
            existing.handleDatagram(datagram, from: endpoint(of: key))
            drain(session: existing, on: connection)
            return
        }
        // Unknown peer: does the datagram address our responder connection ID?
        let responderID = SSU2InitiatorHandshake.responderConnectionID(
            for: localStaticKey.publicKey.rawRepresentation)
        guard SSU2HeaderProtection.detectPhase(datagram, introKey: introKey,
                                               expectedDestinationConnectionID: responderID) != nil else {
            return // unauthenticated noise drops silently
        }
        let session = SSU2Session(role: .responder, localStaticKey: localStaticKey,
                                  remoteStaticKey: nil, remoteIntroKey: introKey,
                                  localRouterInfo: localRouterInfo,
                                  tokenManager: tokenManager,
                                  publishedEndpoint: publishedEndpoint,
                                  mlKemSecretKey: mlKemSecretKey)
        session.delegate = self
        lock.lock()
        sessionsByEndpoint[key] = session
        lock.unlock()
        session.outboundHandler = { [weak connection] datagram, _ in
            connection?.send(content: datagram, completion: .contentProcessed { _ in })
        }
        session.handleDatagram(datagram, from: endpoint(of: key))
        drain(session: session, on: connection)
    }

    private func drain(session: SSU2Session, on connection: NWConnection) {
        for (datagram, _) in session.drainOutbox() {
            connection.send(content: datagram, completion: .contentProcessed { _ in })
        }
    }

    private func endpoint(of key: String) -> SSU2Endpoint {
        // "host:port" — the port is the trailing component after the last ':'.
        let parts = key.split(separator: ":")
        let port = UInt16(parts.last ?? "0") ?? 0
        let host = parts.count > 1 ? parts.dropLast().joined(separator: ":") : key
        return SSU2Endpoint(host: host, port: port)
    }
}

extension SSU2Transport: SSU2SessionDelegate {
    func session(_ session: SSU2Session, didEstablish remoteRouterInfo: I2PRouterInfo?) {
        if let endpoint = session.remoteEndpoint {
            lock.lock()
            sessionsByEndpoint[endpoint.description] = session
            lock.unlock()
        }
        delegate?.transport(self, sessionEstablished: session)
    }

    func session(_ session: SSU2Session, didReceiveData data: Data) {
        delegate?.transport(self, session: session, didReceiveData: data)
    }

    func session(_ session: SSU2Session, didClose error: Error?) {
        if let endpoint = session.remoteEndpoint {
            lock.lock()
            sessionsByEndpoint.removeValue(forKey: endpoint.description)
            lock.unlock()
        }
        delegate?.transport(self, sessionDidClose: session)
    }
}
// MARK: - Self-test suite

enum I2PSSU2SelfTest {
    /// Loopback endpoints shared by the engine-level tests. The initiator's
    /// loopback address shares its published IP with a different port so the
    /// peer-test classification lands on port-mapped.
    static let aliceLoopbackEndpoint = SSU2Endpoint(host: "203.0.113.9", port: 9999)
    static let bobLoopbackEndpoint = SSU2Endpoint(host: "192.0.2.20", port: 8888)
    static let bobIntroKey = I2PCrypto.randomBytes(32)

    static func runAll() async -> [I2PSelfTestResult] {
        var results: [I2PSelfTestResult] = []
        func run(_ name: String, _ body: () throws -> String) {
            do {
                let detail = try body()
                results.append(I2PSelfTestResult(name: name, passed: true, detail: detail))
            } catch {
                results.append(I2PSelfTestResult(name: name, passed: false, detail: String(describing: error)))
            }
        }
        func runAsync(_ name: String, _ body: () async throws -> String) async {
            do {
                let detail = try await body()
                results.append(I2PSelfTestResult(name: name, passed: true, detail: detail))
            } catch {
                results.append(I2PSelfTestResult(name: name, passed: false, detail: String(describing: error)))
            }
        }

        run("SSU2 headers · long/short round trip + validation") {
            let dst = SSU2PacketHeader.randomConnectionID()
            let src = SSU2PacketHeader.randomConnectionID(distinctFrom: dst)
            let header = SSU2PacketHeader(destinationConnectionID: dst, packetNumber: 42,
                                          type: .sessionRequest, sourceConnectionID: src,
                                          token: Data(repeating: 0x5A, count: 8))
            let bytes = header.serialize()
            guard bytes.count == 32 else { throw SSU2Error.invalidHeader }
            let parsed = try SSU2PacketHeader.parse(bytes)
            guard parsed.destinationConnectionID == dst, parsed.packetNumber == 42,
                  parsed.type == .sessionRequest, parsed.sourceConnectionID == src,
                  parsed.token == Data(repeating: 0x5A, count: 8), parsed.isLong else {
                throw SSU2Error.invalidHeader
            }
            // Version and network ID validation: versions 2/3/4 accepted (3/4 bind
            // the ML-KEM hybrid legs), anything else fails closed.
            var bad = bytes
            bad[13] = 5
            guard (try? SSU2PacketHeader.parse(Data(bad))) == nil else { throw SSU2Error.unsupportedVersion }
            var v3 = bytes
            v3[13] = 3
            guard try SSU2PacketHeader.parse(Data(v3)).pqVersion == .mlKem512 else {
                throw SSU2Error.testFailed("version 3 lost its ML-KEM-512 binding")
            }
            var v4 = bytes
            v4[13] = 4
            guard try SSU2PacketHeader.parse(Data(v4)).pqVersion == .mlKem768 else {
                throw SSU2Error.testFailed("version 4 lost its ML-KEM-768 binding")
            }
            var badNet = bytes
            badNet[14] = 9
            guard (try? SSU2PacketHeader.parse(Data(badNet))) == nil else { throw SSU2Error.unsupportedNetworkID }
            // Short header (SessionConfirmed fragment).
            let short = SSU2PacketHeader(shortDestinationConnectionID: dst, packetNumber: 7,
                                         type: .sessionConfirmed, fragmentIndex: 2, totalFragments: 5)
            let parsedShort = try SSU2PacketHeader.parse(short.serialize())
            guard parsedShort.fragmentIndex == 2, parsedShort.totalFragments == 5,
                  !parsedShort.isLong else { throw SSU2Error.invalidHeader }
            // Connection IDs: immutable pair rule — identical src/dst rejected.
            do {
                try SSU2PacketHeader.validatePair(dst, dst)
                throw SSU2Error.testFailed("identical connection IDs accepted")
            } catch let error as SSU2Error {
                guard case .invalidHeader = error else { throw error }
            }
            // Random connection IDs never collide with an existing one.
            guard SSU2PacketHeader.randomConnectionID(distinctFrom: dst) != dst else {
                throw SSU2Error.invalidHeader
            }
            return "32-byte long + 16-byte short headers round-tripped; versions 2/3/4 accepted (3/4 = ML-KEM hybrid legs), netID/connID rules enforced"
        }

        run("SSU2 header protection · 7 phases, tail-IV masking, phase detection") {
            let introKey = I2PCrypto.randomBytes(32)
            let packet = SSU2PacketHeader(destinationConnectionID: SSU2PacketHeader.randomConnectionID(),
                                          packetNumber: 9, type: .sessionRequest,
                                          sourceConnectionID: SSU2PacketHeader.randomConnectionID()).serialize()
                + I2PCrypto.randomBytes(60)
            // Each phase masks to a distinct first 16 bytes; mask/unmask is an involution.
            let baseline = Data(packet.prefix(16))
            for phase in SSU2HeaderPhase.allCases {
                var masked = Data(packet)
                try SSU2HeaderProtection.maskHeader(&masked, phase: phase, introKey: introKey)
                guard masked.prefix(16) != baseline else { throw SSU2Error.testFailed("\(phase) did not mask") }
                try SSU2HeaderProtection.unmaskHeader(&masked, phase: phase, introKey: introKey)
                guard masked == packet else { throw SSU2Error.testFailed("\(phase) unmask not an involution") }
            }
            var distinct: Set<Data> = []
            for phase in SSU2HeaderPhase.introKeyPhases {
                var masked = Data(packet)
                try SSU2HeaderProtection.maskHeader(&masked, phase: phase, introKey: introKey)
                distinct.insert(Data(masked.prefix(16)))
            }
            guard distinct.count == SSU2HeaderPhase.introKeyPhases.count else {
                throw SSU2Error.testFailed("phase keys collided")
            }
            // Receiver-side phase detection on the real packet shape.
            var request = SSU2PacketHeader(
                destinationConnectionID: SSU2InitiatorHandshake.responderConnectionID(for: introKey),
                packetNumber: 0, type: .sessionRequest,
                sourceConnectionID: SSU2PacketHeader.randomConnectionID()).serialize()
                + I2PCrypto.randomBytes(60)
            try SSU2HeaderProtection.maskHeader(&request, phase: .sessionRequest, introKey: introKey)
            guard SSU2HeaderProtection.detectPhase(request, introKey: introKey,
                                                   expectedDestinationConnectionID: SSU2InitiatorHandshake.responderConnectionID(for: introKey)) == .sessionRequest else {
                throw SSU2Error.testFailed("phase detection missed sessionRequest")
            }
            // The ephemeral region obfuscation is also an involution.
            try SSU2HeaderProtection.obfuscateEphemeralRegion(&request, introKey: introKey, responderStaticKey: introKey)
            try SSU2HeaderProtection.obfuscateEphemeralRegion(&request, introKey: introKey, responderStaticKey: introKey)
            return "all 7 phases mask/unmask with tail-derived IVs; phase detection resolves the intro-key phases"
        }

        run("SSU2 tokens · issue, validate, expiry, rate limit") {
            let manager = SSU2TokenManager(tokenLifetime: 600, maxRequestsPerWindow: 3, requestWindow: 60)
            let requester = Data(repeating: 7, count: 8)
            guard let token = manager.issue(for: requester) else { throw SSU2Error.testFailed("issue failed") }
            guard token.count == 8 else { throw SSU2Error.testFailed("token size") }
            guard manager.validate(token, for: requester) else { throw SSU2Error.invalidToken }
            guard !manager.validate(token, for: Data(repeating: 9, count: 8)) else {
                throw SSU2Error.testFailed("token leaked across requesters")
            }
            guard !manager.validate(Data(repeating: 1, count: 8), for: requester) else {
                throw SSU2Error.testFailed("unknown token accepted")
            }
            // Expiry, checked without time-travelling the manager: validating at
            // now+700 s also ages out the 60 s rate-limit window, so the rate
            // assertions below need a window that has not been fast-forwarded.
            let expiryManager = SSU2TokenManager(tokenLifetime: 600, maxRequestsPerWindow: 3, requestWindow: 60)
            guard let expiring = expiryManager.issue(for: requester) else {
                throw SSU2Error.testFailed("issue failed")
            }
            guard !expiryManager.validate(expiring, for: requester,
                                          now: Date().addingTimeInterval(700)) else {
                throw SSU2Error.testFailed("expired token accepted")
            }
            // Rate limiting: the window already holds one request; two more pass, the fourth fails.
            _ = manager.issue(for: requester)
            _ = manager.issue(for: requester)
            guard manager.issue(for: requester) == nil else { throw SSU2Error.testFailed("rate limit not enforced") }
            // A different requester is unaffected.
            guard manager.issue(for: Data(repeating: 8, count: 8)) != nil else {
                throw SSU2Error.testFailed("rate limit leaked across requesters")
            }
            return "8-byte tokens bound to the requester, expiring and rate-limited per window"
        }

        run("SSU2 Noise handshake · token request → retry → request → created → confirmed") {
            let (aliceState, bobState) = try loopbackHandshake()
            // Key mirroring: identical split keys in opposite directions.
            guard aliceState.send.aeadKey == bobState.recv.aeadKey,
                  aliceState.recv.aeadKey == bobState.send.aeadKey else {
                throw SSU2Error.testFailed("split keys not mirrored")
            }
            return "full token-request path: Retry issued, token validated, keys mirrored across the split"
        }

        run("SSU2 handshake fast + retry paths · cached token, invalid token → Retry") {
            let aliceKey = Curve25519.KeyAgreement.PrivateKey()
            let bobKey = Curve25519.KeyAgreement.PrivateKey()
            let bobStatic = bobKey.publicKey.rawRepresentation
            let introKey = I2PCrypto.randomBytes(32)
            let aliceRI = try I2PSamples.sampleRouterInfo()
            let bobRI = try I2PSamples.sampleRouterInfo()

            // Fast path: a cached token rides straight into the SessionRequest
            // (no TokenRequest datagram is ever sent).
            let manager = SSU2TokenManager()
            let aliceFast = SSU2Session(role: .initiator, localStaticKey: aliceKey,
                                        remoteStaticKey: bobStatic, remoteIntroKey: introKey,
                                        localRouterInfo: aliceRI)
            aliceFast.tokenCache.store(token: manager.issue(for: aliceFast.localConnectionID)!,
                                       for: bobStatic)
            let bobFast = SSU2Session(role: .responder, localStaticKey: bobKey,
                                      remoteStaticKey: nil, remoteIntroKey: introKey,
                                      localRouterInfo: bobRI, tokenManager: manager)
            var firstAlicePacketType: SSU2MessageType?
            aliceFast.outboundHandler = { datagram, _ in
                if firstAlicePacketType == nil {
                    firstAlicePacketType = Self.phaseType(datagram, phase: .sessionRequest,
                                                          introKey: introKey)
                }
                bobFast.handleDatagram(datagram, from: aliceLoopbackEndpoint)
            }
            bobFast.outboundHandler = { datagram, _ in
                aliceFast.handleDatagram(datagram, from: bobLoopbackEndpoint)
            }
            try aliceFast.startHandshake()
            // The nested flushes completed the handshake; the SessionConfirmed
            // fragments still queue until pumped to the responder.
            pumpBoth(aliceFast, bobFast)
            guard aliceFast.isEstablished, bobFast.isEstablished else {
                throw SSU2Error.testFailed("fast path did not complete")
            }
            guard firstAlicePacketType == SSU2MessageType.sessionRequest else {
                throw SSU2Error.testFailed("fast path used a token request")
            }

            // Retry path: an invalid token earns a Retry, then the handshake completes.
            let aliceRetry = SSU2Session(role: .initiator, localStaticKey: aliceKey,
                                         remoteStaticKey: bobStatic, remoteIntroKey: introKey,
                                         localRouterInfo: aliceRI)
            let bobRetry = SSU2Session(role: .responder, localStaticKey: bobKey,
                                       remoteStaticKey: nil, remoteIntroKey: introKey,
                                       localRouterInfo: bobRI, tokenManager: SSU2TokenManager())
            var sawRetry = false
            aliceRetry.outboundHandler = { datagram, _ in
                bobRetry.handleDatagram(datagram, from: aliceLoopbackEndpoint)
            }
            bobRetry.outboundHandler = { datagram, _ in
                if Self.phaseType(datagram, phase: .retry, introKey: introKey) == .retry {
                    sawRetry = true
                }
                aliceRetry.handleDatagram(datagram, from: bobLoopbackEndpoint)
            }
            try aliceRetry.startHandshake(useCachedToken: false, forceInvalidToken: true)
            pumpBoth(aliceRetry, bobRetry)
            guard aliceRetry.isEstablished, bobRetry.isEstablished else {
                throw SSU2Error.testFailed("retry path did not complete")
            }
            guard sawRetry else {
                throw SSU2Error.testFailed("no Retry issued on the invalid token")
            }
            return "fast path completes with no token request; the retry path earns and uses a Retry token"
        }

        run("SSU2 data phase · replay, out-of-order, size bounds, tamper rejection") {
            let key = I2PCrypto.randomBytes(32)
            let cipher = SSU2DataCipher(key: key)
            let dst = SSU2PacketHeader.randomConnectionID()
            let header = SSU2PacketHeader(shortDestinationConnectionID: dst, packetNumber: 5, type: .data)
            let packet = try cipher.seal(Data("i2np payload".utf8), header: header.serialize(), packetNumber: 5)
            guard packet.count >= SSU2DataCipher.minimumMessageLength else { throw SSU2Error.invalidPacket }
            let opened = try cipher.open(packet)
            guard opened == Data("i2np payload".utf8) else { throw SSU2Error.invalidPacket }
            // Replay window: duplicates and out-of-window numbers rejected, in-window reordering accepted.
            let window = SSU2ReplayWindow()
            guard window.checkAndInsert(10) else { throw SSU2Error.replayedPacket }
            guard window.checkAndInsert(4) else { throw SSU2Error.replayedPacket } // below window
            guard window.checkAndInsert(9) else { throw SSU2Error.replayedPacket } // in-window reorder OK
            guard !window.checkAndInsert(9) else { throw SSU2Error.testFailed("duplicate accepted") }
            guard !window.checkAndInsert(10) else { throw SSU2Error.testFailed("duplicate accepted") }
            guard window.checkAndInsert(80) else { throw SSU2Error.replayedPacket }
            // Size bounds.
            do {
                _ = try cipher.seal(Data("tiny".utf8), header: header.serialize(), packetNumber: 6)
                throw SSU2Error.testFailed("sub-minimum payload accepted")
            } catch let error as SSU2Error {
                guard case .invalidPacket = error else { throw error }
            }
            let oversized = SSU2PacketHeader(shortDestinationConnectionID: dst, packetNumber: 7, type: .data)
            do {
                _ = try cipher.seal(Data(repeating: 0, count: 1441), header: oversized.serialize(), packetNumber: 7)
                throw SSU2Error.testFailed("oversized datagram accepted")
            } catch let error as SSU2Error {
                guard case .invalidPacket = error else { throw error }
            }
            // Tamper rejection: a flipped ciphertext byte fails the MAC.
            var tampered = packet
            tampered[tampered.count - 20] ^= 0xff
            do {
                _ = try cipher.open(tampered)
                throw SSU2Error.testFailed("tampered packet authenticated")
            } catch let error as SSU2Error {
                guard case .decryptFailed = error else { throw error }
            }
            return "data phase sealed/opened; replay window, size bounds and MAC tamper rejection verified"
        }

        run("SSU2 SessionConfirmed fragmentation · up to 15 fragments reassembled") {
            let payload = I2PCrypto.randomBytes(2600)
            let chunks = try SSU2ConfirmedFragmenter.split(payload, maximumFragmentPayload: 1000)
            guard chunks.count == 3, chunks.count <= 15 else { throw SSU2Error.invalidPacket }
            let reassembler = SSU2ConfirmedReassembler()
            var complete: Data?
            for (index, chunk) in chunks.enumerated() {
                complete = try reassembler.add(fragmentIndex: index, totalFragments: chunks.count,
                                               payload: chunk, timeout: 30)
            }
            guard complete == payload else { throw SSU2Error.testFailed("fragment reassembly mismatch") }
            // Fragment bounds: 16 fragments rejected.
            do {
                _ = try SSU2ConfirmedFragmenter.split(I2PCrypto.randomBytes(15 * 1000 + 1),
                                                      maximumFragmentPayload: 1000)
                throw SSU2Error.testFailed("16-fragment split accepted")
            } catch let error as SSU2Error {
                guard case .invalidPacket = error else { throw error }
            }
            // Reassembly timeout.
            let timedOut = SSU2ConfirmedReassembler()
            _ = try timedOut.add(fragmentIndex: 0, totalFragments: 2, payload: chunks[0], timeout: 5,
                                 now: Date(timeIntervalSinceNow: -30))
            do {
                _ = try timedOut.add(fragmentIndex: 1, totalFragments: 2, payload: chunks[1], timeout: 5)
                throw SSU2Error.testFailed("stale reassembly accepted")
            } catch let error as SSU2Error {
                guard case .fragmentTimeout = error else { throw error }
            }
            return "3-fragment SessionConfirmed reassembled byte-exact; 16-fragment and stale reassembly rejected"
        }

        run("SSU2 I2NP fragmentation inside data packets") {
            let message = I2PCrypto.randomBytes(3000)
            let fragments = try SSU2MessageFragmenter.split(message, messageID: 0x1122_3344,
                                                            maximumFragmentPayload: 1200)
            guard fragments.count == 3 else { throw SSU2Error.invalidPacket }
            let reassembler = SSU2MessageReassembler()
            var complete: Data?
            for fragment in fragments {
                guard case .dataFragment(let id, let index, let total, let chunk) = fragment else {
                    throw SSU2Error.testFailed("unexpected block type")
                }
                complete = try reassembler.add(fragmentIndex: index, totalFragments: total,
                                               payload: chunk, timeout: 30)
                guard id == 0x1122_3344 else { throw SSU2Error.testFailed("message ID drift") }
            }
            guard complete == message else { throw SSU2Error.testFailed("I2NP reassembly mismatch") }
            return "3000-byte I2NP message split into 3 data-block fragments and reassembled byte-exact"
        }

        run("SSU2 peer test · nonce correlation, classification, result cache") {
            // Message round trips.
            let request = SSU2PeerTestMessage.requestBody(nonce: 0x0102_0304)
            let parsed = try SSU2PeerTestMessage.parse(request)
            guard parsed.nonce == 0x0102_0304, parsed.observed == nil else { throw SSU2Error.invalidPacket }
            let published = SSU2Endpoint(host: "203.0.113.9", port: 8887)
            let response = SSU2PeerTestMessage.responseBody(nonce: 0x0102_0304,
                                                             observed: SSU2Endpoint(host: "198.51.100.2", port: 54321))
            let parsedResponse = try SSU2PeerTestMessage.parse(response)
            guard parsedResponse.observed == SSU2Endpoint(host: "198.51.100.2", port: 54321) else {
                throw SSU2Error.testFailed("observed endpoint lost")
            }
            // Classification matrix.
            guard SSU2PeerTestCoordinator.classify(observed: published, published: published) == .direct,
                  SSU2PeerTestCoordinator.classify(observed: SSU2Endpoint(host: "203.0.113.9", port: 54321),
                                                   published: published) == .portMapped,
                  SSU2PeerTestCoordinator.classify(observed: SSU2Endpoint(host: "198.51.100.2", port: 54321),
                                                   published: published) == .symmetricNAT,
                  SSU2PeerTestCoordinator.classify(observed: nil, published: published) == .unreachable else {
                throw SSU2Error.testFailed("classification matrix broken")
            }
            // Full session-level exchange on the loopback wiring: the responder
            // reports Alice's loopback address (same IP, mapped port).
            let (alice, alicePeer) = try loopbackPair(aliceKey: Curve25519.KeyAgreement.PrivateKey(),
                                              bobKey: Curve25519.KeyAgreement.PrivateKey(),
                                              alicePublished: published)
            let nonce: UInt32 = 0xABCD_EF01
            try alice.startPeerTest(nonce: nonce)
            pumpBoth(alice, alicePeer)
            guard let result = alice.peerTest.result(for: nonce) else {
                throw SSU2Error.testFailed("peer test result missing")
            }
            guard result.classification == .portMapped else {
                throw SSU2Error.testFailed("unexpected classification \(result.classification)")
            }
            // Cache expiry: results lapse after the configured lifetime.
            guard alice.peerTest.result(for: nonce, now: Date().addingTimeInterval(7200)) == nil else {
                throw SSU2Error.testFailed("expired result still cached")
            }
            return "nonce-correlated request/response, reachability classified, cache expires"
        }

        run("SSU2 relay · request, response, hole punch") {
            let relayEntry = SSU2RelayEntry(introductionKey: I2PCrypto.randomBytes(32),
                                            host: "198.51.100.7", port: 9090,
                                            sessionID: 0x00C0_FFEE,
                                            supportsPeerTest: true, supportsHolePunch: true)
            let coordinator = SSU2RelayCoordinator()
            let targetHash = I2PCrypto.sha256(Data("bob-identity".utf8))
            let request = coordinator.buildRelayRequest(nonce: 7, targetHash: targetHash, targetPort: 8888)
            let parsedRequest = try SSU2RelayMessage.parseRequest(request)
            guard parsedRequest.nonce == 7, parsedRequest.targetHash == targetHash,
                  parsedRequest.targetPort == 8888 else { throw SSU2Error.invalidPacket }
            guard try coordinator.handleRelayResponse(SSU2RelayMessage.response(nonce: 7, status: 0)) else {
                throw SSU2Error.testFailed("relay rejected")
            }
            // Hole punch as a type-11 long-header datagram.
            let punch = try coordinator.buildHolePunch(nonce: 0x5150, packetNumber: 1,
                                                       destinationConnectionID: SSU2PacketHeader.randomConnectionID(),
                                                       sourceConnectionID: SSU2PacketHeader.randomConnectionID(),
                                                       introKey: relayEntry.introductionKey)
            // The datagram leaves masked: the type byte is only readable after
            // the hole-punch phase unmask (a masked byte 12 is random).
            var unmaskedPunch = Data(punch)
            try SSU2HeaderProtection.unmaskHeader(&unmaskedPunch, phase: .holePunch,
                                                  introKey: relayEntry.introductionKey)
            guard try SSU2PacketHeader.parse(unmaskedPunch).type == .holePunch else {
                throw SSU2Error.invalidPacket
            }
            let receiving = SSU2RelayCoordinator()
            let receivedNonce = try receiving.handleHolePunch(punch, introKey: relayEntry.introductionKey)
            guard receivedNonce == 0x5150 else { throw SSU2Error.testFailed("hole punch nonce lost") }
            guard receiving.phase == .completed else { throw SSU2Error.testFailed("punch not completed") }
            return "relay request/response round-tripped; type-11 hole punch masked, delivered and decoded"
        }

        run("SSU2 connection migration · path challenge/response, immutable conn IDs") {
            let (alice, bob) = try loopbackPair(aliceKey: Curve25519.KeyAgreement.PrivateKey(),
                                                bobKey: Curve25519.KeyAgreement.PrivateKey())
            let localIDs = (alice.localConnectionID, bob.localConnectionID)
            let remoteIDs = (alice.remoteConnectionID, bob.remoteConnectionID)
            // Bob now hears from Alice on a NEW address (WiFi → cellular): he
            // challenges the new path before switching. Any datagram from the
            // new address triggers the challenge.
            let newEndpoint = SSU2Endpoint(host: "10.6.0.9", port: 41234)
            bob.handleDatagram(Data(), from: newEndpoint)
            pumpBoth(alice, bob)
            guard bob.remoteEndpoint == newEndpoint else {
                throw SSU2Error.testFailed("path not migrated to the validated address")
            }
            // Connection IDs are immutable across the migration.
            guard (alice.localConnectionID, bob.localConnectionID) == localIDs,
                  (alice.remoteConnectionID, bob.remoteConnectionID) == remoteIDs else {
                throw SSU2Error.testFailed("connection IDs changed during migration")
            }
            return "new address challenged, validated by the echoed response, conn IDs untouched"
        }

        run("SSU2 termination · terminal block, retransmission, idle teardown") {
            let (alice, bob) = try loopbackPair(aliceKey: Curve25519.KeyAgreement.PrivateKey(),
                                                bobKey: Curve25519.KeyAgreement.PrivateKey())
            try alice.close(reason: 0, detail: "bye")
            pumpBoth(alice, bob)
            guard bob.state == .closed else { throw SSU2Error.testFailed("peer did not close") }
            guard alice.state == .terminating else { throw SSU2Error.testFailed("terminator state") }
            // Terminal packet retransmission is bounded.
            try alice.retransmitTermination()
            try alice.retransmitTermination()
            try alice.retransmitTermination()
            do {
                try alice.retransmitTermination()
                throw SSU2Error.testFailed("retransmission unbounded")
            } catch let error as SSU2Error {
                guard case .notEstablished = error else { throw error }
            }
            // Idle teardown.
            let quiet = try loopbackPair(aliceKey: Curve25519.KeyAgreement.PrivateKey(),
                                         bobKey: Curve25519.KeyAgreement.PrivateKey()).0
            guard !quiet.checkIdle(timeout: 60) else { throw SSU2Error.testFailed("idle fired too early") }
            guard quiet.checkIdle(timeout: 60, now: Date().addingTimeInterval(3600)) else {
                throw SSU2Error.testFailed("idle teardown did not fire")
            }
            guard quiet.state == .closed else { throw SSU2Error.testFailed("idle state") }
            return "termination block delivered, 3 retransmissions bounded, idle timeout tears down"
        }

        await runAsync("SSU2 UDP transport · real loopback handshake and data") {
            try await udpLoopbackTest()
        }

        run("SSU2 established session · end-to-end data exchange on the loopback wiring") {
            let (alice, bob) = try loopbackPair(aliceKey: Curve25519.KeyAgreement.PrivateKey(),
                                                bobKey: Curve25519.KeyAgreement.PrivateKey())
            var received: [Data] = []
            let bobDelegate = LoopbackDelegate(onData: { received.append($0) })
            bob.delegate = bobDelegate
            let message = I2NPMessage(type: .dataMessage, payload: Data("ssu2 e2e".utf8)).serialize()
            try alice.sendData(message)
            pumpBoth(alice, bob)
            guard received.count == 1, received[0] == message else {
                throw SSU2Error.testFailed("end-to-end data lost")
            }
            // RouterInfo exchange rode the SessionConfirmed.
            guard bob.remoteRouterInfo != nil else {
                throw SSU2Error.testFailed("RouterInfo missing from the SessionConfirmed")
            }
            return "encrypted I2NP data delivered end-to-end; RouterInfo exchanged in the SessionConfirmed"
        }

        run("SSU2 PQ hybrid · ML-KEM-512 (version 3) offer and accept on the loopback") {
            let bobPQ = I2PMLKEMSecretKey(version: .mlKem512)
            let (alice, bob) = try loopbackPair(aliceKey: Curve25519.KeyAgreement.PrivateKey(),
                                                bobKey: Curve25519.KeyAgreement.PrivateKey(),
                                                bobMLKEMSecret: bobPQ,
                                                bobAdvertisedPQKey: bobPQ.encapsulationKeyData)
            guard alice.negotiatedPQVersion == .mlKem512, bob.negotiatedPQVersion == .mlKem512 else {
                throw SSU2Error.testFailed("hybrid leg not negotiated to ML-KEM-512")
            }
            // Dual-leg binding: only peers that completed BOTH legs derive the
            // same split keys — the end-to-end data phase under those keys proves it.
            var received: [Data] = []
            // The session holds its delegate weakly: keep the stub alive here.
            let bobDelegate = LoopbackDelegate(onData: { received.append($0) })
            bob.delegate = bobDelegate
            defer { withExtendedLifetime(bobDelegate) {} }
            let message = I2NPMessage(type: .dataMessage, payload: Data("pq hybrid 512 e2e".utf8)).serialize()
            try alice.sendData(message)
            pumpBoth(alice, bob)
            guard received == [message] else { throw SSU2Error.testFailed("hybrid data phase lost") }
            return "v3 offer with a 768-byte FIPS 203 ML-KEM-512 ENCAPS; accepted, decapsulated, dual-leg keys mirrored, data delivered end-to-end"
        }

        run("SSU2 PQ hybrid · ML-KEM-768 (version 4) offer and accept on the loopback") {
            let bobPQ = I2PMLKEMSecretKey(version: .mlKem768)
            let (alice, bob) = try loopbackPair(aliceKey: Curve25519.KeyAgreement.PrivateKey(),
                                                bobKey: Curve25519.KeyAgreement.PrivateKey(),
                                                bobMLKEMSecret: bobPQ,
                                                bobAdvertisedPQKey: bobPQ.encapsulationKeyData)
            guard alice.negotiatedPQVersion == .mlKem768, bob.negotiatedPQVersion == .mlKem768 else {
                throw SSU2Error.testFailed("hybrid leg not negotiated to ML-KEM-768")
            }
            var received: [Data] = []
            let bobDelegate = LoopbackDelegate(onData: { received.append($0) })
            bob.delegate = bobDelegate
            defer { withExtendedLifetime(bobDelegate) {} }
            let message = I2NPMessage(type: .dataMessage, payload: Data("pq hybrid 768 e2e".utf8)).serialize()
            try alice.sendData(message)
            pumpBoth(alice, bob)
            guard received == [message] else { throw SSU2Error.testFailed("hybrid data phase lost") }
            return "v4 offer with a 1088-byte FIPS 203 ML-KEM-768 ENCAPS; accepted, decapsulated, dual-leg keys mirrored, data delivered end-to-end"
        }

        run("SSU2 PQ down-negotiation · classical fallback when the peer takes no hybrid") {
            // Bob's ML-KEM key is advertised to Alice, but his transport accepts
            // no hybrid sessions: the offer earns a Retry and the handshake
            // continues on the classical long-header variant.
            let advertised = I2PMLKEMSecretKey(version: .mlKem512)
            let aliceKey = Curve25519.KeyAgreement.PrivateKey()
            let bobKey = Curve25519.KeyAgreement.PrivateKey()
            let aliceRI = try I2PSamples.sampleRouterInfo()
            let bobRI = try I2PSamples.sampleRouterInfo()
            let alice = SSU2Session(role: .initiator, localStaticKey: aliceKey,
                                    remoteStaticKey: bobKey.publicKey.rawRepresentation,
                                    remoteIntroKey: bobIntroKey, localRouterInfo: aliceRI,
                                    remoteMLKEMKeyData: advertised.encapsulationKeyData)
            let bob = SSU2Session(role: .responder, localStaticKey: bobKey,
                                  remoteStaticKey: nil, remoteIntroKey: bobIntroKey,
                                  localRouterInfo: bobRI)
            var offeredVersion: UInt8?
            var sawRetry = false
            alice.outboundHandler = { datagram, _ in
                if offeredVersion == nil {
                    var unmasked = Data(datagram)
                    try? SSU2HeaderProtection.unmaskHeader(&unmasked, phase: .sessionRequest,
                                                           introKey: bobIntroKey)
                    offeredVersion = (try? SSU2PacketHeader.parse(unmasked))?.version
                }
                bob.handleDatagram(datagram, from: aliceLoopbackEndpoint)
            }
            bob.outboundHandler = { datagram, _ in
                if Self.phaseType(datagram, phase: .retry, introKey: bobIntroKey) == .retry {
                    sawRetry = true
                }
                alice.handleDatagram(datagram, from: bobLoopbackEndpoint)
            }
            try alice.startHandshake(useCachedToken: true, forceInvalidToken: true)
            pumpBoth(alice, bob)
            guard offeredVersion == I2PSSU2PQVersion.mlKem512.rawValue else {
                throw SSU2Error.testFailed("the offer did not carry the version-3 byte")
            }
            guard sawRetry else { throw SSU2Error.testFailed("no-PQ peer did not signal with a Retry") }
            guard alice.negotiatedPQVersion == nil, bob.negotiatedPQVersion == nil else {
                throw SSU2Error.testFailed("down-negotiation failed")
            }
            guard alice.isEstablished, bob.isEstablished else {
                throw SSU2Error.testFailed("classical fallback did not establish")
            }
            return "v3 offer signaled, Retry earned, down-negotiated to the classical handshake and established"
        }

        run("ML-KEM FIPS 203 · Keccak vector, NTT homomorphism, encaps/decaps") {
            // SHA3-256 known answer (empty input) pins the Keccak sponge.
            guard Keccak.sha3_256(Data()).hex
                    == "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a" else {
                throw SSU2Error.testFailed("SHA3-256 empty-input vector mismatch")
            }
            // The NTT must round-trip and be a ring homomorphism: the transform
            // product must equal the schoolbook negacyclic convolution.
            func randomPoly() -> [Int] {
                (0..<MLKEM.n).map { _ in Int.random(in: 0..<MLKEM.q) }
            }
            let f = randomPoly()
            let g = randomPoly()
            guard MLKEM.inverseNTT(MLKEM.ntt(f)) == f else {
                throw SSU2Error.testFailed("NTT is not invertible")
            }
            var schoolbook = [Int](repeating: 0, count: MLKEM.n)
            for i in 0..<MLKEM.n {
                for j in 0..<MLKEM.n {
                    let target = (i + j) % MLKEM.n
                    let sign = (i + j) >= MLKEM.n ? MLKEM.q - 1 : 1
                    schoolbook[target] = (schoolbook[target] + sign * f[i] * g[j]) % MLKEM.q
                }
            }
            let transformed = MLKEM.inverseNTT(
                MLKEM.multiplyNTTs(MLKEM.ntt(f), MLKEM.ntt(g)))
            guard transformed == schoolbook else {
                throw SSU2Error.testFailed("NTT is not a homomorphism for X^256 + 1")
            }
            // Both parameter sets: deterministic keygen from (d, z), exact FIPS
            // 203 wire shapes, ENCAPS/DECAPS agreement, implicit rejection.
            let d = [UInt8](I2PCrypto.randomBytes(32))
            let z = [UInt8](I2PCrypto.randomBytes(32))
            for (version, parameters) in [(I2PSSU2PQVersion.mlKem512, MLKEM.Parameters.mlKem512),
                                          (I2PSSU2PQVersion.mlKem768, MLKEM.Parameters.mlKem768)] {
                let first = MLKEM.keyGen(d: d, z: z, parameters: parameters)
                let second = MLKEM.keyGen(d: d, z: z, parameters: parameters)
                guard first.ek == second.ek else {
                    throw SSU2Error.testFailed("\(version.name) keygen is not deterministic in (d, z)")
                }
                guard first.ek.count == version.mlKemEncapsulationKeyLength else {
                    throw SSU2Error.testFailed("\(version.name) encapsulation key shape broken")
                }
                let peer = try I2PMLKEMPublicKey(keyData: first.ek)
                let capsule = try peer.encapsulate()
                guard capsule.ciphertext.count == version.mlKemCiphertextLength,
                      capsule.sharedSecret.count == 32 else {
                    throw SSU2Error.testFailed("\(version.name) capsule shape broken")
                }
                let decapsulated = try first.decapsulate(capsule.ciphertext)
                guard decapsulated == capsule.sharedSecret else {
                    throw SSU2Error.testFailed("\(version.name) DECAPS disagreed with ENCAPS")
                }
                var tampered = capsule.ciphertext
                tampered[tampered.count / 2] ^= 0xff
                let rejected = try first.decapsulate(tampered)
                guard rejected != capsule.sharedSecret, rejected.count == 32 else {
                    throw SSU2Error.testFailed("\(version.name) implicit rejection failed")
                }
            }
            return "SHA3-256 vector exact; NTT inverts and multiplies homomorphically; ML-KEM-512/768 round-trip with implicit rejection"
        }

        await runAsync("SSU2 PQ hybrid transport · ML-KEM-512 session over the UDP loopback") {
            try await udpHybridLoopbackTest(version: .mlKem512)
        }

        await runAsync("SSU2 PQ hybrid transport · ML-KEM-768 session over the UDP loopback") {
            try await udpHybridLoopbackTest(version: .mlKem768)
        }

        return results
    }

    // MARK: Loopback helpers

    /// The message type of a datagram under a given header-protection phase.
    /// Wire packets carry masked headers, so tests must unmask before reading
    /// the type or version byte (a masked byte is random).
    static func phaseType(_ datagram: Data, phase: SSU2HeaderPhase,
                          introKey: Data, sessionKey: Data? = nil) -> SSU2MessageType? {
        var unmasked = Data(datagram)
        try? SSU2HeaderProtection.unmaskHeader(&unmasked, phase: phase,
                                               introKey: introKey, sessionKey: sessionKey)
        return (try? SSU2PacketHeader.parse(unmasked))?.type
    }

    private final class LoopbackDelegate: SSU2SessionDelegate {
        private let onData: ((Data) -> Void)?
        private let onEstablish: (() -> Void)?
        init(onData: ((Data) -> Void)? = nil, onEstablish: (() -> Void)? = nil) {
            self.onData = onData
            self.onEstablish = onEstablish
        }
        func session(_ session: SSU2Session, didEstablish remoteRouterInfo: I2PRouterInfo?) {
            onEstablish?()
        }
        func session(_ session: SSU2Session, didReceiveData data: Data) {
            onData?(data)
        }
        func session(_ session: SSU2Session, didClose error: Error?) {}
    }

    /// Builds an established initiator/responder pair on the loopback wiring.
    static func loopbackPair(aliceKey: Curve25519.KeyAgreement.PrivateKey,
                                     bobKey: Curve25519.KeyAgreement.PrivateKey,
                                     alicePublished: SSU2Endpoint? = nil,
                                      bobMLKEMSecret: I2PMLKEMSecretKey? = nil,
                                      bobAdvertisedPQKey: Data? = nil) throws -> (SSU2Session, SSU2Session) {
        let aliceRI = try I2PSamples.sampleRouterInfo()
        let bobRI = try I2PSamples.sampleRouterInfo()
        let alice = SSU2Session(role: .initiator, localStaticKey: aliceKey,
                                remoteStaticKey: bobKey.publicKey.rawRepresentation,
                                remoteIntroKey: bobIntroKey, localRouterInfo: aliceRI,
                                publishedEndpoint: alicePublished,
                                remoteMLKEMKeyData: bobAdvertisedPQKey)
        let bob = SSU2Session(role: .responder, localStaticKey: bobKey,
                              remoteStaticKey: nil, remoteIntroKey: bobIntroKey,
                              localRouterInfo: bobRI, mlKemSecretKey: bobMLKEMSecret)
        alice.outboundHandler = { datagram, _ in bob.handleDatagram(datagram, from: aliceLoopbackEndpoint) }
        bob.outboundHandler = { datagram, _ in alice.handleDatagram(datagram, from: bobLoopbackEndpoint) }
        // Token-request path: the Retry answers a TokenRequest, not a refused
        // hybrid offer, so the PQ leg stays offered on the SessionRequest that
        // follows. (Forcing an invalid SessionRequest token instead would be a
        // legitimate no-PQ signal and downgrade the handshake.)
        try alice.startHandshake(useCachedToken: false)
        pumpBoth(alice, bob)
        guard alice.isEstablished, bob.isEstablished else {
            throw SSU2Error.testFailed("loopback handshake failed")
        }
        return (alice, bob)
    }

    /// Runs the full token-request handshake path and returns both key sets.
    static func handshakeKeySets() throws -> (SSU2SessionKeys, SSU2SessionKeys) {
        try loopbackHandshake()
    }

    private static func loopbackHandshake() throws -> (SSU2SessionKeys, SSU2SessionKeys) {
        let aliceKey = Curve25519.KeyAgreement.PrivateKey()
        let bobKey = Curve25519.KeyAgreement.PrivateKey()
        let bobStatic = bobKey.publicKey.rawRepresentation
        let introKey = I2PCrypto.randomBytes(32)
        let manager = SSU2TokenManager()
        let aliceRI = try I2PSamples.sampleRouterInfo()
        let bobRI = try I2PSamples.sampleRouterInfo()
        let alice = SSU2Session(role: .initiator, localStaticKey: aliceKey,
                                remoteStaticKey: bobStatic, remoteIntroKey: introKey,
                                localRouterInfo: aliceRI)
        let bob = SSU2Session(role: .responder, localStaticKey: bobKey,
                              remoteStaticKey: nil, remoteIntroKey: introKey,
                              localRouterInfo: bobRI, tokenManager: manager)
        alice.outboundHandler = { datagram, _ in bob.handleDatagram(datagram, from: aliceLoopbackEndpoint) }
        bob.outboundHandler = { datagram, _ in alice.handleDatagram(datagram, from: bobLoopbackEndpoint) }
        try alice.startHandshake(useCachedToken: false)
        pumpBoth(alice, bob)
        guard alice.isEstablished, bob.isEstablished else {
            throw SSU2Error.testFailed("handshake did not complete")
        }
        guard let aliceEngine = alice.initiatorEngineKeys, let bobEngineKeys = bob.responderEngineKeys else {
            throw SSU2Error.testFailed("keys unavailable")
        }
        return (aliceEngine, bobEngineKeys)
    }

    /// Bidirectional pump for loopback pairs: each flush triggers nested
    /// synchronous delivery, so two rounds clear both directions.
    static func pumpBoth(_ a: SSU2Session, _ b: SSU2Session) {
        a.flushOutbox()
        b.flushOutbox()
        a.flushOutbox()
        b.flushOutbox()
    }

    // MARK: UDP loopback

    static func udpLoopbackTest() async throws -> String {
        let bobKey = Curve25519.KeyAgreement.PrivateKey()
        let bobRI = try I2PSamples.sampleRouterInfo()
        let transport = SSU2Transport(localStaticKey: bobKey, introKey: bobIntroKey,
                                      localRouterInfo: bobRI,
                                      publishedEndpoint: SSU2Endpoint(host: "127.0.0.1", port: 8888))
        defer { transport.shutdown() }
        _ = try transport.startListener(port: 0)
        // The listener binds asynchronously; wait for the state handler to
        // publish the assigned ephemeral port (near-instant on the simulator,
        // slower on device).
        var port = transport.listenerPort ?? 0
        var waited = 0.0
        while port == 0 && waited < 5 {
            try await Task.sleep(nanoseconds: 100_000_000)
            waited += 0.1
            port = transport.listenerPort ?? 0
        }
        guard port > 0 else { throw SSU2Error.testFailed("no listener port") }

        let responderEstablished = Expectation()
        let responderStub = TransportDelegateStub(onEstablish: { responderEstablished.fulfill() })
        transport.delegate = responderStub

        let initiatorEstablished = Expectation()
        let initiatorStub = LoopbackDelegate(onEstablish: { initiatorEstablished.fulfill() })
        let session = try transport.connect(host: "127.0.0.1", port: port,
                                            remoteStaticKey: bobKey.publicKey.rawRepresentation,
                                            remoteIntroKey: bobIntroKey,
                                            sessionDelegate: initiatorStub)

        try await responderEstablished.wait(seconds: 10)
        try await initiatorEstablished.wait(seconds: 10)
        guard session.isEstablished else { throw SSU2Error.testFailed("UDP handshake incomplete") }

        let dataReceived = Expectation()
        let dataStub = TransportDelegateStub(onEstablish: { responderEstablished.fulfill() },
                                             onData: { _ in dataReceived.fulfill() })
        transport.delegate = dataStub
        let message = I2NPMessage(type: .dataMessage, payload: Data("over real udp".utf8)).serialize()
        try session.sendData(message)
        try await dataReceived.wait(seconds: 10)
        _ = (responderStub, initiatorStub, dataStub)
        return "real UDP loopback: handshake established both sides, I2NP data delivered"
    }

    /// The ML-KEM hybrid long-header handshake over REAL UDP sockets: Bob's
    /// transport carries an ML-KEM key pair, Alice is handed Bob's advertised
    /// encapsulation key, and the negotiated hybrid session carries I2NP data.
    static func udpHybridLoopbackTest(version: I2PSSU2PQVersion) async throws -> String {
        let bobKey = Curve25519.KeyAgreement.PrivateKey()
        let bobPQ = I2PMLKEMSecretKey(version: version)
        let bobRI = try I2PSamples.sampleRouterInfo()
        let transport = SSU2Transport(localStaticKey: bobKey, introKey: bobIntroKey,
                                      localRouterInfo: bobRI,
                                      publishedEndpoint: SSU2Endpoint(host: "127.0.0.1", port: 8888),
                                      mlKemSecretKey: bobPQ)
        defer { transport.shutdown() }
        _ = try transport.startListener(port: 0)
        var port = transport.listenerPort ?? 0
        var waited = 0.0
        while port == 0 && waited < 5 {
            try await Task.sleep(nanoseconds: 100_000_000)
            waited += 0.1
            port = transport.listenerPort ?? 0
        }
        guard port > 0 else { throw SSU2Error.testFailed("no listener port") }

        let responderEstablished = Expectation()
        let responderStub = TransportDelegateStub(onEstablish: { responderEstablished.fulfill() })
        transport.delegate = responderStub

        let initiatorEstablished = Expectation()
        let initiatorStub = LoopbackDelegate(onEstablish: { initiatorEstablished.fulfill() })
        let session = try transport.connect(host: "127.0.0.1", port: port,
                                            remoteStaticKey: bobKey.publicKey.rawRepresentation,
                                            remoteIntroKey: bobIntroKey,
                                            remoteMLKEMKey: bobPQ.encapsulationKeyData,
                                            sessionDelegate: initiatorStub)

        try await responderEstablished.wait(seconds: 10)
        try await initiatorEstablished.wait(seconds: 10)
        guard session.isEstablished else { throw SSU2Error.testFailed("UDP hybrid handshake incomplete") }
        guard session.negotiatedPQVersion == version else {
            throw SSU2Error.testFailed("UDP session did not negotiate \(version.name)")
        }

        let dataReceived = Expectation()
        let dataStub = TransportDelegateStub(onEstablish: { responderEstablished.fulfill() },
                                             onData: { _ in dataReceived.fulfill() })
        transport.delegate = dataStub
        let message = I2NPMessage(type: .dataMessage,
                                  payload: Data("over real udp (\(version.name))".utf8)).serialize()
        try session.sendData(message)
        try await dataReceived.wait(seconds: 10)
        _ = (responderStub, initiatorStub, dataStub)
        return "real UDP loopback (\(version.name)): version \(version.rawValue) hybrid handshake established, I2NP data delivered on the PQ-bound keys"
    }

    private final class TransportDelegateStub: SSU2TransportDelegate {
        private let onEstablish: (() -> Void)?
        private let onData: ((Data) -> Void)?
        init(onEstablish: (() -> Void)? = nil, onData: ((Data) -> Void)? = nil) {
            self.onEstablish = onEstablish
            self.onData = onData
        }
        func transport(_ transport: SSU2Transport, sessionEstablished session: SSU2Session) {
            onEstablish?()
        }
        func transport(_ transport: SSU2Transport, session: SSU2Session, didReceiveData data: Data) {
            onData?(data)
        }
        func transport(_ transport: SSU2Transport, sessionDidClose session: SSU2Session) {}
    }

    /// Test expectation with a bounded wait. The timeout fires on a dispatch
    /// queue (never from an async context) so the lock is always taken
    /// synchronously.
    private final class Expectation {
        private let lock = NSLock()
        private var fulfilled = false
        private var continuation: CheckedContinuation<Void, Error>?

        func fulfill() {
            lock.lock()
            fulfilled = true
            let pending = continuation
            continuation = nil
            lock.unlock()
            pending?.resume()
        }

        private func expire() {
            lock.lock()
            guard !fulfilled else {
                lock.unlock()
                return
            }
            fulfilled = true
            let pending = continuation
            continuation = nil
            lock.unlock()
            pending?.resume(throwing: SSU2Error.testFailed("timed out"))
        }

        func wait(seconds: TimeInterval) async throws {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                lock.lock()
                if fulfilled {
                    lock.unlock()
                    cont.resume()
                    return
                }
                continuation = cont
                lock.unlock()
                DispatchQueue.global().asyncAfter(deadline: .now() + seconds) { [weak self] in
                    self?.expire()
                }
            }
        }
    }
}