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

    private var chain = NTCP2NoiseChain()
    private let localStaticKey: Curve25519.KeyAgreement.PrivateKey
    private let remoteStaticKey: Data
    private let introKey: Data
    private let ephemeral = Curve25519.KeyAgreement.PrivateKey()
    private var aliceHeader: Data?

    /// The responder's demultiplex connection ID, derived from its static key
    /// so inbound handshake packets land without prior state.
    static func responderConnectionID(for remoteStaticKey: Data) -> Data {
        Data(I2PCrypto.sha256(remoteStaticKey + Data("SSU2 dst conn".utf8)).prefix(8))
    }

    init(localStaticKey: Curve25519.KeyAgreement.PrivateKey,
         remoteStaticKey: Data, introKey: Data) {
        precondition(remoteStaticKey.count == 32 && introKey.count == 32)
        self.localStaticKey = localStaticKey
        self.remoteStaticKey = remoteStaticKey
        self.introKey = introKey
    }

    /// TokenRequest (type 10): a long-header packet addressed to the responder's
    /// derived connection ID, asking for a Retry with a fresh token. The header
    /// is masked with the session-request phase key (token requests share it).
    func makeTokenRequest(localConnectionID: Data) throws -> Data {
        let header = SSU2PacketHeader(
            destinationConnectionID: SSU2InitiatorHandshake.responderConnectionID(for: remoteStaticKey),
            packetNumber: 0, type: .tokenRequest,
            sourceConnectionID: localConnectionID,
            token: Data(repeating: 0, count: 8))
        var packet = header.serialize()
        packet.append(ssu2Timestamp(Date()))
        try SSU2HeaderProtection.maskHeader(&packet, phase: .sessionRequest, introKey: introKey)
        stage = .awaitingRetryOrCreated
        return packet
    }

    /// SessionRequest (type 0): fresh Noise chain (each attempt starts clean),
    /// header MixHash binding, ephemeral key in the obfuscated region, encrypted
    /// static section (48 bytes), encrypted options payload.
    func makeSessionRequest(localConnectionID: Data, token: Data) throws -> Data {
        chain = NTCP2NoiseChain()
        let header = SSU2PacketHeader(
            destinationConnectionID: SSU2InitiatorHandshake.responderConnectionID(for: remoteStaticKey),
            packetNumber: 0, type: .sessionRequest,
            sourceConnectionID: localConnectionID, token: token)
        aliceHeader = header.serialize()
        chain.mixHash(aliceHeader!)
        var packet = aliceHeader! + ephemeral.publicKey.rawRepresentation

        let responderStatic = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: remoteStaticKey)
        let es = try ephemeral.sharedSecretFromKeyAgreement(with: responderStatic)
        chain.mixKey(es.withUnsafeBytes { Data($0) })
        let staticPlain = localStaticKey.publicKey.rawRepresentation + Data(repeating: 0, count: 16)
        packet.append(try chain.encrypt(staticPlain))
        let ss = try localStaticKey.sharedSecretFromKeyAgreement(with: responderStatic)
        chain.mixKey(ss.withUnsafeBytes { Data($0) })
        var payload = ssu2Timestamp(Date())
        payload.append(contentsOf: Data("SSU2".utf8))
        packet.append(try chain.encrypt(payload))

        try SSU2HeaderProtection.obfuscateEphemeralRegion(&packet, introKey: introKey,
                                                          responderStaticKey: remoteStaticKey)
        try SSU2HeaderProtection.maskHeader(&packet, phase: .sessionRequest, introKey: introKey)
        stage = .awaitingCreated
        return packet
    }

    /// Retry (type 9): unmasked with the retry phase key; the fresh token rides
    /// in the header token field. Returns the token for the token cache.
    func processRetry(_ packet: Data) throws -> Data {
        guard stage == .awaitingRetryOrCreated else {
            throw SSU2Error.handshakeFailed("Retry outside the token-request stage")
        }
        var masked = Data(packet)
        try SSU2HeaderProtection.unmaskHeader(&masked, phase: .retry, introKey: introKey)
        let header = try SSU2PacketHeader.parse(masked)
        guard header.type == .retry, header.isLong, let token = header.token else {
            throw SSU2Error.invalidPacket
        }
        guard header.destinationConnectionID == aliceHeader?.subdata(in: 16..<24) else {
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
        _ = try chain.decrypt(masked.subdata(in: 112..<masked.count))
        stage = .confirmed
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
    private var aliceEphemeralPub: Data?
    private var aliceStaticPub: Data?

    private var chain = NTCP2NoiseChain()
    private let localStaticKey: Curve25519.KeyAgreement.PrivateKey
    private let introKey: Data
    private let localConnectionID: Data
    private let tokenManager: SSU2TokenManager

    init(localStaticKey: Curve25519.KeyAgreement.PrivateKey, localConnectionID: Data,
         introKey: Data, tokenManager: SSU2TokenManager) {
        self.localStaticKey = localStaticKey
        self.localConnectionID = localConnectionID
        self.introKey = introKey
        self.tokenManager = tokenManager
    }

    /// Retry (type 9) carrying a fresh token in the header token field.
    func makeRetry(for requesterConnectionID: Data, token: Data) throws -> Data {
        let header = SSU2PacketHeader(
            destinationConnectionID: requesterConnectionID, packetNumber: 0,
            type: .retry, sourceConnectionID: localConnectionID, token: token)
        var packet = header.serialize()
        packet.append(ssu2Timestamp(Date()))
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
        let staticPlain = try chain.decrypt(masked.subdata(in: 64..<112))
        remoteStaticKey = staticPlain.prefix(32)
        self.aliceStaticPub = remoteStaticKey
        let aliceStatic = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: remoteStaticKey!)
        let ss = try localStaticKey.sharedSecretFromKeyAgreement(with: aliceStatic)
        chain.mixKey(ss.withUnsafeBytes { Data($0) })
        _ = try chain.decrypt(masked.subdata(in: 112..<masked.count))
        return try makeSessionCreated()
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
            type: .sessionCreated, sourceConnectionID: localConnectionID)
        chain.mixHash(header.serialize())
        var packet = header.serialize() + ephemeral.publicKey.rawRepresentation

        let aliceEphemeral = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: aliceEphemeralPub!)
        let ee = try ephemeral.sharedSecretFromKeyAgreement(with: aliceEphemeral)
        chain.mixKey(ee.withUnsafeBytes { Data($0) })
        let staticPlain = localStaticKey.publicKey.rawRepresentation + Data(repeating: 0, count: 16)
        packet.append(try chain.encrypt(staticPlain))

        let aliceStatic = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: aliceStaticPub!)
        let se = try ephemeral.sharedSecretFromKeyAgreement(with: aliceStatic)
        chain.mixKey(se.withUnsafeBytes { Data($0) })
        var payload = ssu2Timestamp(Date())
        payload.append(contentsOf: Data("SSU2".utf8))
        packet.append(try chain.encrypt(payload))

        try SSU2HeaderProtection.obfuscateEphemeralRegion(&packet, introKey: introKey,
                                                          responderStaticKey: localStaticKey.publicKey.rawRepresentation)
        try SSU2HeaderProtection.maskHeader(&packet, phase: .sessionCreated, introKey: introKey)
        return packet
    }

    func complete() throws -> SSU2SessionKeys {
        guard stage == .awaitingConfirmed else {
            throw SSU2Error.handshakeFailed("SessionRequest not processed")
        }
        return SSU2KeySchedule.split(chainingKey: chain.chainingKey)
    }
}
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

    private var chain = NTCP2NoiseChain()
    private let localStaticKey: Curve25519.KeyAgreement.PrivateKey
    private let remoteStaticKey: Data
    private let introKey: Data
    private let ephemeral = Curve25519.KeyAgreement.PrivateKey()
    private var aliceHeader: Data?

    /// The responder's demultiplex connection ID, derived from its static key
    /// so inbound handshake packets land without prior state.
    static func responderConnectionID(for remoteStaticKey: Data) -> Data {
        Data(I2PCrypto.sha256(remoteStaticKey + Data("SSU2 dst conn".utf8)).prefix(8))
    }

    init(localStaticKey: Curve25519.KeyAgreement.PrivateKey,
         remoteStaticKey: Data, introKey: Data) {
        precondition(remoteStaticKey.count == 32 && introKey.count == 32)
        self.localStaticKey = localStaticKey
        self.remoteStaticKey = remoteStaticKey
        self.introKey = introKey
    }

    /// TokenRequest (type 10): a long-header packet addressed to the responder's
    /// derived connection ID, asking for a Retry with a fresh token. The header
    /// is masked with the session-request phase key (token requests share it).
    func makeTokenRequest(localConnectionID: Data) throws -> Data {
        let header = SSU2PacketHeader(
            destinationConnectionID: SSU2InitiatorHandshake.responderConnectionID(for: remoteStaticKey),
            packetNumber: 0, type: .tokenRequest,
            sourceConnectionID: localConnectionID,
            token: Data(repeating: 0, count: 8))
        var packet = header.serialize()
        packet.append(ssu2Timestamp(Date()))
        try SSU2HeaderProtection.maskHeader(&packet, phase: .sessionRequest, introKey: introKey)
        stage = .awaitingRetryOrCreated
        return packet
    }

    /// SessionRequest (type 0): fresh Noise chain (each attempt starts clean),
    /// header MixHash binding, ephemeral key in the obfuscated region, encrypted
    /// static section (48 bytes), encrypted options payload.
    func makeSessionRequest(localConnectionID: Data, token: Data) throws -> Data {
        chain = NTCP2NoiseChain()
        let header = SSU2PacketHeader(
            destinationConnectionID: SSU2InitiatorHandshake.responderConnectionID(for: remoteStaticKey),
            packetNumber: 0, type: .sessionRequest,
            sourceConnectionID: localConnectionID, token: token)
        aliceHeader = header.serialize()
        chain.mixHash(aliceHeader!)
        var packet = aliceHeader! + ephemeral.publicKey.rawRepresentation

        let responderStatic = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: remoteStaticKey)
        let es = try ephemeral.sharedSecretFromKeyAgreement(with: responderStatic)
        chain.mixKey(es.withUnsafeBytes { Data($0) })
        let staticPlain = localStaticKey.publicKey.rawRepresentation + Data(repeating: 0, count: 16)
        packet.append(try chain.encrypt(staticPlain))
        let ss = try localStaticKey.sharedSecretFromKeyAgreement(with: responderStatic)
        chain.mixKey(ss.withUnsafeBytes { Data($0) })
        var payload = ssu2Timestamp(Date())
        payload.append(contentsOf: Data("SSU2".utf8))
        packet.append(try chain.encrypt(payload))

        try SSU2HeaderProtection.obfuscateEphemeralRegion(&packet, introKey: introKey,
                                                          responderStaticKey: remoteStaticKey)
        try SSU2HeaderProtection.maskHeader(&packet, phase: .sessionRequest, introKey: introKey)
        stage = .awaitingCreated
        return packet
    }

    /// Retry (type 9): unmasked with the retry phase key; the fresh token rides
    /// in the header token field. Returns the token for the token cache.
    func processRetry(_ packet: Data) throws -> Data {
        guard stage == .awaitingRetryOrCreated else {
            throw SSU2Error.handshakeFailed("Retry outside the token-request stage")
        }
        var masked = Data(packet)
        try SSU2HeaderProtection.unmaskHeader(&masked, phase: .retry, introKey: introKey)
        let header = try SSU2PacketHeader.parse(masked)
        guard header.type == .retry, header.isLong, let token = header.token else {
            throw SSU2Error.invalidPacket
        }
        guard header.destinationConnectionID == aliceHeader?.subdata(in: 16..<24) else {
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
        _ = try chain.decrypt(masked.subdata(in: 112..<masked.count))
        stage = .confirmed
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
    private var aliceEphemeralPub: Data?
    private var aliceStaticPub: Data?

    private var chain = NTCP2NoiseChain()
    private let localStaticKey: Curve25519.KeyAgreement.PrivateKey
    private let introKey: Data
    private let localConnectionID: Data
    private let tokenManager: SSU2TokenManager

    init(localStaticKey: Curve25519.KeyAgreement.PrivateKey, localConnectionID: Data,
         introKey: Data, tokenManager: SSU2TokenManager) {
        self.localStaticKey = localStaticKey
        self.localConnectionID = localConnectionID
        self.introKey = introKey
        self.tokenManager = tokenManager
    }

    /// Retry (type 9) carrying a fresh token in the header token field.
    func makeRetry(for requesterConnectionID: Data, token: Data) throws -> Data {
        let header = SSU2PacketHeader(
            destinationConnectionID: requesterConnectionID, packetNumber: 0,
            type: .retry, sourceConnectionID: localConnectionID, token: token)
        var packet = header.serialize()
        packet.append(ssu2Timestamp(Date()))
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
        let staticPlain = try chain.decrypt(masked.subdata(in: 64..<112))
        remoteStaticKey = staticPlain.prefix(32)
        self.aliceStaticPub = remoteStaticKey
        let aliceStatic = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: remoteStaticKey!)
        let ss = try localStaticKey.sharedSecretFromKeyAgreement(with: aliceStatic)
        chain.mixKey(ss.withUnsafeBytes { Data($0) })
        _ = try chain.decrypt(masked.subdata(in: 112..<masked.count))
        return try makeSessionCreated()
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
            type: .sessionCreated, sourceConnectionID: localConnectionID)
        chain.mixHash(header.serialize())
        var packet = header.serialize() + ephemeral.publicKey.rawRepresentation

        let aliceEphemeral = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: aliceEphemeralPub!)
        let ee = try ephemeral.sharedSecretFromKeyAgreement(with: aliceEphemeral)
        chain.mixKey(ee.withUnsafeBytes { Data($0) })
        let staticPlain = localStaticKey.publicKey.rawRepresentation + Data(repeating: 0, count: 16)
        packet.append(try chain.encrypt(staticPlain))

        let aliceStatic = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: aliceStaticPub!)
        let se = try ephemeral.sharedSecretFromKeyAgreement(with: aliceStatic)
        chain.mixKey(se.withUnsafeBytes { Data($0) })
        var payload = ssu2Timestamp(Date())
        payload.append(contentsOf: Data("SSU2".utf8))
        packet.append(try chain.encrypt(payload))

        try SSU2HeaderProtection.obfuscateEphemeralRegion(&packet, introKey: introKey,
                                                          responderStaticKey: localStaticKey.publicKey.rawRepresentation)
        try SSU2HeaderProtection.maskHeader(&packet, phase: .sessionCreated, introKey: introKey)
        return packet
    }

    func complete() throws -> SSU2SessionKeys {
        guard stage == .awaitingConfirmed else {
            throw SSU2Error.handshakeFailed("SessionRequest not processed")
        }
        return SSU2KeySchedule.split(chainingKey: chain.chainingKey)
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
        let (nonce, status) = try SSU2RelayMessage.parseResponse(body)
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