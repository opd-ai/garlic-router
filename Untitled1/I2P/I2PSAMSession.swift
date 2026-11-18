//
//  I2PSAMSession.swift
//  SAM session layer: transient destination key material, the garlic-framed
//  stream/datagram wire format, inbound reassembly, and per-session state
//  (destination, tunnel pool, LeaseSet publication, garlic sessions).
//

import Foundation
import CryptoKit

// MARK: - Destination keys

/// Destination key material for a SAM session: Ed25519 signing seed plus
/// X25519 encryption key. The SAM private-key encoding is base64(seed ‖ key).
struct I2PSAMDestinationKeys {
    let signingSeed: Data
    let encryptionKey: Curve25519.KeyAgreement.PrivateKey
    let destination: I2PDestination

    /// 64-byte SAM private destination: [Ed25519 seed (32)][X25519 private (32)].
    var privateKeyData: Data { signingSeed + encryptionKey.rawRepresentation }

    static func generate() -> I2PSAMDestinationKeys {
        let seed = I2PCrypto.generateEd25519Seed()
        let encryption = Curve25519.KeyAgreement.PrivateKey()
        return I2PSAMDestinationKeys(
            signingSeed: seed,
            encryptionKey: encryption,
            destination: I2PKeysAndCert(
                encryptionPublicKey: encryption.publicKey.rawRepresentation,
                signingPublicKey: I2PCrypto.ed25519PublicKey(fromSeed: seed)
            )
        )
    }

    static func parse(_ data: Data) throws -> I2PSAMDestinationKeys {
        let bytes = Array(data)
        guard bytes.count == 64 else { throw I2PSAMError.invalidDestination }
        let seed = Data(bytes[0..<32])
        let encryption = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(bytes[32..<64]))
        return I2PSAMDestinationKeys(
            signingSeed: seed,
            encryptionKey: encryption,
            destination: I2PKeysAndCert(
                encryptionPublicKey: encryption.publicKey.rawRepresentation,
                signingPublicKey: I2PCrypto.ed25519PublicKey(fromSeed: seed)
            )
        )
    }
}

// MARK: - Garlic stream/datagram frames

/// The SAM frame carried inside a garlic'd I2NP data message:
/// [streamID (4)][flags (1)][sequence (4)][fromPort (4)][toPort (4)]
/// [chunkIndex (2)][chunkCount (2)][chunkLength (2)][chunk][attachment?]
/// The attachment rides on chunk 0 of a SYN (stream) or DATAGRAM message and
/// carries the sender's destination keys-and-certificate (raw, for replies).
struct I2PSAMFrame {
    struct Flags: OptionSet {
        let rawValue: UInt8
        static let syn = Flags(rawValue: 0x01)
        static let fin = Flags(rawValue: 0x02)
        static let rst = Flags(rawValue: 0x04)
        static let datagram = Flags(rawValue: 0x08)
    }

    let streamID: UInt32
    let flags: Flags
    let sequence: UInt32
    let fromPort: UInt32
    let toPort: UInt32
    let chunkIndex: UInt16
    let chunkCount: UInt16
    var chunk: Data
    var attached: Data

    static let headerLength = 23

    func serialize() -> Data {
        var w = I2PWriter()
        w.integer(streamID)
        w.byte(flags.rawValue)
        w.integer(sequence)
        w.integer(fromPort)
        w.integer(toPort)
        w.short(chunkIndex)
        w.short(chunkCount)
        w.short(UInt16(chunk.count))
        w.raw(chunk)
        w.raw(attached)
        return w.data
    }

    static func parse(_ data: Data) -> I2PSAMFrame? {
        let bytes = Array(data)
        guard bytes.count >= headerLength else { return nil }
        func u32(_ offset: Int) -> UInt32 {
            (UInt32(bytes[offset]) << 24) | (UInt32(bytes[offset + 1]) << 16)
                | (UInt32(bytes[offset + 2]) << 8) | UInt32(bytes[offset + 3])
        }
        func u16(_ offset: Int) -> UInt16 {
            (UInt16(bytes[offset]) << 8) | UInt16(bytes[offset + 1])
        }
        let chunkLength = Int(u16(21))
        guard bytes.count >= headerLength + chunkLength else { return nil }
        return I2PSAMFrame(
            streamID: u32(0),
            flags: Flags(rawValue: bytes[4]),
            sequence: u32(5),
            fromPort: u32(9),
            toPort: u32(13),
            chunkIndex: u16(17),
            chunkCount: u16(19),
            chunk: Data(bytes[headerLength..<(headerLength + chunkLength)]),
            attached: Data(bytes[(headerLength + chunkLength)...])
        )
    }
}

/// Splits outbound bytes into garlic-sized chunks.
enum I2PSAMChunker {
    /// The largest serialized frame that still rides one tunnel message: the
    /// tunnel's 1008-byte body minus the gateway/TunnelGateway I2NP headers,
    /// the garlic envelope (three-section new-session worst case) and its
    /// blocks. A frame that overflows the budget makes the tunnel layer reject
    /// the whole message, so chunking has to respect it.
    static let maxFrameBytes = 760

    /// Splits `data` into chunks that fit the frame budget. `attachmentLength`
    /// is the sender destination carried on the first chunk; it shrinks that
    /// chunk so the first frame stays inside the budget too.
    static func split(_ data: Data, attachmentLength: Int = 0,
                      size: Int = I2PSAMLimits.chunkSize) -> [Data] {
        let header = I2PSAMFrame.headerLength
        var firstBudget = min(size, maxFrameBytes - header - attachmentLength)
        let restBudget = min(size, maxFrameBytes - header)
        if firstBudget <= 0 { firstBudget = min(size, max(1, restBudget)) }
        guard !data.isEmpty else { return [Data()] }
        let bytes = Array(data)
        var out: [Data] = []
        var index = 0
        while index < bytes.count {
            let budget = out.isEmpty ? firstBudget : restBudget
            let end = min(index + budget, bytes.count)
            out.append(Data(bytes[index..<end]))
            index = end
        }
        return out
    }
}

// MARK: - Inbound reassembly

/// Reassembles chunked garlic frames and delivers completed messages.
/// Stream sessions deliver in sequence order; datagram sessions deliver on
/// completion (each datagram is independent).
final class I2PSAMInboundAssembler {
    struct Completed {
        let streamID: UInt32
        let sequence: UInt32
        let flags: I2PSAMFrame.Flags
        let data: Data
        let attached: Data?
    }

    private struct ChunkedMessage {
        var flags: I2PSAMFrame.Flags
        let chunkCount: UInt16
        var chunks: [Data?]
        var received = 0
        var attached: Data?
    }

    private let ordered: Bool
    private let lock = NSLock()
    private var messages: [UInt64: ChunkedMessage] = [:]
    private var nextSequence: [UInt32: UInt32] = [:]
    private var held: [UInt32: [UInt32: Completed]] = [:]
    var onCompleted: ((Completed) -> Void)?

    init(ordered: Bool) { self.ordered = ordered }

    func ingest(_ frame: I2PSAMFrame) {
        lock.lock()
        let key = (UInt64(frame.streamID) << 32) | UInt64(frame.sequence)
        var message = messages[key] ?? ChunkedMessage(
            flags: frame.flags,
            chunkCount: frame.chunkCount,
            chunks: .init(repeating: nil, count: Int(frame.chunkCount)),
            received: 0,
            attached: nil
        )
        let index = Int(frame.chunkIndex)
        guard index < message.chunks.count, message.chunks[index] == nil, message.received < Int(message.chunkCount) else {
            lock.unlock()
            return
        }
        message.chunks[index] = frame.chunk
        message.received += 1
        if frame.chunkIndex == 0 {
            message.flags = frame.flags
            message.attached = frame.attached.isEmpty ? nil : frame.attached
        }
        messages[key] = message
        var completed: Completed?
        if message.received == Int(message.chunkCount) {
            messages[key] = nil
            let data = message.chunks.compactMap { $0 }.reduce(Data(), +)
            completed = Completed(streamID: frame.streamID,
                                  sequence: frame.sequence,
                                  flags: message.flags,
                                  data: data,
                                  attached: message.attached)
        }
        pruneLocked()
        lock.unlock()
        if let completed { deliver(completed) }
    }

    private func deliver(_ completed: Completed) {
        guard ordered else { onCompleted?(completed); return }
        lock.lock()
        let streamID = completed.streamID
        let next = nextSequence[streamID] ?? 0
        guard completed.sequence >= next else {
            lock.unlock()
            return // stale duplicate
        }
        held[streamID, default: [:]][completed.sequence] = completed
        var ready: [Completed] = []
        var cursor = next
        while let item = held[streamID]?[cursor] {
            held[streamID]?[cursor] = nil
            ready.append(item)
            cursor += 1
        }
        nextSequence[streamID] = cursor
        if held[streamID]?.isEmpty == true { held[streamID] = nil }
        lock.unlock()
        ready.forEach { onCompleted?($0) }
    }

    /// Bounds memory: at most 128 pending chunked messages.
    private func pruneLocked() {
        guard messages.count > 128 else { return }
        let keys = messages.keys.sorted().prefix(messages.count - 128)
        keys.forEach { messages[$0] = nil }
    }
}

// MARK: - SAM session

/// One SAM session: a destination, its own tunnel pool, LeaseSet publication,
/// garlic sessions toward peers, and the stream/datagram state it serves.
final class I2PSAMSession {
    let nickname: String
    let style: I2PSAMStyle
    let keys: I2PSAMDestinationKeys
    let pool: I2PTunnelPool
    let transport: I2PSAMGarlicTransport
    let inboundManager: I2PGarlicInboundSessionManager
    let garlicHandler: I2PGarlicMessageHandler
    private let assembler: I2PSAMInboundAssembler
    private let lock = NSLock()
    private var garlicSessions: [Data: I2PGarlicSession] = [:]
    private(set) var leaseSet: I2PLeaseSet?
    private(set) var bytesTx = 0
    private(set) var bytesRx = 0
    /// Messages (not chunks) exchanged in each direction, split by style.
    private var streamsSent = 0
    private var streamsReceived = 0
    private var datagramsSent = 0
    private var datagramsReceived = 0
    /// When the client created the session (the detail screen's uptime).
    let createdAt: Date
    /// Cached at-cap verdict for the send log, refreshed at most once a second.
    private var lastCapCheck = Date.distantPast
    private var wasAtCap = false
    /// Connections waiting for an inbound stream (STREAM ACCEPT).
    var pendingAccept: I2PSAMConnection?
    /// One buffered inbound SYN for the accept-after-connect race.
    private var bufferedSyn: (frame: I2PSAMFrame, sender: I2PDestination)?
    private(set) var datagramStreamID: UInt32 = UInt32.random(in: 1...UInt32.max)
    weak var owner: I2PSAMConnection?
    var udpEndpoint: (host: String, port: UInt16)?
    private var udpSender: I2PSAMUDPDatagramSender?
    /// Track the latest peer destination's LeaseSet per reply path.
    private var replyLeases: [Data: I2PGarlicLease] = [:]

    // MARK: Encrypted (b33) LeaseSet2 publication

    /// When set, the session publishes its leases as a LeaseSet2 encrypted
    /// under its destination's blinded b33 key instead of a plain LeaseSet —
    /// no plain entry is stored under the destination hash.
    let publishesEncryptedLeaseSet: Bool
    /// Credentials the envelope is sealed to and the blinding reads: the
    /// destination's Ed25519 signing seed plus its ECIES X25519 private key.
    private let b33Credentials: I2PB33Credentials
    /// The blinded key set derived from the destination credentials
    /// (nil unless encrypted publication is enabled).
    private let blindedKeys: I2PB33Blinding.BlindedKey?
    /// The last published encrypted LeaseSet2 envelope.
    private(set) var encryptedLeaseSet: I2PLeaseSet2?
    /// Identifiers of the leases the published envelope carries, so a lease
    /// rotation can be detected and re-published.
    private var encryptedLeaseKeys: Set<String> = []
    /// When the encrypted entry was last published (re-publish cadence).
    private var lastEncryptedPublication = Date.distantPast

    /// The session's own b33 address to hand out (nil unless encrypted
    /// publication is enabled).
    var b33Address: String? { blindedKeys?.b33Address }

    /// The blinded netdb key the encrypted entry is stored under.
    var blindedNetDBKey: Data? { blindedKeys?.netDBKey }

    /// The b33 host this session publishes under, together with the
    /// destination credentials that unlock it (nil unless encrypted
    /// publication is enabled). Drives the b33 host book's resolvable rows.
    var b33Host: (address: String, credentials: I2PB33Credentials)? {
        guard let address = b33Address else { return nil }
        return (address, b33Credentials)
    }

    var destinationHash: Data { keys.destination.hash }
    var destinationBase64: String { keys.destination.raw.base64EncodedString() }

    /// The key this session's bandwidth ceiling is saved and measured under:
    /// the SAM session ID the client created it with.
    var bandwidthKey: String { nickname }

    init(nickname: String, style: I2PSAMStyle, keys: I2PSAMDestinationKeys,
         pool: I2PTunnelPool, transport: I2PSAMGarlicTransport,
         delivery: I2PDeliveryTransport, encryptedPublication: Bool = false,
         createdAt: Date = Date()) {
        self.nickname = nickname
        self.style = style
        self.keys = keys
        self.pool = pool
        self.transport = transport
        self.createdAt = createdAt
        self.publishesEncryptedLeaseSet = encryptedPublication
        self.b33Credentials = I2PB33Credentials(
            ed25519Seed: keys.signingSeed,
            x25519PrivateKey: keys.encryptionKey.rawRepresentation)
        self.blindedKeys = encryptedPublication
            ? try? I2PB33Blinding.blind(
                destinationSeed: keys.signingSeed,
                encryptionPublicKey: keys.encryptionKey.publicKey.rawRepresentation)
            : nil
        self.inboundManager = I2PGarlicInboundSessionManager(localKey: keys.encryptionKey)
        self.garlicHandler = I2PGarlicMessageHandler(sessionManager: inboundManager, deliveryTransport: delivery)
        self.assembler = I2PSAMInboundAssembler(ordered: style == .stream)
        garlicHandler.onError = { [weak self] line in self?.event(line) }
        garlicHandler.onMessage = { [weak self] line in self?.event(line) }
        assembler.onCompleted = { [weak self] completed in
            self?.routeInbound(completed)
        }
        garlicHandler.addLocalConsumer { [weak self] message, _ in
            guard let self, message.type == .dataMessage else { return }
            // The Data body is length-prefixed; a body whose length is wrong is
            // dropped rather than read as a frame.
            guard let body = try? I2NPDataMessage.parse(message.payload) else {
                self.event("inbound data body unparseable (\(message.payload.count)B)")
                return
            }
            guard let frame = I2PSAMFrame.parse(body) else {
                self.event("inbound frame unparseable (\(body.count)B)")
                return
            }
            self.assembler.ingest(frame)
        }
    }

    // MARK: Outbound

    func garlicSession(toward destination: I2PDestination) throws -> I2PGarlicSession {
        lock.lock()
        if let existing = garlicSessions[destination.hash] {
            lock.unlock()
            return existing
        }
        lock.unlock()
        let peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: destination.encryptionPublicKey)
        let session = I2PGarlicSession(peerPublicKey: peer, tagsPerHandshake: 16)
        lock.lock()
        garlicSessions[destination.hash] = session
        lock.unlock()
        return session
    }

    func send(_ frame: I2PSAMFrame, to lease: I2PGarlicLease, remote: I2PDestination) async throws {
        let payload = frame.serialize()
        // The session's own ceiling shapes every stream and datagram send that
        // leaves it, on top of the router-wide caps: one client cannot consume
        // the whole router cap.
        await I2PBandwidthGovernor.shared.admitSessionSend(bandwidthKey, bytes: payload.count)
        let message = I2NPMessage(type: .dataMessage,
                                  payload: I2NPDataMessage(payload: payload).serialize())
        let garlic = try garlicSession(toward: remote)
        try await transport.send(message, to: lease, garlicSession: garlic, pool: pool)
        lock.lock()
        bytesTx += frame.chunk.count
        if frame.flags.contains(.datagram), frame.chunkIndex == 0 {
            replyLeases[remote.hash] = lease
        }
        // Counters are per message, not per chunk: only the first chunk of a
        // message speaks for it.
        if frame.chunkIndex == 0 {
            if frame.flags.contains(.datagram) {
                datagramsSent += 1
            } else {
                streamsSent += 1
            }
        }
        lock.unlock()
        if frame.chunkIndex == 0 {
            noteSend(frame)
        }
    }

    /// One bridge log line per message sent, so the session's recent-activity
    /// list says what it did between its inbound frames.
    private func noteSend(_ frame: I2PSAMFrame) {
        var line: String
        if frame.flags.contains(.datagram) {
            line = "datagram \(frame.chunk.count)B"
        } else if frame.flags.contains(.syn) {
            line = "stream syn"
        } else if frame.flags.contains(.fin) {
            line = "stream fin"
        } else {
            line = "send \(frame.chunk.count)B"
        }
        let now = Date()
        lock.lock()
        let recheck = now.timeIntervalSince(lastCapCheck) >= 1
        var atCap = wasAtCap
        lock.unlock()
        if recheck {
            // The governor's reading walks its whole sample window, so a busy
            // session asks it once a second rather than once per message.
            let reading = I2PBandwidthGovernor.shared.sessionReading(bandwidthKey)
            atCap = reading.capBytesPerSecond > 0
                && reading.bytesPerSecond >= Double(reading.capBytesPerSecond) * 0.9
            lock.lock()
            lastCapCheck = now
            wasAtCap = atCap
            lock.unlock()
        }
        if atCap {
            line += " · at cap"
        }
        event(line)
    }

    // MARK: LeaseSet publication

    /// Lease lifetime the publication caps each entry at (10 minutes).
    private static let leaseWindow: TimeInterval = 600
    /// How long a published encrypted entry stands before it is re-published.
    private static let encryptedRepublishInterval: TimeInterval = 300

    /// The leases to publish: one per live inbound tunnel (its gateway hash
    /// plus the tunnel ID the gateway routes to), expiring with the tunnel or
    /// at most 10 minutes out.
    private func currentLeases(now: Date = Date()) -> [I2PLease] {
        pool.inboundTunnels
            .filter { !$0.isExpired() }
            .map { tunnel in
                I2PLease(gatewayHash: tunnel.hops[0].routerHash,
                         tunnelId: tunnel.gatewayTunnelID,
                         expiration: min(tunnel.expiresAt,
                                         now.addingTimeInterval(Self.leaseWindow)))
            }
    }

    /// Publishes the session's leases: a plain LeaseSet under the session's
    /// destination, or — when encrypted publication is enabled — a LeaseSet2
    /// envelope stored under the destination's blinded b33 netdb key.
    /// Renewal re-publishes on a cycle.
    @discardableResult
    func publishLeaseSet() async -> Bool {
        let now = Date()
        let leases = currentLeases(now: now)
        guard !leases.isEmpty else { return false }
        if publishesEncryptedLeaseSet {
            return await publishEncryptedLeaseSet(leases: leases, now: now)
        }
        var leaseSet = I2PLeaseSet(destination: keys.destination, published: now, leases: leases)
        do { try leaseSet.sign(withSeed: keys.signingSeed) } catch { return false }
        _ = await transport.core.netDB.publish(leaseSet: leaseSet)
        lock.lock()
        self.leaseSet = leaseSet
        lock.unlock()
        return true
    }

    /// Keeps the encrypted (b33) entry current: re-publishes it when the leases
    /// it carries have rotated (a tunnel expired or a new one joined) and on
    /// the re-publish cadence. A no-op for sessions publishing a plain
    /// LeaseSet.
    @discardableResult
    func refreshEncryptedPublication(now: Date = Date()) async -> Bool {
        guard publishesEncryptedLeaseSet else { return false }
        let leases = currentLeases(now: now)
        guard !leases.isEmpty else { return false }
        let identifiers = leaseIdentifiers(leases)
        lock.lock()
        let published = encryptedLeaseKeys
        let lastPublished = lastEncryptedPublication
        lock.unlock()
        let rotated = !published.isEmpty && identifiers != published
        let due = published.isEmpty
            || now.timeIntervalSince(lastPublished) >= Self.encryptedRepublishInterval
        guard rotated || due else { return false }
        return await publishEncryptedLeaseSet(leases: leases, now: now)
    }

    /// Builds the encrypted LeaseSet2 for the given leases and stores it to the
    /// floodfills under the destination's blinded netdb key: the inner plain
    /// LeaseSet2 is sealed to the destination's ECIES key, the envelope carries
    /// the blinded signing key (its hash is the blinded netdb key) and is signed
    /// by the blinded private key derived from the destination credentials.
    @discardableResult
    func publishEncryptedLeaseSet(leases: [I2PLease], now: Date = Date()) async -> Bool {
        guard publishesEncryptedLeaseSet, blindedKeys != nil, !leases.isEmpty else { return false }
        do {
            let inner = try I2PLeaseSet2.build(
                storeType: .plain,
                destination: keys.destination,
                published: now,
                expiresOffsetSeconds: UInt16(Self.leaseWindow),
                leases: leases.map {
                    I2PLease2(gatewayHash: $0.gatewayHash, tunnelId: $0.tunnelId,
                              expiration: $0.expiration)
                },
                signingSeed: keys.signingSeed)
            let envelope = try I2PB33Blinding.buildEncryptedLeaseSet2(
                inner: inner, credentials: b33Credentials)
            _ = await transport.core.netDB.publish(leaseSet2: envelope)
            lock.lock()
            encryptedLeaseSet = envelope
            encryptedLeaseKeys = leaseIdentifiers(leases)
            lastEncryptedPublication = now
            lock.unlock()
            return true
        } catch {
            return false
        }
    }

    private func leaseIdentifiers(_ leases: [I2PLease]) -> Set<String> {
        Set(leases.map { "\($0.tunnelId):\($0.gatewayHash.hex)" })
    }

    // MARK: Inbound

    /// Parses the sender destination attached to a SYN/DATAGRAM chunk 0.
    private static func destination(fromAttached attached: Data?) -> I2PDestination? {
        guard let attached, !attached.isEmpty else { return nil }
        var reader = I2PReader(attached)
        return try? I2PKeysAndCert.parse(&reader)
    }

    /// Optional operational log hook (the SAM bridge's activity log), so a
    /// stalled inbound frame says which stage it reached.
    var onEvent: ((String) -> Void)?

    private func event(_ line: String) {
        onEvent?(line)
    }

    private func routeInbound(_ completed: I2PSAMInboundAssembler.Completed) {
        lock.lock()
        bytesRx += completed.data.count
        if completed.flags.contains(.datagram) {
            datagramsReceived += 1
        } else {
            streamsReceived += 1
        }
        let owner = self.owner
        lock.unlock()
        event("inbound frame: \(completed.data.count)B flags=\(completed.flags.rawValue) stream=\(completed.streamID)")
        guard let owner else { return }
        if completed.flags.contains(.datagram) {
            let sender = Self.destination(fromAttached: completed.attached)
            owner.deliverDatagram(sender: sender, payload: completed.data)
        } else {
            let sender = Self.destination(fromAttached: completed.attached)
            owner.handleStreamMessage(streamID: completed.streamID,
                                      sequence: completed.sequence,
                                      flags: completed.flags,
                                      sender: sender,
                                      data: completed.data)
        }
    }

    /// A remote SYN arrived with no pending ACCEPT: buffer it so a later
    /// ACCEPT on this session completes immediately.
    func bufferSyn(frame: I2PSAMFrame, sender: I2PDestination) {
        lock.lock()
        bufferedSyn = (frame, sender)
        lock.unlock()
    }

    func takeBufferedSyn() -> (frame: I2PSAMFrame, sender: I2PDestination)? {
        lock.lock()
        defer { lock.unlock() }
        return bufferedSyn
    }

    func shutdown() {
        pool.stop()
        udpSender?.shutdown()
        // Frees the bucket; the ceiling itself stays saved under the session key.
        I2PBandwidthGovernor.shared.forgetSession(bandwidthKey)
    }

    /// Lazily creates the UDP delivery socket and sends a datagram to the
    /// client's announced endpoint (SAM v3 datagram replies).
    func enqueueUDPDelivery(_ data: Data) {
        lock.lock()
        if udpSender == nil, let endpoint = udpEndpoint {
            udpSender = I2PSAMUDPDatagramSender(host: endpoint.host, port: endpoint.port)
        }
        let sender = udpSender
        lock.unlock()
        sender?.send(data)
    }

    func summary() -> I2PSAMSessionSummary {
        lock.lock()
        let tx = bytesTx
        let rx = bytesRx
        let published = leaseSet != nil || encryptedLeaseSet != nil
        lock.unlock()
        let bandwidth = I2PBandwidthGovernor.shared.sessionReading(bandwidthKey)
        return I2PSAMSessionSummary(
            nickname: nickname,
            style: style.rawValue,
            destinationHash: destinationHash.hex.prefix(12).description,
            tunnelsOut: pool.activeCount(.outbound),
            tunnelsIn: pool.activeCount(.inbound),
            published: published,
            bytesTx: tx,
            bytesRx: rx,
            sendBytesPerSecond: bandwidth.bytesPerSecond,
            capBytesPerSecond: bandwidth.capBytesPerSecond
        )
    }

    /// Everything the session detail screen reads: the destination, the tunnel
    /// pool per direction with each live tunnel's remaining lifetime, the
    /// stream/datagram counters, the live send rate against the saved cap, and
    /// the bridge log lines that belong to this session (supplied by the
    /// bridge, which owns the log).
    func detail(logLines: [String] = []) -> I2PSAMSessionDetail {
        let outbound = pool.outboundTunnels
            .sorted { $0.expiresAt < $1.expiresAt }
            .map { tunnel in
                I2PSAMTunnelReading(gatewayTunnelID: tunnel.gatewayTunnelID,
                                    hopCount: tunnel.hopCount,
                                    remainingLifetime: tunnel.remainingLifetime())
            }
        let inbound = pool.inboundTunnels
            .sorted { $0.expiresAt < $1.expiresAt }
            .map { tunnel in
                I2PSAMTunnelReading(gatewayTunnelID: tunnel.gatewayTunnelID,
                                    hopCount: tunnel.hopCount,
                                    remainingLifetime: tunnel.remainingLifetime())
            }
        lock.lock()
        let streams = (sent: streamsSent, received: streamsReceived)
        let datagrams = (sent: datagramsSent, received: datagramsReceived)
        let tx = bytesTx
        let rx = bytesRx
        let published = leaseSet != nil || encryptedLeaseSet != nil
        lock.unlock()
        let bandwidth = I2PBandwidthGovernor.shared.sessionReading(bandwidthKey)
        return I2PSAMSessionDetail(
            nickname: nickname,
            style: style.rawValue,
            createdAt: createdAt,
            destinationHashHex: destinationHash.hex,
            destinationBase64: destinationBase64,
            b33Address: b33Address,
            leasePublished: published,
            tunnelsOut: outbound,
            tunnelsOutTarget: pool.targetCount(.outbound),
            tunnelsIn: inbound,
            tunnelsInTarget: pool.targetCount(.inbound),
            streamsSent: streams.sent,
            streamsReceived: streams.received,
            datagramsSent: datagrams.sent,
            datagramsReceived: datagrams.received,
            bytesTx: tx,
            bytesRx: rx,
            sendBytesPerSecond: bandwidth.bytesPerSecond,
            capBytesPerSecond: bandwidth.capBytesPerSecond,
            logLines: logLines
        )
    }
}

/// View-facing session summary.
struct I2PSAMSessionSummary {
    let nickname: String
    let style: String
    let destinationHash: String
    let tunnelsOut: Int
    let tunnelsIn: Int
    let published: Bool
    let bytesTx: Int
    let bytesRx: Int
    /// The session's measured send rate over the last minute.
    let sendBytesPerSecond: Double
    /// The per-session cap it is held to; 0 means uncapped.
    let capBytesPerSecond: Int
}

/// One live tunnel of a session's pool, as the detail screen's countdowns see
/// it.
struct I2PSAMTunnelReading: Identifiable {
    /// The gateway's receive tunnel ID, unique within the pool.
    var id: UInt32 { gatewayTunnelID }
    let gatewayTunnelID: UInt32
    let hopCount: Int
    let remainingLifetime: TimeInterval
}

/// The live reading behind the SAM session detail screen.
struct I2PSAMSessionDetail {
    let nickname: String
    let style: String
    let createdAt: Date
    /// The full destination hash in hex; the screen shows its prefix.
    let destinationHashHex: String
    /// The full destination, as the copy button hands it out.
    let destinationBase64: String
    /// The session's b33 host when it publishes an encrypted LeaseSet.
    let b33Address: String?
    let leasePublished: Bool
    /// Live tunnels per direction, soonest expiry first.
    let tunnelsOut: [I2PSAMTunnelReading]
    let tunnelsOutTarget: Int
    let tunnelsIn: [I2PSAMTunnelReading]
    let tunnelsInTarget: Int
    let streamsSent: Int
    let streamsReceived: Int
    let datagramsSent: Int
    let datagramsReceived: Int
    let bytesTx: Int
    let bytesRx: Int
    let sendBytesPerSecond: Double
    let capBytesPerSecond: Int
    /// The bridge log lines that belong to this session, oldest first.
    let logLines: [String]
}
// MARK: - Session key persistence

/// Optional session persistence (PERSISTENT=true): destination private keys
/// are saved under the session nickname so a re-created session restores the
/// same destination across bridge restarts.
final class I2PSAMKeyStore {
    private let directory: URL
    private let lock = NSLock()

    init(directory: URL = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)
        .first!.appendingPathComponent("i2p-sam-keys", isDirectory: true)) {
        self.directory = directory
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    /// Filenames are keyed on the nickname's SHA-256 so any nickname string
    /// maps to exactly one file.
    private func file(for nickname: String) -> URL {
        directory.appendingPathComponent(I2PCrypto.sha256(Data(nickname.utf8)).hex + ".key")
    }

    func load(nickname: String) -> Data? {
        lock.lock(); defer { lock.unlock() }
        guard let raw = try? Data(contentsOf: file(for: nickname)),
              let decoded = I2PSAMEncoding.normalizedBase64(String(decoding: raw, as: UTF8.self)) else {
            return nil
        }
        return decoded
    }

    func save(nickname: String, privateKey: Data) {
        lock.lock(); defer { lock.unlock() }
        try? privateKey.base64EncodedString().write(to: file(for: nickname),
                                                    atomically: true, encoding: .utf8)
    }

    func remove(nickname: String) {
        lock.lock(); defer { lock.unlock() }
        try? FileManager.default.removeItem(at: file(for: nickname))
    }
}