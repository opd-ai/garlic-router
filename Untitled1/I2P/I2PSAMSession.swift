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
    static func split(_ data: Data, size: Int = I2PSAMLimits.chunkSize) -> [Data] {
        guard !data.isEmpty else { return [Data()] }
        let bytes = Array(data)
        var out: [Data] = []
        var index = 0
        while index < bytes.count {
            let end = min(index + size, bytes.count)
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

    var destinationHash: Data { keys.destination.hash }
    var destinationBase64: String { keys.destination.raw.base64EncodedString() }

    init(nickname: String, style: I2PSAMStyle, keys: I2PSAMDestinationKeys,
         pool: I2PTunnelPool, transport: I2PSAMGarlicTransport, delivery: I2PDeliveryTransport) {
        self.nickname = nickname
        self.style = style
        self.keys = keys
        self.pool = pool
        self.transport = transport
        self.inboundManager = I2PGarlicInboundSessionManager(localKey: keys.encryptionKey)
        self.garlicHandler = I2PGarlicMessageHandler(sessionManager: inboundManager, deliveryTransport: delivery)
        self.assembler = I2PSAMInboundAssembler(ordered: style == .stream)
        assembler.onCompleted = { [weak self] completed in
            self?.routeInbound(completed)
        }
        garlicHandler.addLocalConsumer { [weak self] message, _ in
            guard let self, message.type == .dataMessage, let frame = I2PSAMFrame.parse(message.payload) else { return }
            assembler.ingest(frame)
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
        let message = I2NPMessage(type: .dataMessage, payload: frame.serialize())
        let garlic = try garlicSession(toward: remote)
        try await transport.send(message, to: lease, garlicSession: garlic, pool: pool)
        lock.lock()
        bytesTx += frame.chunk.count
        if frame.flags.contains(.datagram), frame.chunkIndex == 0 {
            replyLeases[remote.hash] = lease
        }
        lock.unlock()
    }

    // MARK: LeaseSet publication

    /// Publishes a LeaseSet under the session's destination (leases point at
    /// this router's inbound tunnels). Renewal re-publishes on a cycle.
    @discardableResult
    func publishLeaseSet() async -> Bool {
        let inbound = pool.inboundTunnels.filter { !$0.isExpired() }
        guard !inbound.isEmpty else { return false }
        let now = Date()
        let leases = inbound.map { tunnel in
            I2PLease(gatewayHash: tunnel.hops[0].routerHash,
                     tunnelId: tunnel.gatewayTunnelID,
                     expiration: min(tunnel.expiresAt, now.addingTimeInterval(600)))
        }
        var leaseSet = I2PLeaseSet(destination: keys.destination, published: now, leases: leases)
        do { try leaseSet.sign(withSeed: keys.signingSeed) } catch { return false }
        _ = await transport.core.netDB.publish(leaseSet: leaseSet)
        lock.lock()
        self.leaseSet = leaseSet
        lock.unlock()
        return true
    }

    // MARK: Inbound

    /// Parses the sender destination attached to a SYN/DATAGRAM chunk 0.
    private static func destination(fromAttached attached: Data?) -> I2PDestination? {
        guard let attached, !attached.isEmpty else { return nil }
        var reader = I2PReader(attached)
        return try? I2PKeysAndCert.parse(&reader)
    }

    private func routeInbound(_ completed: I2PSAMInboundAssembler.Completed) {
        lock.lock()
        bytesRx += completed.data.count
        let owner = self.owner
        lock.unlock()
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
        let published = leaseSet != nil
        lock.unlock()
        return I2PSAMSessionSummary(
            nickname: nickname,
            style: style.rawValue,
            destinationHash: destinationHash.hex.prefix(12).description,
            tunnelsOut: pool.activeCount(.outbound),
            tunnelsIn: pool.activeCount(.inbound),
            published: published,
            bytesTx: tx,
            bytesRx: rx
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