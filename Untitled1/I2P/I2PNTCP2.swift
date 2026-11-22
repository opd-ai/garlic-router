//
//  I2PNTCP2.swift
//  I2P
//
//  NTCP2 TCP transport built on the Network framework: session state machine,
//  graceful termination, and a connection manager supporting a listener plus
//  multiple concurrent peer sessions.
//

import Foundation
import Network
import CryptoKit

protocol NTCP2SessionDelegate: AnyObject {
    func session(_ session: NTCP2Session, didEstablishWith remoteRouterHash: Data?, remoteRouterInfo: I2PRouterInfo?)
    func session(_ session: NTCP2Session, didReceiveData data: Data)
    func session(_ session: NTCP2Session, didClose error: Error?)
}

/// One NTCP2 TCP connection: runs the Noise_XK handshake, then the data phase
/// with SipHash-obfuscated framed ChaChaPoly blocks.
final class NTCP2Session: NSObject {
    enum Role { case initiator, responder }
    enum State { case handshaking, established, closing, closed }

    private(set) var state: State = .handshaking
    private(set) var remoteRouterHash: Data?
    private(set) var remoteRouterInfo: I2PRouterInfo?

    weak var delegate: NTCP2SessionDelegate?

    private let connection: NWConnection
    private let role: Role
    private let localStaticKey: Curve25519.KeyAgreement.PrivateKey
    /// Canonical RFC 7748 wire form of `localStaticKey`'s public key. It must
    /// be the exact byte string published as the RouterAddress "s" option:
    /// responders compare the two and drop the session on any mismatch.
    private let localStaticPublicKey: Data
    private let localRouterInfoData: Data
    private let localRouterHash: Data
    private let localIV: Data?
    private let remoteStaticKey: Data?
    private let expectedRemoteRouterHash: Data?
    private let expectedRemoteIV: Data?
    private let queue: DispatchQueue

    /// Marks a network queue of ours, so `onQueue` can tell whether it is
    /// already running on one and must not `sync` onto it again (which would
    /// deadlock).
    private static let queueKey = DispatchSpecificKey<Bool>()

    /// Runs `body` on the session's queue.
    ///
    /// The receive path, the state handler and the handshake timers all mutate
    /// `state`, the frame codecs and the receive buffer on that queue. Callers
    /// on other threads — a probe closing a session, the transport's maintenance,
    /// a router delivery sending a message — must not touch the same state
    /// directly: ThreadSanitizer caught `close(reason:)` racing the receive
    /// path's frame codec on 2026-11-18. Inline when already on the queue,
    /// `sync` otherwise, so reads stay synchronous and `send`/`close` keep their
    /// meaning.
    private func onQueue<T>(_ body: () throws -> T) rethrows -> T {
        if DispatchQueue.getSpecific(key: Self.queueKey) != nil {
            return try body()
        }
        return try queue.sync(execute: body)
    }

    private var initiator: NTCP2InitiatorHandshake?
    private var responder: NTCP2ResponderHandshake?
    private var sendCodec: NTCP2FrameCodec?
    private var recvCodec: NTCP2FrameCodec?
    private var rxBuffer = Data()
    private var didNotifyEstablished = false
    // Per-peer session readings for the peer inspector.
    private(set) var establishedAt: Date?
    private(set) var bytesIn = 0
    private(set) var bytesOut = 0
    /// Why this session ended, for the transport's diagnostics.
    private(set) var closeReason: String?
    private var terminationReason: UInt8?
    /// Raw TCP byte counts for the handshake phase. Peers that reject a
    /// handshake close without a Termination block, so the only evidence of how
    /// far the exchange got is how much was written and read before the EOF.
    private var handshakeBytesIn = 0
    private var handshakeBytesOut = 0
    private var sessionCreatedReceived = false

    // MARK: - Idle/keepalive bookkeeping (NTCP2 §Data Phase)

    /// How long a session may stay silent before this router sends a keepalive
    /// frame. Reference routers expire an idle connection with a Termination
    /// block (reason 2) once *their* budget runs out, and Java I2P's budget is
    /// adaptive — it can shrink to about two minutes under connection pressure —
    /// so waiting for the nominal ~11 minute ceiling gets the session killed by
    /// the peer first. A minute of silence is well under any implementation's
    /// minimum budget and costs one small frame.
    static let keepaliveQuietInterval: TimeInterval = 60

    /// The last time this session sent or received anything.
    private var lastActivity = Date()
    /// The last time this session **sent** something. The peer's idle timer runs
    /// on bytes it *receives*, so a session that only hears from the peer still
    /// has to send its own keepalive — counting received traffic as activity
    /// leaves both sides waiting on each other until the peer expires us.
    private var lastSent = Date()
    /// Pending keepalive timer.
    private var keepaliveTask: Task<Void, Never>?

    /// Stops the keepalive timer (handshake failure, termination, close).
    private func stopKeepalive() {
        keepaliveTask?.cancel()
        keepaliveTask = nil
    }

    /// Arms a repeating timer that sends a datetime-block keepalive frame
    /// whenever this session has not *sent* anything for
    /// `keepaliveQuietInterval`. Received traffic does not postpone it: the
    /// peer's idle clock counts the bytes it receives from us, so only our own
    /// sends keep the session alive in its view.
    private func armKeepalive() {
        stopKeepalive()
        keepaliveTask = Task { [weak self] in
            while let self, !Task.isCancelled {
                let quiet = Date().timeIntervalSince(self.lastSent)
                let next = max(Self.keepaliveQuietInterval - quiet, 5)
                try? await Task.sleep(for: .seconds(next))
                guard !Task.isCancelled, self.state == .established else { break }
                guard Date().timeIntervalSince(self.lastSent) >= Self.keepaliveQuietInterval - 5 else {
                    continue
                }
                self.sendKeepalive()
            }
        }
    }

    /// Sends a data-phase frame carrying only the datetime block: the spec's
    /// time-sync block is exactly what reference routers exchange when they
    /// have nothing else to send (Java I2P's NTCP2Payload.DateTimeBlock), and it
    /// is what keeps a quiet session from being expired by the peer.
    private func sendKeepalive() {
        guard state == .established, let codec = sendCodec else { return }
        do {
            var payload = try NTCP2Block.encode(NTCP2Block.keepalive(at: Date()))
            payload = NTCP2Block.aligned(payload)
            let frame = try codec.frame(payload)
            lastSent = Date()
            lastActivity = Date()
            connection.send(content: frame, completion: .contentProcessed { [weak self] error in
                if let error {
                    // The keepalive failing is a transport failure like any
                    // other: close with its cause instead of timing out blind.
                    self?.finish(error: error)
                }
            })
        } catch {
            finish(error: error)
        }
    }

    var isEstablished: Bool { onQueue { state == .established } }

    init(role: Role,
         connection: NWConnection,
         localStaticKey: Curve25519.KeyAgreement.PrivateKey,
         localStaticPublicKey: Data,
         localRouterInfoData: Data,
         localRouterHash: Data,
         localIV: Data?,
         remoteStaticKey: Data?,
         remoteRouterHash: Data?,
         remoteIV: Data?,
         queue: DispatchQueue) {
        self.connection = connection
        self.role = role
        self.localStaticKey = localStaticKey
        self.localStaticPublicKey = localStaticPublicKey
        self.localRouterInfoData = localRouterInfoData
        self.localRouterHash = localRouterHash
        self.localIV = localIV
        self.remoteStaticKey = remoteStaticKey
        self.expectedRemoteRouterHash = remoteRouterHash
        self.expectedRemoteIV = remoteIV
        // The initiator knows the peer it dialed before any handshake byte:
        // naming it in a session ending (rather than "unknown") is what the
        // live audit's session-endings line reads.
        if role == .initiator { self.remoteRouterHash = remoteRouterHash }
        self.queue = queue
        queue.setSpecific(key: Self.queueKey, value: true)
    }

    func start() {
        connection.stateUpdateHandler = { [weak self] newState in
            guard let self else { return }
            switch newState {
            case .ready:
                self.beginHandshakeIfNeeded()
                self.receiveNext()
            case .waiting(let pending):
                // Network framework retries a waiting connection on its own;
                // record why it is stalled (no route, DNS, policy) so a probe
                // run can report the reason rather than a bare timeout.
                I2PSecurityAuditLog.append(category: "transport",
                                           detail: "ntcp2 \(self.role) connection waiting: \(pending)")
            case .failed(let connectionError):
                self.finish(error: connectionError)
            case .cancelled:
                self.finish(error: nil)
            default:
                break
            }
        }
        connection.start(queue: queue)
        // A dead endpoint must not hold a session slot for the whole handshake
        // budget: bound the *connect* phase here, and start the handshake clock
        // only when message 1 actually goes out (see beginHandshakeIfNeeded).
        // Peers that accept TCP and then never answer look identical to dead
        // addresses otherwise, and a rota of candidates stalls behind them.
        queue.asyncAfter(deadline: .now() + 8) { [weak self] in
            guard let self, self.state == .handshaking else { return }
            if self.role == .initiator, self.initiator == nil {
                self.finish(error: NTCP2Error.handshakeFailed("peer did not accept the TCP connection within 8s"))
            }
        }
        // A responder session is bounded from accept: the initiator must send
        // message 1 promptly, so a silent socket is dropped there too.
        queue.asyncAfter(deadline: .now() + 20) { [weak self] in
            guard let self, self.role == .responder, self.state == .handshaking else { return }
            self.finish(error: NTCP2Error.handshakeFailed("handshake did not complete within 20s"))
        }
    }

    // MARK: - Handshake

    private func beginHandshakeIfNeeded() {
        guard role == .initiator, initiator == nil else { return }
        guard let remoteStaticKey else {
            finish(error: NTCP2Error.handshakeFailed("initiator without remote static key"))
            return
        }
        guard let remoteRouterHash = expectedRemoteRouterHash, let remoteIV = expectedRemoteIV else {
            finish(error: NTCP2Error.handshakeFailed("peer RouterInfo publishes no NTCP2 'i' obfuscation IV"))
            return
        }
        do {
            let engine = try NTCP2InitiatorHandshake(localStaticKey: localStaticKey,
                                                     localStaticPublicKey: localStaticPublicKey,
                                                     remoteStaticKey: remoteStaticKey,
                                                     remoteRouterHash: remoteRouterHash,
                                                     remoteIV: remoteIV)
            initiator = engine
            let request = try engine.makeSessionRequest(routerInfo: localRouterInfoData)
            sendRaw(request)
            // Message 1 is out: the handshake clock starts here, so the budget
            // measures the peer's SessionCreated rather than our TCP connect.
            queue.asyncAfter(deadline: .now() + 20) { [weak self] in
                guard let self, self.state == .handshaking else { return }
                self.finish(error: NTCP2Error.handshakeFailed("handshake did not complete within 20s"))
            }
        } catch {
            finish(error: error)
        }
    }

    /// Returns true when a handshake step progressed; false when waiting for data.
    private func performHandshakeStep() throws -> Bool {
        switch role {
        case .initiator:
            guard let engine = initiator else {
                throw NTCP2Error.handshakeFailed("missing initiator engine")
            }
            let result = try engine.processSessionCreated(rxBuffer)
            rxBuffer = Data(rxBuffer.dropFirst(result.consumed))
            sessionCreatedReceived = true
            sendRaw(result.message)
            try establish(asInitiator: true)
            return true

        case .responder:
            if responder == nil {
                guard let localIV else {
                    throw NTCP2Error.handshakeFailed("this router publishes no NTCP2 'i' option — peers cannot obfuscate their ephemeral key")
                }
                responder = try NTCP2ResponderHandshake(localStaticKey: localStaticKey,
                                                       localStaticPublicKey: localStaticPublicKey,
                                                       localRouterHash: localRouterHash,
                                                       localIV: localIV)
            }
            guard let engine = responder else { return false }
            switch engine.stage {
            case .awaitingRequest:
                let result = try engine.processSessionRequest(rxBuffer)
                rxBuffer = Data(rxBuffer.dropFirst(result.consumed))
                sendRaw(result.reply)
                return true
            case .awaitingConfirm:
                let consumed = try engine.processSessionConfirm(rxBuffer)
                rxBuffer = Data(rxBuffer.dropFirst(consumed))
                try establish(asInitiator: false)
                return true
            case .established:
                return false
            }
        }
    }

    private func establish(asInitiator: Bool) throws {
        let keys: NTCP2SessionKeys
        if asInitiator {
            keys = try initiator!.complete()
        } else {
            keys = try responder!.complete()
        }
        sendCodec = NTCP2FrameCodec(directionKeys: keys.sendKeys)
        recvCodec = NTCP2FrameCodec(directionKeys: keys.recvKeys)
        state = .established
        if establishedAt == nil { establishedAt = Date() }
        // Start the idle/keepalive clock now, from the handshake's last
        // exchange: reference routers count idle time the same way.
        lastActivity = Date()
        armKeepalive()

        if asInitiator {
            // The peer's router hash is known from the RouterInfo we dialed
            // from. Bob's RouterInfo block in the data phase is optional per
            // spec, so the session must be registered under the expected hash
            // now rather than waiting for a block that may never arrive.
            if remoteRouterHash == nil { remoteRouterHash = expectedRemoteRouterHash }
            notifyEstablishedIfNeeded()
        } else {            // Responder announces its RouterInfo in the first data-phase frame.
            var payload = try NTCP2Block.encode([.routerInfo(localRouterInfoData), .time(Date())])
            payload = NTCP2Block.aligned(payload)
            if let codec = sendCodec {
                sendRaw(try codec.frame(payload))
            }
            if let remoteData = responder?.remoteRouterInfo,
               let parsed = try? I2PRouterInfo.parse(remoteData) {
                remoteRouterInfo = parsed
                remoteRouterHash = parsed.identity.hash
            }
            notifyEstablishedIfNeeded()
        }
    }

    private func notifyEstablishedIfNeeded() {
        guard !didNotifyEstablished else { return }
        didNotifyEstablished = true
        delegate?.session(self, didEstablishWith: remoteRouterHash, remoteRouterInfo: remoteRouterInfo)
    }

    // MARK: - Receive path

    private func receiveNext() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                if self.state == .handshaking { self.handshakeBytesIn += data.count }
                self.rxBuffer += data
                // Any inbound bytes feed the idle timer, exactly as they do for
                // reference routers' connections.
                self.lastActivity = Date()
                self.drainBuffer()
            }
            if isComplete || error != nil {
                self.finish(error: error)
                return
            }
            if self.state == .handshaking || self.state == .established {
                self.receiveNext()
            }
        }
    }

    private func drainBuffer() {
        while state == .handshaking || state == .established {
            if state == .handshaking {
                do {
                    let progressed = try performHandshakeStep()
                    if !progressed { break }
                } catch NTCP2Error.needMoreData {
                    break
                } catch {
                    finish(error: error)
                    return
                }
            } else {
                guard let codec = recvCodec else {
                    finish(error: NTCP2Error.notEstablished)
                    return
                }
                do {
                    guard let result = try codec.unframe(rxBuffer) else { break }
                    rxBuffer = Data(rxBuffer.dropFirst(result.consumed))
                    handlePayload(result.payload)
                } catch {
                    finish(error: error)
                    return
                }
            }
        }
    }

    private func handlePayload(_ payload: Data) {
        guard let blocks = try? NTCP2Block.decode(payload) else {
            finish(error: NTCP2Error.invalidBlock)
            return
        }
        for block in blocks {
            switch block {
            case .padding, .options, .time:
                // A datetime block is the keepalive reference routers send
                // when they have nothing else to say (their own traffic shape
                // across idle windows); the receive hook above already fed
                // the idle timer with the frame's bytes.
                break
            case .routerInfo(let data):
                if let parsed = try? I2PRouterInfo.parse(data) {
                    // An established session may refresh the peer's RouterInfo,
                    // but its identity cannot change mid-session.
                    if let known = remoteRouterHash, known != parsed.identity.hash {
                        finish(error: NTCP2Error.handshakeFailed("peer RouterInfo identity changed mid-session"))
                        return
                    }
                    remoteRouterInfo = parsed
                    remoteRouterHash = parsed.identity.hash
                    notifyEstablishedIfNeeded()
                } else {
                    finish(error: NTCP2Error.handshakeFailed("invalid remote RouterInfo"))
                    return
                }
            case .data(let data):
                // Mainnet framing: one short-header I2NP message per data block.
                // Non-I2NP raw payloads (loopback/test traffic) pass through.
                bytesIn += data.count
                if I2NPMessage.looksLikeShortHeaderMessage(data),
                   let message = try? I2NPMessage.parseShort(data) {
                    delegate?.session(self, didReceiveData: message.serialize())
                } else {
                    delegate?.session(self, didReceiveData: data)
                }
            case .termination(let reason, let frames):
                // Graceful close requested by the peer; the reason code says
                // which check this router failed on the peer's side.
                terminationReason = reason
                I2PSecurityAuditLog.append(category: "transport",
                                           detail: "ntcp2 \(role) peer sent termination reason \(reason) (\(NTCP2TerminationReason(rawValue: reason).map(String.init(describing:)) ?? "unknown")) after \(frames) valid frame(s)")
                finish(error: nil)
                return
            }
        }
    }

    // MARK: - Send / close

    func send(_ data: Data) throws {
        try onQueue { try sendOnQueue(data) }
    }

    private func sendOnQueue(_ data: Data) throws {
        guard state == .established, let codec = sendCodec else {
            throw NTCP2Error.notEstablished
        }
        // Data blocks carry exactly one I2NP message in the 5-byte short tunnel
        // header (mainnet NTCP2 framing). Full internal (17-byte-header) messages
        // are re-framed to the short header; anything that is not a parsable
        // I2NP message (test/loopback payloads) rides the block ungated.
        let shortMessage: Data
        if let message = try? I2NPMessage.parse(data) {
            shortMessage = message.serializeShort()
        } else {
            shortMessage = data
        }
        guard shortMessage.count <= 65519 else {
            throw NTCP2Error.notEstablished
        }
        bytesOut += shortMessage.count
        lastActivity = Date()
        var payload = try NTCP2Block.encode([.data(shortMessage), .time(Date())])
        payload = NTCP2Block.aligned(payload)
        sendRaw(try codec.frame(payload))
    }

    private func sendRaw(_ data: Data) {
        if state == .handshaking { handshakeBytesOut += data.count }
        lastSent = Date()
        connection.send(content: data, completion: .contentProcessed { [weak self] error in
            if let error { self?.finish(error: error) }
        })
    }

    /// Graceful termination: a termination block, then TCP close.
    func close(reason: UInt8 = 0) {
        onQueue { closeOnQueue(reason: reason) }
    }

    private func closeOnQueue(reason: UInt8) {
        guard state == .established, let codec = sendCodec else {
            connection.cancel()
            return
        }
        state = .closing
        let payload = (try? NTCP2Block.encode([.termination(reason: reason,
                                                            validFrames: recvCodec?.counter ?? 0)])) ?? Data()
        let frame = (try? codec.frame(NTCP2Block.aligned(payload))) ?? Data()
        connection.send(content: frame, completion: .contentProcessed { [weak self] _ in
            self?.connection.cancel()
        })
        // Safety net: always tear the socket down shortly after.
        queue.asyncAfter(deadline: .now() + 2.0) { [weak self] in
            self?.connection.cancel()
        }
    }

    /// Immediate teardown without the termination exchange.
    func abort() {
        onQueue { connection.cancel() }
    }

    private func finish(error: Error?) {
        guard state != .closed else { return }
        stopKeepalive()
        let wasHandshaking = state == .handshaking
        state = .closed
        connection.cancel()
        if let error {
            closeReason = "\(error)"
            // Peer-session failures are the interesting part of a transport
            // audit: record the reason (and the traffic that preceded it) so a
            // failed handshake can be diagnosed rather than merely counted.
            I2PSecurityAuditLog.append(category: "transport",
                                       detail: "ntcp2 \(role) session closed: \(error) after \(bytesIn) bytes in / \(bytesOut) bytes out")
        } else if wasHandshaking {
            // A peer that rejects our handshake closes without a Termination
            // block, so name the phase it died in from the traffic exchanged:
            // nothing sent/received is a connect-level failure, no
            // SessionCreated means message 1 was refused, and a close after
            // message 3 means the peer rejected our RouterInfo or key.
            let phase: String
            switch role {
            case .initiator:
                if sessionCreatedReceived {
                    phase = "after SessionConfirmed"
                } else if handshakeBytesOut > 0 {
                    phase = "after SessionRequest (no SessionCreated)"
                } else {
                    phase = "before SessionRequest"
                }
            case .responder:
                if responder?.stage == .awaitingConfirm {
                    phase = "after SessionCreated (no SessionConfirmed)"
                } else if responder?.stage == .established {
                    phase = "after SessionConfirmed"
                } else {
                    phase = "before SessionRequest"
                }
            }
            closeReason = "peer closed during the handshake \(phase) — \(handshakeBytesOut) B sent, \(handshakeBytesIn) B received"
            I2PSecurityAuditLog.append(category: "transport",
                                       detail: "ntcp2 \(role) peer hung up mid-handshake \(phase) after \(handshakeBytesIn) bytes in / \(handshakeBytesOut) bytes out")
        } else {
            // A Termination block names which check the peer failed (the
            // spec's reason codes); a peer close without one is just a hangup.
            if let reason = terminationReason {
                // The reason code's name is what the live audit reads, so the
                // lookup is shared by the close line and the audit entry.
                let named = NTCP2TerminationReason(rawValue: reason)
                var line = "peer terminated: reason \(reason)"
                if let named {
                    line += " (\(String(describing: named)))"
                }
                closeReason = line
                // Every termination is recorded with the session's traffic and
                // the reference reason code's name: an idle-timeout
                // termination is a router-management close, not a failure of
                // ours, and the transport keeps the dialable peer in its
                // candidate set either way.
                let reasonName = named.map { String(describing: $0) } ?? "unknown"
                I2PSecurityAuditLog.append(category: "transport",
                                           detail: "ntcp2 \(role) peer sent termination reason \(reason) (\(reasonName)) after \(bytesIn) bytes in / \(bytesOut) bytes out")
            } else {
                closeReason = "peer closed the session"
            }
        }
        delegate?.session(self, didClose: error)
    }
}

/// A peer endpoint taken from an NTCP2 RouterAddress ("s" static key option,
/// "i" handshake-obfuscation IV).
struct NTCP2PeerEndpoint {
    let host: String
    let port: UInt16
    let staticKey: Data
    /// The `i` option: the 16-byte AES IV the peer publishes for handshake
    /// obfuscation. Every mainnet NTCP2 address carries one; without it the
    /// SessionRequest's ephemeral key cannot be obfuscated.
    let iv: Data?

    init?(routerAddress: I2PRouterAddress) {
        guard routerAddress.transportStyle == "NTCP2" else { return nil }
        guard let encodedKey = routerAddress.options["s"],
              let key = Self.base64Decode(encodedKey),
              key.count == 32 else { return nil }
        guard let portText = routerAddress.options["port"], let port = UInt16(portText) else { return nil }
        host = routerAddress.options["host"] ?? "127.0.0.1"
        self.port = port
        staticKey = key
        if let encodedIV = routerAddress.options["i"],
           let decodedIV = Self.base64Decode(encodedIV),
           decodedIV.count == 16 {
            iv = decodedIV
        } else {
            iv = nil
        }
    }

    static func base64Decode(_ text: String) -> Data? {
        I2PCrypto.i2pBase64Decode(text)
    }

    /// The endpoint to dial out of a peer's RouterInfo: a published IPv4 NTCP2
    /// address carrying the handshake IV first, then any IV-bearing address,
    /// then anything dialable. Preferring IPv4 matters on cellular, where an
    /// IPv6-only candidate can never be reached.
    static func preferred(from addresses: [I2PRouterAddress]) -> NTCP2PeerEndpoint? {
        let endpoints = addresses.compactMap { NTCP2PeerEndpoint(routerAddress: $0) }
        return endpoints.first(where: { $0.iv != nil && !$0.host.contains(":") })
            ?? endpoints.first(where: { $0.iv != nil })
            ?? endpoints.first
    }
}

protocol NTCP2TransportDelegate: AnyObject {
    func transport(_ transport: NTCP2Transport, sessionEstablished session: NTCP2Session)
    func transport(_ transport: NTCP2Transport, session: NTCP2Session, didReceiveData data: Data)
    func transport(_ transport: NTCP2Transport, sessionDidClose session: NTCP2Session)
}

/// Connection manager: TCP listener for inbound sessions plus outgoing
/// connections, tracking concurrent peer sessions by router hash.
final class NTCP2Transport {
    weak var delegate: NTCP2TransportDelegate?

    private var localRouterInfo: I2PRouterInfo
    private var localRouterInfoData: Data
    private let localStaticKey: Curve25519.KeyAgreement.PrivateKey
    /// Canonical public key for `localStaticKey` — the bytes the RouterInfo
    /// publishes as "s" and message 3 part 1 must carry verbatim.
    private let localStaticPublicKey: Data
    private let localRouterHash: Data
    private var localIV: Data?
    private let queue = DispatchQueue(label: "i2p.ntcp2.transport")
    private let lock = NSLock()
    private var listener: NWListener?
    private var sessions: [NTCP2Session] = []
    private var sessionsByHash: [Data: NTCP2Session] = [:]
    private var recentCloseReasons: [String] = []
    private let sessionLedger = I2PResourceLedger()
    /// TCP connections the listener has accepted since launch. Peers can only
    /// hand us a tunnel build over a new inbound connection (the first build of
    /// any tunnel arrives that way), so a count that stays at zero while we
    /// advertise an address is what a NAT or firewall looks like from here —
    /// and a count above zero with no builds is a real selection finding.
    private var acceptedInboundConnections = 0
    /// Lifetime totals for the dashboard's totals card: the bytes carried by
    /// sessions that have already closed, banked when the session ends so the
    /// cumulative figures never fall when a peer hangs up. Live sessions add
    /// their own running counters on top.
    private var closedSessionBytesIn = 0
    private var closedSessionBytesOut = 0
    private var establishedSessionTotal = 0

    /// TCP connections the listener has accepted since launch.
    var inboundConnectionCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return acceptedInboundConnections
    }

    init(localRouterInfo: I2PRouterInfo, staticKey: Curve25519.KeyAgreement.PrivateKey,
         localStaticPublicKey: Data? = nil) {
        self.localRouterInfo = localRouterInfo
        self.localRouterInfoData = localRouterInfo.serialize()
        self.localStaticKey = staticKey
        // The 32 static-key bytes message 3 part 1 carries must be identical to
        // the RouterInfo's "s" option: reference routers follow SessionConfirmed
        // with `memcmp(staticKeyFromMessage3, address.s)` and silently close the
        // session when the two differ. CryptoKit's raw public key may carry the
        // X25519 u-coordinate's top bit, while "s" must have it cleared (i2pd
        // rejects a non-canonical "s" outright), so both sides are normalized
        // here — the two encodings are the same curve point.
        let canonical = I2PCrypto.canonicalX25519PublicKey(staticKey.publicKey.rawRepresentation)
        let requested = localStaticPublicKey.map(I2PCrypto.canonicalX25519PublicKey) ?? canonical
        if let published = Self.publishedStaticKey(localRouterInfo), published != requested {
            I2PSecurityAuditLog.append(
                category: "transport",
                detail: "ntcp2 local static key differs from the RouterInfo 's' option — peers reject message 3; using \(requested.hex.prefix(8)) vs published \(published.hex.prefix(8))")
        }
        self.localStaticPublicKey = requested
        localRouterHash = localRouterInfo.identity.hash
        localIV = NTCP2Transport.publishedIV(localRouterInfo)
    }

    /// The static key a RouterInfo publishes for its NTCP2 addresses.
    private static func publishedStaticKey(_ info: I2PRouterInfo) -> Data? {
        for address in info.addresses where address.transportStyle == "NTCP2" {
            guard let text = address.options["s"],
                  let key = NTCP2PeerEndpoint.base64Decode(text),
                  key.count == 32 else { continue }
            return key
        }
        return nil
    }

    /// Replaces the RouterInfo presented to peers in message 3 after the router
    /// re-signs with its reachable address. Without this the handshake keeps
    /// advertising the bootstrap address (loopback, port 0) and peers that
    /// compare the observed endpoint against it drop the session right after
    /// message 3. Established sessions keep their negotiated state.
    func updateLocalRouterInfo(_ info: I2PRouterInfo) {
        lock.lock()
        defer { lock.unlock() }
        localRouterInfo = info
        localRouterInfoData = info.serialize()
        localIV = NTCP2Transport.publishedIV(info)
    }

    /// The RouterInfo to advertise in a new session's message 3.
    private func currentRouterInfo() -> (data: Data, iv: Data?) {
        lock.lock()
        defer { lock.unlock() }
        return (localRouterInfoData, localIV)
    }

    /// The AES IV this router publishes for handshake obfuscation: the `i`
    /// option of its own NTCP2 RouterAddress.
    private static func publishedIV(_ info: I2PRouterInfo) -> Data? {
        for address in info.addresses where address.transportStyle == "NTCP2" {
            guard let text = address.options["i"],
                  let iv = NTCP2PeerEndpoint.base64Decode(text),
                  iv.count == 16 else { continue }
            return iv
        }
        return nil
    }

    /// Starts the TCP listener; `port` 0 binds an ephemeral port.
    /// The bound port is available shortly after via `listenerPort`.
    @discardableResult
    func startListener(port: UInt16 = 0) throws -> UInt16 {
        lock.lock()
        defer { lock.unlock() }
        guard listener == nil else { return listener?.port?.rawValue ?? port }
        let parameters = NWParameters.tcp
        let nwListener = try NWListener(using: parameters, on: NWEndpoint.Port(rawValue: port) ?? .any)
        nwListener.newConnectionHandler = { [weak self] connection in
            guard let self else { return }
            self.lock.lock()
            self.acceptedInboundConnections += 1
            self.lock.unlock()
            let advertised = self.currentRouterInfo()
            let session = NTCP2Session(role: .responder,
                                       connection: connection,
                                       localStaticKey: self.localStaticKey,
                                       localStaticPublicKey: self.localStaticPublicKey,
                                       localRouterInfoData: advertised.data,
                                       localRouterHash: self.localRouterHash,
                                       localIV: advertised.iv,
                                       remoteStaticKey: nil,
                                       remoteRouterHash: nil,
                                       remoteIV: nil,
                                       queue: self.queue)
            session.delegate = self
            self.register(session)
            session.start()
        }
        nwListener.start(queue: queue)
        listener = nwListener
        return nwListener.port?.rawValue ?? port
    }

    var listenerPort: UInt16? {
        lock.lock()
        defer { lock.unlock() }
        return listener?.port?.rawValue
    }

    /// Opens an outbound session toward a peer. The session is handed back so a
    /// probe can read how that one attempt ended (its close reason names a
    /// refused connect, a hang-up after SessionRequest or a handshake timeout);
    /// every existing caller ignores the result.
    @discardableResult
    func connect(host: String, port: UInt16, remoteRouterHash: Data,
                 remoteStaticKey: Data, remoteIV: Data?) -> NTCP2Session? {
        lock.lock()
        defer { lock.unlock() }
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { return nil }
        let connection = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: .tcp)
        let session = NTCP2Session(role: .initiator,
                                   connection: connection,
                                   localStaticKey: localStaticKey,
                                   localStaticPublicKey: localStaticPublicKey,
                                   localRouterInfoData: localRouterInfoData,
                                   localRouterHash: localRouterHash,
                                   localIV: localIV,
                                   remoteStaticKey: remoteStaticKey,
                                   remoteRouterHash: remoteRouterHash,
                                   remoteIV: remoteIV,
                                   queue: queue)
        session.delegate = self
        register(session)
        session.start()
        return session
    }

    func sessionCount() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return sessions.count
    }

    /// Cumulative session totals since this transport started: every closed
    /// session's bytes banked at close plus the live sessions' running
    /// counters, and how many sessions reached the established state. Memory
    /// only — the dashboard's totals card reads them and nothing persists.
    ///
    /// The session counters are read directly under this transport's lock
    /// (rather than hopping onto a session's own queue) for the reason
    /// `sessionSummaries` does: a session's queue calls back into this
    /// transport on establish and close, so waiting on it while holding this
    /// lock would invert the two.
    func lifetimeTotals() -> (bytesIn: Int, bytesOut: Int, sessions: Int) {
        lock.lock()
        defer { lock.unlock() }
        var bytesIn = closedSessionBytesIn
        var bytesOut = closedSessionBytesOut
        for session in sessions {
            bytesIn += session.bytesIn
            bytesOut += session.bytesOut
        }
        return (bytesIn, bytesOut, establishedSessionTotal)
    }

    /// Per-peer session readings for the peer inspector (established sessions only,
    /// deduplicated by router hash).
    func sessionSummaries() -> [(hash: Data, establishedAt: Date, bytesIn: Int, bytesOut: Int)] {
        lock.lock()
        defer { lock.unlock() }
        var seen: Set<Data> = []
        var out: [(hash: Data, establishedAt: Date, bytesIn: Int, bytesOut: Int)] = []
        for session in sessions {
            guard session.isEstablished,
                  let hash = session.remoteRouterHash,
                  !seen.contains(hash) else { continue }
            seen.insert(hash)
            out.append((hash, session.establishedAt ?? Date(), session.bytesIn, session.bytesOut))
        }
        return out
    }

    func hasSession(for routerHash: Data) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return sessionsByHash[routerHash] != nil
    }

    /// The last few session endings, newest last: hash prefix and reason. Live
    /// audits append these so a failed handshake row names its cause.
    func recentCloses(limit: Int = 5) -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return Array(recentCloseReasons.suffix(limit))
    }

    func send(to routerHash: Data, data: Data) throws {
        lock.lock()
        let session = sessionsByHash[routerHash]
        lock.unlock()
        // Never hold the transport lock across a call into the session. The
        // session runs its state on the network queue, and that queue calls
        // back into this transport (didEstablish / didClose), which takes this
        // same lock — holding it here inverted the two locks and deadlocked
        // the pair.
        guard let session, session.isEstablished else {
            throw NTCP2Error.noSession(forHash: routerHash)
        }
        try session.send(data)
    }

    func closeSession(for routerHash: Data) {
        lock.lock()
        let session = sessionsByHash[routerHash]
        lock.unlock()
        session?.close()
    }

    func shutdown() {
        lock.lock()
        let all = sessions
        listener?.cancel()
        listener = nil
        lock.unlock()
        all.forEach { $0.abort() }
    }

    private func register(_ session: NTCP2Session) {
        // Resource quota: session slots are bounded. A connection arriving at
        // the cap is aborted fail-closed rather than admitted; every
        // exhaustion is recorded in the security audit log.
        guard sessionLedger.tryReserve(name: "ntcp2.sessions") else {
            session.abort()
            I2PSecurityAuditLog.append(category: "transport", detail: "ntcp2 session cap reached; inbound connection aborted")
            return
        }
        sessions.append(session)
    }

    private func remove(_ session: NTCP2Session) {
        lock.lock()
        sessions.removeAll { $0 === session }
        sessionsByHash = sessionsByHash.filter { $0.value !== session }
        lock.unlock()
        sessionLedger.release(name: "ntcp2.sessions")
    }
}

extension NTCP2Transport: NTCP2SessionDelegate {
    func session(_ session: NTCP2Session, didEstablishWith remoteRouterHash: Data?, remoteRouterInfo: I2PRouterInfo?) {
        lock.lock()
        // One established session per session object (a session notifies
        // once), which is exactly what the totals card's sessions figure counts.
        establishedSessionTotal += 1
        if let hash = remoteRouterHash { sessionsByHash[hash] = session }
        lock.unlock()
        delegate?.transport(self, sessionEstablished: session)
    }

    func session(_ session: NTCP2Session, didReceiveData data: Data) {
        delegate?.transport(self, session: session, didReceiveData: data)
    }

    func session(_ session: NTCP2Session, didClose error: Error?) {
        lock.lock()
        // Bank the finished session's bytes before it leaves the list, so the
        // cumulative totals cover every session this transport has carried,
        // not only the ones still live.
        closedSessionBytesIn += session.bytesIn
        closedSessionBytesOut += session.bytesOut
        let label = session.remoteRouterHash.map { String($0.hex.prefix(12)) } ?? "unknown"
        recentCloseReasons.append("\(label): \(session.closeReason ?? "closed")")
        if recentCloseReasons.count > 10 {
            recentCloseReasons.removeFirst(recentCloseReasons.count - 10)
        }
        lock.unlock()
        remove(session)
        delegate?.transport(self, sessionDidClose: session)
    }
}