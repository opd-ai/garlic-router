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
    private let localRouterInfoData: Data
    private let remoteStaticKey: Data?
    private let queue: DispatchQueue

    private var initiator: NTCP2InitiatorHandshake?
    private var responder: NTCP2ResponderHandshake?
    private var sendCodec: NTCP2FrameCodec?
    private var recvCodec: NTCP2FrameCodec?
    private var rxBuffer = Data()
    private var didNotifyEstablished = false

    var isEstablished: Bool { state == .established }

    init(role: Role,
         connection: NWConnection,
         localStaticKey: Curve25519.KeyAgreement.PrivateKey,
         localRouterInfoData: Data,
         remoteStaticKey: Data?,
         queue: DispatchQueue) {
        self.connection = connection
        self.role = role
        self.localStaticKey = localStaticKey
        self.localRouterInfoData = localRouterInfoData
        self.remoteStaticKey = remoteStaticKey
        self.queue = queue
    }

    func start() {
        connection.stateUpdateHandler = { [weak self] newState in
            guard let self else { return }
            switch newState {
            case .ready:
                self.beginHandshakeIfNeeded()
                self.receiveNext()
            case .failed(let connectionError):
                self.finish(error: connectionError)
            case .cancelled:
                self.finish(error: nil)
            default:
                break
            }
        }
        connection.start(queue: queue)
    }

    // MARK: - Handshake

    private func beginHandshakeIfNeeded() {
        guard role == .initiator, initiator == nil else { return }
        guard let remoteStaticKey else {
            finish(error: NTCP2Error.handshakeFailed("initiator without remote static key"))
            return
        }
        do {
            let engine = try NTCP2InitiatorHandshake(localStaticKey: localStaticKey, remoteStaticKey: remoteStaticKey)
            initiator = engine
            let request = try engine.makeSessionRequest(routerInfo: localRouterInfoData)
            sendRaw(request)
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
            sendRaw(result.message)
            try establish(asInitiator: true)
            return true

        case .responder:
            if responder == nil {
                responder = NTCP2ResponderHandshake(localStaticKey: localStaticKey)
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

        if !asInitiator {
            // Responder announces its RouterInfo in the first data-phase frame.
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
                self.rxBuffer += data
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
                break
            case .routerInfo(let data):
                if let parsed = try? I2PRouterInfo.parse(data) {
                    remoteRouterInfo = parsed
                    remoteRouterHash = parsed.identity.hash
                    if role == .initiator {
                        // Initiator learns the responder's RouterInfo from this block.
                        notifyEstablishedIfNeeded()
                    }
                } else {
                    finish(error: NTCP2Error.handshakeFailed("invalid remote RouterInfo"))
                    return
                }
            case .data(let data):
                delegate?.session(self, didReceiveData: data)
            case .termination:
                // Graceful close requested by the peer.
                finish(error: nil)
                return
            }
        }
    }

    // MARK: - Send / close

    func send(_ data: Data) throws {
        guard state == .established, let codec = sendCodec else {
            throw NTCP2Error.notEstablished
        }
        var payload = try NTCP2Block.encode([.data(data), .time(Date())])
        payload = NTCP2Block.aligned(payload)
        sendRaw(try codec.frame(payload))
    }

    private func sendRaw(_ data: Data) {
        connection.send(content: data, completion: .contentProcessed { [weak self] error in
            if let error { self?.finish(error: error) }
        })
    }

    /// Graceful termination: a termination block, then TCP close.
    func close(reason: UInt8 = 0) {
        guard state == .established, let codec = sendCodec else {
            connection.cancel()
            return
        }
        state = .closing
        let payload = (try? NTCP2Block.encode([.termination(reason: reason, validTime: Date())])) ?? Data()
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
        connection.cancel()
    }

    private func finish(error: Error?) {
        guard state != .closed else { return }
        state = .closed
        connection.cancel()
        delegate?.session(self, didClose: error)
    }
}

/// A peer endpoint taken from an NTCP2 RouterAddress ("s" static key option).
struct NTCP2PeerEndpoint {
    let host: String
    let port: UInt16
    let staticKey: Data

    init?(routerAddress: I2PRouterAddress) {
        guard routerAddress.transportStyle == "NTCP2" else { return nil }
        guard let encodedKey = routerAddress.options["s"],
              let key = Self.base64Decode(encodedKey),
              key.count == 32 else { return nil }
        guard let portText = routerAddress.options["port"], let port = UInt16(portText) else { return nil }
        host = routerAddress.options["host"] ?? "127.0.0.1"
        self.port = port
        staticKey = key
    }

    static func base64Decode(_ text: String) -> Data? {
        var sanitized = text
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while sanitized.count % 4 != 0 { sanitized += "=" }
        return Data(base64Encoded: sanitized)
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

    private let localRouterInfo: I2PRouterInfo
    private let localStaticKey: Curve25519.KeyAgreement.PrivateKey
    private let queue = DispatchQueue(label: "i2p.ntcp2.transport")
    private let lock = NSLock()
    private var listener: NWListener?
    private var sessions: [NTCP2Session] = []
    private var sessionsByHash: [Data: NTCP2Session] = [:]

    init(localRouterInfo: I2PRouterInfo, staticKey: Curve25519.KeyAgreement.PrivateKey) {
        self.localRouterInfo = localRouterInfo
        self.localStaticKey = staticKey
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
            let session = NTCP2Session(role: .responder,
                                       connection: connection,
                                       localStaticKey: self.localStaticKey,
                                       localRouterInfoData: self.localRouterInfo.serialize(),
                                       remoteStaticKey: nil,
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

    func connect(host: String, port: UInt16, remoteStaticKey: Data) {
        lock.lock()
        defer { lock.unlock() }
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { return }
        let connection = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: .tcp)
        let session = NTCP2Session(role: .initiator,
                                   connection: connection,
                                   localStaticKey: localStaticKey,
                                   localRouterInfoData: localRouterInfo.serialize(),
                                   remoteStaticKey: remoteStaticKey,
                                   queue: queue)
        session.delegate = self
        register(session)
        session.start()
    }

    func sessionCount() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return sessions.count
    }

    func hasSession(for routerHash: Data) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return sessionsByHash[routerHash] != nil
    }

    func send(to routerHash: Data, data: Data) throws {
        lock.lock()
        defer { lock.unlock() }
        guard let session = sessionsByHash[routerHash], session.isEstablished else {
            throw NTCP2Error.noSession(forHash: routerHash)
        }
        try session.send(data)
    }

    func closeSession(for routerHash: Data) {
        lock.lock()
        defer { lock.unlock() }
        sessionsByHash[routerHash]?.close()
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
        sessions.append(session)
    }

    private func remove(_ session: NTCP2Session) {
        lock.lock()
        sessions.removeAll { $0 === session }
        sessionsByHash = sessionsByHash.filter { $0.value !== session }
        lock.unlock()
    }
}

extension NTCP2Transport: NTCP2SessionDelegate {
    func session(_ session: NTCP2Session, didEstablishWith remoteRouterHash: Data?, remoteRouterInfo: I2PRouterInfo?) {
        if let hash = remoteRouterHash {
            lock.lock()
            sessionsByHash[hash] = session
            lock.unlock()
        }
        delegate?.transport(self, sessionEstablished: session)
    }

    func session(_ session: NTCP2Session, didReceiveData data: Data) {
        delegate?.transport(self, session: session, didReceiveData: data)
    }

    func session(_ session: NTCP2Session, didClose error: Error?) {
        remove(session)
        delegate?.transport(self, sessionDidClose: session)
    }
}