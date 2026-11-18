//
//  I2PLiveInterop.swift
//  The live interoperability probe behind the "Live interoperability" screen:
//  one reseed/bootstrap reading and one real dial attempt per peer, with the
//  transport that carried it and the way its handshake ended.
//
//  This probe reports handshakes only. It never builds a tunnel, sends an I2NP
//  message or publishes anything, so its rows must never be read as proof of
//  tunnel or message interoperability — the screen says so in as many words.
//
//  Everything here is memory only: the last report lives in the store for the
//  lifetime of the process and is never written to disk.
//

import Foundation

// MARK: - Report model

/// One peer a live probe dialled, the transport it used and how the attempt
/// ended. Reasons are taken from the transports' own close diagnostics, never
/// guessed from a bare timeout.
struct I2PLivePeerAttempt: Identifiable, Equatable {
    enum Transport: String, Equatable {
        case ntcp2 = "NTCP2"
        case ssu2 = "SSU2"
    }

    enum Ending: Equatable {
        case established
        case closedAfterSessionRequest
        case connectTimeout
        case handshakeTimeout
        /// Anything outside the endings above: the peer's own words stay in its
        /// log, as the screen's footnote says.
        case failed
    }

    let id: String            // the peer's full router hash, hex
    let transport: Transport
    let host: String
    let port: UInt16
    let ending: Ending

    var hashLabel: String {
        guard id.count > 10 else { return id }
        return "\(id.prefix(6))…\(id.suffix(4))"
    }

    var endpointLabel: String { "\(host):\(port)" }

    var statusLabel: String {
        switch ending {
        case .established: return "Established"
        case .closedAfterSessionRequest: return "Closed after SessionRequest"
        case .connectTimeout: return "Connect timed out"
        case .handshakeTimeout: return "Handshake timed out"
        case .failed: return "Handshake failed"
        }
    }

    var isEstablished: Bool { ending == .established }
}

/// The bootstrap reading a probe run rests on: the reseed host that answered,
/// what it delivered, and the floodfill set that resulted.
struct I2PLiveBootstrapResult: Equatable {
    /// The reseed host that answered; nil when none did.
    let source: String?
    let accepted: Int
    let rejected: Int
    let floodfills: Int
    /// Why no host answered, when `source` is nil.
    let failure: String?

    var didReseed: Bool { source != nil }

    /// "75 accepted · 0 rejected · 57 floodfills"
    var routerInfoLine: String {
        "\(accepted) accepted · \(rejected) rejected · \(floodfills) floodfills"
    }
}

struct I2PLiveProbeReport: Equatable {
    let ranAt: Date
    let bootstrap: I2PLiveBootstrapResult
    let peers: [I2PLivePeerAttempt]

    var establishedCount: Int { peers.filter(\.isEstablished).count }

    /// "1 of 3 peers accepted a handshake"
    var ratioLine: String {
        "\(establishedCount) of \(peers.count) peer\(peers.count == 1 ? "" : "s") accepted a handshake"
    }
}

// MARK: - Probe

enum I2PLiveInteropProbe {
    /// How many peers one run dials: enough to see a mix of outcomes without
    /// turning the probe into a connection burst.
    static let peerLimit = 3

    /// The dial window. A peer's NTCP2 session already bounds its own connect
    /// (8s) and handshake (20s); this window covers a whole run of peers
    /// dialled together.
    static let dialWindow: TimeInterval = 22

    /// The router's own bootstrap reseeds on its keep-alive cycle; a report
    /// that fresh is the bootstrap this router actually used, so a probe run
    /// reuses it instead of hammering reseed hosts a second time.
    static let reseedReuseWindow: TimeInterval = 30 * 60

    struct Target {
        let hash: Data
        let info: I2PRouterInfo
        let ntcp2: NTCP2PeerEndpoint?
        let ssu2: SSU2PeerEndpoint?
    }

    struct Planned {
        let target: Target
        let transport: I2PLivePeerAttempt.Transport
    }

    /// Runs one probe: bootstrap reading, reachability advertisement, then a
    /// real dial per chosen peer. `onStage` receives plain-language progress.
    static func run(onStage: ((String) async -> Void)? = nil) async -> I2PLiveProbeReport {
        I2PRouterAppContext.shared.start()
        let context = I2PRouterAppContext.shared

        await onStage?("Bootstrapping from reseed servers")
        let bootstrap = await bootstrapResult(context: context, netDB: context.mainnetNetDB)

        // Message 3 of the handshake carries our RouterInfo; peers compare its
        // published address against the endpoint they observe and drop a
        // session whose address is still the bootstrap placeholder.
        await onStage?("Advertising this router's address")
        await context.ensureReachableAddress()

        await onStage?("Choosing peers to dial")
        let planned = await plan(netDB: context.mainnetNetDB,
                                 ntcp2: context.mainnetNTCP2,
                                 ssu2: context.mainnetSSU2)

        await onStage?("Dialling \(planned.count) peer\(planned.count == 1 ? "" : "s")")
        let peers = await dial(planned, context: context)

        return I2PLiveProbeReport(ranAt: Date(), bootstrap: bootstrap, peers: peers)
    }

    // MARK: Bootstrap

    static func bootstrapResult(context: I2PRouterAppContext,
                                netDB: I2PNetworkDatabase) async -> I2PLiveBootstrapResult {
        let knownFloodfills = await netDB.floodfillCount()
        if let report = context.lastReseedReport,
           Date().timeIntervalSince(context.lastReseedAt) < reseedReuseWindow {
            return I2PLiveBootstrapResult(source: report.fetchedFrom,
                                          accepted: report.ingested,
                                          rejected: report.rejected,
                                          floodfills: knownFloodfills,
                                          failure: nil)
        }
        do {
            let report = try await I2PReseedService.reseed(into: netDB)
            return I2PLiveBootstrapResult(source: report.fetchedFrom,
                                          accepted: report.ingested,
                                          rejected: report.rejected,
                                          floodfills: await netDB.floodfillCount(),
                                          failure: nil)
        } catch {
            return I2PLiveBootstrapResult(source: nil,
                                          accepted: 0,
                                          rejected: 0,
                                          floodfills: knownFloodfills,
                                          failure: I2PReseedService.summarize(error))
        }
    }

    // MARK: Peer selection

    /// Draws fresh floodfill RouterInfos with a dialable address and plans one
    /// dial per peer. Peers this router already holds a session to are used only
    /// when nothing else is left, so nearly every row is a fresh attempt rather
    /// than the state an earlier bootstrap left behind. The second slot goes
    /// over SSU2 when that peer publishes one, so a single run observes both
    /// transports; every other slot takes NTCP2 where it exists.
    static func plan(netDB: I2PNetworkDatabase, ntcp2: NTCP2Transport,
                     ssu2: SSU2Transport, limit: Int = peerLimit) async -> [Planned] {
        let probeKey = I2PCrypto.randomBytes(32)
        let hashes = await netDB.selectFloodfills(for: probeKey, count: 96)
        var candidates: [Target] = []
        for hash in hashes where candidates.count < 24 {
            guard let info = await netDB.lookupRouterInfo(hash, timeoutPerRound: 1, maxRounds: 1) else {
                continue
            }
            let ntcp2Endpoint = NTCP2PeerEndpoint.preferred(from: info.addresses)
            let ssu2Endpoint = SSU2PeerEndpoint.preferred(from: info.addresses)
            guard ntcp2Endpoint != nil || ssu2Endpoint != nil else { continue }
            candidates.append(Target(hash: hash, info: info,
                                     ntcp2: ntcp2Endpoint, ssu2: ssu2Endpoint))
        }
        // Session-free peers first: a dial to a peer we already hold a session
        // to says nothing new about its handshake.
        func connected(_ target: Target) -> Bool {
            ntcp2.hasSession(for: target.hash) || ssu2.hasSession(forRouterHash: target.hash)
        }
        candidates = candidates.filter { !connected($0) } + candidates.filter { connected($0) }

        var planned: [Planned] = []
        for target in candidates {
            guard planned.count < limit else { break }
            let slot = planned.count
            let transport: I2PLivePeerAttempt.Transport
            if slot == 1, target.ssu2 != nil {
                transport = .ssu2
            } else if target.ntcp2 != nil {
                transport = .ntcp2
            } else if target.ssu2 != nil {
                transport = .ssu2
            } else {
                continue
            }
            planned.append(Planned(target: target, transport: transport))
        }
        return planned
    }

    // MARK: Dialling

    private final class InFlight {
        let planned: Planned
        let ntcp2Session: NTCP2Session?
        let ssu2Session: SSU2Session?

        init(planned: Planned, ntcp2Session: NTCP2Session?, ssu2Session: SSU2Session?) {
            self.planned = planned
            self.ntcp2Session = ntcp2Session
            self.ssu2Session = ssu2Session
        }
    }

    static func dial(_ planned: [Planned], context: I2PRouterAppContext) async -> [I2PLivePeerAttempt] {
        let ntcp2 = context.mainnetNTCP2
        let ssu2 = context.mainnetSSU2
        var inFlight: [InFlight] = []

        for item in planned {
            switch item.transport {
            case .ntcp2:
                guard let endpoint = item.target.ntcp2 else { continue }
                let session = ntcp2.connect(host: endpoint.host, port: endpoint.port,
                                            remoteRouterHash: item.target.hash,
                                            remoteStaticKey: endpoint.staticKey,
                                            remoteIV: endpoint.iv)
                inFlight.append(InFlight(planned: item, ntcp2Session: session, ssu2Session: nil))
            case .ssu2:
                guard let endpoint = item.target.ssu2 else { continue }
                let session = try? ssu2.connect(host: endpoint.host, port: endpoint.port,
                                                remoteStaticKey: endpoint.staticKey,
                                                remoteIntroKey: endpoint.introKey)
                inFlight.append(InFlight(planned: item, ntcp2Session: nil, ssu2Session: session))
            }
        }

        let deadline = Date().addingTimeInterval(dialWindow)
        while Date() < deadline {
            if inFlight.allSatisfy({ isDecided($0, ntcp2: ntcp2, ssu2: ssu2) }) { break }
            try? await Task.sleep(for: .milliseconds(250))
        }

        var attempts: [I2PLivePeerAttempt] = []
        for item in inFlight {
            attempts.append(attempt(for: item, ntcp2: ntcp2, ssu2: ssu2))
        }
        // A half-open attempt is left to the transport's own connect and
        // handshake timers: closing it by peer hash could cancel a session this
        // probe did not open. An established session is real connectivity and
        // is kept either way.
        return attempts
    }

    private static func isDecided(_ item: InFlight, ntcp2: NTCP2Transport,
                                  ssu2: SSU2Transport) -> Bool {
        switch item.planned.transport {
        case .ntcp2:
            guard let session = item.ntcp2Session else { return true }
            return session.isEstablished || session.state == .closed
        case .ssu2:
            if ssu2.hasSession(forRouterHash: item.planned.target.hash) { return true }
            guard let session = item.ssu2Session else { return true }
            return session.state == .closed
        }
    }

    private static func attempt(for item: InFlight, ntcp2: NTCP2Transport,
                                ssu2: SSU2Transport) -> I2PLivePeerAttempt {
        let target = item.planned.target
        let transport = item.planned.transport
        let host: String
        let port: UInt16
        switch transport {
        case .ntcp2:
            host = target.ntcp2?.host ?? ""
            port = target.ntcp2?.port ?? 0
        case .ssu2:
            host = target.ssu2?.host ?? ""
            port = target.ssu2?.port ?? 0
        }

        let ending: I2PLivePeerAttempt.Ending
        switch transport {
        case .ntcp2:
            ending = ntcp2Ending(session: item.ntcp2Session)
        case .ssu2:
            if ssu2.hasSession(forRouterHash: target.hash) {
                ending = .established
            } else if let session = item.ssu2Session {
                if session.state == .closed {
                    ending = ssu2Ending(error: session.lastError)
                } else {
                    // Still in the token or handshake phase when the window
                    // closed: the peer never answered the SessionRequest.
                    ending = .handshakeTimeout
                }
            } else {
                // The transport refused to open the flow at all (an unusable
                // endpoint), which is not a peer handshake outcome.
                ending = .failed
            }
        }

        return I2PLivePeerAttempt(id: target.hash.hex,
                                  transport: transport,
                                  host: host,
                                  port: port,
                                  ending: ending)
    }

    // MARK: Ending classification

    /// Maps an NTCP2 session's close reason onto the row's ending. The session
    /// words each failure itself — a refused TCP connect, a hang-up after
    /// SessionRequest, an unanswered handshake — so the row repeats the
    /// transport's verdict instead of inventing one.
    static func ntcp2Ending(session: NTCP2Session?) -> I2PLivePeerAttempt.Ending {
        guard let session else { return .failed }
        if session.isEstablished { return .established }
        guard session.state == .closed else { return .handshakeTimeout }
        return ntcp2Ending(closeReason: session.closeReason)
    }

    static func ntcp2Ending(closeReason: String?) -> I2PLivePeerAttempt.Ending {
        guard let reason = closeReason?.lowercased() else { return .failed }
        if reason.contains("did not accept the tcp connection") { return .connectTimeout }
        if reason.contains("peer closed during the handshake") {
            return reason.contains("after sessionrequest")
                ? .closedAfterSessionRequest
                : .failed
        }
        if reason.contains("handshake did not complete") { return .handshakeTimeout }
        return .failed
    }

    /// Maps an SSU2 session's last error onto the same scale.
    static func ssu2Ending(error: Error?) -> I2PLivePeerAttempt.Ending {
        guard let error else { return .failed }
        let text = String(describing: error).lowercased()
        if text.contains("session request") || text.contains("sessionrequest") {
            return .closedAfterSessionRequest
        }
        if text.contains("handshake") || text.contains("timeout") || text.contains("timed out") {
            return .handshakeTimeout
        }
        return .failed
    }
}

// MARK: - Self-test

/// The report is only as honest as its classification and its summary line, so
/// both are pinned here. Pure: no sockets, no router.
enum I2PLiveInteropSelfTest {
    static func runAll() -> [I2PSelfTestResult] {
        var results: [I2PSelfTestResult] = []
        func check(_ name: String, _ body: () -> String?) {
            if let detail = body() {
                results.append(I2PSelfTestResult(name: name, passed: true, detail: detail))
            } else {
                results.append(I2PSelfTestResult(
                    name: name,
                    passed: false,
                    detail: "live interoperability classification did not match the expected ending"))
            }
        }

        check("Live interop · a hang-up after SessionRequest is named as such") {
            let ending = I2PLiveInteropProbe.ntcp2Ending(
                closeReason: "peer closed during the handshake after SessionRequest — 288 B sent, 0 B received")
            return ending == .closedAfterSessionRequest ? "closedAfterSessionRequest" : nil
        }

        check("Live interop · a refused TCP connect is a connect timeout") {
            let ending = I2PLiveInteropProbe.ntcp2Ending(
                closeReason: "peer did not accept the TCP connection within 8s")
            return ending == .connectTimeout ? "connectTimeout" : nil
        }

        check("Live interop · an unanswered handshake is a handshake timeout") {
            let ending = I2PLiveInteropProbe.ntcp2Ending(
                closeReason: "handshake did not complete within 20s")
            return ending == .handshakeTimeout ? "handshakeTimeout" : nil
        }

        check("Live interop · an unclassifiable ending stays 'failed' rather than invented") {
            guard I2PLiveInteropProbe.ntcp2Ending(closeReason: nil) == .failed,
                  I2PLiveInteropProbe.ntcp2Ending(closeReason: "peer closed the session") == .failed else {
                return nil
            }
            return "failed"
        }

        check("Live interop · an SSU2 session-request rejection is named as such") {
            let error = I2PLiveInteropProbe.ssu2Ending(
                error: I2PMainnetFailure(message: "session request was refused by the peer"))
            return error == .closedAfterSessionRequest ? "closedAfterSessionRequest" : nil
        }

        check("Live interop · the summary line counts only established handshakes") {
            let report = I2PLiveProbeReport(
                ranAt: Date(),
                bootstrap: I2PLiveBootstrapResult(source: "https://reseed.diva.exchange",
                                                  accepted: 75, rejected: 0, floodfills: 57,
                                                  failure: nil),
                peers: [
                    I2PLivePeerAttempt(id: String(repeating: "ab", count: 32), transport: .ntcp2,
                                       host: "163.245.216.254", port: 31452, ending: .established),
                    I2PLivePeerAttempt(id: String(repeating: "cd", count: 32), transport: .ssu2,
                                       host: "198.51.100.27", port: 45671,
                                       ending: .closedAfterSessionRequest),
                    I2PLivePeerAttempt(id: String(repeating: "ef", count: 32), transport: .ntcp2,
                                       host: "203.0.113.88", port: 32109, ending: .connectTimeout)
                ])
            guard report.establishedCount == 1,
                  report.ratioLine == "1 of 3 peers accepted a handshake" else { return nil }
            return report.ratioLine
        }

        check("Live interop · a peer row labels its hash and endpoint without shortening the endpoint") {
            let attempt = I2PLivePeerAttempt(id: "099ae2f13c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e2b4",
                                             transport: .ssu2,
                                             host: "198.51.100.27", port: 45671,
                                             ending: .closedAfterSessionRequest)
            guard attempt.hashLabel == "099ae2…e2b4",
                  attempt.endpointLabel == "198.51.100.27:45671",
                  attempt.statusLabel == "Closed after SessionRequest" else { return nil }
            return "\(attempt.hashLabel) · \(attempt.endpointLabel)"
        }

        return results
    }
}
