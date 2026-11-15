//
//  I2PLiveMainnetChecks.swift
//  Test infrastructure for the end-to-end live mainnet CI suite: failure
//  classification (transient network vs implementation gap vs environment
//  limitation vs modern-only policy boundary), periodic checkpoints that
//  record netdb size, tunnel counts and peer connection state, well-known
//  mainnet destination resolution over the live DHT (hosts.txt over HTTPS,
//  no synthetic fallback), and an inbound tunnel participation monitor that
//  dispatches organic tunnel-build traffic arriving over live sessions.
//

import Foundation
import CryptoKit

// MARK: - Failure classification

enum I2PLiveFailureKind: String {
    case transient = "transient network condition"
    case implementation = "implementation gap"
    case environment = "environment limitation"
    case policy = "modern-only crypto policy boundary"
}

/// Classifies a live-suite failure so CI reports separate transient network
/// conditions from real implementation bugs (the audit's flakiness rule).
enum I2PLiveFailureClassifier {
    static func classify(_ error: Error) -> I2PLiveFailureKind {
        if error is URLError { return .transient }
        let text = String(describing: error).lowercased()
        if text.contains("reachability") || text.contains("environment") || text.contains("organic") {
            return .environment
        }
        if text.contains("policy") || text.contains("legacy") || text.contains("unsupported")
            || text.contains("leasetype") || text.contains("ecies") {
            return .policy
        }
        if text.contains("timeout") || text.contains("timed out") || text.contains("no mainnet response")
            || text.contains("handshake") || text.contains("connection") || text.contains("dial")
            || text.contains("unreachable") || text.contains("no live session") || text.contains("reseed")
            // Cascade conditions: a probe whose prerequisite (reseed, a live
            // session, a resolved lease) already failed transiently upstream is
            // itself transient — classifying it as an implementation gap would
            // misreport a network outage as a router bug.
            || text.contains("no established session") || text.contains("never sent")
            || text.contains("no mainnet peers") || text.contains("no mainnet routers known")
            || text.contains("no lease-bearing") || text.contains("hosts.txt")
            || text.contains("non-200") || text.contains("nothing to dial") {
            return .transient
        }
        return .implementation
    }

    static func annotated(_ error: Error) -> String {
        "\(String(describing: error)) — classified \(classify(error).rawValue)"
    }
}

// MARK: - Periodic checkpoints

struct I2PLiveCheckpoint {
    let recordedAt: Date
    let netdbEntries: Int
    let netdbFloodfills: Int
    let netdbPeers: Int
    let ntcp2Sessions: Int
    let outboundTunnels: Int
    let inboundTunnels: Int
}

/// Records periodic snapshots of router state (netdb size, tunnel counts,
/// peer connection state) so the post-run analysis can compare trajectories
/// against mainnet norms.
final class I2PLiveCheckpointRecorder {
    private let lock = NSLock()
    private(set) var checkpoints: [I2PLiveCheckpoint] = []

    func capture(netDB: I2PNetworkDatabase, ntcp2: NTCP2Transport,
                 pool: I2PTunnelPool) async {
        let snapshot = I2PLiveCheckpoint(
            recordedAt: Date(),
            netdbEntries: await netDB.entryCount(),
            netdbFloodfills: await netDB.floodfillCount(),
            netdbPeers: await netDB.knownPeerCount(),
            ntcp2Sessions: ntcp2.sessionCount(),
            outboundTunnels: pool.outboundCount,
            inboundTunnels: pool.inboundCount
        )
        lock.lock()
        checkpoints.append(snapshot)
        lock.unlock()
    }

    var summary: String {
        lock.lock()
        defer { lock.unlock() }
        guard let first = checkpoints.first, let last = checkpoints.last, checkpoints.count > 1 else {
            return "\(checkpoints.count) checkpoint(s) captured"
        }
        return String(format: "%d checkpoints over %.0fs (netdb %d→%d entries, %d→%d floodfills, %d→%d live NTCP2 sessions, tunnels %d+%d→%d+%d)",
                      checkpoints.count, last.recordedAt.timeIntervalSince(first.recordedAt),
                      first.netdbEntries, last.netdbEntries,
                      first.netdbFloodfills, last.netdbFloodfills,
                      first.ntcp2Sessions, last.ntcp2Sessions,
                      first.outboundTunnels, first.inboundTunnels,
                      last.outboundTunnels, last.inboundTunnels)
    }
}

// MARK: - Well-known mainnet destinations (hosts.txt over HTTPS)

struct I2PWellKnownDestination {
    let name: String
    /// SHA-256 of the raw destination bytes — the netdb key the LeaseSet is stored under.
    let netdbKey: Data
    let destinationRaw: Data
    /// The signature type the host's own destination declares (nil when the shape
    /// is not readable). Only a type this router implements can be verified.
    let signatureTypeCode: UInt16?

    /// Whether a LeaseSet published by this host can be verified here at all. A
    /// long-lived identity that signs with a legacy type (a null-certificate
    /// DSA-SHA1 destination, or RSA-2048) can never resolve under this router's
    /// modern-only policy, so it must not spend the probe budget.
    var signsWithImplementedType: Bool {
        guard let signatureTypeCode else { return false }
        return I2PSigType(rawValue: signatureTypeCode) != nil
    }
}

/// Resolves well-known public I2P services by fetching the standard hosts.txt
/// (destination base64 per entry) over HTTPS from the I2P source repository and
/// computing each destination's netdb key. No synthetic destinations.
enum I2PMainnetHosts {
    /// Clearnet mirrors of the standard hosts.txt (Java I2P keeps the canonical
    /// file at installer/resources/hosts.txt, not the repo root — the old paths
    /// 404'd, which is what the live audit reported as "non-200"). The CDN and
    /// GitLab mirrors of the same file absorb GitHub rate limits, and the I2P
    /// Projekt copy is the same list served directly.
    static let sources = [
        "https://raw.githubusercontent.com/i2p/i2p.i2p/master/installer/resources/hosts.txt",
        "https://cdn.jsdelivr.net/gh/i2p/i2p.i2p@master/installer/resources/hosts.txt",
        "https://gitlab.com/i2p/i2p.i2p/-/raw/master/installer/resources/hosts.txt",
        "https://cdn.statically.io/gh/i2p/i2p.i2p/master/installer/resources/hosts.txt",
        "https://i2p-projekt.de/hosts.txt",
    ]

    /// Long-lived public services worth probing first (i2pwiki and friends).
    static let preferredNames = [
        "i2p-projekt.i2p", "stats.i2p", "psi.i2p", "zzz.i2p",
        "i2pwiki.i2p", "tracker.welterde.i2p", "echelon.i2p"
    ]

    static func fetchWellKnownDestinations(limit: Int = 6) async throws -> [I2PWellKnownDestination] {
        var lastError: Error = I2PMainnetFailure(message: "no hosts.txt source reachable")
        var refused: [String] = []
        for source in sources {
            do {
                guard let url = URL(string: source) else { continue }
                var request = URLRequest(url: url)
                request.timeoutInterval = 20
                // The mirrors serve a static file; a wget-style agent is the
                // same accepted family the reseed path uses.
                request.setValue("Wget/1.14 (linux-gnu)", forHTTPHeaderField: "User-Agent")
                let (data, response) = try await URLSession.shared.data(for: request)
                guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
                    let status = (response as? HTTPURLResponse)?.statusCode ?? -1
                    refused.append("\(source) — hosts.txt fetch returned a non-200 status (HTTP \(status))")
                    continue
                }
                let entries = parse(data)
                guard !entries.isEmpty else {
                    throw I2PMainnetFailure(message: "hosts.txt contained no parseable destinations")
                }
                // Order the probe list by what this router can actually verify.
                // Most *preferred* names are the network's oldest destinations,
                // and an old identity keeps a legacy signing key (null-certificate
                // DSA-SHA1, or RSA-2048), so preferring them spent the whole probe
                // budget on guaranteed misses — 3 of 6, and 10 inbound stores
                // rejected as unsupported, while modern hosts were never asked.
                let verifiable = entries.filter(\.signsWithImplementedType)
                let legacy = entries.filter { !$0.signsWithImplementedType }
                var ordered: [I2PWellKnownDestination] = []
                for pool in [verifiable, legacy] where ordered.count < limit {
                    for name in preferredNames {
                        if let entry = pool.first(where: { $0.name == name }),
                           !ordered.contains(where: { $0.name == name }) {
                            ordered.append(entry)
                        }
                    }
                    for entry in pool where !ordered.contains(where: { $0.name == entry.name }) {
                        if ordered.count >= limit { break }
                        ordered.append(entry)
                    }
                }
                guard !ordered.isEmpty else {
                    throw I2PMainnetFailure(message: "hosts.txt yielded no probe destinations")
                }
                return Array(ordered.prefix(limit))
            } catch {
                refused.append("\(source) — \(String(describing: error))")
                lastError = error
            }
        }
        throw I2PMainnetFailure(message: "no hosts.txt source reachable (\(refused.joined(separator: "; "))); last: \(String(describing: lastError))")
    }

    static func parse(_ data: Data) -> [I2PWellKnownDestination] {
        var out: [I2PWellKnownDestination] = []
        let text = String(decoding: data, as: UTF8.self)
        for line in text.split(separator: "\n") {
            guard let separator = line.firstIndex(of: "=") else { continue }
            let name = String(line[line.startIndex..<separator]).trimmingCharacters(in: .whitespaces)
            let base64 = String(line[line.index(after: separator)...]).trimmingCharacters(in: .whitespaces)
            // A Destination is at least 387 bytes (keys + cert + signature).
            guard !name.isEmpty, !base64.isEmpty,
                  let destination = base64Decode(base64), destination.count >= 387 else { continue }
            out.append(I2PWellKnownDestination(name: name,
                                               netdbKey: I2PCrypto.sha256(destination),
                                               destinationRaw: destination,
                                               signatureTypeCode: I2PKeysAndCert
                                                .declaredSignatureTypeCode(in: destination)))
            if out.count >= 64 { break }
        }
        return out
    }

    static func base64Decode(_ text: String) -> Data? {
        // The I2P base64 alphabet is standard base64 with '-' for '+' and '~'
        // for '/'. hosts.txt is written in it, so a decoder that only maps the
        // URL-safe '_' back to '/' rejects every entry.
        I2PCrypto.i2pBase64Decode(text)
    }
}

// MARK: - Inbound tunnel participation monitor

/// Watches every routed I2NP body arriving over the live sessions for organic
/// tunnel-build traffic (VariableTunnelBuild / TunnelBuildReply) from mainnet
/// routers, counting what the I2NP router dispatches.
final class I2PLiveInboundMonitor {
    private let lock = NSLock()
    private(set) var tunnelBuildMessages = 0
    private(set) var tunnelBuildReplyMessages = 0
    private(set) var routedBodies = 0

    func observe(_ message: I2NPMessage) {
        lock.lock()
        defer { lock.unlock() }
        routedBodies += 1
        switch message.type {
        case .tunnelBuild: tunnelBuildMessages += 1
        case .tunnelBuildReply: tunnelBuildReplyMessages += 1
        default: break
        }
    }

    var summary: String {
        lock.lock()
        defer { lock.unlock() }
        return "\(routedBodies) routed bodies: \(tunnelBuildMessages) tunnel builds, \(tunnelBuildReplyMessages) build replies"
    }
}
// MARK: - Reachability advertisement (public IPv4 discovery)

/// Discovers our public IPv4 address over clearnet HTTPS — the CI-friendly
/// equivalent of the SSU2 peer test (the simulator cannot receive inbound
/// peer-test datagrams). Real routers learn the same information from peer
/// tests; both feed the RouterInfo's published transport address.
enum I2PExternalAddressDiscovery {
    static let sources = [
        "https://api.ipify.org",
        "https://checkip.amazonaws.com",
    ]

    static func publicIPv4Address() async throws -> String {
        var lastError: Error = I2PMainnetFailure(message: "no address source reachable")
        for source in sources {
            do {
                guard let url = URL(string: source) else { continue }
                var request = URLRequest(url: url)
                request.timeoutInterval = 10
                let (data, response) = try await URLSession.shared.data(for: request)
                guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
                    throw I2PMainnetFailure(message: "address probe returned a non-200 status")
                }
                let text = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
                let parts = text.split(separator: ".")
                guard parts.count == 4,
                      parts.allSatisfy({ !$0.isEmpty && (0...255).contains(Int($0) ?? -1) }) else {
                    throw I2PMainnetFailure(message: "address probe returned non-IPv4 content")
                }
                return text
            } catch {
                lastError = error
            }
        }
        throw lastError
    }
}

// MARK: - Mainnet tunnel build plumbing (surfaced by the live suite)

/// Carries VariableTunnelBuild / BuildReply I2NP envelopes over live NTCP2
/// sessions — the wire path the loopback build bus could never serve. With a
/// demand-dial hook wired, a build toward a hop we hold no session for resolves
/// the hop's RouterInfo (netdb cache-first), dials it, and retries the send
/// until the handshake completes — so tunnel builds reach any known hop.
final class I2PNTCP2TunnelBuildTransport: I2PTunnelBuildTransport {
    private weak var ntcp2: NTCP2Transport?
    /// Demand-dial hook: resolves the endpoint for a router hash and initiates
    /// the NTCP2 connect. Wired by the running router context.
    var dialPeer: ((Data) async -> Bool)?
    /// Dial window before a build send gives up on a fresh handshake.
    var dialTimeout: TimeInterval = 6

    init(ntcp2: NTCP2Transport) {
        self.ntcp2 = ntcp2
    }

    func sendBuild(_ message: I2PTunnelBuildMessage, to routerHash: Data) {
        let envelope = I2NPMessage(type: .tunnelBuild,
                                   messageID: message.messageID,
                                   expiration: Date().addingTimeInterval(60),
                                   payload: message.serialize())
        sendAfterDial(envelope.serialize(), to: routerHash)
    }

    func sendBuildReply(_ body: Data, to routerHash: Data) {
        let envelope = I2NPMessage(type: .tunnelBuildReply,
                                   expiration: Date().addingTimeInterval(60),
                                   payload: body)
        sendAfterDial(envelope.serialize(), to: routerHash)
    }

    /// The NTCP2 transport carries tunnel data, so an outbound endpoint's reply
    /// can ride the creator's inbound tunnel: the OutboundTunnelBuildReply is
    /// wrapped in a TunnelGateway addressed to the reply route's tunnel ID and
    /// delivered to that tunnel's gateway. Without this a creator behind NAT can
    /// never receive the reply a remote OBEP sends to its reply route.
    let supportsTunnelBuildReplies = true

    func sendBuildReply(_ body: Data, throughTunnel tunnelID: UInt32, to gatewayRouterHash: Data) {
        let inner = I2NPMessage(type: .tunnelBuildReply,
                                expiration: Date().addingTimeInterval(60),
                                payload: body)
        let gateway = I2PTunnelGatewayPayload(gatewayID: tunnelID,
                                              message: inner.serialize())
        let envelope = I2NPMessage(type: .tunnelGateway, payload: gateway.serialize())
        sendAfterDial(envelope.serialize(), to: gatewayRouterHash)
    }

    /// Sends immediately over an established session; otherwise dials and
    /// retries inside the dial window so a fresh handshake can carry the build.
    private func sendAfterDial(_ i2npBytes: Data, to routerHash: Data) {
        guard let ntcp2 else { return }
        if ntcp2.hasSession(for: routerHash) {
            try? ntcp2.send(to: routerHash, data: i2npBytes)
            return
        }
        Task { [weak self] in
            guard let self else { return }
            if let dialPeer {
                _ = await dialPeer(routerHash)
            }
            let deadline = Date().addingTimeInterval(dialTimeout)
            while !ntcp2.hasSession(for: routerHash), Date() < deadline {
                try? await Task.sleep(for: .milliseconds(300))
            }
            guard ntcp2.hasSession(for: routerHash) else { return }
            try? ntcp2.send(to: routerHash, data: i2npBytes)
        }
    }
}

/// Supplies real mainnet routers as tunnel-hop candidates: the signature-verified
/// RouterInfos in the live netdb (not the floodfill set alone — hop selection
/// draws on every known peer and prefers ordinary routers). Candidates are
/// filtered and scored by I2PTunnelPeerSelector: freshness, a usable X25519
/// identity, a reachable NTCP2/SSU2 address, and each peer's build profile.
/// Build records encrypt to each hop's X25519 identity key.
final class I2PMainnetTunnelPeerProvider: I2PTunnelPeerProvider {
    /// Hop candidates the netdb supplies: enough for several concurrent pools
    /// without turning the cache into a selection cost.
    static let candidateLimit = 256
    /// The candidate snapshot is refreshed on this cadence; the pool also asks
    /// for a refresh whenever it runs short of hops.
    static let candidateRefreshInterval: TimeInterval = 120

    private let netDB: I2PNetworkDatabase
    private let selector: I2PTunnelPeerSelector
    private let lock = NSLock()
    private var candidates: [(hash: Data, info: I2PRouterInfo)] = []
    private var lastRefresh = Date.distantPast
    private var refreshing = false

    /// Whether this router holds a live session to a peer; forwarded to the
    /// selector so connected peers outrank cold ones as hops.
    var isConnected: ((Data) -> Bool)? {
        get { selector.isConnected }
        set { selector.isConnected = newValue }
    }

    init(netDB: I2PNetworkDatabase, selector: I2PTunnelPeerSelector = I2PTunnelPeerSelector()) {
        self.netDB = netDB
        self.selector = selector
    }

    /// Refreshes the hop candidates from the live netdb (cache-first RouterInfo
    /// reads; only modern identities survive the netdb's signature-verified
    /// ingest, so every candidate carries a usable X25519 encryption key).
    func refreshCandidates(limit: Int = I2PMainnetTunnelPeerProvider.candidateLimit) async {
        lock.lock()
        refreshing = true
        lock.unlock()
        let snapshot = await netDB.cachedRouterInfos(limit: limit)
        lock.lock()
        candidates = snapshot
        lastRefresh = Date()
        refreshing = false
        lock.unlock()
    }

    func peers(count: Int, excluding: Set<Data>) -> [I2PTunnelPeer] {
        refreshIfStale()
        lock.lock()
        let snapshot = candidates
        lock.unlock()
        return selector.select(count: count, excluding: excluding, from: snapshot,
                               localRouterHash: netDB.localRouterHash)
    }

    func refreshPeers() async -> Bool {
        await refreshCandidates()
        return !peers(count: 1, excluding: []).isEmpty
    }

    func recordBuildOutcome(_ outcome: I2PTunnelPeerBuildOutcome) {
        selector.recordBuildOutcome(outcome)
    }

    /// Live candidate count, for diagnostics and the audit surfaces.
    var candidateCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return candidates.count
    }

    /// Kicks off a background refresh when the candidate snapshot has aged out.
    private func refreshIfStale() {
        lock.lock()
        let stale = Date().timeIntervalSince(lastRefresh) >= Self.candidateRefreshInterval
        let busy = refreshing
        if stale && !busy { refreshing = true }
        lock.unlock()
        guard stale && !busy else { return }
        Task { [weak self] in
            guard let self else { return }
            let snapshot = await netDB.cachedRouterInfos(limit: Self.candidateLimit)
            lock.lock()
            candidates = snapshot
            lastRefresh = Date()
            refreshing = false
            lock.unlock()
        }
    }
}