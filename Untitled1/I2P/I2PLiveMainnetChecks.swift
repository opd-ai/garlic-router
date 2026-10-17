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
            || text.contains("unreachable") || text.contains("no live session") || text.contains("reseed") {
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
}

/// Resolves well-known public I2P services by fetching the standard hosts.txt
/// (destination base64 per entry) over HTTPS from the I2P source repository and
/// computing each destination's netdb key. No synthetic destinations.
enum I2PMainnetHosts {
    static let sources = [
        "https://raw.githubusercontent.com/i2p/i2p.i2p/master/hosts.txt"
    ]

    /// Long-lived public services worth probing first (i2pwiki and friends).
    static let preferredNames = [
        "i2p-projekt.i2p", "stats.i2p", "psi.i2p", "zzz.i2p",
        "i2pwiki.i2p", "tracker.welterde.i2p", "echelon.i2p"
    ]

    static func fetchWellKnownDestinations(limit: Int = 6) async throws -> [I2PWellKnownDestination] {
        var lastError: Error = I2PMainnetFailure(message: "no hosts.txt source reachable")
        for source in sources {
            do {
                guard let url = URL(string: source) else { continue }
                var request = URLRequest(url: url)
                request.timeoutInterval = 20
                request.setValue("I2P-Swift-Router/0.1", forHTTPHeaderField: "User-Agent")
                let (data, response) = try await URLSession.shared.data(for: request)
                guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
                    throw I2PMainnetFailure(message: "hosts.txt fetch returned a non-200 status")
                }
                let entries = parse(data)
                guard !entries.isEmpty else {
                    throw I2PMainnetFailure(message: "hosts.txt contained no parseable destinations")
                }
                var ordered: [I2PWellKnownDestination] = []
                for name in preferredNames {
                    if let entry = entries.first(where: { $0.name == name }), !ordered.contains(where: { $0.name == name }) {
                        ordered.append(entry)
                    }
                }
                for entry in entries where !ordered.contains(where: { $0.name == entry.name }) {
                    if ordered.count >= limit { break }
                    ordered.append(entry)
                }
                guard !ordered.isEmpty else {
                    throw I2PMainnetFailure(message: "hosts.txt yielded no probe destinations")
                }
                return Array(ordered.prefix(limit))
            } catch {
                lastError = error
            }
        }
        throw lastError
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
                                               destinationRaw: destination))
            if out.count >= 64 { break }
        }
        return out
    }

    static func base64Decode(_ text: String) -> Data? {
        var sanitized = text
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while sanitized.count % 4 != 0 { sanitized += "=" }
        return Data(base64Encoded: sanitized)
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