//
//  I2PMainnetVerification.swift
//  Continuous (CI-style) live-network verification: reseed from public
//  reseed servers over HTTPS, establish NTCP2 handshakes with 3-5 mainnet
//  floodfill routers, and run a real Kademlia DatabaseLookup round-trip
//  through a live floodfill session.
//
//  Runs as part of the automated self-test suite so every build verifies the
//  router against the main I2P network. Mainnet connectivity from CI is
//  intentional and authorized — reseeding and connecting to floodfills is
//  ordinary router behavior.
//

import Foundation

/// Error carrying a human-readable detail line for test reporting.
struct I2PMainnetFailure: Error, CustomStringConvertible {
    let message: String
    var description: String { message }
}

enum I2PMainnetVerification {
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

        // The live checks ride the running router's netdb and NTCP2 transport.
        I2PRouterAppContext.shared.start()
        let context = I2PRouterAppContext.shared
        let netDB = context.mainnetNetDB
        let ntcp2 = context.mainnetNTCP2

        var reseed: I2PReseedReport?

        await run("Mainnet reseed over HTTPS (Ed25519-verified RouterInfos)") {
            let report = try await I2PReseedService.reseed(into: netDB)
            reseed = report
            return String(format: "%@: %d RouterInfos fetched, %d ingested after signature verification, %d rejected, %d floodfills known",
                          report.fetchedFrom, report.totalEntries,
                          report.ingested, report.rejected, report.floodfillCount)
        }

        await run("NTCP2 handshake with mainnet floodfills (baseline 3-5)") {
            guard let reseed, reseed.floodfillCount > 0 else {
                throw I2PMainnetFailure(message: "reseed produced no floodfill peers to dial")
            }
            let targets = try await dialTargets(netDB: netDB, ntcp2: ntcp2, limit: 5)
            for target in targets where !ntcp2.hasSession(for: target.hash) {
                ntcp2.connect(host: target.endpoint.host, port: target.endpoint.port,
                              remoteStaticKey: target.endpoint.staticKey)
            }
            let deadline = Date().addingTimeInterval(10)
            while Date() < deadline {
                let established = targets.filter { ntcp2.hasSession(for: $0.hash) }.count
                if established >= targets.count { break }
                try? await Task.sleep(for: .milliseconds(250))
            }
            let established = targets.filter { ntcp2.hasSession(for: $0.hash) }
            let failed = targets.filter { !ntcp2.hasSession(for: $0.hash) }
            for target in failed {
                ntcp2.closeSession(for: target.hash) // tear down half-open attempts
            }
            let detail = targets.map { target -> String in
                let ok = ntcp2.hasSession(for: target.hash)
                return "\(target.label): \(ok ? "handshake established" : "handshake failed")"
            }.joined(separator: "; ")
            guard established.count >= min(3, targets.count) else {
                throw I2PMainnetFailure(message: "mainnet NTCP2 handshakes \(established.count)/\(targets.count) — \(detail)")
            }
            return "mainnet NTCP2 handshakes \(established.count)/\(targets.count) established — \(detail)"
        }

        await run("Kademlia DHT DatabaseLookup round-trip with mainnet floodfills") {
            guard let reseed, !reseed.deferredHashes.isEmpty else {
                throw I2PMainnetFailure(message: "no deferred lookup target — reseed ingested everything")
            }
            let target = reseed.deferredHashes[0]
            let started = Date()
            let entry = await netDB.lookup(target, timeoutPerRound: 3, maxRounds: 2)
            let latency = Date().timeIntervalSince(started)
            guard let entry else {
                let sessions = ntcp2.sessionCount()
                throw I2PMainnetFailure(message: sessions == 0
                    ? "no established mainnet sessions — the DatabaseLookup was never sent"
                    : "no mainnet response for \(target.hex.prefix(12)) within 6s")
            }
            guard entry.routerInfo != nil else {
                throw I2PMainnetFailure(message: "mainnet response was not a RouterInfo")
            }
            return String(format: "DatabaseLookup for %@ answered over a live floodfill session in %.0fms; RouterInfo received, signature-verified and cached",
                          String(target.hex.prefix(12)), latency * 1000)
        }

        return results
    }

    private static func dialTargets(netDB: I2PNetworkDatabase, ntcp2: NTCP2Transport,
                                    limit: Int) async throws -> [(hash: Data, endpoint: NTCP2PeerEndpoint, label: String)] {
        var targets: [(hash: Data, endpoint: NTCP2PeerEndpoint, label: String)] = []
        let probeKey = I2PCrypto.randomBytes(32)
        let candidates = await netDB.selectFloodfills(for: probeKey, count: 80)
        for hash in candidates {
            if targets.count >= limit { break }
            guard let routerInfo = await netDB.lookupRouterInfo(hash, timeoutPerRound: 1, maxRounds: 1) else { continue }
            guard let endpoint = routerInfo.addresses.compactMap({ NTCP2PeerEndpoint(routerAddress: $0) }).first else { continue }
            targets.append((hash, endpoint, String(routerInfo.identity.hash.hex.prefix(12))))
        }
        guard !targets.isEmpty else {
            throw I2PMainnetFailure(message: "no floodfill RouterInfo with an NTCP2 endpoint in the reseed data")
        }
        return targets
    }
}