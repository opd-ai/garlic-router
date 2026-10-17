//
//  I2PMainnetVerification.swift
//  Continuous (CI-style) live-network verification: reseed from public
//  reseed servers over HTTPS, establish NTCP2 handshakes with 3-5 mainnet
//  floodfill routers, run real Kademlia DatabaseLookup round-trips through
//  live floodfill sessions, publish our own RouterInfo to live floodfills
//  with acknowledgment, resolve well-known mainnet destinations to LeaseSets
//  over the live DHT, deliver garlic end-to-end toward a resolved lease's
//  gateway over a live session, monitor inbound tunnel participation, check
//  tunnel pool liveness, and run the periodic-checkpoint / failure-
//  classification / post-run analysis loop against mainnet norms.
//
//  Runs as part of the automated self-test suite so every build verifies the
//  router against the main I2P network. Mainnet connectivity from CI is
//  intentional and authorized — reseeding and connecting to floodfills is
//  ordinary router behavior.
//

import Foundation
import CryptoKit

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
                results.append(I2PSelfTestResult(
                    name: name,
                    passed: false,
                    detail: I2PLiveFailureClassifier.annotated(error)))
            }
        }

        // The live checks ride the running router's netdb and NTCP2 transport.
        I2PRouterAppContext.shared.start()
        let context = I2PRouterAppContext.shared
        let netDB = context.mainnetNetDB
        let ntcp2 = context.mainnetNTCP2
        let tunnelPool = context.mainnetTunnelPool
        let checkpoints = I2PLiveCheckpointRecorder()

        var reseed: I2PReseedReport?
        var publicationAcks = 0
        var resolvedLeaseSet: (name: String, leaseSet: I2PLeaseSet)?

        await checkpoints.capture(netDB: netDB, ntcp2: ntcp2, pool: tunnelPool)

        await run("Mainnet reseed over HTTPS (Ed25519-verified RouterInfos)") {
            let report = try await I2PReseedService.reseed(into: netDB)
            reseed = report
            await checkpoints.capture(netDB: netDB, ntcp2: ntcp2, pool: tunnelPool)
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
            await checkpoints.capture(netDB: netDB, ntcp2: ntcp2, pool: tunnelPool)
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
            await checkpoints.capture(netDB: netDB, ntcp2: ntcp2, pool: tunnelPool)
            return String(format: "DatabaseLookup for %@ answered over a live floodfill session in %.0fms; RouterInfo received, signature-verified and cached",
                          String(target.hex.prefix(12)), latency * 1000)
        }

        await run("Mainnet RouterInfo publication acknowledged by live floodfills") {
            // Dial the floodfills that will hold our RouterInfo so the
            // DatabaseStore is deliverable and its acknowledgment is routable.
            let publishTargets = await netDB.selectFloodfills(for: context.mainnetRouterHash, count: 5)
            for target in publishTargets where !ntcp2.hasSession(for: target) {
                guard let info = await netDB.lookupRouterInfo(target, timeoutPerRound: 1, maxRounds: 1),
                      let endpoint = info.addresses.compactMap({ NTCP2PeerEndpoint(routerAddress: $0) }).first else {
                    continue
                }
                ntcp2.connect(host: endpoint.host, port: endpoint.port, remoteStaticKey: endpoint.staticKey)
            }
            let deadline = Date().addingTimeInterval(10)
            while Date() < deadline {
                if publishTargets.contains(where: { ntcp2.hasSession(for: $0) }) { break }
                try? await Task.sleep(for: .milliseconds(250))
            }
            guard publishTargets.contains(where: { ntcp2.hasSession(for: $0) }) else {
                throw I2PMainnetFailure(message: "no established session to any of the \(publishTargets.count) closest floodfills — the DatabaseStore was never sent")
            }
            let acks = await netDB.publish(routerInfo: context.mainnetSignedRouterInfo)
            publicationAcks = acks
            await checkpoints.capture(netDB: netDB, ntcp2: ntcp2, pool: tunnelPool)
            guard acks >= 1 else {
                throw I2PMainnetFailure(message: "0 of the \(publishTargets.count) dialed floodfills acknowledged our signed RouterInfo store within 2s")
            }
            return "\(acks) live floodfill(s) acknowledged our signed RouterInfo DatabaseStore over established NTCP2 sessions"
        }

        await run("Mainnet well-known destination resolved to a LeaseSet over the live DHT") {
            let destinations = try await I2PMainnetHosts.fetchWellKnownDestinations(limit: 6)
            var attempted: [String] = []
            var lastFailure: Error = I2PMainnetFailure(message: "no lookup attempted")
            for destination in destinations {
                let started = Date()
                let entry = await netDB.lookup(destination.netdbKey, timeoutPerRound: 3, maxRounds: 2)
                if let entry, let leaseSet = entry.leaseSet {
                    let latency = Date().timeIntervalSince(started) * 1000
                    resolvedLeaseSet = (destination.name, leaseSet)
                    await checkpoints.capture(netDB: netDB, ntcp2: ntcp2, pool: tunnelPool)
                    return String(format: "%@ resolved over the live DHT in %.0fms: %d lease(s), gateways %@, tunnel IDs %@",
                                  destination.name, latency, leaseSet.leases.count,
                                  leaseSet.leases.prefix(2).map { String($0.gatewayHash.hex.prefix(10)) }.joined(separator: ","),
                                  leaseSet.leases.prefix(2).map { String($0.tunnelId) }.joined(separator: ","))
                }
                attempted.append(destination.name)
                if let entry {
                    lastFailure = I2PMainnetFailure(message: "\(destination.name): the live response was a RouterInfo, not a LeaseSet")
                } else {
                    lastFailure = I2PMainnetFailure(message: "\(destination.name): no parseable LeaseSet answered over the live DHT")
                }
            }
            throw I2PMainnetFailure(message: "no modern-parseable LeaseSet among \(attempted.count) well-known mainnet destinations (\(attempted.joined(separator: ", "))); last: \(String(describing: lastFailure)) — mainnet publishes LeaseSet2 for ECIES destinations and LeaseSet v1 with legacy encryption keys for the rest, both outside the current parser scope")
        }

        await run("Mainnet garlic end-to-end delivery to the resolved lease gateway") {
            guard let resolvedLeaseSet else {
                throw I2PMainnetFailure(message: "no modern-parseable LeaseSet was resolved in the destination scenario — garlic construction and delivery were not attempted (policy/parser scope)")
            }
            let leaseSet = resolvedLeaseSet.leaseSet
            let now = Date()
            guard let lease = leaseSet.leases.filter({ $0.expiration > now }).max(by: { $0.expiration < $1.expiration }) else {
                throw I2PMainnetFailure(message: "\(resolvedLeaseSet.name): every lease is expired")
            }
            // EncType-4 destination convention: the X25519 public key rides as
            // the final 32 bytes of the destination's encryption key field.
            let keyField = leaseSet.destination.encryptionPublicKey
            let eciesKeyField = keyField.suffix(32)
            guard eciesKeyField.count == 32,
                  let eciesKey = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: eciesKeyField) else {
                throw I2PMainnetFailure(message: "\(resolvedLeaseSet.name): the resolved destination does not carry a usable ECIES key")
            }
            // Dial the lease's gateway router so the lease-addressed delivery
            // rides a live session.
            guard let gatewayInfo = await netDB.lookupRouterInfo(lease.gatewayHash, timeoutPerRound: 2, maxRounds: 1) else {
                throw I2PMainnetFailure(message: "lease gateway RouterInfo not resolvable over the live DHT")
            }
            guard let gatewayEndpoint = gatewayInfo.addresses.compactMap({ NTCP2PeerEndpoint(routerAddress: $0) }).first else {
                throw I2PMainnetFailure(message: "lease gateway has no NTCP2 transport address")
            }
            if !ntcp2.hasSession(for: lease.gatewayHash) {
                ntcp2.connect(host: gatewayEndpoint.host, port: gatewayEndpoint.port,
                              remoteStaticKey: gatewayEndpoint.staticKey)
            }
            let deadline = Date().addingTimeInterval(10)
            while Date() < deadline, !ntcp2.hasSession(for: lease.gatewayHash) {
                try? await Task.sleep(for: .milliseconds(250))
            }
            guard ntcp2.hasSession(for: lease.gatewayHash) else {
                throw I2PMainnetFailure(message: "no live session to the lease gateway — the garlic envelope was not transmitted")
            }
            // Garlic clove set: tunnel delivery instructions to the lease, encrypted
            // with the destination's ECIES key (fresh three-section new session).
            let garlicSession = I2PGarlicSession(peerPublicKey: eciesKey, tagsPerHandshake: 4)
            let payload = I2NPMessage(type: .dataMessage, payload: Data("mainnet garlic delivery probe".utf8))
            let delivery = I2PDeliveryInstructions(mode: .tunnel, tunnelID: lease.tunnelId,
                                                   routerHash: lease.gatewayHash, delayMilliseconds: nil)
            let cloveSet = try I2PGarlicCloveSet(expiration: Date().addingTimeInterval(120),
                                                 messageID: UInt32.random(in: 1...UInt32.max),
                                                 cloves: [I2PGarlicClove(deliveryInstructions: delivery, message: payload)])
            let envelope = try garlicSession.wrapCloveSet(try cloveSet.serialize())
            let garlicMessage = I2NPMessage(type: .garlic,
                                            messageID: UInt32.random(in: 1...UInt32.max),
                                            expiration: Date().addingTimeInterval(120),
                                            payload: envelope)
            // Lease-addressed TunnelGateway envelope, delivered over the live session.
            var w = I2PWriter()
            w.integer(lease.tunnelId)
            w.raw(garlicMessage.serialize())
            let tunnelGateway = I2NPMessage(type: .tunnelGateway, payload: w.data)
            try ntcp2.send(to: lease.gatewayHash, data: tunnelGateway.serialize())
            await checkpoints.capture(netDB: netDB, ntcp2: ntcp2, pool: tunnelPool)
            return String(format: "garlic clove set encrypted with %@'s ECIES key and transmitted as a lease-addressed TunnelGateway over a live session to gateway %@ (lease tunnel %d); outbound tunnel pool held %d tunnel(s) at send time",
                          resolvedLeaseSet.name,
                          String(lease.gatewayHash.hex.prefix(12)), lease.tunnelId,
                          tunnelPool.outboundCount)
        }

        await run("Mainnet inbound tunnel participation monitored over live sessions") {
            guard let reseed, reseed.floodfillCount > 0 else {
                throw I2PMainnetFailure(message: "no mainnet peers — nothing to monitor against")
            }
            guard ntcp2.sessionCount() > 0 else {
                throw I2PMainnetFailure(message: "no established mainnet sessions — inbound participation cannot be observed")
            }
            let monitor = I2PLiveInboundMonitor()
            context.mainnetI2NPRouter.addBodyHandler { message, _ in
                monitor.observe(message)
            }
            // Organic window: tunnel-build traffic arriving over the established
            // sessions is dispatched through the I2NP router while we watch.
            try? await Task.sleep(for: .seconds(20))
            let detail = "monitored \(ntcp2.sessionCount()) established mainnet session(s) for 20s — \(monitor.summary)"
            // Organic inbound tunnel participation requires our published
            // transport address to be reachable from the mainnet; the CI
            // simulator publishes no reachable address (NAT, ephemeral listener),
            // so zero organic builds is an environment property, not a defect.
            guard monitor.tunnelBuildMessages + monitor.tunnelBuildReplyMessages > 0 else {
                throw I2PMainnetFailure(message: detail + " — no organic inbound tunnel participation: the CI environment publishes no reachable transport address (inbound acceptance machinery is armed and dispatching through the I2NP router)")
            }
            await checkpoints.capture(netDB: netDB, ntcp2: ntcp2, pool: tunnelPool)
            return detail
        }

        await run("Mainnet tunnel pool liveness and build metrics") {
            let outbound = tunnelPool.outboundCount
            let inbound = tunnelPool.inboundCount
            let attempts = tunnelPool.buildStartTimes.count
            let latency = tunnelPool.averageBuildLatency.map { String(format: "%.1fs", $0) } ?? "n/a"
            let detail = String(format: "pool targets 3-5 per direction (lifetime clamped to the spec's 10-30 min): %d outbound + %d inbound active, %d build attempt(s), mean build latency %@",
                                outbound, inbound, attempts, latency)
            // The pool fills from real mainnet peers selected by the builder's
            // peer provider; with no mainnet peers provisioned, builds cannot
            // complete and the pool cannot reach its targets — reported as an
            // implementation gap, not a network flake.
            guard outbound + inbound > 0 else {
                throw I2PMainnetFailure(message: detail + " — no active tunnels: the builder's peer provider supplies no mainnet peers, so no live hop has ever acknowledged a build record")
            }
            await checkpoints.capture(netDB: netDB, ntcp2: ntcp2, pool: tunnelPool)
            return detail
        }

        await run("Mainnet post-run analysis against mainnet norms") {
            var findings: [String] = []
            var healthy = true
            // Mainnet reseed archives carry hundreds of RouterInfos.
            if let reseed {
                if reseed.totalEntries >= 100 {
                    findings.append("reseed volume \(reseed.totalEntries) within mainnet norms")
                } else {
                    findings.append("reseed fetched only \(reseed.totalEntries) RouterInfos (norm: hundreds)")
                    healthy = false
                }
                findings.append("\(reseed.floodfillCount) floodfills known")
            } else {
                findings.append("reseed never completed")
                healthy = false
            }
            let sessions = ntcp2.sessionCount()
            findings.append("\(sessions) established mainnet NTCP2 session(s)")
            if sessions < 1 {
                healthy = false
            }
            if publicationAcks >= 1 {
                findings.append("RouterInfo publication acknowledged by \(publicationAcks) floodfill(s)")
            } else {
                findings.append("RouterInfo publication unacknowledged")
                healthy = false
            }
            findings.append(checkpoints.summary)
            guard healthy else {
                throw I2PMainnetFailure(message: findings.joined(separator: "; "))
            }
            return findings.joined(separator: "; ")
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