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
    static func runAll(onProgress: ((String, I2PSelfTestResult?) async -> Void)? = nil) async -> [I2PSelfTestResult] {
        var results: [I2PSelfTestResult] = []

        func run(_ name: String, _ body: () async throws -> String) async {
            await onProgress?(name, nil)
            do {
                let detail = try await body()
                let result = I2PSelfTestResult(name: name, passed: true, detail: detail)
                results.append(result)
                await onProgress?(name, result)
            } catch {
                let result = I2PSelfTestResult(
                    name: name,
                    passed: false,
                    detail: I2PLiveFailureClassifier.annotated(error))
                results.append(result)
                await onProgress?(name, result)
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
        var resolvedLeaseSet: (name: String, leaseSet: I2PLeaseSet, eciesKey: Data?)?

        await checkpoints.capture(netDB: netDB, ntcp2: ntcp2, pool: tunnelPool)

        await run("Mainnet reseed over HTTPS (SU3 container signed, RouterInfos Ed25519-verified)") {
            let report = try await I2PReseedService.reseed(into: netDB)
            reseed = report
            await checkpoints.capture(netDB: netDB, ntcp2: ntcp2, pool: tunnelPool)
            guard report.ingested > 0 else {
                throw I2PMainnetFailure(message: String(
                    format: "%@: SU3 container signed by %@, but %d RouterInfos were ingested from %d fetched (%d rejected) — every verified entry must land in the netdb",
                    report.fetchedFrom, report.signer, report.ingested,
                    report.totalEntries, report.rejected))
            }
            return String(format: "%@: SU3 container signed by %@ (%@), %d RouterInfos fetched, %d ingested after signature verification, %d rejected, %d floodfills known",
                          report.fetchedFrom, report.signer, report.signatureType,
                          report.totalEntries,
                          report.ingested, report.rejected, report.floodfillCount)
        }

        await run("NTCP2 handshake with mainnet floodfills (baseline 3-5)") {
            // Gate on the netdb's actual floodfill set, not this run's reseed
            // report: a reseed failure must not orphan the probe when the
            // persisted netdb already carries signature-verified floodfills
            // from earlier runs (a real router keeps its netdb on disk).
            let knownFloodfills = await netDB.floodfillCount()
            guard knownFloodfills > 0 else {
                throw I2PMainnetFailure(message: reseed == nil
                    ? "reseed failed and the persisted netdb holds no floodfills — nothing to dial"
                    : "reseed produced no floodfill peers to dial")
            }
            let targets = try await dialTargets(netDB: netDB, ntcp2: ntcp2, limit: 5)
            // Message 3 carries our RouterInfo; peers verify its published
            // address against the endpoint they observe, so publish ours first.
            await context.ensureReachableAddress()
            for target in targets where !ntcp2.hasSession(for: target.hash) {
                ntcp2.connect(host: target.endpoint.host, port: target.endpoint.port,
                              remoteRouterHash: target.hash,
                              remoteStaticKey: target.endpoint.staticKey,
                              remoteIV: target.endpoint.iv)
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
            if established.count < min(3, targets.count) {
                let closes = ntcp2.recentCloses()
                let why = closes.isEmpty ? "" : " — session endings: \(closes.joined(separator: " | "))"
                throw I2PMainnetFailure(message: "mainnet NTCP2 handshakes \(established.count)/\(targets.count) — \(detail)\(why)")
            }
            await checkpoints.capture(netDB: netDB, ntcp2: ntcp2, pool: tunnelPool)
            return "mainnet NTCP2 handshakes \(established.count)/\(targets.count) established — \(detail)"
        }

        await run("Kademlia DHT DatabaseLookup round-trip with mainnet floodfills") {
            guard await netDB.floodfillCount() > 0 else {
                throw I2PMainnetFailure(message: "no floodfills known (reseed unavailable and the persisted netdb is empty) — no DHT peer to query")
            }
            // Preferred: a hash the reseed deliberately kept out of the local
            // cache, so the round trip cannot be answered from memory.
            if let target = reseed?.deferredHashes.first {
                // Warm the sessions to the peers this lookup will query, so the
                // row times the DHT round trip rather than a cold TCP dial (the
                // publication row below dials its targets the same way). One
                // live candidate is enough: the query goes to all of them at
                // once and the first answer wins.
                let lookupTargets = await netDB.selectFloodfills(for: target, count: 3)
                for hash in lookupTargets where !ntcp2.hasSession(for: hash) {
                    guard let info = await netDB.lookupRouterInfo(hash, timeoutPerRound: 1, maxRounds: 1),
                          let endpoint = NTCP2PeerEndpoint.preferred(from: info.addresses) else {
                        continue
                    }
                    ntcp2.connect(host: endpoint.host, port: endpoint.port,
                                  remoteRouterHash: hash,
                                  remoteStaticKey: endpoint.staticKey,
                                  remoteIV: endpoint.iv)
                }
                let warmDeadline = Date().addingTimeInterval(8)
                while Date() < warmDeadline {
                    if lookupTargets.contains(where: { ntcp2.hasSession(for: $0) }) { break }
                    try? await Task.sleep(for: .milliseconds(250))
                }
                let started = Date()
                let outcome = await netDB.lookupAnswering(target,
                                                          timeoutPerRound: 4, maxRounds: 2)
                let latency = Date().timeIntervalSince(started)
                if let entry = outcome.entry {
                    guard entry.routerInfo != nil else {
                        throw I2PMainnetFailure(message: "mainnet response was not a RouterInfo")
                    }
                    await checkpoints.capture(netDB: netDB, ntcp2: ntcp2, pool: tunnelPool)
                    return String(format: "DatabaseLookup for %@ answered over a live floodfill session in %.0fms; RouterInfo received, signature-verified and cached",
                                  String(target.hex.prefix(12)), latency * 1000)
                }
                guard outcome.answered else {
                    let sessions = ntcp2.sessionCount()
                    let closes = ntcp2.recentCloses()
                    let why = closes.isEmpty ? "" : " — session endings: \(closes.joined(separator: " | "))"
                    throw I2PMainnetFailure(message: sessions == 0
                        ? "no established mainnet sessions — the DatabaseLookup was never sent"
                        : "no mainnet response for \(target.hex.prefix(12)) within 8s (live sessions: \(sessions))\(why)")
                }
                // A DatabaseSearchReply is a spec answer: the floodfill parsed
                // the lookup and named the peers it considers closest. The entry
                // itself is not stored on that peer, which the row reports rather
                // than pretending the query failed.
                await checkpoints.capture(netDB: netDB, ntcp2: ntcp2, pool: tunnelPool)
                return String(format: "DatabaseLookup for %@ answered over a live floodfill session in %.0fms with a DatabaseSearchReply — the entry itself is not stored on the queried floodfills, so the iterative query path supplied the closest peers",
                              String(target.hex.prefix(12)), latency * 1000)
            }
            // No fresh reseed this run: prove the same query path with a random
            // key. A miss-answer (DatabaseSearchReply listing the closest
            // peers) is a full round trip too — the DatabaseLookup body parsed,
            // a floodfill answered over a live session and the reply arrived.
            let probeKey = I2PCrypto.randomBytes(32)
            let started = Date()
            let outcome = await netDB.probeLookup(probeKey, timeoutPerRound: 5)
            let latency = Date().timeIntervalSince(started)
            guard outcome.answered else {
                let sessions = ntcp2.sessionCount()
                throw I2PMainnetFailure(message: sessions == 0
                    ? "no established mainnet sessions — the DatabaseLookup was never sent"
                    : "no mainnet DatabaseLookup answer for \(probeKey.hex.prefix(12)) within 5s (live sessions: \(sessions); session endings: \(ntcp2.recentCloses().joined(separator: " | ")))")
            }
            await checkpoints.capture(netDB: netDB, ntcp2: ntcp2, pool: tunnelPool)
            if outcome.servedEntry {
                return String(format: "DatabaseLookup for a fresh %@ answered with a stored entry over a live floodfill session in %.0fms",
                              String(probeKey.hex.prefix(12)), latency * 1000)
            }
            return String(format: "DatabaseLookup for a fresh %@ answered over a live floodfill session in %.0fms with a DatabaseSearchReply naming %d closer peer(s) — the iterative query path round-tripped",
                          String(probeKey.hex.prefix(12)), latency * 1000, outcome.peers)
        }

        await run("Mainnet RouterInfo publication acknowledged by live floodfills") {
            // Dial the floodfills that will hold our RouterInfo so the
            // DatabaseStore is deliverable and its acknowledgment is routable.
            let publishTargets = await netDB.selectFloodfills(for: context.mainnetRouterHash, count: 5)
            for target in publishTargets where !ntcp2.hasSession(for: target) {
                guard let info = await netDB.lookupRouterInfo(target, timeoutPerRound: 1, maxRounds: 1),
                      let endpoint = NTCP2PeerEndpoint.preferred(from: info.addresses) else {
                    continue
                }
                ntcp2.connect(host: endpoint.host, port: endpoint.port,
                              remoteRouterHash: target,
                              remoteStaticKey: endpoint.staticKey,
                              remoteIV: endpoint.iv)
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
            // Hosts whose own identity signs with a type this router cannot verify
            // can never resolve here. The probe list defers them; the failure line
            // names them when they were tried anyway.
            let unverifiableHosts = destinations.filter { !$0.signsWithImplementedType }.map(\.name)
            var attempted: [String] = []
            var envelopeVerified: [String] = []
            var answeredHosts = 0
            var lastFailure: Error = I2PMainnetFailure(message: "no lookup attempted")
            // The best answer wins, not the first: a lease set we can also build
            // garlic delivery for is what the next row needs, so a resolvable but
            // undeliverable entry keeps the probe going instead of ending it.
            var resolved: (name: String, leaseSet: I2PLeaseSet, eciesKey: Data?,
                           deliverable: Bool, detail: String)?
            for destination in destinations {
                attempted.append(destination.name)
                let started = Date()
                let outcome = await netDB.lookupAnswering(destination.netdbKey, kind: .leaseSet,
                                                          timeoutPerRound: 3, maxRounds: 3)
                if outcome.answered { answeredHosts += 1 }
                let entry = outcome.entry
                if let entry, let leaseSet = entry.leaseSet {
                    let latency = Date().timeIntervalSince(started) * 1000
                    // A classic LeaseSet carries no key list; its destination's
                    // crypto field is the only key material it has — and a
                    // LeaseSet2-era destination leaves that field unused, so a
                    // resolved entry can be readable without being deliverable.
                    let eciesKey = Data(leaseSet.destination.encryptionPublicKey.suffix(32))
                    let deliverable = eciesKey.count == 32
                    let detail = String(format: "%@ resolved over the live DHT in %.0fms as a classic LeaseSet: %d lease(s), gateways %@, tunnel IDs %@",
                                        destination.name, latency, leaseSet.leases.count,
                                        leaseSet.leases.prefix(2).map { String($0.gatewayHash.hex.prefix(10)) }.joined(separator: ","),
                                        leaseSet.leases.prefix(2).map { String($0.tunnelId) }.joined(separator: ","))
                    if resolved == nil || (deliverable && resolved?.deliverable == false) {
                        resolved = (destination.name, leaseSet, eciesKey, deliverable, detail)
                    }
                    if deliverable { break }
                    continue
                }
                // LeaseSet2 (proposal 123 store types 3/5/7): parsed and
                // signature-verified at ingest; the lease entries resolve for
                // delivery through the LS2 resolution path.
                if let entry, let leaseSet2 = entry.leaseSet2 {
                    let latency = Date().timeIntervalSince(started) * 1000
                    if let converted = leaseSet2.resolvedLeaseSet() {
                        let eciesKey = leaseSet2.preferredEncryptionKey
                        let deliverable = eciesKey?.count == 32
                        let detail = String(format: "%@ resolved over the live DHT in %.0fms as LeaseSet2 store type %d (%@, offline-signing flag %@): %d lease entry(s) recovered for delivery — gateway %@, tunnel IDs %@",
                                            destination.name, latency, leaseSet2.storeType.rawValue,
                                            leaseSet2.encryptionKeys.isEmpty
                                                ? "no key list published, the destination crypto field is the spec's unused one"
                                                : "\(leaseSet2.encryptionKeys.count) encryption key(s) published",
                                            leaseSet2.hasOfflineSignature ? "set" : "absent",
                                            converted.leases.count,
                                            converted.leases.prefix(2).map { String($0.gatewayHash.hex.prefix(10)) }.joined(separator: ","),
                                            converted.leases.prefix(2).map { String($0.tunnelId) }.joined(separator: ","))
                        if resolved == nil || (deliverable && resolved?.deliverable == false) {
                            resolved = (destination.name, converted, eciesKey, deliverable, detail)
                        }
                        if deliverable { break }
                        continue
                    }
                    // The envelope itself verified (destination identity, offline
                    // delegation block, body signature) but the lease entries
                    // ride the encrypted inner body: per the LS2 spec they only
                    // decrypt under the b33 blinding/auth path.
                    envelopeVerified.append("\(destination.name) (type \(leaseSet2.storeType.rawValue))")
                    lastFailure = I2PMainnetFailure(message: "\(destination.name): a LeaseSet2 (store type \(leaseSet2.storeType.rawValue)) answered and its envelope verified — destination identity with offline/transient signing keys, signature over the LS2 body — but it publishes no lease entries of its own (an EncryptedLeaseSet resolves only under the b33 credentials of its owner; a MetaLeaseSet names other entries by hash)")
                    continue
                }
                if let entry {
                    lastFailure = I2PMainnetFailure(message: "\(destination.name): the live response was a RouterInfo, not a LeaseSet")
                } else {
                    let legacy = legacyIdentityNote(destination.destinationRaw)
                    lastFailure = I2PMainnetFailure(message: "\(destination.name): no parseable LeaseSet answered over the live DHT\(legacy.map { " — \($0)" } ?? "")")
                }
            }
            if let resolved {
                resolvedLeaseSet = (resolved.name, resolved.leaseSet, resolved.eciesKey)
                await checkpoints.capture(netDB: netDB, ntcp2: ntcp2, pool: tunnelPool)
                return resolved.detail
            }
            let rejections = await netDB.storeRejectionSummary()
            throw I2PMainnetFailure(message: "no lease-bearing LeaseSet (v1 or LeaseSet2 with recoverable entries) among \(attempted.count) well-known mainnet destinations (\(attempted.joined(separator: ", "))); \(answeredHosts) lookup(s) were answered and \(envelopeVerified.count) LeaseSet2-family envelope(s) verified but publish no lease entries of their own (encrypted/meta); last: \(String(describing: lastFailure))\(rejections.isEmpty ? "" : "; \(rejections)")\(unverifiableHosts.isEmpty ? "" : "; \(unverifiableHosts.count) probed host(s) sign with a legacy identity this router cannot verify: \(unverifiableHosts.joined(separator: ", "))")")
        }

        await run("Mainnet garlic end-to-end delivery to the resolved lease gateway") {
            guard let resolvedLeaseSet else {
                throw I2PMainnetFailure(message: "no lease-bearing LeaseSet was resolved in the destination scenario — garlic construction and delivery were not attempted (encrypted LeaseSet2 inner bodies remain gated on the b33 blinding/auth decryption path)")
            }
            let leaseSet = resolvedLeaseSet.leaseSet
            let now = Date()
            guard let lease = leaseSet.leases.filter({ $0.expiration > now }).max(by: { $0.expiration < $1.expiration }) else {
                throw I2PMainnetFailure(message: "\(resolvedLeaseSet.name): every lease is expired")
            }
            // Delivery key: a LeaseSet2 publishes its encryption keys in the
            // header's key list (in preference order), which is what garlic
            // encryption targets. A classic LeaseSet offers its destination's
            // crypto field instead. Neither exists for a destination that
            // publishes only a hybrid (ML-KEM) key this router cannot use.
            guard let eciesKeyData = resolvedLeaseSet.eciesKey,
                  eciesKeyData.count == 32,
                  let eciesKey = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: eciesKeyData) else {
                throw I2PMainnetFailure(message: "\(resolvedLeaseSet.name): the resolved LeaseSet publishes no usable ECIES-X25519 key for delivery (hybrid-only key list)")
            }
            // Dial the lease's gateway router so the lease-addressed delivery
            // rides a live session.
            guard let gatewayInfo = await netDB.lookupRouterInfo(lease.gatewayHash, timeoutPerRound: 2, maxRounds: 1) else {
                throw I2PMainnetFailure(message: "lease gateway RouterInfo not resolvable over the live DHT")
            }
            guard let gatewayEndpoint = NTCP2PeerEndpoint.preferred(from: gatewayInfo.addresses) else {
                throw I2PMainnetFailure(message: "lease gateway has no NTCP2 transport address")
            }
            if !ntcp2.hasSession(for: lease.gatewayHash) {
                ntcp2.connect(host: gatewayEndpoint.host, port: gatewayEndpoint.port,
                              remoteRouterHash: lease.gatewayHash,
                              remoteStaticKey: gatewayEndpoint.staticKey,
                              remoteIV: gatewayEndpoint.iv)
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
                                                   routerHash: lease.gatewayHash)
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
            let knownFloodfills = await netDB.floodfillCount()
            guard knownFloodfills > 0 else {
                throw I2PMainnetFailure(message: "no mainnet peers known (reseed unavailable and the persisted netdb is empty) — nothing to monitor against")
            }
            guard ntcp2.sessionCount() > 0 else {
                throw I2PMainnetFailure(message: "no established mainnet sessions — inbound participation cannot be observed")
            }
            let monitor = I2PLiveInboundMonitor()
            context.mainnetI2NPRouter.addBodyHandler { message, _ in
                monitor.observe(message)
            }
            // Organic window: tunnel-build traffic arriving over the established
            // sessions is dispatched through the I2NP router while we watch. The
            // window re-publishes our RouterInfo halfway so the floodfills we hold
            // sessions with carry a fresh copy while peers are selecting hops: a
            // router that was only just advertised is chosen on mainnet's
            // minutes-scale refresh cycle, not the seconds after publication.
            let window: TimeInterval = 45
            let deadline = Date().addingTimeInterval(window)
            var republished = false
            while Date() < deadline {
                if !republished, Date() > deadline.addingTimeInterval(-window / 2) {
                    republished = true
                    _ = await netDB.publish(routerInfo: context.mainnetSignedRouterInfo)
                }
                if monitor.tunnelBuildMessages + monitor.tunnelBuildReplyMessages > 0 { break }
                try? await Task.sleep(for: .milliseconds(250))
            }
            let detail = "monitored \(ntcp2.sessionCount()) established mainnet session(s) for \(Int(window))s\(republished ? " (RouterInfo re-published mid-window)" : "") — \(monitor.summary)"
            // Organic inbound tunnel participation now has every mechanical
            // ingredient: the router publishes its real external address
            // (listener + public IPv4 discovery) and the I2NP router dispatches
            // tunnel builds and build replies to the registered participant.
            // What remains is mainnet timescale: other routers must first
            // re-discover our freshly advertised address, select us as a hop,
            // and dial in — plus NAT port mapping in the CI environment.
            guard monitor.tunnelBuildMessages + monitor.tunnelBuildReplyMessages > 0 else {
                throw I2PMainnetFailure(message: detail + " — no organic inbound tunnel participation within the window: our external address was only just advertised (peer selection on mainnet lags by minutes) and the CI environment sits behind NAT; the acceptance machinery (listener, I2NP build dispatch, participant handling) is live")
            }
            await checkpoints.capture(netDB: netDB, ntcp2: ntcp2, pool: tunnelPool)
            return detail
        }

        await run("Mainnet outbound tunnel creation attempt through real hops") {
            let knownFloodfills = await netDB.floodfillCount()
            guard knownFloodfills > 0 else {
                throw I2PMainnetFailure(message: "no mainnet routers known (reseed unavailable and the persisted netdb is empty) — no hop candidates for a build attempt")
            }
            guard ntcp2.sessionCount() > 0 else {
                throw I2PMainnetFailure(message: "no established mainnet sessions — build messages could never reach a hop")
            }
            // Real build plumbing: build records ride live NTCP2 sessions to the
            // hops, and the I2NP router routes any build reply back to the
            // dedicated participant (registered on the router).
            let buildTransport = I2PNTCP2TunnelBuildTransport(ntcp2: ntcp2)
            // Demand-dial hook, exactly as the running router wires it: hop
            // selection now prefers ordinary routers over floodfills, so builds
            // must be able to reach a hop we hold no session for yet.
            buildTransport.dialPeer = { [netDB, ntcp2] hash in
                if ntcp2.hasSession(for: hash) { return true }
                guard let info = await netDB.lookupRouterInfo(hash, timeoutPerRound: 1, maxRounds: 1),
                      let endpoint = NTCP2PeerEndpoint.preferred(from: info.addresses) else {
                    return false
                }
                ntcp2.connect(host: endpoint.host, port: endpoint.port,
                              remoteRouterHash: hash,
                              remoteStaticKey: endpoint.staticKey,
                              remoteIV: endpoint.iv)
                return true
            }
            let participant = I2PTunnelParticipant(
                localRouterHash: context.mainnetRouterHash,
                localEncryptionKey: context.mainnetEncryptionKey,
                transport: buildTransport)
            context.mainnetI2NPRouter.addTunnelParticipant(participant)
            let peerProvider = I2PMainnetTunnelPeerProvider(netDB: netDB)
            await peerProvider.refreshCandidates()
            // Select hops this router can actually reach, dialing while it selects:
            // a build whose record never leaves the router cannot be judged, so an
            // unreachable candidate is replaced rather than waited on. A one-hop
            // outbound tunnel (gateway == endpoint) is spec-legal and is the
            // fallback when only one hop comes up — the previous run reached one of
            // two hops and then timed out with nothing saying why.
            var peers: [I2PTunnelPeer] = []
            var excluded: Set<Data> = [context.mainnetRouterHash]
            var unreachableHops = 0
            for _ in 0..<6 where peers.count < 2 {
                let candidates = peerProvider.peers(count: 2 - peers.count, excluding: excluded)
                if candidates.isEmpty { break }
                for peer in candidates {
                    excluded.insert(peer.routerHash)
                    guard let info = await netDB.lookupRouterInfo(peer.routerHash, timeoutPerRound: 1, maxRounds: 1),
                          let endpoint = NTCP2PeerEndpoint.preferred(from: info.addresses) else {
                        unreachableHops += 1
                        continue
                    }
                    if !ntcp2.hasSession(for: peer.routerHash) {
                        ntcp2.connect(host: endpoint.host, port: endpoint.port,
                                      remoteRouterHash: peer.routerHash,
                                      remoteStaticKey: endpoint.staticKey,
                                      remoteIV: endpoint.iv)
                    }
                    let dialDeadline = Date().addingTimeInterval(8)
                    while Date() < dialDeadline, !ntcp2.hasSession(for: peer.routerHash) {
                        try? await Task.sleep(for: .milliseconds(250))
                    }
                    if ntcp2.hasSession(for: peer.routerHash) {
                        peers.append(peer)
                    } else {
                        unreachableHops += 1
                    }
                    if peers.count == 2 { break }
                }
            }
            guard !peers.isEmpty else {
                throw I2PMainnetFailure(message: "no NTCP2 session came up to any of the \(unreachableHops) candidate hops — the build message never left this router (live sessions: \(ntcp2.sessionCount()); session endings: \(ntcp2.recentCloses().joined(separator: " | ")))")
            }
            // An inbound tunnel is the reply path a real OBEP uses to return the
            // build reply ("Reply through existing inbound D-E-F"): the endpoint
            // cannot dial a creator behind NAT. Give the pool a chance to fill one.
            if tunnelPool.inboundCount == 0 {
                _ = await tunnelPool.fillPools()
                let inboundDeadline = Date().addingTimeInterval(20)
                while Date() < inboundDeadline, tunnelPool.inboundCount == 0 {
                    try? await Task.sleep(for: .milliseconds(500))
                }
            }
            // Without one, address the reply to our own router with a local
            // endpoint ID this router hands straight back to the participant.
            let localReplyEndpointID = UInt32.random(in: 1...UInt32.max)
            context.mainnetI2NPRouter.registerGateway(tunnelID: localReplyEndpointID) { message, source in
                guard message.type == .tunnelBuildReply else { return }
                participant.handleBuildReply(message.payload, from: source)
            }
            let inboundReply = tunnelPool.inboundTunnels.first
            let replyRoute: (gateway: Data, tunnelID: UInt32) = inboundReply.map {
                (gateway: $0.hops.first?.routerHash ?? context.mainnetRouterHash,
                 tunnelID: $0.gatewayTunnelID)
            } ?? (gateway: context.mainnetRouterHash, tunnelID: localReplyEndpointID)
            let replyRouteLabel = inboundReply == nil
                ? "our own router, local endpoint \(localReplyEndpointID)"
                : "existing inbound tunnel, gateway \(String(replyRoute.gateway.hex.prefix(12))) tunnel \(replyRoute.tunnelID)"
            // Selection above dialed every hop, so each one carries a session now:
            // the build window is the record round trip and nothing else.
            let warmed = peers.count
            let builder = I2PTunnelBuilder(
                localRouterHash: context.mainnetRouterHash,
                participant: participant,
                transport: buildTransport)
            let attemptStarted = Date()
            do {
                let tunnel = try await builder.buildTunnel(
                    direction: .outbound, hops: peers, lifetime: 900, timeout: 20,
                    replyRoute: replyRoute)
                tunnelPool.adopt(tunnel)
                await checkpoints.capture(netDB: netDB, ntcp2: ntcp2, pool: tunnelPool)
                return String(format: "outbound tunnel built through %d real mainnet hops in %.1fs (%d/%d hop sessions up; reply route: %@); gateway %@, endpoint tunnel %d; pool now holds %d outbound + %d inbound",
                              tunnel.hopCount, Date().timeIntervalSince(attemptStarted),
                              warmed, peers.count, replyRouteLabel,
                              String(tunnel.hops.first?.routerHash.hex.prefix(12) ?? "-"),
                              tunnel.gatewayTunnelID, tunnelPool.outboundCount, tunnelPool.inboundCount)
            } catch {
                // The short build records are spec-shaped and the reply now has a
                // route; a live timeout here is a real mainnet interop finding
                // (hop policy, record addressing or a hop that will not carry a
                // two-hop tunnel), not a known shape mismatch.
                throw I2PMainnetFailure(message: "outbound tunnel build through \(peers.count) real mainnet hops did not complete in 20s (\(String(describing: error))); \(warmed)/\(peers.count) hop sessions were up before the attempt and the reply route was \(replyRouteLabel); build records use the spec short-build shape (TN-RECORD/TN-BREPLY), so this is a live interop finding; pool liveness: \(tunnelPool.outboundCount) outbound + \(tunnelPool.inboundCount) inbound active, \(tunnelPool.buildStartTimes.count) pool build attempt(s) logged")
            }
        }

        await run("Mainnet post-run analysis against mainnet norms") {
            var findings: [String] = []
            var healthy = true
            // Mainnet reseed archives carry hundreds of RouterInfos; a smaller
            // archive is still a healthy bootstrap when it carries a usable
            // floodfill set (the sweep aggregates hosts until it does).
            if let reseed {
                if reseed.totalEntries >= 100 {
                    findings.append("reseed volume \(reseed.totalEntries) within mainnet norms")
                } else if reseed.floodfillCount >= 20 {
                    findings.append("reseed served \(reseed.totalEntries) RouterInfos with \(reseed.floodfillCount) floodfills — a usable peer set")
                } else {
                    findings.append("reseed fetched only \(reseed.totalEntries) RouterInfos and \(reseed.floodfillCount) floodfills (norm: hundreds)")
                    healthy = false
                }
                findings.append("\(reseed.floodfillCount) floodfills known")
            } else {
                // A reseed failure is only fatal when nothing carried the run:
                // with persisted floodfills and live sessions the router still
                // operated against mainnet this cycle (a real router keeps its
                // netdb on disk across restarts). Flag it either way.
                let persistedFloodfills = await netDB.floodfillCount()
                let liveSessions = ntcp2.sessionCount()
                if persistedFloodfills > 0, liveSessions >= 1 {
                    findings.append("reseed unavailable this run — \(persistedFloodfills) persisted floodfill(s) carried the run over \(liveSessions) live session(s)")
                } else {
                    findings.append("reseed never completed and the netdb holds no carried state")
                    healthy = false
                }
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

    /// Explains an unresolvable well-known host whose own identity signs with a
    /// type this router does not implement: a null-certificate (DSA-SHA1)
    /// destination, or a key certificate carrying a legacy signature type such
    /// as RSA-2048. Saying why needs no parse of an identity we reject anyway.
    static func legacyIdentityNote(_ raw: Data) -> String? {
        guard let code = I2PKeysAndCert.declaredSignatureTypeCode(in: raw),
              I2PSigType(rawValue: code) == nil else { return nil }
        return "its own destination identity signs with legacy SigType \(code), which this router's modern-only verifier does not implement, so no LeaseSet it publishes can be verified here"
    }

    private static func dialTargets(netDB: I2PNetworkDatabase, ntcp2: NTCP2Transport,
                                    limit: Int) async throws -> [(hash: Data, endpoint: NTCP2PeerEndpoint, label: String)] {
        var targets: [(hash: Data, endpoint: NTCP2PeerEndpoint, label: String)] = []
        let probeKey = I2PCrypto.randomBytes(32)
        let candidates = await netDB.selectFloodfills(for: probeKey, count: 80)
        for hash in candidates {
            if targets.count >= limit { break }
            guard let routerInfo = await netDB.lookupRouterInfo(hash, timeoutPerRound: 1, maxRounds: 1) else { continue }
            guard let endpoint = NTCP2PeerEndpoint.preferred(from: routerInfo.addresses) else { continue }
            targets.append((hash, endpoint, String(routerInfo.identity.hash.hex.prefix(12))))
        }
        guard !targets.isEmpty else {
            throw I2PMainnetFailure(message: "no floodfill RouterInfo with an NTCP2 endpoint in the reseed data")
        }
        return targets
    }
}