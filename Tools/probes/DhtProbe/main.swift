// DHT round-trip diagnosis: which floodfills a lookup picks, whether they have
// live sessions, and what actually comes back. Not part of the app target.

import Foundation
import CryptoKit

final class InboundCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var counts: [String: Int] = [:]
    func record(_ message: I2NPMessage) {
        lock.lock(); counts[String(describing: message.type), default: 0] += 1; lock.unlock()
    }
    func snapshot() -> String {
        lock.lock(); defer { lock.unlock() }
        return counts.map { "\($0.key)=\($0.value)" }.sorted().joined(separator: " ")
    }
}

let context = I2PRouterAppContext.shared
context.start()
let netDB = context.mainnetNetDB
let ntcp2 = context.mainnetNTCP2

if let report = try? await I2PReseedService.reseed(into: netDB) {
    print("reseed: from=\(report.fetchedFrom) ingested=\(report.ingested) floodfills=\(report.floodfillCount) deferred=\(report.deferredHashes.count)")
} else {
    print("reseed: failed")
}
await context.ensureReachableAddress()
print("netdb before: entries=\(await netDB.entryCount()) floodfills=\(await netDB.floodfillCount()) peers=\(await netDB.knownPeerCount())")

let counter = InboundCounter()
context.mainnetI2NPRouter.addBodyHandler { message, _ in counter.record(message) }

// Dial the closest floodfills for our own hash, as the publish row does.
let targets = await netDB.selectFloodfills(for: context.mainnetRouterHash, count: 8)
for hash in targets.prefix(5) where !ntcp2.hasSession(for: hash) {
    guard let info = await netDB.lookupRouterInfo(hash, timeoutPerRound: 2, maxRounds: 1),
          let endpoint = NTCP2PeerEndpoint.preferred(from: info.addresses) else { continue }
    ntcp2.connect(host: endpoint.host, port: endpoint.port,
                  remoteRouterHash: hash,
                  remoteStaticKey: endpoint.staticKey,
                  remoteIV: endpoint.iv)
}
try? await Task.sleep(for: .seconds(10))
print("sessions=\(ntcp2.sessionCount()) of \(targets.count) closest floodfills")
let acks = await netDB.publish(routerInfo: context.mainnetSignedRouterInfo)
print("publish acks=\(acks)")

// What does a lookup actually pick, and can any of them be reached now?
let probeKey = I2PCrypto.randomBytes(32)
let picked = await netDB.selectFloodfills(for: probeKey, count: 5)
for hash in picked {
    print("lookup candidate \(String(hash.hex.prefix(8))) session=\(ntcp2.hasSession(for: hash))")
}
let started = Date()
let outcome = await netDB.probeLookup(probeKey, timeoutPerRound: 8)
print("probeLookup answered=\(outcome.answered) servedEntry=\(outcome.servedEntry) peers=\(outcome.peers) in \(String(format: "%.2f", Date().timeIntervalSince(started)))s")
print("inbound after probe: \(counter.snapshot())")
print("sessions after probe=\(ntcp2.sessionCount())")
for close in ntcp2.recentCloses(limit: 6) { print("close: \(close)") }
exit(0)
