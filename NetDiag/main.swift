// Live NTCP2 diagnosis: prints our published RouterInfo next to real
// floodfills' and reports exactly how far each handshake gets.
// Not part of the app target.
//
// Top-level code on purpose: this file is named main.swift, so it already
// provides the entry point and the compiler rejects an `@main` type here.
//
//    swiftc -swift-version 5 -o .probe-build/netdiag \
//        Untitled1/I2P/*.swift NetDiag/main.swift
//    ./.probe-build/netdiag

import Foundation
import CryptoKit

I2PRouterAppContext.shared.start()
let context = I2PRouterAppContext.shared
let netDB = context.mainnetNetDB
let ntcp2 = context.mainnetNTCP2

await context.ensureReachableAddress()
let own = context.mainnetSignedRouterInfo
print("OUR RI published=\(own.published) sigOK=\(own.verifySignature())")
print("  options: \(own.options)")
for address in own.addresses {
    print("  address cost=\(address.cost) style=\(address.transportStyle) expiration=\(String(describing: address.expiration))")
    print("    options: \(address.options)")
}
print("  routerHash: \(context.mainnetRouterHash.hex)")

do {
    let report = try await I2PReseedService.reseed(into: netDB)
    print("reseed: \(report.fetchedFrom) ingested=\(report.ingested) rejected=\(report.rejected) floodfills=\(report.floodfillCount)")
} catch {
    print("reseed failed: \(error)")
}

let candidates = await netDB.selectFloodfills(for: I2PCrypto.randomBytes(32), count: 40)
var dialed: [(hash: Data, endpoint: NTCP2PeerEndpoint)] = []
for hash in candidates {
    if dialed.count >= 3 { break }
    guard let info = await netDB.lookupRouterInfo(hash, timeoutPerRound: 1, maxRounds: 1),
          let endpoint = NTCP2PeerEndpoint.preferred(from: info.addresses) else { continue }
    print("\nPEER \(String(hash.hex.prefix(12))) options=\(info.options)")
    for address in info.addresses {
        print("  address cost=\(address.cost) style=\(address.transportStyle) options=\(address.options)")
    }
    print("  dialing \(endpoint.host):\(endpoint.port) iv=\(endpoint.iv?.count ?? -1)B")
    dialed.append((hash, endpoint))
}

for target in dialed where !ntcp2.hasSession(for: target.hash) {
    ntcp2.connect(host: target.endpoint.host, port: target.endpoint.port,
                  remoteRouterHash: target.hash,
                  remoteStaticKey: target.endpoint.staticKey,
                  remoteIV: target.endpoint.iv)
}
try? await Task.sleep(for: .seconds(20))
print("\nsessions: \(ntcp2.sessionCount())")
print("summaries: \(ntcp2.sessionSummaries().map { String($0.hash.hex.prefix(12)) })")
print("closes:")
for close in ntcp2.recentCloses() { print("  \(close)") }
print("audit log:")
for entry in I2PSecurityAuditLog.recent(limit: 30) where entry.category == "transport" {
    print("  [\(entry.category)] \(entry.detail)")
}
exit(0)
