// Live state diagnosis for the mainnet suite: what the netdb, transport and
// lookup paths actually hold over time, so a failing row can be pinned to a
// real cause instead of a cascade. Not part of the app target.

import Foundation
import CryptoKit

@main
struct Diagnose {
    static func main() async {
        let context = I2PRouterAppContext.shared
        context.start()
        let netDB = context.mainnetNetDB
        let ntcp2 = context.mainnetNTCP2

        for tick in 1...12 {
            try? await Task.sleep(for: .seconds(5))
            let entries = await netDB.entryCount()
            let floodfills = await netDB.floodfillCount()
            let peers = await netDB.knownPeerCount()
            print("t=\(tick * 5)s entries=\(entries) floodfills=\(floodfills) peers=\(peers) sessions=\(ntcp2.sessionCount())")
        }

        print("--- reseed")
        do {
            let report = try await I2PReseedService.reseed(into: netDB)
            print("reseed OK from=\(report.fetchedFrom) signer=\(report.signer) entries=\(report.totalEntries) ingested=\(report.ingested) rejected=\(report.rejected) floodfills=\(report.floodfillCount)")
        } catch {
            print("reseed failed: \(error)")
        }

        print("--- netdb after reseed: entries=\(await netDB.entryCount()) floodfills=\(await netDB.floodfillCount()) peers=\(await netDB.knownPeerCount()) sessions=\(ntcp2.sessionCount())")

        print("--- hosts.txt")
        do {
            let destinations = try await I2PMainnetHosts.fetchWellKnownDestinations(limit: 6)
            print("hosts: \(destinations.map { $0.name })")
            for destination in destinations.prefix(3) {
                let started = Date()
                let entry = await netDB.lookup(destination.netdbKey, timeoutPerRound: 3, maxRounds: 2)
                let ms = Int(Date().timeIntervalSince(started) * 1000)
                if let entry {
                    print("lookup \(destination.name) in \(ms)ms: type=\(entry.entryType) ri=\(entry.routerInfo != nil) ls=\(entry.leaseSet != nil) ls2=\(entry.leaseSet2 != nil) rawBytes=\(entry.rawPayload.count)")
                    if let ls2 = entry.leaseSet2 {
                        print("   ls2 storeType=\(ls2.storeType.rawValue) leases=\(ls2.leases.count) offline=\(ls2.hasOfflineSignature) resolved=\(ls2.resolvedLeaseSet()?.leases.count ?? -1)")
                    }
                } else {
                    print("lookup \(destination.name) in \(ms)ms: nothing (sessions=\(ntcp2.sessionCount()))")
                }
            }
        } catch {
            print("hosts failed: \(error)")
        }

        print("--- closes")
        for close in ntcp2.recentCloses(limit: 12) { print("  \(close)") }
        print("--- transport audit")
        for entry in I2PSecurityAuditLog.recent(limit: 40) where entry.category == "transport" {
            print("  \(entry.detail)")
        }
        exit(0)
    }
}
