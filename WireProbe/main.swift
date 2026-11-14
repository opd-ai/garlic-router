// Message-3 diagnosis: after the handshake "completes" on our side, does the
// peer keep the session when we send nothing? That separates a message-3
// rejection from a data-phase frame rejection. Not part of the app target.

import Foundation
import CryptoKit

@main
struct WireProbe {
    static func main() async {
        let context = I2PRouterAppContext.shared
        context.start()
        let netDB = context.mainnetNetDB
        let ntcp2 = context.mainnetNTCP2
        await context.ensureReachableAddress()
        let own = context.mainnetSignedRouterInfo
        print("our RI cost=\(own.addresses.first?.cost ?? -1) options=\(own.addresses.first?.options ?? [:])")
        print("router info version=\(own.options)")

        var floodfills = 0
        for _ in 0..<15 {
            floodfills = await netDB.floodfillCount()
            if floodfills > 0 { break }
            try? await Task.sleep(for: .seconds(2))
        }
        print("netdb entries=\(await netDB.entryCount()) floodfills=\(floodfills)")

        let candidates = await netDB.selectFloodfills(for: context.mainnetRouterHash, count: 40)
        var dialed = 0
        for hash in candidates {
            guard dialed < 3 else { break }
            guard let info = await netDB.lookupRouterInfo(hash, timeoutPerRound: 1, maxRounds: 1),
                  let endpoint = NTCP2PeerEndpoint.preferred(from: info.addresses) else { continue }
            print("=== peer \(String(hash.hex.prefix(12))) at \(endpoint.host):\(endpoint.port)")
            dialed += 1
            ntcp2.connect(host: endpoint.host, port: endpoint.port,
                          remoteRouterHash: hash,
                          remoteStaticKey: endpoint.staticKey,
                          remoteIV: endpoint.iv)
            var established = false
            for _ in 0..<32 {
                try? await Task.sleep(for: .milliseconds(250))
                if ntcp2.hasSession(for: hash) { established = true; break }
            }
            guard established else {
                print("handshake never completed: \(ntcp2.recentCloses(limit: 2))")
                continue
            }
            print("ours says established; sending nothing for 6s")
            try? await Task.sleep(for: .seconds(6))
            print("after 6s idle: alive=\(ntcp2.hasSession(for: hash))")

            let key = I2PCrypto.randomBytes(32)
            let lookup = I2PDatabaseLookup(queryKey: key, fromHash: context.mainnetRouterHash)
            try? ntcp2.send(to: hash, data: I2PNetDBI2NPBridge.outbound(.lookup(lookup)).serialize())
            for tick in 1...6 {
                try? await Task.sleep(for: .seconds(1))
                print("  t=\(tick)s after lookup alive=\(ntcp2.hasSession(for: hash))")
            }
        }

        print("\n=== audit log")
        for entry in I2PSecurityAuditLog.recent(limit: 70) {
            print("  [\(entry.category)] \(entry.detail)")
        }
        print("closes: \(ntcp2.recentCloses(limit: 10))")
        exit(0)
    }
}
