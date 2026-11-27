// NetDB wire diagnosis: does anything come back over an established session?
// Not part of the app target.

import Foundation
import CryptoKit

final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var byType: [String: Int] = [:]
    func record(_ message: I2NPMessage) {
        lock.lock(); byType[String(describing: message.type), default: 0] += 1; lock.unlock()
    }
    func snapshot() -> String {
        lock.lock(); defer { lock.unlock() }
        return byType.map { "\($0.key)=\($0.value)" }.sorted().joined(separator: " ")
    }
}

@main
struct DbProbe {
    static func main() async {
        let context = I2PRouterAppContext.shared
        context.start()
        let netDB = context.mainnetNetDB
        let ntcp2 = context.mainnetNTCP2
        _ = try? await I2PReseedService.reseed(into: netDB)
        await context.ensureReachableAddress()

        let counter = Counter()
        context.mainnetI2NPRouter.addBodyHandler { message, _ in
            counter.record(message)
        }

        let targets = await netDB.selectFloodfills(for: context.mainnetRouterHash, count: 12)
        var dialed: [Data] = []
        for hash in targets where dialed.count < 5 {
            guard let info = await netDB.lookupRouterInfo(hash, timeoutPerRound: 1, maxRounds: 1),
                  let endpoint = NTCP2PeerEndpoint.preferred(from: info.addresses) else { continue }
            if !ntcp2.hasSession(for: hash) {
                ntcp2.connect(host: endpoint.host, port: endpoint.port,
                              remoteRouterHash: hash,
                              remoteStaticKey: endpoint.staticKey,
                              remoteIV: endpoint.iv)
            }
            dialed.append(hash)
        }
        try? await Task.sleep(for: .seconds(8))
        print("sessions=\(ntcp2.sessionCount()) dialed=\(dialed.count)")
        print("inbound after handshakes: \(counter.snapshot())")

        let acks = await netDB.publish(routerInfo: context.mainnetSignedRouterInfo)
        print("publish acks=\(acks) sessions-after=\(ntcp2.sessionCount())")
        try? await Task.sleep(for: .seconds(6))
        print("inbound after publish: \(counter.snapshot()) sessions=\(ntcp2.sessionCount())")

        // Control: a trivial DeliveryStatus proves whether the data-phase frame
        // itself is accepted before blaming a netdb message body.
        var live: [Data] = []
        for hash in targets where live.count < 3 {
            if ntcp2.hasSession(for: hash) { live.append(hash) }
        }
        let before = Set(live.filter { ntcp2.hasSession(for: $0) })
        var status = I2PWriter()
        status.integer(12345)
        status.long(UInt64(Date().timeIntervalSince1970 * 1000))
        let statusMessage = I2NPMessage(type: .deliveryStatus, messageID: 4242, payload: status.data)
        for hash in live {
            do {
                try ntcp2.send(to: hash, data: statusMessage.serialize())
                print("sent DeliveryStatus to \(String(hash.hex.prefix(8)))")
            } catch { print("status send failed: \(error)") }
        }
        try? await Task.sleep(for: .seconds(8))
        let stillAlive = before.filter { ntcp2.hasSession(for: $0) }
        print("status control: \(stillAlive.count)/\(before.count) sessions still up; sessions=\(ntcp2.sessionCount())")

        let probeKey = I2PCrypto.randomBytes(32)
        print("lookup floodfills with sessions: \(live.map { String($0.hex.prefix(8)) })")
        if !live.isEmpty {
            let lookup = I2PDatabaseLookup(queryKey: probeKey, fromHash: context.mainnetRouterHash)
            let body = I2PNetDBI2NPBridge.outbound(.lookup(lookup)).serialize()
            for hash in live {
                do {
                    try ntcp2.send(to: hash, data: body)
                    print("sent lookup to \(String(hash.hex.prefix(8)))")
                } catch {
                    print("lookup send failed: \(error)")
                }
            }
        }
        try? await Task.sleep(for: .seconds(6))
        print("inbound after lookup: \(counter.snapshot()) sessions=\(ntcp2.sessionCount())")
        print("closes:")
        for close in ntcp2.recentCloses(limit: 8) { print("  \(close)") }
        exit(0)
    }
}
