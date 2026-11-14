// Message-1 diagnosis: produces a real SessionRequest toward a reseeded
// floodfill and prints every ingredient needed to validate it independently.

import Foundation
import CryptoKit

@main
struct Msg1Probe {
    static func main() async {
        let context = I2PRouterAppContext.shared
        context.start()
        let netDB = context.mainnetNetDB
        _ = try? await I2PReseedService.reseed(into: netDB)
        let candidates = await netDB.selectFloodfills(for: I2PCrypto.randomBytes(32), count: 40)
        for hash in candidates {
            guard let info = await netDB.lookupRouterInfo(hash, timeoutPerRound: 1, maxRounds: 1),
                  let endpoint = NTCP2PeerEndpoint.preferred(from: info.addresses),
                  let iv = endpoint.iv else { continue }
            print("peerHash=\(info.identity.hash.hex)")
            print("peerS=\(endpoint.staticKey.hex)")
            print("peerIV=\(iv.hex)")
            let engine = try! NTCP2InitiatorHandshake(localStaticKey: context.mainnetEncryptionKey,
                                                     remoteStaticKey: endpoint.staticKey,
                                                     remoteRouterHash: info.identity.hash,
                                                     remoteIV: iv)
            let request = try! engine.makeSessionRequest(routerInfo: context.mainnetSignedRouterInfo.serialize())
            print("msg1=\(request.hex)")
            print("m3p2len=\(engine.announcedPart2Length)")
            #if false
            #endif
            // Ephemeral secret for independent Noise verification (Mirror reads
            // the engine's private stored property; this is a throwaway key).
            let mirror = Mirror(reflecting: engine)
            for child in mirror.children where child.label == "ephemeral" {
                if let value = child.value as? Curve25519.KeyAgreement.PrivateKey?,
                   let key = value {
                    print("ephemeralPriv=\(key.rawRepresentation.hex)")
                }
            }
            // Independent recomputation of the Noise prefix for cross-checking.
            var chain = NTCP2NoiseChain()
            chain.mixHash(endpoint.staticKey)
            print("hAfterRs=\(chain.hash.hex) ckAfterRs=\(chain.chainingKey.hex)")
            break
        }
        exit(0)
    }
}
