//
//  I2PSelfTest.swift
//  Round-trip serialization tests, crypto self-checks and sample structure builders.
//

import Foundation
import CryptoKit

struct I2PSelfTestResult {
    let name: String
    let passed: Bool
    let detail: String
}

extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}

// MARK: - Sample structure builders

enum I2PSamples {
    /// Generates a fresh Ed25519 seed plus a matching modern identity.
    static func sampleIdentity() -> (identity: I2PKeysAndCert, seed: Data) {
        let seed = I2PCrypto.generateEd25519Seed()
        let x25519 = I2PCrypto.generateX25519KeyPair()
        let identity = I2PKeysAndCert(
            encryptionPublicKey: x25519.publicKey,
            signingPublicKey: I2PCrypto.ed25519PublicKey(fromSeed: seed)
        )
        return (identity, seed)
    }

    static func sampleDestination() -> I2PDestination {
        let x25519 = I2PCrypto.generateX25519KeyPair()
        return I2PKeysAndCert(
            encryptionPublicKey: x25519.publicKey,
            signingPublicKey: I2PCrypto.ed25519PublicKey(fromSeed: I2PCrypto.generateEd25519Seed())
        )
    }

    static func sampleRouterInfo() throws -> I2PRouterInfo {
        let (identity, seed) = sampleIdentity()
        var info = I2PRouterInfo(
            identity: identity,
            published: Date(),
            addresses: [
                I2PRouterAddress(
                    cost: 5,
                    transportStyle: "NTCP2",
                    expiration: nil,
                    options: ["host": "192.0.2.1", "port": "8887"]
                )
            ],
            options: ["netid": "2", "router.version": "0.9.62"]
        )
        try info.sign(withSeed: seed)
        return info
    }

    static func sampleLeaseSet() throws -> I2PLeaseSet {
        let (destination, seed) = sampleIdentity()
        var leaseSet = I2PLeaseSet(
            destination: destination,
            published: Date(),
            leases: [
                I2PLease(
                    gatewayHash: I2PCrypto.sha256(Data("gateway-1".utf8)),
                    tunnelId: 0x1122_3344,
                    expiration: Date().addingTimeInterval(600)
                ),
                I2PLease(
                    gatewayHash: I2PCrypto.sha256(Data("gateway-2".utf8)),
                    tunnelId: 0x5566_7788,
                    expiration: Date().addingTimeInterval(700)
                )
            ]
        )
        try leaseSet.sign(withSeed: seed)
        return leaseSet
    }
}

// MARK: - Self-test suite

enum I2PSelfTest {
    /// Runs the synchronous core checks plus the async NetDB, NTCP2, and tunnel suites.
    static func runAll() async -> [I2PSelfTestResult] {
        var results = runCoreTests()
        results.append(contentsOf: await I2PNetDBSelfTest.runAll())
        results.append(contentsOf: await I2PNTCP2SelfTest.runAll())
        results.append(contentsOf: await I2PTunnelSelfTest.runAll())
        results.append(contentsOf: await I2NPSelfTest.runAll())
        results.append(contentsOf: await I2PGarlicSelfTest.runAll())
        return results
    }

    static func runCoreTests() -> [I2PSelfTestResult] {
        var results: [I2PSelfTestResult] = []
        func run(_ name: String, _ body: () throws -> String) {
            do {
                let detail = try body()
                results.append(I2PSelfTestResult(name: name, passed: true, detail: detail))
            } catch {
                results.append(I2PSelfTestResult(name: name, passed: false, detail: String(describing: error)))
            }
        }

        run("X25519 key agreement · EncType 4") {
            let a = I2PCrypto.generateX25519KeyPair()
            let b = I2PCrypto.generateX25519KeyPair()
            let ab = try I2PCrypto.x25519SharedSecret(privateKey: a.privateKey, peerPublicKey: b.publicKey)
            let ba = try I2PCrypto.x25519SharedSecret(privateKey: b.privateKey, peerPublicKey: a.publicKey)
            guard ab == ba, ab.count == 32 else { throw I2PWireError.invalidFormat }
            return "32-byte shared secret agreed both directions"
        }

        run("HKDF-SHA256 · RFC 5869 vector") {
            let ikm = Data(repeating: 0x0b, count: 22)
            let salt = Data((0x00...0x0c).map { UInt8($0) })
            let info = Data((0xf0...0xf9).map { UInt8($0) })
            let okm = I2PCrypto.hkdfSHA256(inputKeyMaterial: ikm, salt: salt, info: info, outputLength: 42)
            let expected = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
            guard okm.hex == expected else { throw I2PWireError.invalidFormat }
            return "42-byte output matches RFC 5869 test case 1"
        }

        run("ChaCha20-Poly1305 AEAD") {
            let key = I2PCrypto.randomBytes(32)
            let nonce = I2PCrypto.randomBytes(12)
            let message = I2PCrypto.randomBytes(97)
            let aad = Data("aad".utf8)
            let sealed = try I2PCrypto.chacha20Poly1305Seal(key: key, nonce: nonce, plaintext: message, aad: aad)
            let opened = try I2PCrypto.chacha20Poly1305Open(key: key, nonce: nonce, ciphertextAndTag: sealed, aad: aad)
            guard opened == message else { throw I2PWireError.invalidFormat }
            var tampered = sealed
            tampered[tampered.count - 5] ^= 0xff
            guard (try? I2PCrypto.chacha20Poly1305Open(key: key, nonce: nonce, ciphertextAndTag: tampered, aad: aad)) == nil else {
                throw I2PWireError.invalidSignature
            }
            return "\(sealed.count)-byte box sealed, opened, tamper rejected"
        }

        run("Ed25519 sign/verify · SigType 7") {
            let seed = I2PCrypto.generateEd25519Seed()
            let publicKey = I2PCrypto.ed25519PublicKey(fromSeed: seed)
            let message = Data("router-info-body".utf8)
            let signature = try I2PCrypto.ed25519Sign(message, seed: seed)
            guard signature.count == 64 else { throw I2PWireError.invalidFormat }
            guard I2PCrypto.ed25519Verify(signature: signature, message: message, publicKey: publicKey) else {
                throw I2PWireError.invalidSignature
            }
            guard !I2PCrypto.ed25519Verify(signature: signature, message: Data("tampered".utf8), publicKey: publicKey) else {
                throw I2PWireError.invalidSignature
            }
            return "64-byte signature verified, tamper rejected"
        }

        run("Ed25519ph sign/verify · SigType 11") {
            let seed = I2PCrypto.generateEd25519Seed()
            let publicKey = I2PCrypto.ed25519PurePublicKey(fromSeed: seed)
            let message = I2PCrypto.randomBytes(2048)
            guard let signature = I2PCrypto.ed25519phSign(message, seed: seed) else {
                throw I2PWireError.invalidFormat
            }
            guard I2PCrypto.ed25519phVerify(signature: signature, message: message, publicKey: publicKey) else {
                throw I2PWireError.invalidSignature
            }
            guard !I2PCrypto.ed25519phVerify(signature: signature, message: I2PCrypto.randomBytes(2048), publicKey: publicKey) else {
                throw I2PWireError.invalidSignature
            }
            return "pre-hashed EdDSA (dom2) verified, tamper rejected"
        }

        run("Pure Ed25519 ↔ CryptoKit cross-check") {
            let seed = I2PCrypto.generateEd25519Seed()
            let purePublic = I2PCrypto.ed25519PurePublicKey(fromSeed: seed)
            let kitPublic = I2PCrypto.ed25519PublicKey(fromSeed: seed)
            guard purePublic == kitPublic else { throw I2PWireError.invalidFormat }
            let message = Data("cross-validation".utf8)
            guard let pureSignature = I2PCrypto.ed25519PureSign(message, seed: seed) else {
                throw I2PWireError.invalidFormat
            }
            guard I2PCrypto.ed25519Verify(signature: pureSignature, message: message, publicKey: kitPublic) else {
                throw I2PWireError.invalidSignature
            }
            let kitSignature = try I2PCrypto.ed25519Sign(message, seed: seed)
            guard I2PCrypto.ed25519PureVerify(signature: kitSignature, message: message, publicKey: purePublic) else {
                throw I2PWireError.invalidSignature
            }
            return "public keys match; signatures interoperate both ways"
        }

        run("Binary primitives round trip") {
            var w = I2PWriter()
            w.byte(0xAB)
            w.short(0xCAFE)
            w.integer(0xDEAD_BEEF)
            w.long(0x0123_4567_89AB_CDEF)
            let hashValue = Data(repeating: 7, count: 32)
            w.hash(hashValue)
            w.string("NTCP2")
            w.mapping(["host": "192.0.2.1", "port": "8887"])
            let stamp = Date(timeIntervalSince1970: 1_700_000_000)
            w.date(stamp)
            var r = I2PReader(w.data)
            guard try r.byte() == 0xAB else { throw I2PWireError.invalidFormat }
            guard try r.short() == 0xCAFE else { throw I2PWireError.invalidFormat }
            guard try r.integer() == 0xDEAD_BEEF else { throw I2PWireError.invalidFormat }
            guard try r.long() == 0x0123_4567_89AB_CDEF else { throw I2PWireError.invalidFormat }
            guard try r.hash() == hashValue else { throw I2PWireError.invalidFormat }
            guard try r.string() == "NTCP2" else { throw I2PWireError.invalidFormat }
            let mapping = try r.mapping()
            guard mapping["host"] == "192.0.2.1", mapping["port"] == "8887" else {
                throw I2PWireError.invalidFormat
            }
            let readDate = try r.date()
            guard let readDate, abs(readDate.timeIntervalSince(stamp)) < 0.002 else {
                throw I2PWireError.invalidFormat
            }
            guard r.remaining == 0 else { throw I2PWireError.trailingData }
            return "\(w.data.count) bytes round-tripped"
        }

        run("Destination round trip + hash") {
            let destination = I2PSamples.sampleDestination()
            var r = I2PReader(destination.raw)
            let parsed = try I2PKeysAndCert.parse(&r)
            guard r.remaining == 0 else { throw I2PWireError.trailingData }
            guard parsed.raw == destination.raw, parsed.hash == destination.hash else {
                throw I2PWireError.invalidFormat
            }
            return "\(destination.raw.count) bytes · SHA-256 identity hash stable"
        }

        run("RouterInfo round trip + signature") {
            let info = try I2PSamples.sampleRouterInfo()
            let encoded = info.serialize()
            let parsed = try I2PRouterInfo.parse(encoded)
            guard parsed.verifySignature() else { throw I2PWireError.invalidSignature }
            guard parsed.identity.hash == info.identity.hash else { throw I2PWireError.invalidFormat }
            var tampered = encoded
            tampered[tampered.count - 70] ^= 0xff
            guard (try? I2PRouterInfo.parse(tampered)) == nil else {
                throw I2PWireError.invalidSignature
            }
            return "\(encoded.count) bytes · verified on parse, tamper rejected"
        }

        run("LeaseSet round trip + signature") {
            let leaseSet = try I2PSamples.sampleLeaseSet()
            let encoded = leaseSet.serialize()
            let parsed = try I2PLeaseSet.parse(encoded)
            guard parsed.verifySignature() else { throw I2PWireError.invalidSignature }
            guard parsed.leases.count == 2 else { throw I2PWireError.invalidFormat }
            var tampered = encoded
            tampered[tampered.count - 70] ^= 0xff
            guard (try? I2PLeaseSet.parse(tampered)) == nil else {
                throw I2PWireError.invalidSignature
            }
            return "\(encoded.count) bytes · destination-signed, tamper rejected"
        }

        run("NetDB XOR distance metric") {
            let a = I2PCrypto.sha256(Data("peer-a".utf8))
            let b = I2PCrypto.sha256(Data("peer-b".utf8))
            let d = I2PNetworkDatabase.xorDistance(a, b)
            guard d.count == 32 else { throw I2PWireError.invalidFormat }
            for i in 0..<32 {
                guard d[i] == a[i] ^ b[i] else { throw I2PWireError.invalidFormat }
            }
            // A node is always at distance 0 from its own key, hence closest.
            guard I2PNetworkDatabase.isCloser(a, than: b, to: a) else { throw I2PWireError.invalidFormat }
            guard !I2PNetworkDatabase.isCloser(a, than: b, to: b) else { throw I2PWireError.invalidFormat }
            return "byte-wise XOR metric with lexicographic ordering verified"
        }

        run("NetDB message round trip (store/lookup/searchReply)") {
            let key = I2PCrypto.sha256(Data("netdb-key".utf8))
            let gateway = I2PCrypto.sha256(Data("netdb-gateway".utf8))
            let store = I2PDatabaseStore(
                key: key, entryType: .leaseSet, replyToken: 0x1122_3344,
                replyTunnelId: 7, replyGateway: gateway, payload: Data(repeating: 0xAB, count: 40)
            )
            let parsedStore = try I2PDatabaseStore.parse(store.serialize())
            guard parsedStore.key == key, parsedStore.entryType == .leaseSet,
                  parsedStore.replyToken == 0x1122_3344, parsedStore.replyTunnelId == 7,
                  parsedStore.replyGateway == gateway,
                  parsedStore.payload == Data(repeating: 0xAB, count: 40) else {
                throw I2PWireError.invalidFormat
            }
            let lookup = I2PDatabaseLookup(
                queryKey: key, fromHash: gateway, excludedPeers: [key, gateway],
                replyTunnels: [(gateway, 9)], replyToken: 5, replyTunnelId: 3, replyGateway: key
            )
            let parsedLookup = try I2PDatabaseLookup.parse(lookup.serialize())
            guard parsedLookup.queryKey == key, parsedLookup.fromHash == gateway,
                  parsedLookup.excludedPeers == [key, gateway],
                  parsedLookup.replyTunnels.count == 1, parsedLookup.replyTunnels[0].tunnelId == 9,
                  parsedLookup.replyToken == 5 else {
                throw I2PWireError.invalidFormat
            }
            let reply = I2PDatabaseSearchReply(queryKey: key, fromHash: gateway, peerHashes: [key, gateway])
            let parsedReply = try I2PDatabaseSearchReply.parse(reply.serialize())
            guard parsedReply.peerHashes == [key, gateway] else { throw I2PWireError.invalidFormat }
            let message = I2PNetDBMessage.store(store)
            let reparsed = try I2PNetDBMessage.parse(message.serialize(), i2npType: message.i2npType)
            guard case .store(let s2) = reparsed, s2.replyToken == 0x1122_3344 else {
                throw I2PWireError.invalidFormat
            }
            return "DatabaseStore/Lookup/SearchReply round-tripped with I2NP type codes"
        }

        run("BLAKE2b-512 vector") {
            let digest = BLAKE2b.digest([], outLen: 64)
            let hex = Data(digest).hex
            guard hex.hasPrefix("786a02f7673b5856") else { throw I2PWireError.invalidFormat }
            return "empty-input digest matches reference vector"
        }

        return results
    }

    static func sampleByteSizes() -> [(name: String, bytes: Int)] {
        var sizes: [(name: String, bytes: Int)] = []
        let destination = I2PSamples.sampleDestination()
        sizes.append(("Destination", destination.raw.count))
        if let routerInfo = try? I2PSamples.sampleRouterInfo() {
            sizes.append(("RouterInfo", routerInfo.serialize().count))
        }
        if let leaseSet = try? I2PSamples.sampleLeaseSet() {
            sizes.append(("LeaseSet", leaseSet.serialize().count))
        }
        return sizes
    }
}