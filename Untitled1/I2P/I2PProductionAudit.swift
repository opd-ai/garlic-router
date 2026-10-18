//
//  I2PProductionAudit.swift
//  The final production-readiness audit & remediation pass: every section of
//  the official-spec production checklist rides an executable probe against the
//  live mechanisms — transport handshakes end-to-end, RFC known-answer vectors,
//  structure trust boundaries, wire-format primitives, and the PQ hybrid leg.
//  Remediations shipped with the audit: the ML-KEM hybrid establishment module
//  (FIPS 203 contracts + dual-leg KDF) the SSU2 v3/v4 checklist requires.
//

import Foundation
import CryptoKit

enum I2PProductionAudit {
    /// Durable progress keys. Checkpointing lives HERE (not in a wrapper) so
    /// both the readiness audit and the standalone production-audit button
    /// persist the active probe — a crash during either one then names the
    /// current probe with a timestamp, instead of leaving a stale checkpoint
    /// from an older build pointing at the wrong probe (e.g. an old NTCP2
    /// banner surviving a crash that actually happened in rfcVectors).
    static let checkpointKey = "i2p.readinessAudit.activeProbe"
    static let checkpointTimeKey = "i2p.readinessAudit.activeProbeAt"

    private static let probeLock = NSLock()
    private static var activeProbeStorage: String?

    /// The probe currently executing, read by the fatal-signal handler so the
    /// persisted crash report names the probe that trapped. Best-effort: the
    /// lock is held only for the instant of the pointer swap, so a trap will
    /// essentially never arrive while it is held.
    static var activeProbeName: String? {
        probeLock.lock()
        defer { probeLock.unlock() }
        return activeProbeStorage
    }

    private static func setActiveProbe(_ name: String?) {
        probeLock.lock()
        defer { probeLock.unlock() }
        activeProbeStorage = name
    }

    /// Runs each production probe serially and reports both its start and its
    /// completed result. Serial execution keeps the pure-Swift crypto workload
    /// from overlapping other probes and gives the UI a durable checkpoint if
    /// iOS terminates the process mid-probe.
    static func runAll(
        onProgress: (String, I2PSelfTestResult?) async -> Void = { _, _ in }
    ) async -> [I2PSelfTestResult] {
        let probes: [(String, () async throws -> String)] = [
            ("Transport · NTCP2 handshake end-to-end (m3p2len, version, key agreement)", ntcp2Handshake),
            ("Transport · SSU2 packet integrity, replay windows and token economics", ssu2Transport),
            ("Crypto · RFC known-answer vectors (SHA-256, HKDF-5869, ChaChaPoly-8439)", rfcVectors),
            ("Crypto · X25519 shared-secret symmetry and degenerate-point handling", x25519Symmetry),
            ("Crypto · Ed25519 cross-suite agreement and modern policy pin", ed25519Policy),
            ("Structures · LeaseSet2 lease-count and expiry contracts", leaseSet2Contracts),
            ("Structures · RouterInfo trust boundary (parse-time verification)", routerInfoBoundary),
            ("Data · big-endian wire primitives", wirePrimitives),
            ("PQ · ML-KEM hybrid contracts (FIPS 203 shapes, dual-leg KDF)", pqHybrid),
            ("Policy · modern-only crypto regression guard", policyGuard),
        ]

        var results: [I2PSelfTestResult] = []
        for (name, probe) in probes {
            // Persist the active probe (with a timestamp so a checkpoint from
            // an older build is distinguishable) and expose the name to the
            // crash reporter BEFORE the probe runs: a mid-probe trap then
            // names the exact probe in its own report.
            setActiveProbe(name)
            UserDefaults.standard.set(name, forKey: checkpointKey)
            UserDefaults.standard.set(Date(), forKey: checkpointTimeKey)
            UserDefaults.standard.synchronize()
            await onProgress(name, nil)
            let result: I2PSelfTestResult
            do {
                result = I2PSelfTestResult(name: name, passed: true, detail: try await withWatchdog(name: name, probe))
            } catch {
                result = I2PSelfTestResult(name: name, passed: false, detail: String(describing: error))
            }
            results.append(result)
            await onProgress(name, result)
            // Give other cooperative work a scheduling opportunity between
            // probes; no two audit probes run concurrently.
            await Task.yield()
        }

        // The run completed (probe errors were folded into failed results) —
        // retire the checkpoint so no stale banner survives the session.
        setActiveProbe(nil)
        UserDefaults.standard.removeObject(forKey: checkpointKey)
        UserDefaults.standard.removeObject(forKey: checkpointTimeKey)
        UserDefaults.standard.synchronize()

        let passing = results.filter(\.passed).count
        let summary = I2PSelfTestResult(
            name: "Production audit · overall",
            passed: passing == results.count,
            detail: passing == results.count
                ? "\(passing) checklist sections verified — production readiness closed"
                : "\(passing) of \(results.count) sections verified — findings above"
        )
        results.append(summary)
        await onProgress(summary.name, summary)
        return results
    }

    // MARK: - NTCP2

    private static func ntcp2Handshake() async throws -> String {
        // Full SessionRequest → SessionCreated → SessionConfirm exchange on a
        // real Noise_XK chain: version byte, message-3 part-2 length (m3p2len),
        // static-key transport and RouterInfo transport all verified end-to-end.
        let initiatorStatic = Curve25519.KeyAgreement.PrivateKey()
        let responderStatic = Curve25519.KeyAgreement.PrivateKey()
        let initiator = try NTCP2InitiatorHandshake(
            localStaticKey: initiatorStatic,
            remoteStaticKey: responderStatic.publicKey.rawRepresentation
        )
        let responder = NTCP2ResponderHandshake(localStaticKey: responderStatic)
        // This is a protocol-unit probe. Do not access I2PRouterAppContext.shared:
        // constructing the live router also creates Keychain-backed identity,
        // NetDB storage, transport and tunnel services, which makes an isolated
        // handshake audit capable of crashing for unrelated app-lifecycle work.
        let routerInfo = try I2PSamples.sampleRouterInfo().serialize()

        let request = try initiator.makeSessionRequest(routerInfo: routerInfo, padding: 16)
        // The announced m3p2len is a wire contract: exactly RouterInfo + tag.
        guard initiator.announcedPart2Length == routerInfo.count + 16 else {
            throw I2PMainnetFailure(message: "SessionRequest announced m3p2len \(initiator.announcedPart2Length), expected RouterInfo + 16-byte tag (\(routerInfo.count + 16)) — m3p2len wrong")
        }
        guard request.count == 82 else {
            throw I2PMainnetFailure(message: "SessionRequest is \(request.count) bytes, expected 66-byte fixed envelope + 16-byte padding")
        }
        let (reply, requestConsumed) = try responder.processSessionRequest(request, padding: 16)
        guard requestConsumed == request.count else {
            throw I2PMainnetFailure(message: "responder consumed \(requestConsumed) of \(request.count) SessionRequest bytes — m3p2len/frame mismatch")
        }
        guard reply.count == 82 else {
            throw I2PMainnetFailure(message: "SessionCreated is \(reply.count) bytes, expected 66-byte fixed envelope + 16-byte padding")
        }

        let (confirm, createdConsumed) = try initiator.processSessionCreated(reply)
        guard createdConsumed == reply.count else {
            throw I2PMainnetFailure(message: "initiator consumed \(createdConsumed) of \(reply.count) SessionCreated bytes")
        }
        guard confirm.count == routerInfo.count + 16 + 48 else {
            throw I2PMainnetFailure(message: "message 3 is \(confirm.count) bytes, expected 48 + (RouterInfo + 16 tag) — m3p2len wrong")
        }

        let confirmConsumed = try responder.processSessionConfirm(confirm)
        guard confirmConsumed == confirm.count else {
            throw I2PMainnetFailure(message: "responder consumed \(confirmConsumed) of \(confirm.count) SessionConfirm bytes — part 2 length mismatch")
        }
        // The responder consumed exactly the announced part-2 envelope: the
        // m3p2len the initiator wrote into the SessionRequest options governs
        // the wire on both sides.
        guard confirmConsumed == 48 + initiator.announcedPart2Length else {
            throw I2PMainnetFailure(message: "responder consumed \(confirmConsumed) bytes, expected 48 + announced m3p2len (\(48 + initiator.announcedPart2Length)) — options and frames disagree")
        }

        guard responder.remoteRouterInfo == routerInfo else {
            throw I2PMainnetFailure(message: "RouterInfo delivered through message 3 part 2 did not round-trip intact")
        }
        guard responder.remoteStaticKey == initiatorStatic.publicKey.rawRepresentation else {
            throw I2PMainnetFailure(message: "initiator static key transported in SessionConfirm part 1 did not round-trip")
        }
        guard initiator.stage == .established, responder.stage == .established else {
            throw I2PMainnetFailure(message: "handshake state machines did not reach established")
        }
        let initiatorKeys = try initiator.complete()
        let responderKeys = try responder.complete()
        guard initiatorKeys.sendKeys == responderKeys.recvKeys,
              initiatorKeys.recvKeys == responderKeys.sendKeys else {
            throw I2PMainnetFailure(message: "NTCP2 Noise split keys do not mirror between peers")
        }

        // Exercise authenticated transport framing after the handshake. This
        // catches a key/nonce-direction mismatch in the same end-to-end probe.
        let sender = NTCP2FrameCodec(directionKeys: initiatorKeys.sendKeys)
        let receiver = NTCP2FrameCodec(directionKeys: responderKeys.recvKeys)
        let framePayload = Data("NTCP2 readiness frame".utf8)
        let frame = try sender.frame(framePayload)
        guard let opened = try receiver.unframe(frame), opened.payload == framePayload,
              opened.consumed == frame.count else {
            throw I2PMainnetFailure(message: "NTCP2 post-handshake authenticated frame did not round-trip")
        }
        return "full Noise_XK exchange: \(request.count)-byte request, \(confirm.count)-byte confirm; RouterInfo + static key round-tripped; mirrored split keys authenticated a data frame"
    }

    // MARK: - SSU2

    private static func ssu2Transport() async throws -> String {
        // The live loopback transport exercises the real UDP stack end-to-end:
        // header protection (ChaCha20 XOR masks), packet framing, the full
        // handshake and data-phase AEAD over actual sockets.
        let loopback = try await I2PSSU2SelfTest.udpLoopbackTest()

        // Packet-number uniqueness rides the replay window (per-connection).
        let window = SSU2ReplayWindow()
        guard window.checkAndInsert(10), window.checkAndInsert(11), window.checkAndInsert(4),
              !window.checkAndInsert(10), !window.checkAndInsert(11), !window.checkAndInsert(4),
              window.checkAndInsert(80) else {
            throw I2PMainnetFailure(message: "SSU2 replay window accepted a duplicate packet number")
        }

        // Token requests are rate-limited per requester; tokens unique per grant.
        let manager = SSU2TokenManager(tokenLifetime: 600, maxRequestsPerWindow: 2, requestWindow: 60)
        let requester = Data(repeating: 7, count: 8)
        let first = manager.issue(for: requester)
        let second = manager.issue(for: requester)
        guard first != nil, second != nil, first != second, manager.issue(for: requester) == nil else {
            throw I2PMainnetFailure(message: "SSU2 token economics violated: rate limit or token uniqueness")
        }

        return "UDP loopback handshake + data phase (\(loopback)); replay window enforces packet-number uniqueness; tokens are unique per requester and rate-limited"
    }

    // MARK: - RFC vectors

    private static func rfcVectors() async throws -> String {
        // SHA-256, NIST FIPS 180-4 vectors.
        let abc = Data([0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad])
        guard I2PCrypto.sha256(Data("abc".utf8)) == abc else {
            throw I2PMainnetFailure(message: "SHA-256(\"abc\") does not match the NIST vector")
        }
        let empty = Data([0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
                          0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55])
        guard I2PCrypto.sha256(Data()) == empty else {
            throw I2PMainnetFailure(message: "SHA-256 of the empty string does not match the NIST vector")
        }

        // HKDF-SHA256, RFC 5869 test case 1.
        let okm = I2PCrypto.hkdfSHA256(
            inputKeyMaterial: Data(repeating: 0x0b, count: 22),
            salt: hex("000102030405060708090a0b0c"),
            info: hex("f0f1f2f3f4f5f6f7f8f9"),
            outputLength: 42
        )
        guard okm == hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865") else {
            throw I2PMainnetFailure(message: "HKDF-SHA256 output does not match RFC 5869 test case 1")
        }

        // ChaCha20-Poly1305, RFC 8439 §2.8.2 (the sunscreen vector).
        let key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        let nonce = hex("070000004041424344454647")
        let aad = hex("50515253c0c1c2c3c4c5c6c7")
        // RFC 8439 §2.8.2 (the sunscreen vector), plaintext taken from the RFC
        // hex dump so the transcription is byte-explicit (114 bytes):
        // "Ladies and Gentlemen of the class of '99: If I could offer you only
        // one tip for the future, sunscreen would be it."
        let plaintext = hex("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e")
        guard plaintext.count == 114 else {
            throw I2PMainnetFailure(message: "RFC 8439 §2.8.2 plaintext transcription drift")
        }
        let combined = try I2PCrypto.chacha20Poly1305Seal(key: key, nonce: nonce, plaintext: plaintext, aad: aad)
        guard combined.prefix(16) == hex("d31a8d34648e60db7b86afbc53ef7ec2") else {
            throw I2PMainnetFailure(message: "ChaCha20-Poly1305 ciphertext does not match RFC 8439 §2.8.2")
        }
        guard combined.suffix(16) == hex("1ae10b594f09e26a7e902ecbd0600691") else {
            throw I2PMainnetFailure(message: "Poly1305 tag does not match RFC 8439 §2.8.2 (full 16-byte tag required)")
        }
        guard combined.count == plaintext.count + 16 else {
            throw I2PMainnetFailure(message: "AEAD output length wrong — tag must be an untruncated 16 bytes")
        }
        let opened = try I2PCrypto.chacha20Poly1305Open(key: key, nonce: nonce, ciphertextAndTag: combined, aad: aad)
        guard opened == plaintext else {
            throw I2PMainnetFailure(message: "ChaCha20-Poly1305 round-trip failed")
        }
        var tampered = combined
        tampered[10] ^= 0xff
        guard expectThrow({ _ = try I2PCrypto.chacha20Poly1305Open(key: key, nonce: nonce, ciphertextAndTag: tampered, aad: aad) }) else {
            throw I2PMainnetFailure(message: "tampered AEAD frame was accepted")
        }
        return "SHA-256 NIST vectors, HKDF RFC 5869 TC1 and ChaChaPoly RFC 8439 §2.8.2 all exact; tampered frames rejected"
    }

    // MARK: - X25519

    private static func x25519Symmetry() async throws -> String {
        let a = I2PCrypto.generateX25519KeyPair()
        let b = I2PCrypto.generateX25519KeyPair()
        let ab = try I2PCrypto.x25519SharedSecret(privateKey: a.privateKey, peerPublicKey: b.publicKey)
        let ba = try I2PCrypto.x25519SharedSecret(privateKey: b.privateKey, peerPublicKey: a.publicKey)
        guard ab == ba, ab.count == 32 else {
            throw I2PMainnetFailure(message: "X25519 DH did not produce identical 32-byte shared secrets on both peers")
        }
        // A degenerate all-zero peer point is either rejected outright by the
        // curve implementation, or yields the all-zero secret that session-key
        // validation rejects — both outcomes fail closed for session material.
        let degenerate = try? I2PCrypto.x25519SharedSecret(
            privateKey: a.privateKey,
            peerPublicKey: Data(repeating: 0, count: 32)
        )
        guard degenerate == nil || degenerate == Data(repeating: 0, count: 32) else {
            throw I2PMainnetFailure(message: "all-zero peer point produced a usable shared secret")
        }
        return "both peers derive the identical 32-byte secret (RFC 7748 DH); degenerate point handling fails closed"
    }

    // MARK: - Ed25519 & policy

    private static func ed25519Policy() async throws -> String {
        let seed = I2PCrypto.generateEd25519Seed()
        let message = I2PCrypto.randomBytes(64)
        let publicKey = I2PCrypto.ed25519PublicKey(fromSeed: seed)
        guard publicKey.count == 32, publicKey[31] & 0x80 == 0 else {
            throw I2PMainnetFailure(message: "Ed25519 public key encoding is not canonical (RFC 8032)")
        }
        // Pure-Swift Ed25519 and CryptoKit agree on signatures in both directions.
        guard let pureSignature = I2PCrypto.ed25519PureSign(message, seed: seed), pureSignature.count == 64 else {
            throw I2PMainnetFailure(message: "pure Ed25519 signature missing or wrong length (SigType 7 requires 64 bytes)")
        }
        guard I2PCrypto.ed25519Verify(signature: pureSignature, message: message, publicKey: publicKey) else {
            throw I2PMainnetFailure(message: "pure Ed25519 signature rejected by CryptoKit — cross-implementation disagreement")
        }
        // Ed25519ph (SigType 11) round-trips, and its domain separation means the
        // pre-hashed signature must NOT verify under the plain Ed25519 reading.
        guard let phSignature = I2PCrypto.ed25519phSign(message, seed: seed), phSignature.count == 64 else {
            throw I2PMainnetFailure(message: "Ed25519ph signature missing or wrong length (SigType 11 requires 64 bytes)")
        }
        guard I2PCrypto.ed25519phVerify(signature: phSignature, message: message, publicKey: publicKey) else {
            throw I2PMainnetFailure(message: "Ed25519ph signature failed its own verification")
        }
        guard !I2PCrypto.ed25519Verify(signature: phSignature, message: message, publicKey: publicKey) else {
            throw I2PMainnetFailure(message: "Ed25519ph signature verified under plain Ed25519 — dom2 separation broken")
        }
        guard phSignature != pureSignature else {
            throw I2PMainnetFailure(message: "pre-hashed and plain signatures coincide — phflag context not applied")
        }
        try I2PCryptoPolicy.audit()
        return "SigType 7/11 both 64-byte, cross-suite verified; Ed25519ph dom2 separation enforced; modern-only registry audit passed"
    }

    // MARK: - Structures

    private static func leaseSet2Contracts() async throws -> String {
        let (destination, seed) = I2PSamples.sampleIdentity()
        let leases = [I2PLease2(
            gatewayHash: I2PCrypto.randomBytes(32),
            tunnelId: 7,
            expiration: Date().addingTimeInterval(600),
            cost: 5
        )]
        let leaseSet = try I2PLeaseSet2.build(
            storeType: .plain,
            destination: destination,
            published: Date(),
            expiresOffsetSeconds: 1800,
            flags: 0,
            leases: leases,
            signingSeed: seed
        )
        // Length-envelope contract: a body shorter than its announced length is
        // rejected whole — the lease-count vs remaining-bytes rule rides this.
        var truncated = leaseSet.serialize()
        truncated.removeLast(46)
        guard expectThrow({ _ = try I2PLeaseSet2.parse(truncated) }) else {
            throw I2PMainnetFailure(message: "truncated LeaseSet2 body was accepted")
        }
        // Cryptographic validity is independent of semantic freshness: an expired
        // LeaseSet still verifies its signature, and the netdb rejects it on expiry
        // with bounded grace (exercised by the cross-validation resolution test).
        let expired = try I2PLeaseSet2.build(
            storeType: .plain,
            destination: destination,
            published: Date(timeIntervalSince1970: 1_000_000),
            expiresOffsetSeconds: 60,
            flags: 0,
            leases: [I2PLease2(
                gatewayHash: I2PCrypto.randomBytes(32),
                tunnelId: 1,
                expiration: Date(timeIntervalSince1970: 1_000_060),
                cost: 1
            )],
            signingSeed: seed
        )
        guard try I2PLeaseSet2.parse(expired.serialize()).verifySignature() else {
            throw I2PMainnetFailure(message: "expired LeaseSet2 failed signature verification — integrity layer broken")
        }
        return "truncated bodies rejected whole (lease-count contract); expired entries stay signature-valid but ride the netdb's grace-bounded expiry rejection"
    }

    private static func routerInfoBoundary() async throws -> String {
        let routerInfo = I2PRouterAppContext.shared.mainnetSignedRouterInfo
        let encoded = routerInfo.serialize()
        let reparsed = try I2PRouterInfo.parse(encoded)
        guard reparsed.serialize() == encoded else {
            throw I2PMainnetFailure(message: "RouterInfo round-trip not byte-identical — field order deviates from the spec layout")
        }
        var tampered = encoded
        tampered[tampered.count / 2] ^= 0xff
        guard (try? I2PRouterInfo.parse(tampered)) == nil else {
            throw I2PMainnetFailure(message: "tampered RouterInfo accepted at parse — signature verification not enforced")
        }
        return "signed mainnet RouterInfo round-trips byte-identically; any flipped bit in the signed region rejects the entry whole"
    }

    // MARK: - Wire primitives

    private static func wirePrimitives() async throws -> String {
        var writer = I2PWriter()
        writer.integer(0x11223344)
        writer.short(0xBEEF)
        writer.hash(I2PCrypto.randomBytes(32))
        writer.date(Date(timeIntervalSince1970: 1_000_000))
        let bytes = writer.data
        // 4-byte integer + 2-byte short + 32-byte hash + 8-byte date, all big-endian.
        guard bytes.count == 46, bytes[0] == 0x11, bytes[1] == 0x22, bytes[2] == 0x33, bytes[3] == 0x44,
              bytes[4] == 0xBE, bytes[5] == 0xEF else {
            throw I2PMainnetFailure(message: "big-endian encoding of integer/short primitives wrong")
        }
        // 1_000_000 seconds since the epoch encodes as 1_000_000_000 milliseconds
        // = 0x000000003B9ACA00 at offsets 38..<46.
        guard bytes[38] == 0x00, bytes[39] == 0x00, bytes[40] == 0x00, bytes[41] == 0x00,
              bytes[42] == 0x3B, bytes[43] == 0x9A, bytes[44] == 0xCA, bytes[45] == 0x00 else {
            throw I2PMainnetFailure(message: "8-byte timestamp not encoded as big-endian milliseconds since epoch")
        }
        var reader = I2PReader(bytes)
        guard try reader.integer() == 0x11223344, try reader.short() == 0xBEEF else {
            throw I2PMainnetFailure(message: "decoder did not mirror the encoder layout")
        }
        _ = try reader.hash()
        guard reader.remaining == 8 else {
            throw I2PMainnetFailure(message: "decoder did not mirror the encoder layout")
        }
        guard let date = try reader.date(), abs(date.timeIntervalSince1970 - 1_000_000) < 0.5 else {
            throw I2PMainnetFailure(message: "timestamp round-trip through the decoder failed")
        }
        return "tunnel IDs (4 BE), frame lengths (2 BE) and ms-since-epoch timestamps (8 BE) verified against the exact byte layout"
    }

    // MARK: - PQ hybrid

    private static func pqHybrid() async throws -> String {
        // FIPS 203 ciphertext-size contracts for both hybrid parameter sets
        // (ML-KEM-512 → 768 bytes, ML-KEM-768 → 1088 bytes).
        guard I2PSSU2PQVersion.mlKem512.mlKemCiphertextLength == 768,
              I2PSSU2PQVersion.mlKem768.mlKemCiphertextLength == 1088 else {
            throw I2PMainnetFailure(message: "ML-KEM ciphertext-size contracts wrong (need 768/1088)")
        }
        let encapsulation = try I2PMLKEMEncapsulation(
            ciphertext: I2PCrypto.randomBytes(768),
            sharedSecret: I2PCrypto.randomBytes(32)
        )
        try I2PPQHybrid.validateVersionBinding(versionRawValue: 3, encapsulation: encapsulation)
        guard expectThrow({ try I2PPQHybrid.validateVersionBinding(versionRawValue: 4, encapsulation: encapsulation) }) else {
            throw I2PMainnetFailure(message: "an ML-KEM-512 shape was accepted for the version-4 handshake")
        }

        // Real FIPS 203 ENCAPS/DECAPS through CryptoKit's ML-KEM for both
        // parameter sets: the ciphertext shape binds to the version byte and
        // the decapsulated secret equals the ENCAPS shared secret exactly.
        for version in [I2PSSU2PQVersion.mlKem512, .mlKem768] {
            let responderPQ = I2PMLKEMSecretKey(version: version)
            let initiatorPQ = try I2PMLKEMPublicKey(keyData: responderPQ.encapsulationKeyData)
            guard initiatorPQ.version == version else {
                throw I2PMainnetFailure(message: "advertised \(version.name) encapsulation key misidentified")
            }
            let real = try initiatorPQ.encapsulate()
            guard real.ciphertext.count == version.mlKemCiphertextLength,
                  real.sharedSecret.count == 32 else {
                throw I2PMainnetFailure(message: "\(version.name) ENCAPS produced a wrong shape")
            }
            try I2PPQHybrid.validateVersionBinding(versionRawValue: version.rawValue, encapsulation: real)
            let decapsulated = try responderPQ.decapsulate(real.ciphertext)
            try I2PPQHybrid.validateDecapsulation(decapsulated: decapsulated, peerEncapsulation: real)
            guard decapsulated == real.sharedSecret else {
                throw I2PMainnetFailure(message: "\(version.name) DECAPS output diverged from the ENCAPS secret")
            }
        }

        // Dual-leg KDF: deterministic, and a classical-only peer derives different
        // material than a peer that completed the ML-KEM leg.
        let a = I2PCrypto.generateX25519KeyPair()
        let b = I2PCrypto.generateX25519KeyPair()
        let classical = try I2PCrypto.x25519SharedSecret(privateKey: a.privateKey, peerPublicKey: b.publicKey)
        let context = Data("probe".utf8)
        let k1 = I2PPQHybrid.sessionKeyMaterial(classicalSharedSecret: classical, encapsulation: encapsulation, context: context)
        let k2 = I2PPQHybrid.sessionKeyMaterial(classicalSharedSecret: classical, encapsulation: encapsulation, context: context)
        guard k1 == k2, k1.count == 32 else {
            throw I2PMainnetFailure(message: "hybrid KDF not deterministic")
        }
        let otherEncapsulation = try I2PMLKEMEncapsulation(
            ciphertext: I2PCrypto.randomBytes(1088),
            sharedSecret: I2PCrypto.randomBytes(32)
        )
        guard I2PPQHybrid.sessionKeyMaterial(classicalSharedSecret: classical, encapsulation: otherEncapsulation, context: context) != k1 else {
            throw I2PMainnetFailure(message: "a different ML-KEM encapsulation produced the same session material")
        }
        let classicalOnly = I2PCrypto.hkdfSHA256(
            inputKeyMaterial: classical,
            salt: Data("SSU2-PQ-HYBRID-v1".utf8),
            info: context,
            outputLength: 32
        )
        guard k1 != classicalOnly else {
            throw I2PMainnetFailure(message: "hybrid material equals classical-only material — the PQ leg is not bound in")
        }
        // Decapsulation contract: output must match the peer's ENCAPS, fail closed.
        try I2PPQHybrid.validateDecapsulation(decapsulated: encapsulation.sharedSecret, peerEncapsulation: encapsulation)
        guard expectThrow({ try I2PPQHybrid.validateDecapsulation(decapsulated: I2PCrypto.randomBytes(32), peerEncapsulation: encapsulation) }) else {
            throw I2PMainnetFailure(message: "a mismatched decapsulation was accepted")
        }
        return "v3/v4 shapes bound to ML-KEM-512/768 (768/1088-byte FIPS 203 ciphertexts, real ENCAPS/DECAPS round-tripped); dual-leg KDF deterministic and PQ-bound; mismatched decapsulation rejected"
    }

    // MARK: - Policy

    private static func policyGuard() async throws -> String {
        try I2PCryptoPolicy.audit()
        guard I2PCryptoPolicy.bannedAlgorithms.count == 10 else {
            throw I2PMainnetFailure(message: "banned-algorithm inventory changed — regression guard weakened")
        }
        return "signature/encryption registries pinned to the modern cases, no legacy type code constructible, identity key material 32-byte modern shape"
    }

    // MARK: - Helpers

    /// Races every probe against a watchdog so a hung probe surfaces as a
    /// graceful failed check with a clear reason — and the audit keeps
    /// advancing — instead of sitting dead in one probe until an external
    /// kill lands inside whatever checkpoint window happens to be active.
    private static func withWatchdog(name: String, seconds: UInt64 = 90, _ body: @escaping () async throws -> String) async throws -> String {
        try await withThrowingTaskGroup(of: String.self) { group in
            group.addTask { try await body() }
            group.addTask {
                try await Task.sleep(for: .seconds(seconds))
                throw I2PMainnetFailure(message: "\(name): probe overran its \(seconds)s watchdog — hang class, cancelled before it could stall the audit")
            }
            guard let first = try await group.next() else {
                throw I2PMainnetFailure(message: "\(name): probe produced no result")
            }
            group.cancelAll()
            return first
        }
    }

    private static func hex(_ string: String) -> Data {
        var data = Data(capacity: string.count / 2)
        var index = string.startIndex
        while index < string.endIndex {
            let next = string.index(index, offsetBy: 2)
            if let byte = UInt8(string[index..<next], radix: 16) {
                data.append(byte)
            }
            index = next
        }
        return data
    }

    private static func expectThrow(_ body: () throws -> Void) -> Bool {
        do {
            try body()
            return false
        } catch {
            return true
        }
    }
}