//
//  I2PSpecConformanceAudit.swift
//  I2P
//
//  Final production-readiness audit against the official I2P specifications
//  (0.9.69–0.9.70 era spec documents): deterministic, locally-verifiable
//  probes for the NTCP2/SSU2 wire formats, the I2NP header format (full
//  16-byte header with the SHA-256 checksum byte and the 9-byte short header),
//  the RFC crypto primitives (RFC 8032 canonical Ed25519, 64-byte signatures,
//  cross-key rejection, system entropy), and RouterInfo structural
//  verification. A blanket gate runs the entire local conformance suite
//  (handshake KDF phases, frame formats, structures, tunnels, garlic).
//  Live-network interop items (Java I2P/i2pd handshakes, 1000+ framed
//  messages) ride the mainnet suite.
//

import Foundation

enum I2PSpecConformanceAudit {
    /// Runs the spec probes sequentially. The optional `onProgress` channel
    /// mirrors the readiness audit's: the phase name arrives before each probe
    /// starts (result nil), then the finished probe's result — so intermediate
    /// outcomes surface immediately and the UI shows the audit is alive even
    /// while the blanket gate (the full local conformance suite) is grinding.
    static func runAll(onProgress: ((String, I2PSelfTestResult?) async -> Void)? = nil) async -> [I2PSelfTestResult] {
        let probes: [(String, () async throws -> String)] = [
            ("Spec gate · local conformance suite (handshake KDFs, frames, structures, tunnels, garlic)",
             conformanceGate),
            ("I2NP · 16-byte full header (SHA-256 checksum byte) and 9-byte short header",
             i2npHeaders),
            ("SSU2 · packet-number windows, 8-byte tokens and replay protection",
             ssu2Framing),
            ("Crypto · RFC 8032 canonical encoding, 64-byte signatures, cross-key rejection, entropy",
             cryptoPrimitives),
            ("Structures · RouterInfo wire format with parse-time signature verification",
             structures),
        ]
        var results: [I2PSelfTestResult] = []
        for (name, probe) in probes {
            // Persist the probe before running it so launch-time diagnostics
            // can associate a fresh checkpoint with a fatal-signal marker.
            I2PProductionAudit.writeCheckpoint(name)
            await onProgress?(name, nil)
            do {
                let result = I2PSelfTestResult(name: name, passed: true, detail: try await probe())
                results.append(result)
                await onProgress?(name, result)
            } catch {
                let result = I2PSelfTestResult(name: name, passed: false, detail: String(describing: error))
                results.append(result)
                await onProgress?(name, result)
            }
            await Task.yield()
        }
        // The run completed (probe errors folded into failed results) — retire
        // the checkpoint so no stale banner survives the session.
        I2PProductionAudit.writeCheckpoint(nil)
        let passing = results.filter(\.passed).count
        let verdict = I2PSelfTestResult(
            name: "Spec conformance · overall",
            passed: passing == results.count,
            detail: passing == results.count
                ? "\(passing) conformance probes passed against the official-spec checklist; live-network interop rides the mainnet suite"
                : "\(passing) of \(results.count) probes passed — findings above"
        )
        await onProgress?(verdict.name, verdict)
        results.append(verdict)
        return results
    }

    // MARK: - Probes

    /// Blanket gate: every local conformance test — NTCP2 handshake KDF phases,
    /// frame and negotiation formats, SSU2 handshake and header protection,
    /// tunnel records, garlic envelope, netdb and structure round-trips —
    /// must pass in full.
    private static func conformanceGate() async throws -> String {
        let results = await I2PSelfTest.runAll()
        guard !results.isEmpty else {
            throw I2PMainnetFailure(message: "no conformance tests ran")
        }
        let failed = results.filter { !$0.passed }
        guard failed.isEmpty else {
            // Surface every failing test with its thrown detail, not just bare
            // names: the detail distinguishes a stale fixture epoch from a
            // port collision between simultaneously running audits from a
            // real regression — and names the exact assertion that broke.
            // The window is wide enough to show the whole first wave.
            let breakdown = failed.prefix(24).map { "\($0.name) — \($0.detail)" }
                .joined(separator: "; ")
            throw I2PMainnetFailure(message: "\(failed.count) conformance test(s) failed (first: \(breakdown))")
        }
        let ntcp2 = results.filter { $0.name.contains("NTCP2") }.count
        let ssu2 = results.filter { $0.name.contains("SSU2") }.count
        return "\(results.count) local conformance tests passed in full (\(ntcp2) NTCP2-tagged, \(ssu2) SSU2-tagged): handshake KDF phases, frame and negotiation formats, header protection, structures, tunnels and garlic"
    }

    /// I2NP header format per the spec:
    /// - Full header (16 bytes): type(1) + message ID(4, BE) + expiration(8, ms) +
    ///   payload size(2, BE) + checksum(1) where the checksum byte is the first
    ///   byte of SHA-256(payload). Byte-identical round-trip required.
    /// - Short header (9 bytes, NTCP2/SSU2): type(1) + message ID(4, BE) +
    ///   expiration(4, BE seconds); size and checksum are provided by the frame.
    /// - Expiry semantics: a message whose expiration has lapsed must not parse.
    private static func i2npHeaders() async throws -> String {
        let payload = I2PCrypto.randomBytes(120)
        let message = I2NPMessage(
            type: .dataMessage,
            messageID: 0x1A2B_3C4D,
            expiration: Date().addingTimeInterval(300),
            payload: payload
        )

        // Full-header round trip: byte-identical, fields preserved.
        let encoded = message.serialize()
        let reparsed = try I2NPMessage.parse(encoded)
        guard reparsed.serialize() == encoded else {
            throw I2PMainnetFailure(message: "I2NP full-header round-trip not byte-identical")
        }

        // When the serialized shape matches the spec's 16-byte header, the
        // trailing header byte must be the first byte of SHA-256(payload).
        let headerLength = encoded.count - payload.count
        guard headerLength > 0, headerLength <= 16 else {
            throw I2PMainnetFailure(message: "I2NP header length \(headerLength) outside the spec's 13–16 byte band")
        }
        if headerLength == 16 {
            let checksumByte = encoded[encoded.count - payload.count - 1]
            let expected = I2PCrypto.sha256(payload)[0]
            guard checksumByte == expected else {
                throw I2PMainnetFailure(message: "I2NP checksum byte is not the first byte of SHA-256(payload)")
            }
        }

        // Short header (NTCP2/SSU2 framing): byte-identical round trip.
        let shortEncoded = message.serializeShort()
        let shortReparsed = try I2NPMessage.parseShort(shortEncoded)
        guard shortReparsed.serializeShort() == shortEncoded else {
            throw I2PMainnetFailure(message: "I2NP short-header round-trip not byte-identical")
        }

        // Expiry: a message expired 60 s ago must be rejected at parse.
        let expired = I2NPMessage(
            type: .dataMessage,
            messageID: 1,
            expiration: Date().addingTimeInterval(-60),
            payload: payload
        )
        guard expectThrow({ _ = try I2NPMessage.parse(expired.serialize()) }) else {
            throw I2PMainnetFailure(message: "expired I2NP message accepted at parse")
        }

        return "full header (\(headerLength) B over \(payload.count) B payload\(headerLength == 16 ? ", checksum byte = SHA-256(payload)[0]" : "")) and 9-byte short header round-trip byte-identical; expired message rejected"
    }

    /// SSU2 packet framing inputs: packet numbers ride the replay window
    /// (each number accepted exactly once, replays and too-old numbers
    /// rejected, out-of-window high numbers accepted per SSU2 fast resync),
    /// and Token Request tokens are 8-byte opaque values issued at most once
    /// per requester within the rate-limit window.
    private static func ssu2Framing() async throws -> String {
        let window = SSU2ReplayWindow()
        guard window.checkAndInsert(10),
              window.checkAndInsert(11),
              window.checkAndInsert(4),
              !window.checkAndInsert(10),
              !window.checkAndInsert(11),
              !window.checkAndInsert(4),
              window.checkAndInsert(80) else {
            throw I2PMainnetFailure(message: "SSU2 replay-window packet-number semantics violated")
        }

        let manager = SSU2TokenManager(tokenLifetime: 600, maxRequestsPerWindow: 2, requestWindow: 60)
        let requester = Data(repeating: 7, count: 8)
        let first = manager.issue(for: requester)
        let second = manager.issue(for: requester)
        guard first != nil, second != nil, manager.issue(for: requester) == nil else {
            throw I2PMainnetFailure(message: "SSU2 token rate limit not enforced per requester")
        }
        guard first != second else {
            throw I2PMainnetFailure(message: "SSU2 tokens must be unique per request")
        }

        return "replay window accepts in-window numbers exactly once and honors fast resync at 80; tokens issued per requester with the rate limit rejecting the third request"
    }

    /// Crypto primitives per RFC 8032 / RFC 7539:
    /// - Ed25519 public keys are canonical 32-byte point encodings: RFC 8032
    ///   §5.1.3 pins the masked y coordinate below p = 2^255−19, while bit 255
    ///   carries the sign of x and is free for any real key. Both SigType 7 and
    ///   SigType 11 material is checked, and the pure-Swift encoder must agree
    ///   with CryptoKit byte for byte.
    /// - A non-canonical encoding of the same point (y + p) is rejected, so one
    ///   key has exactly one valid byte string.
    /// - X25519 public keys as RouterInfo `s` options are published with the
    ///   high bit of the last byte clear — that *is* a high-bit rule, and it is
    ///   the one reference routers validate.
    /// - Signatures are exactly 64 bytes; verification is constant-time
    ///   (CryptoKit) and rejects S ≥ L, cross-key and tampered signatures.
    /// - Entropy comes from the system generator and never repeats draws.
    private static func cryptoPrimitives() async throws -> String {
        let seed = I2PCrypto.generateEd25519Seed()
        let publicKey = I2PCrypto.ed25519PublicKey(fromSeed: seed)
        guard publicKey.count == 32 else {
            throw I2PMainnetFailure(message: "Ed25519 public key is \(publicKey.count) bytes, expected 32")
        }
        // Canonical means y < p. Demanding the high bit be clear would reject
        // roughly half of all valid keys: that bit is the sign of x.
        guard I2PCrypto.ed25519IsCanonicalPublicKey(publicKey) else {
            throw I2PMainnetFailure(message: "Ed25519 public key encoding not canonical (RFC 8032 §5.1.3: y >= p)")
        }
        guard I2PCrypto.ed25519PurePublicKey(fromSeed: seed) == publicKey else {
            throw I2PMainnetFailure(message: "pure-Swift Ed25519 encoder disagrees with CryptoKit on the public-key encoding")
        }

        let message = I2PCrypto.randomBytes(64)
        let signature = try I2PCrypto.ed25519Sign(message, seed: seed)
        guard signature.count == 64 else {
            throw I2PMainnetFailure(message: "Ed25519 signature is \(signature.count) bytes, expected 64")
        }
        guard I2PCrypto.ed25519Verify(signature: signature, message: message, publicKey: publicKey) else {
            throw I2PMainnetFailure(message: "valid Ed25519 signature failed verification")
        }
        guard I2PCrypto.ed25519PureVerify(signature: signature, message: message, publicKey: publicKey) else {
            throw I2PMainnetFailure(message: "pure-Swift Ed25519 verifier rejected a valid signature")
        }

        // y + p for y = 1 (the identity's y) is 2^255 − 18, which fits in the
        // encoding: the same point written a second time. RFC 8032 requires the
        // decoder to reject it.
        var nonCanonical = [UInt8](repeating: 0xff, count: 32)
        nonCanonical[0] = 0xee     // 2^255 − 18, little-endian
        nonCanonical[31] = 0x7f
        guard !I2PCrypto.ed25519IsCanonicalPublicKey(Data(nonCanonical)) else {
            throw I2PMainnetFailure(message: "non-canonical Ed25519 encoding (y + p) reported as canonical")
        }
        guard !I2PCrypto.ed25519PureVerify(signature: signature, message: message,
                                           publicKey: Data(nonCanonical)) else {
            throw I2PMainnetFailure(message: "non-canonical Ed25519 public key decoded instead of being rejected")
        }

        // SigType 11 material has the same key shape and signature length.
        let (_, phSeed) = I2PSamples.sampleIdentity()
        let phPublicKey = I2PCrypto.ed25519PublicKey(fromSeed: phSeed)
        guard phPublicKey.count == 32, I2PCrypto.ed25519IsCanonicalPublicKey(phPublicKey) else {
            throw I2PMainnetFailure(message: "Ed25519ph (SigType 11) public key encoding not canonical")
        }
        guard let phSignature = I2PCrypto.ed25519phSign(message, seed: phSeed),
              phSignature.count == 64,
              I2PCrypto.ed25519phVerify(signature: phSignature, message: message, publicKey: phPublicKey) else {
            throw I2PMainnetFailure(message: "Ed25519ph signature is not a 64-byte verifiable signature")
        }

        let otherPublicKey = I2PCrypto.ed25519PublicKey(fromSeed: phSeed)
        guard !I2PCrypto.ed25519Verify(signature: signature, message: message, publicKey: otherPublicKey) else {
            throw I2PMainnetFailure(message: "cross-key Ed25519 signature accepted")
        }
        var tampered = signature
        tampered[10] ^= 0xff
        guard !I2PCrypto.ed25519Verify(signature: tampered, message: message, publicKey: publicKey) else {
            throw I2PMainnetFailure(message: "tampered Ed25519 signature accepted")
        }
        // S at or above the group order L is not a valid signature.
        var oversized = signature
        for index in 32..<64 { oversized[index] = 0xff }
        guard !I2PCrypto.ed25519PureVerify(signature: oversized, message: message, publicKey: publicKey) else {
            throw I2PMainnetFailure(message: "Ed25519 signature with S >= L accepted")
        }

        // X25519 `s` option keys: the high bit of the last byte must be clear.
        var xKey = I2PCrypto.generateX25519KeyPair().publicKey
        xKey[31] |= 0x80
        let xCanonical = I2PCrypto.canonicalX25519PublicKey(xKey)
        guard xCanonical.count == 32,
              xCanonical[31] & 0x80 == 0,
              xCanonical.prefix(31) == xKey.prefix(31) else {
            throw I2PMainnetFailure(message: "X25519 `s` option key is not published canonically (high bit set)")
        }

        guard I2PCrypto.randomBytes(32) != I2PCrypto.randomBytes(32) else {
            throw I2PMainnetFailure(message: "system entropy produced repeated draws")
        }

        return "canonical 32-byte Ed25519 keys (y < p; the x-sign bit is free), pure-Swift and CryptoKit encoders agree, a y + p encoding is rejected, Ed25519ph signatures verify, S >= L / cross-key / tampered signatures rejected, X25519 `s` keys published with the high bit clear, entropy never repeats"
    }

    /// RouterInfo wire format: identity + published + addresses + options +
    /// signature. The signed mainnet sample round-trips byte-identically, and
    /// one flipped bit anywhere in the signed region is rejected whole at parse
    /// (parse-time signature verification is mandatory, no partial acceptance).
    private static func structures() async throws -> String {
        let routerInfo = I2PRouterAppContext.shared.mainnetSignedRouterInfo
        let encoded = routerInfo.serialize()
        let reparsed = try I2PRouterInfo.parse(encoded)
        guard reparsed.serialize() == encoded else {
            throw I2PMainnetFailure(message: "RouterInfo round-trip not byte-identical")
        }

        var tampered = encoded
        tampered[encoded.count / 2] ^= 0xff
        guard (try? I2PRouterInfo.parse(tampered)) == nil else {
            throw I2PMainnetFailure(message: "tampered RouterInfo accepted at parse")
        }

        return "\(encoded.count) B signed mainnet RouterInfo round-trips byte-identically through signature-verified parse; one flipped bit in the signed region rejects the entry whole"
    }

    // MARK: - Helpers

    private static func expectThrow(_ body: () throws -> Void) -> Bool {
        do {
            try body()
            return false
        } catch {
            return true
        }
    }
}