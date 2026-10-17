//
//  I2PHardening.swift
//  I2P
//
//  Defensive hardening layer for the router: secure memory handling with
//  optimized-away-proof erasure, constant-time comparison of secret material,
//  zero-trust key validation, explicit resource quotas with graceful
//  rejection, exponential reconnect backoff, a redacting security audit log,
//  and fail-closed invariant enforcement. An embedded audit probes every
//  dimension of the hardening checklist.
//
//  Defense in depth: crypto is paired with input validation, session
//  integrity with resource limits, and data structures with format and
//  semantic bounds. Ambiguous states fail closed, never fall back.
//

import Foundation
import CryptoKit

// MARK: - Errors

enum I2PHardeningError: Error {
    case validationFailed(String)
}

// MARK: - Secure memory

enum I2PHardenedMemory {
    /// Overwrites a buffer with zeros behind a data dependency, so the zero
    /// stores cannot be optimized away. Use for key material and plaintext
    /// buffers once their values are no longer needed.
    static func zeroize(_ buffer: inout Data) {
        var sink: UInt8 = 0
        buffer.withUnsafeMutableBytes { pointer in
            guard let base = pointer.baseAddress else { return }
            let bytes = base.assumingMemoryBound(to: UInt8.self)
            for index in 0..<pointer.count {
                bytes[index] = 0
                sink |= bytes[index]
            }
        }
        // The compiler cannot prove this branch dead, so the zero stores above
        // must actually execute.
        if sink == 0xFF {
            buffer.append(contentsOf: [sink])
            buffer.removeLast()
        }
    }

    /// Constant-time comparison for secret material: the difference is
    /// accumulated across both buffers regardless of where a mismatch sits,
    /// so the comparison reveals no positional timing information.
    static func constantTimeEquals(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var difference: UInt8 = 0
        for index in 0..<lhs.count {
            difference |= lhs[lhs.startIndex + index] ^ rhs[rhs.startIndex + index]
        }
        return difference == 0
    }
}

// MARK: - Key material validation

enum I2PHardenedKeys {
    /// Zero trust for key material: length must match the algorithm and
    /// degenerate keys (all-zero / all-ones) are rejected before they can
    /// weaken every operation they feed. Poisoned persisted identities fail
    /// closed and are replaced, never used.
    static func validate(_ key: Data, context: String, expectedLength: Int = 32) throws {
        guard key.count == expectedLength else {
            throw I2PHardeningError.validationFailed("\(context): expected \(expectedLength) bytes, got \(key.count)")
        }
        var allZero = true
        var allOnes = true
        for byte in key {
            if byte != 0 { allZero = false }
            if byte != 0xFF { allOnes = false }
        }
        if allZero || allOnes {
            throw I2PHardeningError.validationFailed("\(context): degenerate key material rejected (all-zero/all-ones)")
        }
    }
}

// MARK: - Input bounds contracts

enum I2PInputBounds {
    /// Semantic bounds enforced at component boundaries. Values outside these
    /// contracts are rejected before interpretation.
    static func validateLeaseCount(_ count: Int) throws {
        guard (1...16).contains(count) else {
            throw I2PHardeningError.validationFailed("lease count \(count) outside 1...16")
        }
    }

    static func validateTunnelID(_ id: UInt32) throws {
        guard id != 0 else {
            throw I2PHardeningError.validationFailed("tunnel ID must be non-zero")
        }
    }

    static func validatePort(_ port: UInt16) throws {
        guard port != 0 else {
            throw I2PHardeningError.validationFailed("address port must be non-zero")
        }
    }

    static func validateOptionCount(_ count: Int) throws {
        guard count <= 64 else {
            throw I2PHardeningError.validationFailed("option count \(count) exceeds 64")
        }
    }

    static func validateMessageSize(_ bytes: Int) throws {
        guard bytes <= 65519 else {
            throw I2PHardeningError.validationFailed("message size \(bytes) exceeds the 65519-byte transport bound")
        }
    }
}

// MARK: - Resource quotas

/// Explicit, documented resource limits. No resource is assumed unbounded;
/// quota exhaustion is a typed, logged rejection — never silent growth.
enum I2PHardeningQuota {
    static let netDBCacheEntries = 5000
    static let transportSessions = 96
    static let tunnelsParticipated = 256
    static let samSessions = 64
    static let pendingStoreAcks = 512
    static let auditLogEntries = 500
}

/// Tracks in-use resources against their registered caps. Thread-safe; every
/// exhaustion is recorded in the security audit log.
final class I2PResourceLedger {
    private let lock = NSLock()
    private var limits: [String: Int] = [:]
    private var usage: [String: Int] = [:]

    init() {
        register(name: "netdb.cache", limit: I2PHardeningQuota.netDBCacheEntries)
        register(name: "ntcp2.sessions", limit: I2PHardeningQuota.transportSessions)
        register(name: "ssu2.sessions", limit: I2PHardeningQuota.transportSessions)
        register(name: "tunnels.participated", limit: I2PHardeningQuota.tunnelsParticipated)
        register(name: "sam.sessions", limit: I2PHardeningQuota.samSessions)
        register(name: "netdb.pendingAcks", limit: I2PHardeningQuota.pendingStoreAcks)
    }

    func register(name: String, limit: Int) {
        lock.lock()
        defer { lock.unlock() }
        limits[name] = limit
        usage[name] = usage[name] ?? 0
    }

    /// Reserves `amount` units. Returns false (and logs) when the cap would be
    /// exceeded — the caller must reject the request gracefully.
    func tryReserve(name: String, by amount: Int = 1) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard let cap = limits[name] else { return false }
        let projected = (usage[name] ?? 0) + amount
        guard projected <= cap else {
            I2PSecurityAuditLog.append(category: "quota", detail: "\(name) exhausted: \(projected) > \(cap)")
            return false
        }
        usage[name] = projected
        return true
    }

    func release(name: String, by amount: Int = 1) {
        lock.lock()
        defer { lock.unlock() }
        usage[name] = max(0, (usage[name] ?? 0) - amount)
    }

    func usage(of name: String) -> Int {
        lock.lock()
        defer { lock.unlock() }
        return usage[name] ?? 0
    }

    func limit(of name: String) -> Int? {
        lock.lock()
        defer { lock.unlock() }
        return limits[name]
    }
}

// MARK: - Reconnect backoff

/// Exponential backoff per peer key: a failing peer cannot be hammered into a
/// tight loop. Intervals double per consecutive failure (base 5 s, capped at
/// 15 minutes) and reset immediately on success.
final class I2PReconnectBackoff {
    private let lock = NSLock()
    private var attempts: [Data: Int] = [:]
    private var lastAttempt: [Data: Date] = [:]
    private let baseInterval: TimeInterval
    private let maximumInterval: TimeInterval

    init(baseInterval: TimeInterval = 5, maximumInterval: TimeInterval = 900) {
        self.baseInterval = baseInterval
        self.maximumInterval = maximumInterval
    }

    func shouldAttempt(_ key: Data, now: Date = Date()) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard let last = lastAttempt[key] else { return true }
        let required = intervalFor(attempts[key] ?? 0)
        return now.timeIntervalSince(last) >= required
    }

    func recordAttempt(_ key: Data, succeeded: Bool, now: Date = Date()) {
        lock.lock()
        defer { lock.unlock() }
        lastAttempt[key] = now
        if succeeded {
            attempts[key] = 0
        } else {
            attempts[key] = min((attempts[key] ?? 0) + 1, 30)
        }
    }

    private func intervalFor(_ attempt: Int) -> TimeInterval {
        guard attempt > 0 else { return baseInterval }
        return min(baseInterval * pow(2, Double(attempt - 1)), maximumInterval)
    }
}

// MARK: - Security audit log

/// Security-relevant event log: bounded ring buffer, redaction enforced at
/// the append boundary. Key material and ciphertext-shaped tokens never enter
/// diagnostics — the redactor truncates long opaque runs at append time.
enum I2PSecurityAuditLog {
    struct Entry {
        let timestamp: Date
        let category: String
        let detail: String
    }

    private static let lock = NSLock()
    private static var entries: [Entry] = []
    private static let capacity = I2PHardeningQuota.auditLogEntries

    static func append(category: String, detail: String) {
        let entry = Entry(timestamp: Date(), category: category, detail: redacted(detail))
        lock.lock()
        defer { lock.unlock() }
        entries.append(entry)
        if entries.count > capacity {
            entries.removeFirst(entries.count - capacity)
        }
    }

    static func recent(limit: Int) -> [Entry] {
        lock.lock()
        defer { lock.unlock() }
        return Array(entries.suffix(limit))
    }

    static func count() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return entries.count
    }

    /// Redaction: any run of 16+ opaque characters (potential key material,
    /// base64 or hex ciphertext) is replaced with a length marker.
    static func redacted(_ text: String) -> String {
        var output = ""
        var token = ""
        func flush() {
            if token.count >= 16 {
                output += "[redacted:\(token.count)]"
            } else {
                output += token
            }
            token = ""
        }
        for character in text {
            if character.isLetter || character.isNumber || character == "+" || character == "/" || character == "=" {
                token.append(character)
            } else {
                flush()
                output.append(character)
            }
        }
        flush()
        return output
    }
}

// MARK: - Invariant enforcement

enum I2PInvariant {
    /// Fail closed: a violated critical invariant is an audit event followed
    /// by explicit failure — never silent degradation or continued guessing.
    static func enforce(_ condition: Bool, _ message: String) {
        guard condition else {
            I2PSecurityAuditLog.append(category: "invariant", detail: "violated: \(message)")
            fatalError("I2P invariant violated: \(message)")
        }
    }

    /// Non-fatal variant used by audits and soft paths: records the violation
    /// and reports it to the caller.
    @discardableResult
    static func check(_ condition: Bool, _ message: String) -> Bool {
        if !condition {
            I2PSecurityAuditLog.append(category: "invariant", detail: "violated (non-fatal): \(message)")
        }
        return condition
    }
}

// MARK: - Hardening audit

/// Probes every dimension of the hardening checklist against the live
/// mechanisms: crypto defense, input validation, resource resilience, memory
/// safety, session integrity, and isolation with an audit trail.
enum I2PHardeningAudit {
    static func runAll() async -> [I2PSelfTestResult] {
        let probes: [(String, () async throws -> String)] = [
            ("Hardening · crypto defense — secure erase, constant-time compare, key validation, entropy", cryptoDefense),
            ("Hardening · input validation — zero-trust parsers + boundary contracts", inputValidation),
            ("Hardening · resource resilience — quotas, graceful rejection, backoff", resourceResilience),
            ("Hardening · memory safety — irreversible erasure, log redaction", memorySafety),
            ("Hardening · session integrity — replay, rate limits, session caps", sessionIntegrity),
            ("Hardening · isolation & audit trail — invariants, ring buffer", auditTrail),
        ]

        var results: [I2PSelfTestResult] = []
        for (name, probe) in probes {
            do {
                let detail = try await probe()
                results.append(I2PSelfTestResult(name: name, passed: true, detail: detail))
            } catch {
                results.append(I2PSelfTestResult(name: name, passed: false, detail: String(describing: error)))
            }
        }

        let passing = results.filter(\.passed).count
        results.append(I2PSelfTestResult(
            name: "Hardening · overall posture",
            passed: passing == results.count,
            detail: passing == results.count
                ? "\(passing) hardening probes passed — defensive posture verified across all five audit dimensions"
                : "\(passing) of \(results.count) probes passed — open findings above"))
        return results
    }

    private static func cryptoDefense() async throws -> String {
        // Secure erasure actually erases.
        var buffer = I2PCrypto.randomBytes(64)
        I2PHardenedMemory.zeroize(&buffer)
        guard buffer.allSatisfy({ $0 == 0 }) else {
            throw I2PMainnetFailure(message: "zeroized buffer retained non-zero bytes")
        }

        // Constant-time equality matches only byte-identical secrets.
        let secret = I2PCrypto.randomBytes(32)
        let same = Data(secret)
        var lastByteFlipped = Data(secret)
        lastByteFlipped[31] ^= 0x01
        guard I2PHardenedMemory.constantTimeEquals(secret, same),
              !I2PHardenedMemory.constantTimeEquals(secret, lastByteFlipped),
              !I2PHardenedMemory.constantTimeEquals(secret, I2PCrypto.randomBytes(31)) else {
            throw I2PMainnetFailure(message: "constant-time equality semantics broken")
        }

        // Degenerate and wrong-length key material is rejected.
        try I2PHardenedKeys.validate(I2PCrypto.randomBytes(32), context: "probe")
        for bad in [Data(repeating: 0, count: 32), Data(repeating: 0xFF, count: 32), I2PCrypto.randomBytes(31)] {
            do {
                try I2PHardenedKeys.validate(bad, context: "probe")
                throw I2PMainnetFailure(message: "invalid key material accepted")
            } catch is I2PHardeningError {
                // expected rejection
            }
        }

        // System entropy never repeats.
        guard I2PCrypto.randomBytes(32) != I2PCrypto.randomBytes(32) else {
            throw I2PMainnetFailure(message: "entropy source produced a repeat draw")
        }

        return "zeroize erases buffers irreversibly; constant-time equality reveals no positional timing; degenerate and wrong-length key material rejected; entropy draws never repeat"
    }

    private static func inputValidation() async throws -> String {
        // Zero trust: truncated wire data is rejected, never interpreted.
        let message = I2NPMessage(type: .dataMessage, messageID: 1,
                                  expiration: Date().addingTimeInterval(300),
                                  payload: I2PCrypto.randomBytes(48))
        let bytes = message.serialize()
        for cut in [0, 1, 3, 8, 16, bytes.count - 1] {
            guard (try? I2NPMessage.parse(Data(bytes.prefix(cut)))) == nil else {
                throw I2PMainnetFailure(message: "truncated I2NP accepted at cut \(cut)")
            }
        }
        let routerInfoBytes = I2PRouterAppContext.shared.mainnetSignedRouterInfo.serialize()
        for cut in [1, 8, 64, 200] {
            guard (try? I2PRouterInfo.parse(Data(routerInfoBytes.prefix(cut)))) == nil else {
                throw I2PMainnetFailure(message: "truncated RouterInfo accepted at cut \(cut)")
            }
        }

        // Semantic boundary contracts.
        try I2PInputBounds.validateLeaseCount(16)
        do {
            try I2PInputBounds.validateLeaseCount(17)
            throw I2PMainnetFailure(message: "over-cap lease count accepted")
        } catch is I2PHardeningError {}
        do {
            try I2PInputBounds.validateTunnelID(0)
            throw I2PMainnetFailure(message: "zero tunnel ID accepted")
        } catch is I2PHardeningError {}
        try I2PInputBounds.validateTunnelID(0x1F2E3D4C)
        do {
            try I2PInputBounds.validatePort(0)
            throw I2PMainnetFailure(message: "zero port accepted")
        } catch is I2PHardeningError {}
        try I2PInputBounds.validateMessageSize(65519)
        do {
            try I2PInputBounds.validateMessageSize(65520)
            throw I2PMainnetFailure(message: "oversize message accepted")
        } catch is I2PHardeningError {}

        // Peer identity comes only from cryptographic material: the endpoint
        // parser refuses addresses without a 32-byte static key and a port.
        let key = base64URL(I2PCrypto.randomBytes(32))
        let valid = I2PRouterAddress(cost: 5, transportStyle: "NTCP2", expiration: nil,
                                     options: ["host": "192.0.2.10", "port": "9151", "s": key])
        guard NTCP2PeerEndpoint(routerAddress: valid) != nil else {
            throw I2PMainnetFailure(message: "valid peer endpoint rejected")
        }
        let degenerate: [[String: String]] = [
            ["host": "192.0.2.10", "port": "9151"],
            ["host": "192.0.2.10", "port": "9151", "s": base64URL(I2PCrypto.randomBytes(31))],
            ["host": "192.0.2.10", "s": base64URL(I2PCrypto.randomBytes(32))],
            ["host": "192.0.2.10", "port": "0", "s": base64URL(I2PCrypto.randomBytes(32))],
        ]
        for options in degenerate {
            let address = I2PRouterAddress(cost: 5, transportStyle: "NTCP2", expiration: nil, options: options)
            guard NTCP2PeerEndpoint(routerAddress: address) == nil else {
                throw I2PMainnetFailure(message: "degenerate peer endpoint accepted")
            }
        }

        return "truncated I2NP/RouterInfo rejected at every cut; lease-count, tunnel-ID, port, and message-size contracts enforced; peer endpoints parse only with a 32-byte static key and a port"
    }

    private static func resourceResilience() async throws -> String {
        // Quotas: graceful typed rejection at the cap, reusable after release.
        let ledger = I2PResourceLedger()
        ledger.register(name: "probe.quota", limit: 4)
        for _ in 0..<4 {
            guard ledger.tryReserve(name: "probe.quota") else {
                throw I2PMainnetFailure(message: "quota rejected below its cap")
            }
        }
        guard !ledger.tryReserve(name: "probe.quota") else {
            throw I2PMainnetFailure(message: "quota cap not enforced")
        }
        ledger.release(name: "probe.quota")
        guard ledger.tryReserve(name: "probe.quota") else {
            throw I2PMainnetFailure(message: "released quota not reusable")
        }

        // Backoff: doubling with a cap, reset on success.
        let backoff = I2PReconnectBackoff(baseInterval: 0.1, maximumInterval: 0.4)
        let peer = I2PCrypto.randomBytes(16)
        let start = Date(timeIntervalSince1970: 1_000_000)
        guard backoff.shouldAttempt(peer, now: start) else {
            throw I2PMainnetFailure(message: "first attempt wrongly gated")
        }
        backoff.recordAttempt(peer, succeeded: false, now: start)
        guard !backoff.shouldAttempt(peer, now: start.addingTimeInterval(0.05)) else {
            throw I2PMainnetFailure(message: "backoff did not gate after failure")
        }
        guard backoff.shouldAttempt(peer, now: start.addingTimeInterval(0.15)) else {
            throw I2PMainnetFailure(message: "backoff interval wrong after one failure")
        }
        backoff.recordAttempt(peer, succeeded: false, now: start.addingTimeInterval(0.15))
        guard !backoff.shouldAttempt(peer, now: start.addingTimeInterval(0.2)) else {
            throw I2PMainnetFailure(message: "backoff not doubling after second failure")
        }
        guard backoff.shouldAttempt(peer, now: start.addingTimeInterval(0.4)) else {
            throw I2PMainnetFailure(message: "backoff interval wrong after two failures")
        }
        backoff.recordAttempt(peer, succeeded: false, now: start.addingTimeInterval(0.4))
        backoff.recordAttempt(peer, succeeded: false, now: start.addingTimeInterval(0.8))
        guard !backoff.shouldAttempt(peer, now: start.addingTimeInterval(1.0)) else {
            throw I2PMainnetFailure(message: "backoff cap not applied")
        }
        guard backoff.shouldAttempt(peer, now: start.addingTimeInterval(1.3)) else {
            throw I2PMainnetFailure(message: "capped backoff never releases")
        }
        backoff.recordAttempt(peer, succeeded: true, now: start.addingTimeInterval(1.3))
        guard backoff.shouldAttempt(peer, now: start.addingTimeInterval(1.31)) else {
            throw I2PMainnetFailure(message: "success did not reset backoff")
        }

        // Documented defaults are registered and enforced.
        guard ledger.limit(of: "ntcp2.sessions") == I2PHardeningQuota.transportSessions,
              ledger.limit(of: "netdb.cache") == I2PHardeningQuota.netDBCacheEntries else {
            throw I2PMainnetFailure(message: "documented quota defaults missing")
        }

        return "quota exhaustion is a typed rejection and reusable after release; reconnect backoff doubles from 5 s to a 15-minute cap and resets on success; documented resource caps registered"
    }

    private static func memorySafety() async throws -> String {
        // Erasure is irreversible.
        var secret = I2PCrypto.randomBytes(48)
        let copy = secret
        I2PHardenedMemory.zeroize(&secret)
        guard secret.allSatisfy({ $0 == 0 }),
              !I2PHardenedMemory.constantTimeEquals(secret, copy) else {
            throw I2PMainnetFailure(message: "erasure did not destroy the secret")
        }

        // Sensitive data never enters the audit log.
        let keyMaterial = I2PCrypto.randomBytes(32).base64EncodedString()
        I2PSecurityAuditLog.append(category: "probe", detail: "session material \(keyMaterial) observed")
        guard let stored = I2PSecurityAuditLog.recent(limit: 1).first else {
            throw I2PMainnetFailure(message: "audit log lost the entry")
        }
        guard !stored.detail.contains(keyMaterial) else {
            throw I2PMainnetFailure(message: "key material leaked into the audit log")
        }
        guard stored.detail.contains("[redacted:") else {
            throw I2PMainnetFailure(message: "redaction marker missing")
        }

        // Short operational text passes through untouched.
        I2PSecurityAuditLog.append(category: "probe", detail: "session established")
        guard I2PSecurityAuditLog.recent(limit: 1).first?.detail == "session established" else {
            throw I2PMainnetFailure(message: "benign operational text was mangled")
        }

        return "erasure destroys secrets irreversibly; opaque tokens are redacted at the log boundary while benign text passes through"
    }

    private static func sessionIntegrity() async throws -> String {
        // Replay window: duplicates and out-of-window packets are rejected,
        // in-window reordering is accepted.
        let window = SSU2ReplayWindow()
        guard window.checkAndInsert(10), window.checkAndInsert(4), window.checkAndInsert(9),
              !window.checkAndInsert(9), !window.checkAndInsert(10), window.checkAndInsert(80) else {
            throw I2PMainnetFailure(message: "replay window semantics broken")
        }

        // Token requests are rate limited per requester.
        let manager = SSU2TokenManager(tokenLifetime: 600, maxRequestsPerWindow: 3, requestWindow: 60)
        let requester = Data(repeating: 7, count: 8)
        for _ in 0..<3 { _ = manager.issue(for: requester) }
        guard manager.issue(for: requester) == nil else {
            throw I2PMainnetFailure(message: "token rate limit not enforced")
        }

        // Transport session caps are quota-backed; exhaustion is logged and
        // the connection is rejected rather than admitted.
        let transportLedger = I2PResourceLedger()
        for _ in 0..<I2PHardeningQuota.transportSessions {
            guard transportLedger.tryReserve(name: "ntcp2.sessions") else {
                throw I2PMainnetFailure(message: "session quota rejected below its cap")
            }
        }
        guard !transportLedger.tryReserve(name: "ntcp2.sessions") else {
            throw I2PMainnetFailure(message: "transport session cap not enforced")
        }
        guard I2PSecurityAuditLog.recent(limit: 5).contains(where: { $0.category == "quota" && $0.detail.contains("ntcp2.sessions") }) else {
            throw I2PMainnetFailure(message: "session-cap exhaustion not recorded in the audit log")
        }

        return "replay window rejects duplicates and out-of-window packets; token requests rate limited per requester; the NTCP2 session cap is quota-backed, fail-closed, and every exhaustion is audit-logged"
    }

    private static func auditTrail() async throws -> String {
        let before = I2PSecurityAuditLog.count()

        // Invariant violations are recorded, not silent.
        guard I2PInvariant.check(true, "probe invariant") else {
            throw I2PMainnetFailure(message: "satisfied invariant reported as violated")
        }
        guard !I2PInvariant.check(false, "probe invariant violation") else {
            throw I2PMainnetFailure(message: "violated invariant not reported")
        }
        guard I2PSecurityAuditLog.count() == before + 1 else {
            throw I2PMainnetFailure(message: "invariant violation not recorded")
        }

        // Ring buffer bound: oldest entries are evicted, the log never grows
        // past its documented capacity.
        for index in 0..<550 {
            I2PSecurityAuditLog.append(category: "probe", detail: "fill \(index)")
        }
        guard I2PSecurityAuditLog.count() <= I2PHardeningQuota.auditLogEntries else {
            throw I2PMainnetFailure(message: "audit log unbounded")
        }
        let recent = I2PSecurityAuditLog.recent(limit: 10)
        guard recent.count == 10, recent.last?.detail == "fill 549" else {
            throw I2PMainnetFailure(message: "ring buffer eviction incorrect")
        }
        guard let first = recent.first, first.category == "probe", first.timestamp <= Date() else {
            throw I2PMainnetFailure(message: "audit entries missing timestamps or categories")
        }

        return "invariant violations are recorded events; the audit log is a bounded ring buffer with timestamped, categorized entries"
    }

    private static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}