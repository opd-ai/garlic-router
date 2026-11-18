//
//  I2PPeerHandshakeBackoff.swift
//  In-memory per-peer handshake failure profiles: what an NTCP2 dial to a peer
//  last failed with and when the router may try that peer again.
//
//  A failed handshake is neither a reason to forget a peer nor a reason to
//  hammer it. The dial paths consult this profile, peers still inside their
//  backoff are skipped when the router picks floodfills to dial or hops to
//  connect to, and the maintenance beat dispatches the retry once the window
//  runs out. Only the three endings a retry can help with are recorded — a peer
//  closing after SessionRequest, a TCP connect that times out and a handshake
//  window that expires. An established session is never touched: the profile
//  speaks about dialing, not about sessions.
//
//  Everything here is memory only, and the tracked set is capped, so a large
//  netdb cannot grow it without bound.
//

import Foundation

// MARK: - Failure reason

/// Why a dial to a peer failed, limited to the endings a retry is scheduled for.
enum I2PPeerHandshakeFailureReason: String, Equatable {
    /// The peer accepted TCP and sent SessionRequest's answer, then hung up.
    case peerClosedAfterSessionRequest
    case connectTimeout
    case handshakeTimeout

    /// The words the peer inspector shows beside the last failure.
    var label: String {
        switch self {
        case .peerClosedAfterSessionRequest: return "Peer closed after SessionRequest"
        case .connectTimeout: return "TCP connect timed out"
        case .handshakeTimeout: return "Handshake window expired"
        }
    }

    /// Classifies an NTCP2 session's own close reason. The transport words each
    /// ending itself ("peer did not accept the TCP connection within 8s",
    /// "peer closed during the handshake after SessionRequest (no
    /// SessionCreated)", "handshake did not complete within 20s"), so the
    /// profile repeats the transport's verdict instead of inventing one. Any
    /// other ending is nil: it is not one of the three a retry is scheduled for,
    /// and the peer's own words stay in its log.
    static func classify(closeReason: String?) -> I2PPeerHandshakeFailureReason? {
        guard let text = closeReason?.lowercased() else { return nil }
        if text.contains("did not accept the tcp connection") { return .connectTimeout }
        if text.contains("peer closed during the handshake") {
            return text.contains("after sessionrequest") ? .peerClosedAfterSessionRequest : nil
        }
        if text.contains("handshake did not complete") { return .handshakeTimeout }
        return nil
    }
}

// MARK: - Profile

/// The live dial profile of one peer.
struct I2PPeerHandshakeProfile: Equatable {
    /// Consecutive failed dials since the last successful handshake.
    var consecutiveFailures = 0
    var lastFailureReason: I2PPeerHandshakeFailureReason?
    var lastFailureAt: Date?
    /// When the next attempt is due. nil once a successful handshake reset the
    /// schedule; the failure that came before it stays on record for the peer
    /// inspector.
    var nextAttemptAt: Date?
    /// When the maintenance beat dispatched a scheduled retry, so an
    /// unreachable peer cannot turn the retry beat into a tight loop.
    var retryDispatchedAt: Date?

    func isHeldBack(now: Date) -> Bool {
        guard let nextAttemptAt else { return false }
        return now < nextAttemptAt
    }
}

/// What the peer inspector shows about a peer's last failed dial.
struct I2PPeerHandshakeBackoffReading: Equatable {
    let reason: I2PPeerHandshakeFailureReason
    let failedAt: Date
    let consecutiveFailures: Int
    /// nil when a successful handshake has reset the schedule.
    let nextAttemptAt: Date?

    func isHeldBack(now: Date = Date()) -> Bool {
        guard let nextAttemptAt else { return false }
        return now < nextAttemptAt
    }
}

// MARK: - Store

/// The router's handshake-failure profiles, one per peer identity, kept in
/// memory and bounded.
///
/// Thread-safe: the dial paths, the retry beat, the status engine and the peer
/// inspector all read and write it.
final class I2PPeerHandshakeBackoff: @unchecked Sendable {
    static let shared = I2PPeerHandshakeBackoff()

    /// The retry ladder: the first retry comes after a minute, then 2, 5, 15 and
    /// 30. A peer that keeps failing stays on the last rung instead of growing
    /// an unbounded window.
    static let retrySchedule: [TimeInterval] = [60, 120, 300, 900, 1800]
    /// A peer is not dispatched again sooner than this after a scheduled retry
    /// went out.
    static let retryDispatchSpacing: TimeInterval = 60
    /// Bounded tracked set (bounded like the peer selector's own profiles).
    static let maxTrackedPeers = 2000

    private let lock = NSLock()
    private var profiles: [String: I2PPeerHandshakeProfile] = [:]

    init() {}

    // MARK: Recording

    /// Records one failed dial: the failure advances the peer's ladder and the
    /// next attempt is scheduled from the rung it lands on.
    @discardableResult
    func recordFailure(_ hash: Data, reason: I2PPeerHandshakeFailureReason,
                       now: Date = Date()) -> I2PPeerHandshakeProfile {
        recordFailure(identityHex: Self.hex(hash), reason: reason, now: now)
    }

    @discardableResult
    func recordFailure(identityHex hex: String, reason: I2PPeerHandshakeFailureReason,
                       now: Date = Date()) -> I2PPeerHandshakeProfile {
        let key = Self.normalize(hex)
        lock.lock()
        defer { lock.unlock() }
        var profile = profiles[key] ?? I2PPeerHandshakeProfile()
        profile.consecutiveFailures += 1
        profile.lastFailureReason = reason
        profile.lastFailureAt = now
        profile.nextAttemptAt = now.addingTimeInterval(
            Self.backoff(afterFailures: profile.consecutiveFailures))
        profile.retryDispatchedAt = nil
        profiles[key] = profile
        pruneLocked()
        return profile
    }

    /// A successful handshake — either transport, ours or the peer's — resets
    /// the ladder, so the next failure starts at the first rung again.
    func recordSuccess(_ hash: Data) {
        recordSuccess(identityHex: Self.hex(hash))
    }

    func recordSuccess(identityHex hex: String) {
        let key = Self.normalize(hex)
        lock.lock()
        defer { lock.unlock() }
        guard var profile = profiles[key] else { return }
        profile.consecutiveFailures = 0
        profile.nextAttemptAt = nil
        profile.retryDispatchedAt = nil
        profiles[key] = profile
    }

    /// The schedule rung for a consecutive failure count: 1m, 2m, 5m, 15m, 30m,
    /// then 30m for every further failure.
    static func backoff(afterFailures failures: Int) -> TimeInterval {
        guard failures > 0 else { return 0 }
        return retrySchedule[min(failures - 1, retrySchedule.count - 1)]
    }

    // MARK: Reading

    func profile(_ hash: Data) -> I2PPeerHandshakeProfile? {
        profile(identityHex: Self.hex(hash))
    }

    func profile(identityHex hex: String) -> I2PPeerHandshakeProfile? {
        let key = Self.normalize(hex)
        lock.lock()
        defer { lock.unlock() }
        return profiles[key]
    }

    func reading(identityHex hex: String) -> I2PPeerHandshakeBackoffReading? {
        guard let profile = profile(identityHex: hex),
              let reason = profile.lastFailureReason,
              let failedAt = profile.lastFailureAt else { return nil }
        return I2PPeerHandshakeBackoffReading(reason: reason,
                                              failedAt: failedAt,
                                              consecutiveFailures: profile.consecutiveFailures,
                                              nextAttemptAt: profile.nextAttemptAt)
    }

    func reading(_ hash: Data) -> I2PPeerHandshakeBackoffReading? {
        reading(identityHex: Self.hex(hash))
    }

    /// Whether the peer's next attempt is still in the future.
    func isHeldBack(_ hash: Data, now: Date = Date()) -> Bool {
        isHeldBack(identityHex: Self.hex(hash), now: now)
    }

    func isHeldBack(identityHex hex: String, now: Date = Date()) -> Bool {
        profile(identityHex: hex)?.isHeldBack(now: now) ?? false
    }

    /// How many peers the dial paths are currently skipping.
    func heldBackCount(now: Date = Date()) -> Int {
        lock.lock()
        defer { lock.unlock() }
        return profiles.values.filter { $0.isHeldBack(now: now) }.count
    }

    var trackedCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return profiles.count
    }

    // MARK: Retry dispatch

    /// Peers whose next attempt is due, oldest due first, at most `limit`. The
    /// returned peers are marked as dispatched so the next beat does not repeat
    /// them before their attempt has had time to settle.
    func dispatchableRetries(limit: Int, now: Date = Date()) -> [Data] {
        guard limit > 0 else { return [] }
        lock.lock()
        defer { lock.unlock() }
        let due = profiles.compactMap { key, profile -> (key: String, due: Date)? in
            guard let nextAttemptAt = profile.nextAttemptAt, nextAttemptAt <= now else {
                return nil
            }
            if let dispatched = profile.retryDispatchedAt,
               now.timeIntervalSince(dispatched) < Self.retryDispatchSpacing {
                return nil
            }
            return (key, nextAttemptAt)
        }
        .sorted { $0.due < $1.due }
        .prefix(limit)
        for entry in due { profiles[entry.key]?.retryDispatchedAt = now }
        return due.compactMap { Self.data(fromHex: $0.key) }
    }

    // MARK: Internals

    /// Keeps profile storage bounded: once over the cap, the peers whose last
    /// failure is oldest are forgotten first.
    private func pruneLocked() {
        guard profiles.count > Self.maxTrackedPeers else { return }
        let excess = profiles.count - Self.maxTrackedPeers
        let victims = profiles.keys
            .sorted {
                (profiles[$0]?.lastFailureAt ?? .distantPast)
                    < (profiles[$1]?.lastFailureAt ?? .distantPast)
            }
            .prefix(excess)
        for key in victims { profiles.removeValue(forKey: key) }
    }

    private static func normalize(_ hex: String) -> String {
        hex.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    static func data(fromHex hex: String) -> Data? {
        let text = normalize(hex)
        guard text.count % 2 == 0, !text.isEmpty else { return nil }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(text.count / 2)
        var index = text.startIndex
        while index < text.endIndex {
            let next = text.index(index, offsetBy: 2)
            guard let byte = UInt8(text[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        return Data(bytes)
    }
}

// MARK: - Self-test

/// The retry ladder is the whole feature's contract, so it is pinned here:
/// nothing below opens a socket or touches the router.
enum I2PPeerHandshakeBackoffSelfTest {
    static func runAll() -> [I2PSelfTestResult] {
        var results: [I2PSelfTestResult] = []
        func run(_ name: String, _ body: () throws -> String) {
            do {
                results.append(I2PSelfTestResult(name: name, passed: true, detail: try body()))
            } catch {
                results.append(I2PSelfTestResult(name: name, passed: false, detail: "\(error)"))
            }
        }

        run("Handshake backoff · the ladder is 1, 2, 5, 15 and 30 minutes, then flat") {
            let store = I2PPeerHandshakeBackoff()
            let hash = I2PCrypto.randomBytes(32)
            let start = Date(timeIntervalSince1970: 1_700_000_000)
            let ladder: [TimeInterval] = [60, 120, 300, 900, 1800, 1800]
            for (step, interval) in ladder.enumerated() {
                let profile = store.recordFailure(hash, reason: .peerClosedAfterSessionRequest,
                                                  now: start)
                guard profile.consecutiveFailures == step + 1,
                      let due = profile.nextAttemptAt,
                      due.timeIntervalSince(start) == interval else {
                    throw I2PWireError.invalidFormat
                }
            }
            return "6 failures → 1m, 2m, 5m, 15m, 30m, 30m"
        }

        run("Handshake backoff · a peer inside its window is held back, then due") {
            let store = I2PPeerHandshakeBackoff()
            let hash = I2PCrypto.randomBytes(32)
            let start = Date(timeIntervalSince1970: 1_700_000_000)
            store.recordFailure(hash, reason: .connectTimeout, now: start)
            guard store.isHeldBack(hash, now: start),
                  store.isHeldBack(hash, now: start.addingTimeInterval(59)),
                  !store.isHeldBack(hash, now: start.addingTimeInterval(61)),
                  store.heldBackCount(now: start) == 1,
                  store.heldBackCount(now: start.addingTimeInterval(61)) == 0,
                  store.reading(hash)?.reason == .connectTimeout else {
                throw I2PWireError.invalidFormat
            }
            return "held back for the first minute, due afterwards"
        }

        run("Handshake backoff · a successful handshake resets the schedule") {
            let store = I2PPeerHandshakeBackoff()
            let hash = I2PCrypto.randomBytes(32)
            let start = Date(timeIntervalSince1970: 1_700_000_000)
            for _ in 0..<3 {
                store.recordFailure(hash, reason: .handshakeTimeout, now: start)
            }
            store.recordSuccess(hash)
            guard !store.isHeldBack(hash, now: start),
                  let reset = store.reading(hash),
                  readingIsReset(store, hash: hash),
                  reset.nextAttemptAt == nil,
                  reset.consecutiveFailures == 0,
                  // The last failure stays on record for the inspector.
                  reset.reason == .handshakeTimeout else {
                throw I2PWireError.invalidFormat
            }
            let next = store.recordFailure(hash, reason: .connectTimeout, now: start)
            guard next.consecutiveFailures == 1,
                  next.nextAttemptAt?.timeIntervalSince(start) == 60 else {
                throw I2PWireError.invalidFormat
            }
            return "reset to the first rung; the reset profile keeps its last failure for display"
        }

        run("Handshake backoff · due retries are dispatched once, then spaced") {
            let store = I2PPeerHandshakeBackoff()
            let a = I2PCrypto.randomBytes(32)
            let b = I2PCrypto.randomBytes(32)
            let start = Date(timeIntervalSince1970: 1_700_000_000)
            store.recordFailure(a, reason: .connectTimeout, now: start)
            store.recordFailure(b, reason: .handshakeTimeout, now: start)
            // Nothing is due inside the window.
            guard store.dispatchableRetries(limit: 4, now: start.addingTimeInterval(30)).isEmpty else {
                throw I2PWireError.invalidFormat
            }
            let first = store.dispatchableRetries(limit: 4, now: start.addingTimeInterval(61))
            guard Set(first) == Set([a, b]) else { throw I2PWireError.invalidFormat }
            // The same beat again does not re-dial them before the attempt settles.
            guard store.dispatchableRetries(limit: 4, now: start.addingTimeInterval(75)).isEmpty else {
                throw I2PWireError.invalidFormat
            }
            let later = start.addingTimeInterval(61 + I2PPeerHandshakeBackoff.retryDispatchSpacing + 1)
            guard Set(store.dispatchableRetries(limit: 4, now: later)) == Set([a, b]) else {
                throw I2PWireError.invalidFormat
            }
            return "two due peers dispatched together, then spaced"
        }

        run("Handshake backoff · the tracked set is capped") {
            let store = I2PPeerHandshakeBackoff()
            let start = Date(timeIntervalSince1970: 1_700_000_000)
            let total = I2PPeerHandshakeBackoff.maxTrackedPeers + 25
            for index in 0..<total {
                store.recordFailure(identityHex: String(format: "%064x", index),
                                    reason: .connectTimeout,
                                    now: start.addingTimeInterval(Double(index)))
            }
            guard store.trackedCount == I2PPeerHandshakeBackoff.maxTrackedPeers else {
                throw I2PWireError.invalidFormat
            }
            // The oldest failures are the ones forgotten.
            guard store.profile(identityHex: String(format: "%064x", 0)) == nil,
                  store.profile(identityHex: String(format: "%064x", total - 1)) != nil else {
                throw I2PWireError.invalidFormat
            }
            return "\(total) tracked peers bounded to \(store.trackedCount)"
        }

        run("Handshake backoff · only the three retryable endings are recorded") {
            guard I2PPeerHandshakeFailureReason.classify(
                    closeReason: "handshakeFailed(\"peer did not accept the TCP connection within 8s\")")
                    == .connectTimeout,
                  I2PPeerHandshakeFailureReason.classify(
                    closeReason: "peer closed during the handshake after SessionRequest (no SessionCreated) — 288 B sent, 0 B received")
                    == .peerClosedAfterSessionRequest,
                  I2PPeerHandshakeFailureReason.classify(
                    closeReason: "handshakeFailed(\"handshake did not complete within 20s\")")
                    == .handshakeTimeout,
                  I2PPeerHandshakeFailureReason.classify(closeReason: nil) == nil,
                  I2PPeerHandshakeFailureReason.classify(closeReason: "peer closed the session") == nil,
                  I2PPeerHandshakeFailureReason.classify(
                    closeReason: "peer closed during the handshake before SessionRequest") == nil else {
                throw I2PWireError.invalidFormat
            }
            return "connect timeout, hang-up after SessionRequest and handshake timeout"
        }

        return results
    }

    /// The reset profile has no due time even if a stale reading were asked for.
    private static func readingIsReset(_ store: I2PPeerHandshakeBackoff, hash: Data) -> Bool {
        store.reading(hash)?.isHeldBack(now: Date()) == false
    }
}
