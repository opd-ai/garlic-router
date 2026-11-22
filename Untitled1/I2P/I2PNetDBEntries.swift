//
//  I2PNetDBEntries.swift
//  The browse model for the netdb cache: every live entry flattened into the
//  row the network-database screen lists (type, shortened hash, age, floodfill
//  flag, address/lease count) and the detail behind one row (full hash,
//  publication and expiry, parsed addresses or leases, and whether the stored
//  signature verifies).
//
//  Everything here is derived from the cache the network database actor holds,
//  so the screen never presents an entry the router did not accept: an entry
//  only reaches `entries` after its signature verified at ingest.
//

import Foundation

/// Which of the two netdb kinds a cached row is. The browse screen separates
/// exactly these; the LeaseSet2 family (plain, encrypted, meta) all resolve
/// through the same destination-keyed lookup and list as LeaseSets.
enum I2PNetDBEntryKind: String {
    case routerInfo
    case leaseSet

    /// The badge the row carries: "RI" or "LS".
    var badge: String {
        switch self {
        case .routerInfo: return "RI"
        case .leaseSet: return "LS"
        }
    }

    var title: String {
        switch self {
        case .routerInfo: return "RouterInfo"
        case .leaseSet: return "LeaseSet"
        }
    }
}

/// One live netdb cache entry as the browse screen lists it.
struct I2PNetDBEntrySummary: Identifiable {
    /// The segmented control's three views of the same list.
    enum Filter: String, CaseIterable, Identifiable {
        case all = "All"
        case routerInfos = "RouterInfos"
        case leaseSets = "LeaseSets"

        var id: String { rawValue }

        func includes(_ kind: I2PNetDBEntryKind) -> Bool {
            switch self {
            case .all: return true
            case .routerInfos: return kind == .routerInfo
            case .leaseSets: return kind == .leaseSet
            }
        }
    }

    /// The cache key, hex — also the identity the detail sheet re-reads by.
    let id: String
    let kind: I2PNetDBEntryKind
    /// "RouterInfo", "LeaseSet", "LeaseSet 2", "Encrypted LeaseSet", "Meta LeaseSet".
    let typeLabel: String
    let shortHash: String
    let publishedAt: Date
    let expiresAt: Date
    let isFloodfill: Bool
    /// "2 addresses", "1 lease", "4 meta leases", or "encrypted body".
    let countText: String
}

/// Everything one entry's detail sheet shows.
struct I2PNetDBEntryDetail: Identifiable {
    /// One published RouterAddress, reduced to what a reader needs.
    struct Endpoint: Identifiable {
        let id: String
        let transport: String
        let endpoint: String
        let cost: Int
        let expiration: Date?
    }

    /// One lease entry: the gateway it points at and its tunnel.
    struct Lease: Identifiable {
        let id: String
        let gatewayHashHex: String
        let tunnelId: UInt32
        let expiration: Date
    }

    let id: String
    let kind: I2PNetDBEntryKind
    let typeLabel: String
    let hashHex: String
    let publishedAt: Date
    let expiresAt: Date
    let isFloodfill: Bool
    /// The advertised capability string (RouterInfo), empty when not published.
    let caps: String
    /// True when the stored payload's signature verifies against its own identity.
    let signatureVerified: Bool
    /// The stored payload's size in bytes, exactly as ingested.
    let payloadBytes: Int
    let endpoints: [Endpoint]
    let leases: [Lease]
    /// Set when the lease list is not readable from the envelope itself.
    let leaseNote: String?
}

// MARK: - Cache entry → browse model

extension I2PNetworkDatabase.StoredEntry {
    var browseKind: I2PNetDBEntryKind {
        entryType == .routerInfo ? .routerInfo : .leaseSet
    }

    /// The entry's own publication date, never the cache's storage time: a
    /// RouterInfo and a LeaseSet own theirs, and an entry without one falls back
    /// to its expiry rather than inventing a publication it never carried.
    var browsePublishedAt: Date {
        routerInfo?.published ?? leaseSet?.published ?? leaseSet2?.published ?? expiresAt
    }

    var browseTypeLabel: String {
        switch entryType {
        case .routerInfo: return "RouterInfo"
        case .leaseSet: return "LeaseSet"
        case .leaseSet2: return "LeaseSet 2"
        case .encryptedLeaseSet2: return "Encrypted LeaseSet"
        case .metaLeaseSet2: return "Meta LeaseSet"
        }
    }

    /// A RouterInfo advertises the floodfill capability in its "caps" option.
    /// A LeaseSet names no role of its own, so it is never flagged.
    var browseIsFloodfill: Bool {
        routerInfo?.options["caps"]?.contains("f") == true
    }

    var browseCountText: String {
        if let routerInfo {
            return I2PNetDBEntryText.count(routerInfo.addresses.count, "address", "addresses")
        }
        if let leaseSet {
            return I2PNetDBEntryText.count(leaseSet.leases.count, "lease", "leases")
        }
        if let leaseSet2 {
            switch leaseSet2.storeType {
            case .plain:
                return I2PNetDBEntryText.count(leaseSet2.leases.count, "lease", "leases")
            case .meta:
                return I2PNetDBEntryText.count(leaseSet2.metaEntries.count, "meta lease", "meta leases")
            case .encrypted:
                return "encrypted body"
            }
        }
        return "no payload"
    }

    var browseSummary: I2PNetDBEntrySummary {
        let hashHex = I2PNetDBEntryText.hex(key)
        return I2PNetDBEntrySummary(
            id: hashHex,
            kind: browseKind,
            typeLabel: browseTypeLabel,
            shortHash: I2PNetDBEntryText.shortHash(hashHex),
            publishedAt: browsePublishedAt,
            expiresAt: expiresAt,
            isFloodfill: browseIsFloodfill,
            countText: browseCountText
        )
    }

    var browseDetail: I2PNetDBEntryDetail {
        let addresses = routerInfo.map(\.addresses) ?? []
        let endpoints = addresses.enumerated().map { index, address in
            I2PNetDBEntryDetail.Endpoint(
                id: "\(index)-\(address.transportStyle)",
                transport: address.transportStyle,
                endpoint: I2PNetDBEntryText.endpoint(address),
                cost: Int(address.cost),
                expiration: address.expiration
            )
        }

        var leases: [I2PNetDBEntryDetail.Lease] = []
        var leaseNote: String?
        if let leaseSet {
            leases = leaseSet.leases.enumerated().map { index, lease in
                I2PNetDBEntryDetail.Lease(
                    id: "lease-\(index)",
                    gatewayHashHex: I2PNetDBEntryText.hex(lease.gatewayHash),
                    tunnelId: lease.tunnelId,
                    expiration: lease.expiration
                )
            }
        } else if let leaseSet2 {
            switch leaseSet2.storeType {
            case .plain:
                leases = leaseSet2.leases.enumerated().map { index, lease in
                    I2PNetDBEntryDetail.Lease(
                        id: "lease-\(index)",
                        gatewayHashHex: I2PNetDBEntryText.hex(lease.gatewayHash),
                        tunnelId: lease.tunnelId,
                        expiration: lease.expiration
                    )
                }
            case .meta:
                leaseNote = "A meta LeaseSet points at other netdb entries by hash; each of those resolves separately."
            case .encrypted:
                leaseNote = "The lease body is encrypted. Only a holder of the host's b33 credentials can read its leases."
            }
        }

        let signatureVerified: Bool
        if let routerInfo {
            signatureVerified = routerInfo.verifySignature()
        } else if let leaseSet {
            signatureVerified = leaseSet.verifySignature()
        } else if let leaseSet2 {
            signatureVerified = leaseSet2.verifyTransientBlockSignature() && leaseSet2.verifySignature()
        } else {
            signatureVerified = false
        }

        let hashHex = I2PNetDBEntryText.hex(key)
        return I2PNetDBEntryDetail(
            id: hashHex,
            kind: browseKind,
            typeLabel: browseTypeLabel,
            hashHex: hashHex,
            publishedAt: browsePublishedAt,
            expiresAt: expiresAt,
            isFloodfill: browseIsFloodfill,
            caps: routerInfo?.options["caps"] ?? "",
            signatureVerified: signatureVerified,
            payloadBytes: raw.count,
            endpoints: endpoints,
            leases: leases,
            leaseNote: leaseNote
        )
    }
}

// MARK: - Actor surface

extension I2PNetworkDatabase {
    /// Every live entry in the cache, freshest publication first. Expired
    /// residents are left out: they are not entries the netdb would answer
    /// with, so listing them would claim more than the router holds.
    func browseEntries(now: Date = Date()) -> [I2PNetDBEntrySummary] {
        entries.values
            .filter { !$0.isExpired(now) }
            .sorted { lhs, rhs in
                let left = lhs.browsePublishedAt
                let right = rhs.browsePublishedAt
                if left != right { return left > right }
                return lhs.key.lexicographicallyPrecedes(rhs.key)
            }
            .map(\.browseSummary)
    }

    /// The detail behind one browse row, by the cache key's hex.
    func browseDetail(keyHex: String) -> I2PNetDBEntryDetail? {
        guard let key = I2PNetDBEntryText.data(hex: keyHex) else { return nil }
        return entries[key]?.browseDetail
    }
}

// MARK: - Text

/// The wording the browse screen and its detail sheet share.
enum I2PNetDBEntryText {
    static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    static func data(hex: String) -> Data? {
        let cleaned = hex.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard cleaned.count % 2 == 0, !cleaned.isEmpty else { return nil }
        var bytes = Data()
        var index = cleaned.startIndex
        while index < cleaned.endIndex {
            let next = cleaned.index(index, offsetBy: 2)
            guard let byte = UInt8(cleaned[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        return bytes
    }

    /// The advertised host and port, or the honest note that an unpublished
    /// RouterAddress carries neither. Kept in the core model so command-line
    /// protocol tests do not need to compile a SwiftUI screen to project an entry.
    static func endpoint(_ address: I2PRouterAddress) -> String {
        let host = (address.options["host"] ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let port = (address.options["port"] ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        if !host.isEmpty, !port.isEmpty { return "\(host):\(port)" }
        if !host.isEmpty { return host }
        return "no host or port published"
    }

    /// "a3f9...c21b" — the mockup's shortened hash.
    static func shortHash(_ hex: String) -> String {
        guard hex.count > 12 else { return hex }
        return "\(hex.prefix(4))...\(hex.suffix(4))"
    }

    /// "2 addresses" / "1 lease".
    static func count(_ value: Int, _ singular: String, _ plural: String) -> String {
        "\(value) \(value == 1 ? singular : plural)"
    }

    /// "just now", "12 min ago", "3 h 5 min ago", "2 d ago".
    static func age(_ date: Date, now: Date = Date()) -> String {
        let seconds = max(0, now.timeIntervalSince(date))
        if seconds < 60 { return "just now" }
        if seconds < 3600 { return "\(Int(seconds / 60)) min ago" }
        if seconds < 86_400 {
            let hours = Int(seconds / 3600)
            let minutes = Int(seconds.truncatingRemainder(dividingBy: 3600) / 60)
            return minutes == 0 ? "\(hours) h ago" : "\(hours) h \(minutes) min ago"
        }
        return "\(Int(seconds / 86_400)) d ago"
    }

    /// "51 min", "3 h", "2 d" — the header's oldest-entry reading.
    static func shortDuration(_ interval: TimeInterval) -> String {
        let seconds = max(0, interval)
        if seconds < 60 { return "\(Int(seconds))s" }
        if seconds < 3600 { return "\(Int(seconds / 60)) min" }
        if seconds < 86_400 { return "\(Int(seconds / 3600)) h" }
        return "\(Int(seconds / 86_400)) d"
    }

    /// "in 48 min" or "expired".
    static func expiry(_ date: Date, now: Date = Date()) -> String {
        guard date > now else { return "expired" }
        return "in " + shortDuration(date.timeIntervalSince(now))
    }

    /// "2026-11-18 14:02" — a fixed, unambiguous absolute reading.
    static func absolute(_ date: Date) -> String {
        absoluteFormatter.string(from: date)
    }

    /// The header's counts line: "34 entries · 12 floodfills · oldest 51 min".
    static func header(_ summaries: [I2PNetDBEntrySummary], now: Date = Date()) -> String {
        let entries = count(summaries.count, "entry", "entries")
        let floodfills = count(summaries.filter(\.isFloodfill).count, "floodfill", "floodfills")
        guard let oldest = summaries.map(\.publishedAt).min() else { return entries }
        return "\(entries) · \(floodfills) · oldest \(shortDuration(now.timeIntervalSince(oldest)))"
    }

    /// "published 12 min ago · 2 addresses".
    static func rowDetail(_ summary: I2PNetDBEntrySummary, now: Date = Date()) -> String {
        "published \(age(summary.publishedAt, now: now)) · \(summary.countText)"
    }

    private static let absoluteFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm"
        formatter.locale = Locale(identifier: "en_US_POSIX")
        return formatter
    }()
}

/// Focused regression coverage for the projection used by the NetDB browser.
enum I2PNetDBEntriesSelfTest {
    static func runAll() -> [I2PSelfTestResult] {
        [
            run("NetDB entry detail projects and verifies RouterInfo" , testRouterInfoDetail),
            run("NetDB entry detail handles missing RouterInfo" , testMissingRouterInfo),
            run("NetDB address endpoint formatting" , testEndpointFormatting),
        ]
    }

    private static func run(_ name: String, _ body: () throws -> String) -> I2PSelfTestResult {
        do {
            return I2PSelfTestResult(name: name, passed: true, detail: try body())
        } catch {
            return I2PSelfTestResult(name: name, passed: false, detail: String(describing: error))
        }
    }

    private static func testRouterInfoDetail() throws -> String {
        let seed = I2PCrypto.generateEd25519Seed()
        let encryption = I2PCrypto.generateX25519KeyPair()
        let identity = I2PKeysAndCert(
            encryptionPublicKey: encryption.publicKey,
            signingPublicKey: I2PCrypto.ed25519PublicKey(fromSeed: seed)
        )
        var info = I2PRouterInfo(
            identity: identity,
            published: Date(timeIntervalSince1970: 1_700_000_000),
            addresses: [I2PRouterAddress(
                cost: 5,
                transportStyle: "NTCP2",
                expiration: nil,
                options: ["host": "203.0.113.7", "port": "21457"]
            )],
            options: ["caps": "f"]
        )
        try info.sign(withSeed: seed)
        let entry = I2PNetworkDatabase.StoredEntry(
            entryType: .routerInfo,
            key: identity.hash,
            raw: info.serialize(),
            routerInfo: info,
            leaseSet: nil,
            expiresAt: info.published.addingTimeInterval(3600)
        )
        let detail = entry.browseDetail
        guard detail.signatureVerified,
              detail.isFloodfill,
              detail.endpoints.count == 1,
              detail.endpoints.first?.endpoint == "203.0.113.7:21457" else {
            throw EntryFailure("the verified RouterInfo detail lost its signature, role or endpoint")
        }
        return "signature, floodfill capability and published endpoint preserved"
    }

    private static func testMissingRouterInfo() throws -> String {
        let entry = I2PNetworkDatabase.StoredEntry(
            entryType: .leaseSet,
            key: Data(repeating: 0, count: 32),
            raw: Data(),
            routerInfo: nil,
            leaseSet: nil,
            expiresAt: Date().addingTimeInterval(60)
        )
        guard entry.browseDetail.endpoints.isEmpty else {
            throw EntryFailure("a non-RouterInfo entry exposed RouterInfo endpoints")
        }
        return "non-RouterInfo entry produces an empty endpoint list"
    }

    private static func testEndpointFormatting() throws -> String {
        let complete = I2PRouterAddress(
            cost: 5, transportStyle: "NTCP2", expiration: nil,
            options: ["host": " 203.0.113.7 ", "port": " 21457 "]
        )
        let hostOnly = I2PRouterAddress(
            cost: 5, transportStyle: "NTCP2", expiration: nil,
            options: ["host": "203.0.113.7"]
        )
        let unpublished = I2PRouterAddress(
            cost: 5, transportStyle: "NTCP2", expiration: nil,
            options: [:]
        )
        guard I2PNetDBEntryText.endpoint(complete) == "203.0.113.7:21457",
              I2PNetDBEntryText.endpoint(hostOnly) == "203.0.113.7",
              I2PNetDBEntryText.endpoint(unpublished) == "no host or port published" else {
            throw EntryFailure("published endpoint formatting is incorrect")
        }
        return "complete, partial and unpublished addresses are represented"
    }

    private struct EntryFailure: Error, CustomStringConvertible {
        let description: String
        init(_ description: String) { self.description = description }
    }
}
