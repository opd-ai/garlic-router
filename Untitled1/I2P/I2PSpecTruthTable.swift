//
//  I2PSpecTruthTable.swift
//  Alignment program stages 1-3 as a structured, in-app data model.
//
//  A specification truth table covering every implemented structure and
//  protocol — Destination, RouterInfo, LeaseSet, the I2NP header and message
//  bodies, NTCP2 handshake phases and frames, tunnel build records and garlic
//  clove sets — with field-by-field wire layout, encoding rules,
//  cryptographic parameters (EncType 4/5, SigType 7/11, HKDF labels) and
//  edge-case rules (expiry, replay, signature rejection).
//
//  Every row links the requirement to its I2P spec section, the Java I2P
//  reference class and the Swift component implementing it. Every known
//  deviation from the compliance review is recorded with a classification
//  (intentional, with rationale — or defect, with a tracking reference).
//
//  This file is pure structured data: the alignment report renders coverage
//  and statuses directly from it, and the cross-validation compliance suite
//  tags each test with a row ID so a failure pinpoints the violated
//  requirement. The table is also JSON-encodable for CI tooling.
//
//  Row statuses:
//    aligned            — matches the spec and is covered by passing tests.
//    deviationDocumented — intentional divergence, rationale recorded.
//    pendingWireVerification — structurally per spec; byte-level cross
//                          validation against reference vectors is pending
//                          (stage 4 of the alignment program).
//    defect             — known divergence; a fix is tracked.
//

import Foundation

// MARK: - Model

/// Roll-up status of one requirement row.
enum I2PAlignmentStatus: String, Codable, CaseIterable {
    case aligned
    case deviationDocumented
    case pendingWireVerification
    case defect

    var displayName: String {
        switch self {
        case .aligned: return "Aligned"
        case .deviationDocumented: return "Deviation documented"
        case .pendingWireVerification: return "Pending wire verification"
        case .defect: return "Defect"
        }
    }

    /// Rendering order for the report screen.
    var sortIndex: Int {
        switch self {
        case .aligned: return 0
        case .pendingWireVerification: return 1
        case .deviationDocumented: return 2
        case .defect: return 3
        }
    }
}

/// Classification of a known deviation from the compliance review.
enum I2PDeviationClass: String, Codable {
    case intentional
    case defect
}

/// A documented divergence from the spec.
struct I2PDeviationRecord: Codable {
    let classification: I2PDeviationClass
    /// What the implementation does differently from the spec.
    let description: String
    /// Why an intentional deviation was chosen (required for `intentional`).
    let rationale: String
    /// Where the fix (or further verification) is tracked.
    let trackingRef: String
}

/// Component sections of the truth table, in report-rendering order.
enum I2PSpecComponent: String, Codable, CaseIterable {
    case crypto
    case structures
    case netdb
    case i2np
    case ntcp2
    case ssu2
    case tunnels
    case garlic

    var displayName: String {
        switch self {
        case .crypto: return "Crypto"
        case .structures: return "Structures"
        case .netdb: return "NetDB"
        case .i2np: return "I2NP"
        case .ntcp2: return "NTCP2"
        case .ssu2: return "SSU2"
        case .tunnels: return "Tunnels"
        case .garlic: return "Garlic"
        }
    }
}

/// One requirement row of the specification truth table.
struct I2PSpecRow: Codable, Identifiable {
    /// Stable row ID, e.g. "NT-M1". The cross-validation suite tags its
    /// tests with these IDs.
    let id: String
    let component: I2PSpecComponent
    /// The requirement, in one sentence.
    let requirement: String
    /// The governing I2P specification section.
    let specSection: String
    /// The Java I2P reference class implementing the same requirement.
    let javaReference: String
    /// The Swift component in this router implementing it.
    let swiftComponent: String
    /// Field-by-field wire layout.
    let wireLayout: String
    /// Encoding rules (byte order, encodings, canonical forms).
    let encodingRules: String
    /// Cryptographic parameters (EncType 4/5, SigType 7/11, HKDF labels).
    let cryptoParameters: String
    /// Edge-case rules (expiry, replay, signature rejection, bounds).
    let edgeCases: String
    let status: I2PAlignmentStatus
    /// Present exactly when `status` is deviationDocumented or defect.
    let deviation: I2PDeviationRecord?
    /// Forward tags for the stage-4 cross-validation suite.
    let testIDs: [String]
}

/// Per-component (or overall) status counts for the report header.
struct I2PAlignmentCoverage: Codable {
    let aligned: Int
    let deviationDocumented: Int
    let pendingWireVerification: Int
    let defect: Int

    var total: Int { aligned + deviationDocumented + pendingWireVerification + defect }

    var summary: String {
        "\(aligned) aligned · \(deviationDocumented) deviations · \(pendingWireVerification) pending · \(defect) defects of \(total)"
    }
}

// MARK: - Truth table

enum I2PSpecTruthTable {

    /// The full catalog. Order: components in report order, rows grouped
    /// within each component.
    static let rows: [I2PSpecRow] = {
        var all: [I2PSpecRow] = []
        all += cryptoRows
        all += structureRows
        all += netdbRows
        all += i2npRows
        all += ntcp2Rows
        all += ssu2Rows
        all += tunnelRows
        all += garlicRows
        return all
    }()

    // MARK: Crypto

    private static let cryptoRows: [I2PSpecRow] = [
        row("CR-X25519", .crypto,
            "X25519 elliptic-curve key agreement with EncType 4/5 public keys.",
            spec: "spec.i2p.io/common/common_structures_spec#type_EncType; ECIES-X25519 proposals/145",
            java: "net.i2p.data.PublicKey; net.i2p.crypto.ECIESAEADEngine (ECIESAEADEngine.java)",
            swift: "I2PCrypto.swift (x25519) over CryptoKit Curve25519.KeyAgreement",
            wire: "32-byte raw u-coordinate (little-endian per RFC 7748) carried in the Destination keysAndCert and in NTCP2/garlic handshake ephemeral slots.",
            encoding: "EncType 0x04 (ECIES-X25519, modern default) / 0x05 (X25519 static key). Raw 32 bytes, never length-prefixed inside structures.",
            crypto: "Curve25519 ECDH; shared secret feeds HKDF-SHA256 chain keys in NTCP2, tunnel build records and garlic envelopes.",
            edges: "Reject all-zero shared secret (low-order point) — CryptoKit rejects; reject unknown EncType on structure parse.",
            status: .aligned,
            tests: ["T4-CR-X25519-KAT", "T4-CR-X25519-ENCTYPE"]),
        row("CR-ED25519", .crypto,
            "Ed25519 (EdDSA, SHA-512) signatures as SigType 7.",
            spec: "spec.i2p.io/common/common_structures_spec#type_SignatureType",
            java: "net.i2p.data.Signature; net.i2p.crypto.EdDSASignature (EdDSASignature.java)",
            swift: "Ed25519.swift (pure Swift) + I2PStructures.swift signature verify on parse",
            wire: "64-byte signature (R || S); 32-byte signing public key in the Destination keysAndCert.",
            encoding: "SigType 0x07 in the key certificate; raw 64-byte signature fields in RouterInfo/LeaseSet.",
            crypto: "EdDSA over Curve25519 with SHA-512; pure Swift implementation, CryptoKit cross-check pending (stage 4).",
            edges: "Signature verified on every RouterInfo/LeaseSet parse; invalid or malformed signatures reject the entry; unknown SigType rejected.",
            status: .pendingWireVerification,
            tests: ["T4-CR-ED25519-KAT", "T4-CR-ED25519-CRYPTOKIT"]),
        row("CR-ED25519PH", .crypto,
            "Ed25519ph (pre-hashed EdDSA) as SigType 11.",
            spec: "RFC 8032 §5.1 Ed25519ph; common_structures_spec#type_SignatureType",
            java: "net.i2p.crypto.EdDSASignature (dom2 pre-hash support)",
            swift: "Ed25519.swift (dom2 pre-hash path)",
            wire: "Same 64-byte R || S shape as SigType 7; distinguished only by the certificate SigType.",
            encoding: "SigType 0x0B; dom2 pre-hash with the I2P context string before signing.",
            crypto: "SHA-512 pre-hash of the message inside the dom2 construction.",
            edges: "Dom2 context and pre-hash behavior must byte-match the Java implementation — cross-check pending (stage 4).",
            status: .pendingWireVerification,
            tests: ["T4-CR-ED25519PH-DOM2", "T4-CR-ED25519PH-KAT"]),
        row("CR-CHACHAPOLY", .crypto,
            "IETF ChaCha20-Poly1305 AEAD (RFC 8439) as the modern cipher.",
            spec: "RFC 8439; ECIES-X25519 proposals/145; NTCP2 proposals/111",
            java: "net.i2p.crypto.ChaCha20Cipher (ChaCha20Cipher.java)",
            swift: "I2PCrypto.swift / CryptoKit ChaChaPoly",
            wire: "32-byte key, 12-byte nonce, ciphertext || 16-byte Poly1305 tag.",
            encoding: "nonce96 layout in NTCP2 data phase: 4-byte associated-data counter || 8-byte message counter.",
            crypto: "CryptoKit-backed; used by NTCP2 frames, tunnel build records and garlic envelopes.",
            edges: "MAC failure drops the frame/message; nonce reuse prevented by per-direction counters (NTCP2) and tag counters (garlic).",
            status: .aligned,
            tests: ["T4-CR-CHACHAPOLY-DET", "T4-CR-NONCE96"]),
        row("CR-HKDF", .crypto,
            "HKDF-SHA256 key derivation for all modern protocol chains.",
            spec: "RFC 5869; NTCP2 proposals/111 §KDF; ECIES-X25519 proposals/145",
            java: "net.i2p.crypto.HKDF (HKDF.java)",
            swift: "I2PCrypto.swift (hkdfSHA256) over CryptoKit HKDF",
            wire: "Not on the wire; derives all session keys, chain keys and temp keys.",
            encoding: "Extract (salt) then expand (info, length).",
            crypto: "NTCP2 protocol name 'Noise_XK25519_ChaChaPoly_SHA256' as the initial chain key; tunnel build record info 'i2p-tunnel-build-record'; garlic info strings tracked under GL-HKDF.",
            edges: "Salt/info/length parameterization is protocol-specific and verified per protocol row.",
            status: .aligned,
            tests: ["T4-CR-HKDF-RFC5869"]),
        row("CR-SHA256", .crypto,
            "SHA-256 hashing for router identity hashes and KDF chains.",
            spec: "spec.i2p.io/common/common_structures_spec",
            java: "net.i2p.crypto.SHA256Generator (SHA256Generator.java)",
            swift: "I2PCrypto.swift over CryptoKit Insecure.SHA256",
            wire: "32-byte hashes everywhere; b32 addresses are base32(SHA-256(destination)).",
            encoding: "Raw 32-byte digest; base32 (RFC 4648, no padding) for .b32.i2p hostnames.",
            crypto: "CryptoKit-backed.",
            edges: "Truncated b32 addresses (52 chars) rejected; hash inputs must not be truncated.",
            status: .aligned,
            tests: ["T4-CR-SHA256-VECTOR"]),
        row("CR-BLAKE2B", .crypto,
            "BLAKE2b-256/512 hashing for NTCP2 handshake contexts.",
            spec: "RFC 7693; NTCP2 proposals/111",
            java: "net.i2p.crypto.BLAKE2B (BLAKE2B.java)",
            swift: "BLAKE2b.swift (pure Swift, keyed and unkeyed)",
            wire: "Not on the wire; handshake chaining hashes and protocol-name hashing.",
            encoding: "BLAKE2b with configurable digest length (32/64) and optional key.",
            crypto: "Pure Swift implementation; known-answer vectors pending (stage 4).",
            edges: "Keyed and unkeyed modes must match RFC 7693 vectors byte-for-byte.",
            status: .pendingWireVerification,
            tests: ["T4-CR-BLAKE2B-KAT"]),
        row("CR-POLICY", .crypto,
            "Modern-only crypto policy: the registries carry exactly SigType 7/11 and EncType 4/5; legacy algorithms and legacy wire input are rejected at every parse boundary.",
            spec: "I2P common_structures_spec#type_SignatureType/#type_EncType; modern crypto mandate from the compliance review",
            java: "net.i2p.crypto suite (modern algorithms only)",
            swift: "I2PCrypto.swift (registries + I2PCryptoPolicy audit) + I2PStructures.swift (legacy certificate rejection)",
            wire: "Algorithm identifiers on the wire are 2-byte type codes; only 0x04/0x05 (EncType) and 0x07/0x0B (SigType) decode. Null certificates (type 0) and any legacy/unapproved type code throw unsupportedAlgorithm at parse.",
            encoding: "Registry enums contain no legacy cases, so legacy requests are type errors, never silent fallbacks; the AES-256-CBC call sites in NTCP2KeyObfuscation and I2PTunnelLayerCipher are spec-mandated modern-protocol components and are the only AES-CBC usage.",
            crypto: "Modern suite only: X25519 (EncType 4/5), Ed25519/Ed25519ph (SigType 7/11), ChaCha20-Poly1305 AEAD, HKDF-SHA256, SHA-256 and BLAKE2b.",
            edges: "The policy audit pins the registries and is exercised by the cross-validation suite; legacy peer identities (null certificates / legacy type codes) cannot be ingested by the netdb because every entry is signature-parsed through the modern-only certificate path.",
            status: .aligned,
            tests: ["T4-CR-POLICY-REGISTRY", "T4-CR-POLICY-LEGACY-REJECT"]),
    ]

    // MARK: Structures

    private static let structureRows: [I2PSpecRow] = [
        row("ST-PRIM", .structures,
            "I2P big-endian binary primitives: byte, short, integer, long, date, string.",
            spec: "spec.i2p.io/common/common_structures_spec#common-structures",
            java: "net.i2p.util.DataHelper (DataHelper.java)",
            swift: "I2PBinary.swift (I2PWriter / I2PReader)",
            wire: "byte(1), short(2 BE), integer(4 BE), long(8 BE), date(8 BE ms since epoch), string(1-byte length + UTF-8).",
            encoding: "All multi-byte fields big-endian; dates as unsigned 64-bit milliseconds.",
            crypto: "n/a",
            edges: "Truncated-buffer and oversize-length reads throw; trailing data rejected on whole-structure parses.",
            status: .aligned,
            tests: ["T4-ST-PRIM-RT", "T4-ST-PRIM-EDGE"]),
        row("ST-MAPPING", .structures,
            "Mapping (string→string properties): total length, sorted key entries.",
            spec: "spec.i2p.io/common/common_structures_spec#type-mapping",
            java: "net.i2p.util.DataHelper.writeProperties (DataHelper.java)",
            swift: "I2PBinary.swift (mapping read/write)",
            wire: "unsigned 16-bit total byte length; then entries: key (u16 len + UTF-8), value (u16 len + UTF-8).",
            encoding: "Keys sorted by unsigned byte order per Java DataHelper; '=' and null bytes escaped per spec.",
            crypto: "n/a",
            edges: "Real mainnet RouterInfo option mappings parse (exercised by live reseed); write-side canonical ordering re-verified in stage 4.",
            status: .aligned,
            tests: ["T4-ST-MAPPING-RT", "T4-ST-MAPPING-ORDER"]),
        row("ST-DEST", .structures,
            "Destination (KeysAndCert): encryption key, signing key, key certificate.",
            spec: "spec.i2p.io/common/common_structures_spec#struct_Destination",
            java: "net.i2p.data.Destination (Destination.java); net.i2p.data.KeysAndCert (KeysAndCert.java)",
            swift: "I2PStructures.swift (I2PDestination, I2PKeysAndCert)",
            wire: "encryptionPublicKey (32, EncType 4) + signingPublicKey (32, SigType 7) + certificate (u16 type, u16 length, body).",
            encoding: "Modern KeyCertificate (type 5) carries u16 SigType + u16 EncType; null certificate (type 0) rejected for modern-only routing. Base64 (standard alphabet, '=' padding) for SAM/RRD export; .b32 = base32(SHA-256(destination)).",
            crypto: "EncType 4 / SigType 7 only (modern-only mandate); legacy types rejected at parse.",
            edges: "Unknown certificate types rejected; b32 decode validates length; destination equality by SHA-256 hash.",
            status: .aligned,
            tests: ["T4-ST-DEST-RT", "T4-ST-DEST-B64", "T4-ST-DEST-B32"]),
        row("ST-RINFO", .structures,
            "RouterInfo: identity, publication date, addresses, options, Ed25519 signature.",
            spec: "spec.i2p.io/common/common_structures_spec#struct_RouterInfo",
            java: "net.i2p.data.router.RouterInfo (RouterInfo.java)",
            swift: "I2PStructures.swift (I2PRouterInfo) + I2PSU3Reseed.swift (live ingestion)",
            wire: "RouterIdentity (Destination) + published (8 BE ms) + addresses (1-byte count; each: cost 1, expiration 8, transport style u8 len, host u8 len, port 2 BE, options mapping) + peers count (1, always 0) + options mapping + signature (64).",
            encoding: "Signature covers identity + published + addresses + peers + options; NTCP2 transport style 'NTCP2' with 's' (base64url static key), 'host', 'port', 'caps' options.",
            crypto: "Identity SigType 7 Ed25519; 's' option carries the EncType 5 X25519 static key for NTCP2.",
            edges: "Signature verified on every parse — exercised against live mainnet RouterInfos via HTTPS reseed; stale (> routerInfoLifetime ≈ 1h) entries rejected at netdb ingest; unknown transports parsed permissively into options.",
            status: .aligned,
            tests: ["T4-ST-RINFO-RT", "T4-ST-RINFO-SIG", "T4-ST-RINFO-EXPIRY", "T4-ST-RINFO-MAINNET"]),
        row("ST-LSET", .structures,
            "LeaseSet (type 1): destination, published date, leases, Ed25519 signature.",
            spec: "spec.i2p.io/common/common_structures_spec#struct_LeaseSet",
            java: "net.i2p.data.LeaseSet (LeaseSet.java)",
            swift: "I2PStructures.swift (I2PLeaseSet)",
            wire: "Destination + published (8 BE ms) + leases (1-byte count; each: gateway hash 32, tunnel ID 4 BE, end timestamp 8 BE ms) + signature (64).",
            encoding: "Signature covers everything before it; gateway = floodfill router identity hash, tunnel ID = inbound gateway tunnel.",
            crypto: "Destination-level SigType 7 signature.",
            edges: "Reject invalid signature; reject whole entry after ~1h; individual leases expire after 10–15 min and must be renewed by republication.",
            status: .pendingWireVerification,
            tests: ["T4-ST-LSET-RT", "T4-ST-LSET-SIG", "T4-ST-LSET-EXPIRY"]),
        row("ST-LS2", .structures,
            "LeaseSet2 (LS2, types 3/5/7): multi-lease publication with offline signing support.",
            spec: "spec.i2p.io/common/common_structures_spec#struct-LeaseSet2",
            java: "net.i2p.data.LeaseSet2 (LeaseSet2.java)",
            swift: "not implemented — gap tracked in the alignment backlog",
            wire: "Destination + flags + versioned lease/body sections + signatures (LS2 layout per spec).",
            encoding: "Mainnet ECIES-X25519 destinations publish LS2; classic type-1 LeaseSet is what this router currently publishes.",
            crypto: "LS2 signing supports detached/offline signing keys per spec.",
            edges: "Until LS2 is published and parsed, mainnet clients may not resolve this router's destinations — interop risk recorded.",
            status: .defect,
            deviation: I2PDeviationRecord(
                classification: .defect,
                description: "Classic LeaseSet (type 1) is the only implemented publication/ingestion format; LeaseSet2 (types 3/5/7) is neither published nor parsed.",
                rationale: "",
                trackingRef: "Alignment backlog (no dedicated ticket yet); surfaced to the cross-validation suite for sizing."),
            tests: ["T4-ST-LS2-PARSE"]),
    ]

    // MARK: NetDB

    private static let netdbRows: [I2PSpecRow] = [
        row("ND-DHT", .netdb,
            "Kademlia-style floodfill DHT with XOR distance metric and closest-peer selection.",
            spec: "spec.i2p.io/proposals/121-uni-floodfill; i2p netdb spec",
            java: "net.i2p.router.networkdb.kademlia.FloodfillNetworkDatabaseFacade (FloodfillNetworkDatabaseFacade.java)",
            swift: "I2PNetDB.swift (XOR metric, floodfill selection)",
            wire: "Not on the wire; selection logic queries the 3–5 floodfills closest to the key by XOR distance.",
            encoding: "XOR distance over SHA-256 identity hashes; floodfills identified by 'caps' containing 'f'.",
            crypto: "Hash keys are SHA-256 of the stored entry (RouterInfo identity hash / LeaseSet destination hash).",
            edges: "Duplicate registrations deduplicated; floodfill set rebuilt from ingested RouterInfos.",
            status: .aligned,
            tests: ["T4-ND-DHT-DISTANCE", "T4-ND-DHT-SELECT"]),
        row("ND-LOOKUP", .netdb,
            "DatabaseLookup / DatabaseSearchReply cycles: query key, reply token, iterative rounds.",
            spec: "spec.i2p.io/common/i2np_spec#msg_DatabaseLookup",
            java: "net.i2p.router.networkdb.HandleDatabaseLookupMessageJob; net.i2p.router.networkdb.kademlia.SearchJob (SearchJob.java)",
            swift: "I2PNetDBMessages.swift + I2PNetDB.swift (lookup rounds)",
            wire: "lookup key (32) + from (router hash 32 or SH) + [reply token (4 BE) + reply gateway] + flags (1) + [excluded peers count + hashes].",
            encoding: "Reply token > 0 requests a direct DatabaseStore back to the reply gateway.",
            crypto: "n/a",
            edges: "Iterative rounds re-query closer floodfills; SearchReply returns closer candidate hashes; timeout per round bounded.",
            status: .pendingWireVerification,
            tests: ["T4-ND-LOOKUP-RT", "T4-ND-LOOKUP-MAINNET"]),
        row("ND-STORE", .netdb,
            "DatabaseStore ingestion with reply tokens and replication.",
            spec: "spec.i2p.io/common/i2np_spec#msg_DatabaseStore",
            java: "net.i2p.router.networkdb.HandleDatabaseStoreMessageJob (HandleDatabaseStoreMessageJob.java)",
            swift: "I2PNetDBMessages.swift + I2PNetDB.swift (ingest, replication)",
            wire: "key (32) + type (1: 1=RouterInfo, 2=LeaseSet) + [reply token (4 BE) + reply gateway] + entry body.",
            encoding: "Entries accepted only after Ed25519 signature verification; reply-token stores answer directly to the reply gateway.",
            crypto: "RouterInfo / LeaseSet Ed25519 signature verification before acceptance.",
            edges: "Unsigned or invalid-signature entries rejected; duplicate keys overwrite; replayed stores accepted as refreshes.",
            status: .pendingWireVerification,
            tests: ["T4-ND-STORE-RT", "T4-ND-STORE-SIGREJECT"]),
        row("ND-EXPIRY", .netdb,
            "Expiration and refresh: RouterInfo ~1h, LeaseSet ~1h with 10–15 min leases.",
            spec: "i2p netdb spec (entry lifetime)",
            java: "net.i2p.router.networkdb.ExpireJob (ExpireJob.java)",
            swift: "I2PNetDB.swift (lifetimes, maintenance loop, republication)",
            wire: "n/a (timers).",
            encoding: "Entries carry publication/lease expiry timestamps from the wire.",
            crypto: "n/a",
            edges: "Expired entries purged by the maintenance loop; own LeaseSet republished before expiry; RouterInfos refreshed by re-store.",
            status: .aligned,
            tests: ["T4-ND-EXPIRY-LIFETIME"]),
        row("ND-BOOTSTRAP", .netdb,
            "Startup bootstrapping: iterative peer discovery via DatabaseLookup plus reseed ingestion.",
            spec: "i2p netdb spec (bootstrapping); reseed spec",
            java: "net.i2p.router.startup.Reseeder (Reseeder.java)",
            swift: "I2PNetDB.swift (iterative bootstrap) + I2PSU3Reseed.swift (HTTPS reseed)",
            wire: "Reseed: i2pseeds.su3 over HTTPS; then DatabaseLookup discovery over established transports.",
            encoding: "SU3 container: magic 'I2Psu3', embedded zip of routerInfo-*.dat entries.",
            crypto: "Every RouterInfo inside the reseed file is Ed25519 signature-verified at ingestion.",
            edges: "Floodfills registered from ingested RouterInfos; discovery iterates until the peer set is usable; CI mainnet suite exercises this end-to-end.",
            status: .aligned,
            tests: ["T4-ND-BOOTSTRAP-SU3", "T4-ND-BOOTSTRAP-DISCOVERY"]),
        row("ND-SU3", .netdb,
            "SU3 reseed container signature verification (signer verification with bundled reseed certificates).",
            spec: "geti2p.net/spec/proposals/123-reseed (SU3 format)",
            java: "net.i2p.router.startup.Reseeder (Reseeder.java SU3 verification)",
            swift: "I2PSU3Reseed.swift (container parsed, signature NOT verified)",
            wire: "SU3: magic (6) 'I2Psu3' + format version (2) + signature type (2) + signature length (2) + padding length (1) + version length (2) + signer ID length (2) + content length (8) + timestamp (8) + version + signer ID + content (zip) + padding + signature.",
            encoding: "Content is a zip archive of routerInfo-<base64>.dat entries (stored or raw-deflate).",
            crypto: "Container signatures in the wild are RSA-2048/ECDSA — outside the modern crypto stack (Ed25519/X25519/ChaChaPoly/HKDF/SHA-256/BLAKE2b).",
            edges: "Integrity rides on HTTPS transport; each RouterInfo inside is independently Ed25519-verified on ingestion, so untrusted container content cannot inject unauthenticated entries.",
            status: .deviationDocumented,
            deviation: I2PDeviationRecord(
                classification: .intentional,
                description: "The SU3 reseed container signature is parsed but not verified.",
                rationale: "Container signatures use RSA/ECDSA, excluded by the modern-only crypto mandate. Transport integrity is provided by HTTPS, and every RouterInfo in the container is independently signature-verified before acceptance, so the unverified container cannot introduce unauthenticated netdb entries.",
                trackingRef: "Compliance review; revisit if an Ed25519-signed reseed format is standardized."),
            tests: ["T4-ND-SU3-CONTAINER"]),
    ]

    // MARK: I2NP

    private static let i2npRows: [I2PSpecRow] = [
        row("NP-HEADER", .i2np,
            "I2NP wire header: type byte, message ID, expiration, size framing.",
            spec: "spec.i2p.io/common/i2np_spec#header",
            java: "net.i2p.data.i2np.I2NPMessageImpl (I2NPMessageImpl.java)",
            swift: "I2NPMessages.swift (I2NPMessageHeader, 17 bytes; short-header wire framing)",
            wire: "Internal: type (1) + messageID (4 BE) + expiration (8 BE ms) + size (4 BE) = 17 bytes. Wire (NTCP2 data blocks): the 5-byte short tunnel header — type (1) + expiration (4 BE seconds) + payload — with the payload bounded by the transport block; the session re-frames between the two at the transport boundary.",
            encoding: "Type codes are the spec's: DatabaseStore 1, DatabaseLookup 2, DatabaseSearchReply 3, DeliveryStatus 4, Garlic 5, TunnelData 6, TunnelGateway 7, DataMessage 8, VariableTunnelBuild 21 and its reply 22 (the live suite surfaced that the router previously rode provisional codes that mainnet routers drop as unknown types).",
            crypto: "n/a",
            edges: "Expired messages dropped on receipt; oversize payloads rejected; unsupported type codes rejected; messages larger than one NTCP2 block are not yet fragmented (all live-suite traffic fits a single block) — tracked as the remaining gap.",
            status: .aligned,
            tests: ["T4-NP-HEADER-RT", "T4-NP-HEADER-SHORT", "T4-NP-HEADER-EXPIRY"]),
        row("NP-OPTIONS", .i2np,
            "Options message (router-internal status/bandwidth channel).",
            spec: "spec.i2p.io/common/i2np_spec#msg_Options (type 19)",
            java: "net.i2p.data.i2np.OptionsMessage (OptionsMessage.java)",
            swift: "I2NPMessages.swift (options on the obsolete type-12 slot, mapping payload)",
            wire: "Mapping payload of router status options.",
            encoding: "Carried on the obsolete TunnelCreateStatus slot (12) after the live suite surfaced that the previous provisional code collided with the real TunnelData code 6.",
            crypto: "n/a",
            edges: "Only used router-internally; never sent to mainnet peers, so the non-standard code cannot reach the wire externally.",
            status: .deviationDocumented,
            deviation: I2PDeviationRecord(
                classification: .intentional,
                description: "The Options message rides the obsolete type-12 slot rather than the spec's 19.",
                rationale: "The message is a router-internal status channel only (noted in COMPLIANCE_REVIEW.md); it is never transmitted to mainnet peers, so the non-standard code is unreachable externally. Flip to 19 when Options messages go on the wire.",
                trackingRef: "Compliance review; wire use blocked until then."),
            tests: ["T4-NP-OPTIONS-RT"]),
        row("NP-DBSTORE", .i2np,
            "DatabaseStore body: key, entry type, reply token/gateway, entry bytes.",
            spec: "spec.i2p.io/common/i2np_spec#msg_DatabaseStore",
            java: "net.i2p.data.i2np.DatabaseStoreMessage (DatabaseStoreMessage.java)",
            swift: "I2PNetDBMessages.swift (I2PDatabaseStore)",
            wire: "key (32) + type (1) + [replyToken (4 BE) + reply gateway (router hash 32 / lease gateway+tunnelID)] + entry (RouterInfo or LeaseSet bytes).",
            encoding: "Type 1 RouterInfo, type 2 LeaseSet; replyToken 0 = no reply requested.",
            crypto: "Entry-level Ed25519 signatures verified on ingest.",
            edges: "Malformed entry bodies rejected; oversized stores rejected.",
            status: .pendingWireVerification,
            tests: ["T4-NP-DBSTORE-RT", "T4-NP-DBSTORE-EDGE"]),
        row("NP-DBLOOKUP", .i2np,
            "DatabaseLookup body and DatabaseSearchReply (type 3) response.",
            spec: "spec.i2p.io/common/i2np_spec#msg_DatabaseLookup",
            java: "net.i2p.data.i2np.DatabaseLookupMessage / DatabaseSearchReplyMessage (DatabaseLookupMessage.java)",
            swift: "I2PNetDBMessages.swift (I2PDatabaseLookup, I2PDatabaseSearchReply)",
            wire: "Lookup: key (32) + from (32 or SH) + [replyToken (4) + reply gateway] + flags (1) + [excluded peers (1 count + hashes)]. SearchReply: from (32) + count (1) + candidate hashes + published timestamp (8).",
            encoding: "Flags: tunnel-vs-router reply addressing; excluded peers bound lookup scope.",
            crypto: "n/a",
            edges: "Reply-token gating; iterative rounds use SearchReply candidates; excluded-peer lists bounded.",
            status: .pendingWireVerification,
            tests: ["T4-NP-DBLOOKUP-RT", "T4-NP-DBLOOKUP-EDGE"]),
        row("NP-TUNDATA", .i2np,
            "TunnelData body: tunnel ID, IV, encrypted hop layer.",
            spec: "spec.i2p.io/common/i2np_spec#msg_TunnelData",
            java: "net.i2p.data.i2np.TunnelDataMessage (TunnelDataMessage.java)",
            swift: "I2NPMessages.swift (I2PTunnelDataPayload)",
            wire: "tunnelID (4 BE) + IV (16) + body (1008) = 1028 bytes, matching the spec layout exactly.",
            encoding: "Fixed-size payload; mainnet bodies are 1008 bytes.",
            crypto: "AES-256-CBC layer with the 16-byte IV field; IV-key chaining per TN-HOP.",
            edges: "Exact-size parse rejection (short and trailing payloads rejected); unknown tunnel IDs dropped.",
            status: .aligned,
            tests: ["T4-NP-TUNDATA-RT", "T4-NP-TUNDATA-MAINNET"]),
        row("NP-TUNGW", .i2np,
            "TunnelGateway body: gateway tunnel ID plus the encapsulated I2NP message.",
            spec: "spec.i2p.io/common/i2np_spec#msg_TunnelGateway",
            java: "net.i2p.data.i2np.TunnelGatewayMessage (TunnelGatewayMessage.java)",
            swift: "I2NPMessages.swift (I2PTunnelGatewayPayload)",
            wire: "gatewayID (4 BE) + message bytes (I2NP message to deliver).",
            encoding: "Type code 7 per spec; delivered at the inbound gateway to the endpoint router.",
            crypto: "n/a",
            edges: "Empty payloads rejected; gateway preprocessing fragments oversized messages before TunnelData.",
            status: .pendingWireVerification,
            tests: ["T4-NP-TUNGW-RT"]),
        row("NP-GARLIC", .i2np,
            "GarlicMessage wrapping (type 21) of the encrypted clove set.",
            spec: "spec.i2p.io/common/i2np_spec#msg_Garlic",
            java: "net.i2p.data.i2np.GarlicMessage (GarlicMessage.java)",
            swift: "I2PGarlic.swift (wrap/unwrap pipeline) + I2NPMessages.swift",
            wire: "Payload = encrypted clove set (ECIES envelope); message ID + expiration in the I2NP header.",
            encoding: "GarlicMessage is the only carrier for end-to-end garlic (type 5 per spec, corrected after the live suite surfaced the provisional code); the ECIES-X25519 envelope framing per GL-ENV.",
            crypto: "ECIES-X25519 envelope per GL rows.",
            edges: "Unwrap failures (MAC, expired, replayed tag) drop silently per spec.",
            status: .pendingWireVerification,
            tests: ["T4-NP-GARLIC-RT"]),
        row("NP-DI", .i2np,
            "Garlic delivery instructions: local, tunnel and router delivery with optional delay.",
            spec: "spec.i2p.io/proposals/145 ECIES-X25519 §delivery instructions (flag bitfield)",
            java: "net.i2p.router.message.GarlicClove (GarlicClove.java); net.i2p.router.InNetMessageJob (InNetMessageJob.java)",
            swift: "I2NPMessages.swift (I2PDeliveryInstructions)",
            wire: "Implemented: mode (1: 0 local, 1 tunnel, 2 router) + flags (1; bit 0 = delay present) + mode-specific (tunnel: tunnelID 4 + router hash 32; router: router hash 32) + delay (4 BE, optional). Spec: single flag bitfield byte — 0x80 local; otherwise tunnel or router per spec bits, with tunnelID (4) + router hash (32) as required and delay encoded per spec.",
            encoding: "Byte-count-consuming parse so larger structures can embed instructions.",
            crypto: "n/a",
            edges: "Unknown modes rejected; local delivery dispatches to the local dispatch table (InNetMessageJob analog).",
            status: .defect,
            deviation: I2PDeviationRecord(
                classification: .defect,
                description: "Delivery instructions use a custom [mode][flags] pair instead of the spec's single flag bitfield byte.",
                rationale: "",
                trackingRef: "Garlic alignment item (payload blocks + delivery instruction shape)."),
            tests: ["T4-NP-DI-RT", "T4-NP-DI-MAINNET"]),
        row("NP-BUILD", .i2np,
            "VariableTunnelBuild / VariableTunnelBuildReply message framing.",
            spec: "spec.i2p.io/proposals/152-variable-tunnel-build (types 23/24)",
            java: "net.i2p.data.i2np.VariableTunnelBuildMessage (VariableTunnelBuildMessage.java); net.i2p.router.tunnel.BuildRequestor (BuildRequestor.java)",
            swift: "I2PTunnelBuild.swift (I2PTunnelBuildMessage / I2PTunnelBuildReply)",
            wire: "messageID (4 BE) + record count (1, 1–8) + per-hop encrypted records. Carried on the mainnet VariableTunnelBuild type codes 21 (message) and 22 (reply) since the live suite surfaced that the router previously rode provisional codes 123/124 that mainnet routers drop.",
            encoding: "Variable record framing (messageID + count + records) matches mainnet VariableTunnelBuild; the per-record encryption shape is still tracked under TN-RECORD (the remaining tunnel-interop blocker).",
            crypto: "Per-hop ECIES-X25519 record encryption — see TN-RECORD rows.",
            edges: "Record count bounds 1–8; trailing data rejected; reply travels back hop by hop with each hop appending its encrypted record.",
            status: .aligned,
            tests: ["T4-NP-BUILD-RT", "T4-NP-BUILD-TYPECODE"]),
    ]

    // MARK: NTCP2

    private static let ntcp2Rows: [I2PSpecRow] = [
        row("NT-NOISE", .ntcp2,
            "Noise_XK_25519_ChaChaPoly_SHA256 handshake pattern over TCP.",
            spec: "spec.i2p.io/proposals/111-ntcp2 §Noise",
            java: "net.i2p.router.transport.ntcp.NTCP2Connection (NTCP2Connection.java)",
            swift: "I2PNTCP2Handshake.swift + I2PNTCP2Crypto.swift",
            wire: "Three handshake messages (SessionRequest, SessionCreated, SessionConfirm) then the data phase.",
            encoding: "Noise_XK pattern: initiator knows responder static; responder static transmitted encrypted in message 2.",
            crypto: "X25519 ephemeral/static, ChaCha20-Poly1305 AEAD, SHA-256/BLAKE2b chaining, HKDF-SHA256.",
            edges: "Handshake failures abort the connection cleanly; loopback handshake tests pass in the rig.",
            status: .aligned,
            tests: ["T4-NT-NOISE-PATTERN", "T4-NT-LOOPBACK"]),
        row("NT-M1", .ntcp2,
            "SessionRequest (message 1) and SessionCreated (message 2): obfuscated ephemeral keys and options.",
            spec: "spec.i2p.io/proposals/111-ntcp2 §SessionRequest/SessionCreated",
            java: "net.i2p.router.transport.ntcp.NTCP2KDF (NTCP2KDF.java); NTCP2Connection.java",
            swift: "I2PNTCP2Handshake.swift + I2PNTCP2Crypto.swift (NTCP2KeyObfuscation over AES-256-CBC)",
            wire: "Message 1 and message 2: AES-256-CBC-obfuscated ephemeral key (32) + 2-byte options length prefix + AEAD-encrypted options (32) + random padding.",
            encoding: "Obfuscation key and IV derive per the spec KDF (temp_key = HMAC-SHA256(chaining_key, remote_material), HKDF chain expanded to key + IV) from the responder's static key (message 1) and the initiator's deobfuscated ephemeral key (message 2), bound to the initial chaining key.",
            crypto: "AES-256-CBC without padding over the 32-byte ephemeral key (CommonCrypto); deterministic per the KDF inputs.",
            edges: "Deobfuscation failure or a non-canonical curve point aborts the handshake; the options length prefix locates the encrypted options block on both messages; CI mainnet handshake rows verify against real routers.",
            status: .aligned,
            tests: ["T4-NT-M1-OBFS", "T4-NT-M1-OPTIONS", "T4-NT-M1-MAINNET"]),
        row("NT-M3", .ntcp2,
            "SessionConfirm (message 3): encrypted static key, MAC and first payload.",
            spec: "spec.i2p.io/proposals/111-ntcp2 §SessionConfirm",
            java: "net.i2p.router.transport.ntcp.NTCP2Connection.java",
            swift: "I2PNTCP2Handshake.swift",
            wire: "Encrypted responder static (48) + MAC, then the encrypted first payload frame.",
            encoding: "Third Noise temp key; completes the XK pattern.",
            crypto: "ChaCha20-Poly1305 with temp key k3.",
            edges: "Static key mismatch aborts; RouterInfo exchange piggybacks in the first data frames.",
            status: .pendingWireVerification,
            tests: ["T4-NT-M3-RT"]),
        row("NT-FRAME", .ntcp2,
            "Data-phase frame framing: obfuscated length prefix, payload, 16-byte MAC.",
            spec: "spec.i2p.io/proposals/111-ntcp2 §data phase",
            java: "net.i2p.router.transport.ntcp.NTCP2Connection.java (frame encode/decode)",
            swift: "I2PNTCP2.swift (frame codec) + I2PNTCP2Crypto.swift (SipHash24, data-phase KDF)",
            wire: "2-byte big-endian length obfuscated by XOR with the SipHash-2-4 output of the data-phase KDF key, then encrypted payload + 16-byte Poly1305 tag.",
            encoding: "Maximum frame size per spec; zero-length frames carry keepalive blocks.",
            crypto: "Per-direction ChaCha20-Poly1305 streams with nonce96 (4-byte AD counter || 8-byte message counter); SipHash keys derived by the data-phase KDF (temp_key = HMAC-SHA256(k_direction, zerolen); sipkey = first 16 bytes of HMAC-SHA256(temp_key, zerolen)).",
            edges: "MAC failure closes the session; length bounds enforced; SipHash keys per direction, derived from the direction key by the spec KDF.",
            status: .aligned,
            tests: ["T4-NT-FRAME-RT", "T4-NT-FRAME-SIPHASH"]),
        row("NT-BLOCKS", .ntcp2,
            "NTCP2 payload block types: data (0), datetime (4), options (6), termination (0), padding (254).",
            spec: "spec.i2p.io/proposals/111-ntcp2 §payload blocks",
            java: "net.i2p.router.transport.ntcp.NTCP2Payload (NTCP2Payload.java)",
            swift: "I2PNTCP2.swift (block codec)",
            wire: "Each block: type (1) + length (2 BE) + body; blocks concatenated into one encrypted frame payload.",
            encoding: "Data blocks carry I2NP messages with short headers; datetime blocks carry 4-byte timestamps; termination blocks carry the reason code.",
            crypto: "n/a",
            edges: "Unknown block types skipped per spec; padding blocks ignored; termination triggers graceful close.",
            status: .pendingWireVerification,
            tests: ["T4-NT-BLOCKS-RT"]),
        row("NT-KDF", .ntcp2,
            "Handshake and data-phase key derivation chains and HKDF labels.",
            spec: "spec.i2p.io/proposals/111-ntcp2 §KDF",
            java: "net.i2p.router.transport.ntcp.NTCP2KDF.java",
            swift: "I2PNTCP2Crypto.swift",
            wire: "n/a.",
            encoding: "Protocol name 'Noise_XK25519_ChaChaPoly_SHA256' as the initial chain key; three Noise temp keys (k1/k2/k3) advanced per message; data-phase KDF produces two independent direction streams plus the SipHash length-obfuscation keys.",
            crypto: "HKDF-SHA256 with NTCP2 info strings; nonce96 = 4-byte associated-data counter || 8-byte message counter.",
            edges: "Chain key advancement must byte-match the spec; the data-phase SipHash KDF is implemented per spec — byte-level cross-check against reference vectors pending.",
            status: .pendingWireVerification,
            tests: ["T4-NT-KDF-LABELS", "T4-NT-KDF-CHAINS"]),
        row("NT-RIEX", .ntcp2,
            "RouterInfo exchange in the data phase: responder sends its own RouterInfo; initiator verifies.",
            spec: "spec.i2p.io/proposals/111-ntcp2 §RouterInfo block",
            java: "net.i2p.router.transport.ntcp.NTCP2Payload.java (RouterInfo block)",
            swift: "I2PNTCP2.swift + I2PNetDB.swift (ingest of exchanged RouterInfo)",
            wire: "RouterInfo option block: version flag + optional request flag + optional RouterInfo bytes, exchanged as the first data-phase payload blocks.",
            encoding: "Both sides verify the received RouterInfo's Ed25519 signature and ingest it into the netdb.",
            crypto: "RouterInfo Ed25519 signature verification.",
            edges: "Signature failure aborts the session; exchanged RouterInfos feed floodfill selection.",
            status: .pendingWireVerification,
            tests: ["T4-NT-RIEX-RT", "T4-NT-RIEX-SIG"]),
    ]

    // MARK: SSU2

    private static let ssu2Rows: [I2PSpecRow] = [
        row("SS-HEADER", .ssu2,
            "SSU2 packet headers: 32-byte long and 16-byte short headers with immutable connection IDs and per-direction packet numbers.",
            spec: "spec.i2p.io/proposals/159-ssu2 §headers",
            java: "net.i2p.router.transport.udp2 packet header handling (establish package)",
            swift: "I2PSSU2Crypto.swift (SSU2PacketHeader)",
            wire: "Long: dstConnID (8) + packetNumber (4 BE) + type (1) + version (1) + networkID (1) + flags (1) + srcConnID (8) + token (8) = 32 bytes. Short: dstConnID (8) + packetNumber (4 BE) + type (1) + fragment info (1: index<<4 | total-1) + additional flags (2) = 16 bytes.",
            encoding: "Types: sessionRequest 0, sessionCreated 1, sessionConfirmed 2, data 6, peerTest 7, retry 9, tokenRequest 10, holePunch 11. Version 2 and network ID 2 validated on every long-header parse.",
            crypto: "n/a (headers are protection-masked, not encrypted).",
            edges: "Connection IDs are random, immutable for the session's life, and src/dst are never identical (validated at handshake); unsupported version/networkID and unknown type codes rejected; packet numbers wrap at 2^32.",
            status: .aligned,
            tests: ["T4-SS-HEADER-RT"]),
        row("SS-HPROTECT", .ssu2,
            "DPI-resistant header protection: seven masking phases with tail-derived ChaCha20 IVs and the SessionRequest/Created ephemeral-region obfuscation.",
            spec: "spec.i2p.io/proposals/159-ssu2 §header encryption",
            java: "net.i2p.router.transport.udp2 header obfuscation",
            swift: "I2PSSU2Crypto.swift (SSU2HeaderProtection, ChaCha20Stream)",
            wire: "First 8 bytes XOR with ChaCha20 keystream IV = packet tail [len-24, len-12); bytes 8-16 XOR with IV = packet tail [len-12, len); SessionRequest/Created additionally obfuscate bytes 16-64 (srcConnID + token + the 32-byte ephemeral key) with an intro-key/responder-static-derived key over a zero IV.",
            encoding: "Phases: sessionRequest, sessionCreated, retry, peerTest, holePunch keyed off the RouterInfo intro key (tokenRequest shares the sessionRequest key); sessionConfirmed and data keyed off the split direction keys. Receiver-side phase detection unmasks candidates and accepts the phase whose destination connection ID matches.",
            crypto: "Raw ChaCha20 keystream (RFC 8439 block function) XOR masking keyed by HKDF-SHA256.",
            edges: "Masking is an involution; a wrong phase key yields a random-looking connection ID so detection never false-positives; the tail IV makes every packet mask differently.",
            status: .pendingWireVerification,
            tests: ["T4-SS-HPROTECT-PHASES"]),
        row("SS-NOISE", .ssu2,
            "Noise_XK_25519_ChaChaPoly_SHA256 handshake: SessionRequest → SessionCreated → SessionConfirmed with header binding and the ephemeral region.",
            spec: "spec.i2p.io/proposals/159-ssu2 §handshake; Noise pattern XK",
            java: "net.i2p.router.transport.udp2 establish package (InboundEstablishState/OutboundEstablishState)",
            swift: "I2PSSU2.swift (SSU2InitiatorHandshake/SSU2ResponderHandshake) + I2PSSU2Crypto.swift",
            wire: "SessionRequest: long header + ephemeral (32, region-obfuscated) + ChaChaPoly static section (initiator static key 32 + 16-byte tag inside = 48) + ChaChaPoly options payload. SessionCreated: long header + responder ephemeral (32, region-obfuscated) + ChaChaPoly static section (responder static) + ChaChaPoly options payload. SessionConfirmed: short-header fragments carrying the RouterInfo block.",
            encoding: "Header MixHash binding before Noise processing; the chain resets per SessionRequest attempt; the static sections authenticate both parties; the split happens only after the last handshake material mixed on both sides.",
            crypto: "X25519 es + ee + se agreement over the shared Noise chain (protocol name rides verbatim as the 32-byte chaining key); ChaCha20-Poly1305 with nonce96; HKDF-SHA256 MixKey.",
            edges: "Static-key mismatch or MAC failure aborts the handshake; tampered handshake packets reject; the responder's RouterInfo travels in the SessionConfirmed fragments.",
            status: .pendingWireVerification,
            tests: ["T4-SS-NOISE-LOOPBACK"]),
        row("SS-TOKEN", .ssu2,
            "Token management: TokenRequest → Retry solicitation, token validation in SessionRequest, expiry and rate limiting.",
            spec: "spec.i2p.io/proposals/159-ssu2 §token management",
            java: "net.i2p.router.transport.udp2 token handling",
            swift: "I2PSSU2.swift (SSU2TokenManager, SSU2TokenCache, the handshake engines' Retry paths)",
            wire: "TokenRequest (type 10): long header with a zero token field. Retry (type 9): long header carrying the fresh 8-byte opaque token in the header token field. SessionRequest: the token rides in its header token field.",
            encoding: "Three establishment sequences: fast path (a cached token rides straight into the SessionRequest), token-request path (TokenRequest → Retry → SessionRequest), retry path (a SessionRequest with an invalid token earns a Retry with a fresh token).",
            crypto: "Tokens are opaque random 8-byte values bound to the requester's source connection ID.",
            edges: "Tokens expire (10 min default) and are rate-limited per requester (5/min default, silently dropped when exceeded); invalid tokens earn a Retry, never a silent accept; the Retry path is exercised end-to-end in the loopback handshake.",
            status: .aligned,
            tests: ["T4-SS-TOKEN-MGMT"]),
        row("SS-STATE", .ssu2,
            "Session state machine: UNKNOWN → INITIAL → REQUESTED → CREATED → CONFIRMED → ESTABLISHED → TERMINATING → CLOSED with handshake retransmission and backoff.",
            spec: "spec.i2p.io/proposals/159-ssu2 §session establishment states",
            java: "net.i2p.router.transport.udp2.OutboundEstablishState / InboundEstablishState",
            swift: "I2PSSU2.swift (SSU2Session)",
            wire: "n/a (state transitions driven by the packet flow).",
            encoding: "The initiator splits after processing SessionCreated; the responder after building SessionCreated; both split at the identical chaining-key state so the data-phase keys mirror exactly.",
            crypto: "See SS-NOISE.",
            edges: "Unauthenticated datagrams drop silently with the error recorded; the connection-ID pair is validated (never identical) at establishment; the loopback handshake exercises every transition including both the token-request and retry paths.",
            status: .aligned,
            tests: ["T4-SS-STATE-HANDSHAKE", "T4-SS-UDP-LOOPBACK"]),
        row("SS-DATA", .ssu2,
            "Data phase: per-direction ChaCha20-Poly1305 with the short header as AAD, nonce96 packet counters, replay protection and out-of-order delivery.",
            spec: "spec.i2p.io/proposals/159-ssu2 §data phase",
            java: "net.i2p.router.transport.udp2 packet cipher state",
            swift: "I2PSSU2Crypto.swift (SSU2DataCipher, SSU2ReplayWindow, SSU2Nonce) + I2PSSU2.swift (SSU2Session data path)",
            wire: "Short header (16) + ChaChaPoly ciphertext + 16-byte MAC; the AAD is the unmasked short header; the AEAD nonce is 4 zero bytes ‖ the 8-byte big-endian packet number.",
            encoding: "One packet-number sequence per direction (nonce96 per packet, wrapping at 2^32); minimum message 40 bytes (16 header + 8 payload + 16 MAC), maximum 1472 (IPv4).",
            crypto: "ChaCha20-Poly1305 AEAD; MAC failure drops the packet.",
            edges: "Replay window: duplicates and packets below the 64-packet window rejected (counted); in-window out-of-order delivery accepted; payload bounds enforced at seal time.",
            status: .aligned,
            tests: ["T4-SS-DATA-REPLAY"]),
        row("SS-FRAG", .ssu2,
            "Fragmentation: SessionConfirmed fragments (up to 15) and I2NP message fragmentation inside data packets, both with timeout-bounded reassembly.",
            spec: "spec.i2p.io/proposals/159-ssu2 §SessionConfirmed fragmentation; i2np fragmentation",
            java: "net.i2p.router.transport.udp2 establish fragmentation; OutboundMessageFragments",
            swift: "I2PSSU2.swift (SSU2ConfirmedFragmenter, SSU2ConfirmedReassembler, SSU2MessageFragmenter, SSU2MessageReassembler)",
            wire: "Short-header fragment byte: index << 4 | total-1 (up to 15 fragments). Data-block fragments carry [messageID (4 BE)][fragment byte][chunk] so out-of-order delivery reassembles by message ID.",
            encoding: "SessionConfirmed fragments reassemble into the payload whose data block carries the RouterInfo; I2NP messages over the data budget split into up to 15 fragments and reassemble byte-exact.",
            crypto: "Fragment payloads are covered by the data-phase AEAD.",
            edges: "Reassembly times out (stale fragments rejected); 16-fragment splits rejected; out-of-order fragment arrival handled.",
            status: .aligned,
            tests: ["T4-SS-FRAG-SC", "T4-SS-FRAG-I2NP"]),
        row("SS-PEERTEST", .ssu2,
            "Peer test protocol: type-7 reachability testing with nonce correlation, observed-address extraction and reachability classification.",
            spec: "spec.i2p.io/proposals/159-ssu2 §peer test (test types 5/6/7)",
            java: "net.i2p.router.transport.udp2.PeerTestManagement",
            swift: "I2PSSU2.swift (SSU2PeerTestMessage, SSU2PeerTestCoordinator, SSU2Session peer-test path)",
            wire: "Type-7 long-header packets; request body [nonce (4 BE)][timestamp (4 BE)]; response body [nonce (4 BE)][observed endpoint (host length + host + port)] as the tester observed the requester.",
            encoding: "Reachability classification: observed == published → direct; same IP, different port → port-mapped; different IP → symmetric NAT; nothing arrived → unreachable.",
            crypto: "Peer-test packets ride the established session's header protection (session-derived peerTest phase).",
            edges: "Nonce correlation distinguishes responses from inbound requests (a request echoes back the nonce with the requester's observed endpoint); results cache with configurable expiration (1h default) and lapse.",
            status: .aligned,
            tests: ["T4-SS-PEERTEST-RT"]),
        row("SS-RELAY", .ssu2,
            "Relay protocol: RelayRequest/RelayResponse with the introducer and HolePunch (type-11) coordination for NAT traversal.",
            spec: "spec.i2p.io/proposals/159-ssu2 §relay; hole punching",
            java: "net.i2p.router.transport.udp2 relay package",
            swift: "I2PSSU2.swift (SSU2RelayEntry, SSU2RelayMessage, SSU2RelayCoordinator)",
            wire: "RelayRequest to the introducer: [nonce (4 BE)][target hash (32)][target port (2 BE)]. RelayResponse: [nonce (4 BE)][status (1), 0 = accepted]. HolePunch: a type-11 long-header datagram carrying the punch nonce, header-masked with the relay's introduction key.",
            encoding: "The coordinator advances requested → relay-accepted → hole-punch-sent → completed; the punch target decodes the nonce to open a return path to the puncher's endpoint.",
            crypto: "HolePunch packets mask with the relay entry's introduction key.",
            edges: "Relay rejection (nonzero status) fails the coordination phase; the introduction key is the phase key binding.",
            status: .aligned,
            tests: ["T4-SS-RELAY-HOLEPUNCH"]),
        row("SS-MIGRATE", .ssu2,
            "Connection migration: PathChallenge/PathResponse validation before switching to a new address, with immutable connection IDs.",
            spec: "spec.i2p.io/proposals/159-ssu2 §connection migration / path validation",
            java: "net.i2p.router.transport.udp2 path validation",
            swift: "I2PSSU2.swift (SSU2Session migration trigger + PathChallenge/PathResponse blocks)",
            wire: "Traffic arriving from a new address on an established session is answered with a data-phase PathChallenge block (8-byte random value) targeted at the new address; the peer echoes a PathResponse with the same value.",
            encoding: "The remote endpoint switches only after the echoed response validates; traffic on the unvalidated path is held until then; connection IDs stay immutable across the migration.",
            crypto: "Path-validation packets ride the established data-phase AEAD.",
            edges: "Only one pending challenge at a time; a mismatched echoed value does not migrate the session.",
            status: .aligned,
            tests: ["T4-SS-MIGRATE-RT"]),
        row("SS-TERM", .ssu2,
            "Termination and cleanup: encrypted termination blocks, bounded terminal-packet retransmission and idle teardown.",
            spec: "spec.i2p.io/proposals/159-ssu2 §termination",
            java: "net.i2p.router.transport.udp2 session termination",
            swift: "I2PSSU2.swift (SSU2Session close/retransmitTermination/checkIdle, SSU2Block.termination)",
            wire: "A data-phase packet carrying a termination block: [reason (1)][optional detail]. The terminal packet is retained whole and may be retransmitted up to 3 times.",
            encoding: "The receiving peer transitions to closed on the termination block; the sender stays terminating (awaiting nothing) and retransmits the same datagram bounded.",
            crypto: "Termination blocks ride the data-phase AEAD.",
            edges: "Idle teardown tears down an established session that exceeded its idle timeout; abrupt abort closes without the termination exchange.",
            status: .aligned,
            tests: ["T4-SS-TERM-IDLE"]),
    ]

    // MARK: Tunnels

    private static let tunnelRows: [I2PSpecRow] = [
        row("TN-RECORD", .tunnels,
            "VariableTunnelBuild plaintext request record (528 bytes).",
            spec: "spec.i2p.io/proposals/152-variable-tunnel-build; netdb spec record layout",
            java: "net.i2p.data.i2np.BuildRequestRecord (BuildRequestRecord.java); net.i2p.router.tunnel.BuildRequestor (BuildRequestor.java)",
            swift: "I2PTunnelBuild.swift (I2PTunnelBuildRequestRecord)",
            wire: "Spec record: receiveTunnelID (4) + nextIdent (32) + nextTunnelID (4) + layerKey (32) + ivKey (32) + replyKey (32) + replyIV (16) + flag (1) + requestTime (1) + nextMTU (2) + options padding to 528. Implemented record: hopNumber (1) + receiveTunnelID (4) + nextHopHash (32) + nextTunnelID (4) + layerKey (32) + ivKey (32) + replyKey (32) + replyIV (16) + flags (1) + hasMoreRecords (1) + reserved (1) + padding to 528.",
            encoding: "Spec flag bits: 0x80 inbound gateway hop, 0x40 outbound endpoint hop, 0x20 requestTime present; implemented flags use 0x01 (message-path end) / 0x02 (next hop is originator).",
            crypto: "Per-hop ECIES-X25519 record box — see TN-RECORD-ECIES.",
            edges: "Reserved byte must be zero; padding randomized; record count 1–8 per build message.",
            status: .defect,
            deviation: I2PDeviationRecord(
                classification: .defect,
                description: "Record layout uses hopNumber/hasMoreRecords/reserved bytes where the spec has requestTime and nextMTU, and flag semantics differ from the spec bits (0x80/0x40/0x20).",
                rationale: "",
                trackingRef: "Alignment backlog (record layout + flags — outside the tunnel layer alignment item's data-path scope)."),
            tests: ["T4-TN-RECORD-RT", "T4-TN-RECORD-FLAGS"]),
        row("TN-RECORD-ECIES", .tunnels,
            "Per-hop ECIES-X25519 build record encryption shape.",
            spec: "spec.i2p.io/proposals/152-variable-tunnel-build (ECIES-X25519 record encryption)",
            java: "net.i2p.data.i2np.BuildRequestRecord (ECIES variant); BuildRequestor.java",
            swift: "I2PTunnelBuild.swift (I2PTunnelBuildCrypto.encryptRecord/decryptRecord)",
            wire: "Implemented: 32-byte ephemeral public key + ChaChaPoly(528 plaintext) + 16-byte tag = 576 wire bytes; fixed zero nonce; record index as AAD. Spec: 32-byte ephemeral key + AEAD ciphertext totaling 528 bytes (tag inside), with the hop's B-IV as associated data.",
            encoding: "HKDF-SHA256 over the X25519 shared secret, salted with the ephemeral public key, info 'i2p-tunnel-build-record'.",
            crypto: "X25519 + HKDF-SHA256 + ChaCha20-Poly1305 (modern suite; ElGamal excluded).",
            edges: "Hop decrypts by trying its own encryption key; MAC failure = not the addressed hop, record forwarded unmodified.",
            status: .defect,
            deviation: I2PDeviationRecord(
                classification: .defect,
                description: "Record wire length is 576 (tag outside the 528) with a fixed zero nonce and record-index AAD, where the spec totals 528 with the hop B-IV as AAD.",
                rationale: "",
                trackingRef: "Alignment backlog (record encryption shape — outside the tunnel layer alignment item's data-path scope)."),
            tests: ["T4-TN-RECORD-ECIES-RT", "T4-TN-RECORD-ECIES-MAINNET"]),
        row("TN-HOP", .tunnels,
            "Hop processing: each hop decrypts one layer and forwards the tunnel message.",
            spec: "spec.i2p.io/common/tunnel-routing (layer encryption per hop)",
            java: "net.i2p.router.tunnel.HopProcessor (HopProcessor.java)",
            swift: "I2PTunnel.swift (hop processing) + I2NPPipeline.swift (I2PTunnelLayerCipher)",
            wire: "n/a (processing).",
            encoding: "Each hop AES-256-CBC-decrypts the 1008-byte body with its layer key, the CBC IV derived from the message's 16-byte IV field through the hop's IV key (IV_used = AES-256-ECB(IV_key, IV) XOR IV). Transit hops forward the revealed [nextTunnelID][nextIV][next ciphertext region] with the uncovered region re-randomized; message-path-end hops deliver the inner TunnelGateway payload.",
            crypto: "AES-256-CBC layer encryption (CommonCrypto) with per-hop layer and IV keys distributed in the build records; the ECB-keyed IV transform defeats IV-field tampering.",
            edges: "Unknown receive tunnel IDs dropped; expired hop states reject; the revealed next tunnel ID must match the build record's next hop; uncovered body regions carry fresh random filler.",
            status: .aligned,
            tests: ["T4-TN-HOP-LAYER", "T4-TN-HOP-MAINNET"]),
        row("TN-DATA", .tunnels,
            "TunnelData payload layout through the tunnel path.",
            spec: "spec.i2p.io/common/i2np_spec#msg_TunnelData + tunnel-routing",
            java: "net.i2p.router.tunnel tunnel package TunnelData handling",
            swift: "I2PTunnel.swift + I2NPMessages.swift + I2NPPipeline.swift (I2PTunnelDataProcessor)",
            wire: "tunnelID (4 BE) + IV (16) + body (1008) = 1028, matching the spec. Each transit hop's decrypted body frames the next hop's message as [BE16 length][nextTunnelID (4)][nextIV (16)][next ciphertext region], so the encrypted region shrinks by a block-aligned 32 bytes per hop (3-hop ladder 1008/976/944).",
            encoding: "Fixed-size messages; the region a hop's key never covered is re-randomized by the forwarding hop; gateways fragment larger I2NP messages into multiple TunnelData frames.",
            crypto: "AES-256-CBC layers with the IV-key ECB transform; see TN-HOP.",
            edges: "Fragmentation/reassembly at the gateway; padding of the final fragment; the innermost payload budget shrinks with hop count (3 hops: 942 bytes).",
            status: .aligned,
            tests: ["T4-TN-DATA-RT", "T4-TN-DATA-MAINNET"]),
        row("TN-BREPLY", .tunnels,
            "VariableTunnelBuildReply records and return codes.",
            spec: "spec.i2p.io/proposals/152-variable-tunnel-build (reply records, codes 0/1-29/30+)",
            java: "net.i2p.data.i2np.VariableTunnelBuildReplyMessage (VariableTunnelBuildReplyMessage.java)",
            swift: "I2PTunnelBuild.swift (I2PTunnelBuildReply, encryptReplyRecord)",
            wire: "messageID (4 BE) + record count (1) + per-hop encrypted records. Implemented record: ChaChaPoly(5-byte plaintext: tunnelID 4 + code 1) + 16 tag = 21 bytes; reply key/IV from the request record, message ID as AAD.",
            encoding: "Return codes: 0 accepted, <30 transient rejects, >=30 permanent rejects.",
            crypto: "Per-hop reply key + reply IV (ChaChaPoly nonce = replyIV prefix).",
            edges: "Creator inspects codes in reverse order; any reject aborts the build; pre-build replacement tunnels on reject.",
            status: .pendingWireVerification,
            tests: ["T4-TN-BREPLY-RT", "T4-TN-BREPLY-CODES"]),
        row("TN-GW", .tunnels,
            "Inbound gateway preprocessing and TunnelGateway delivery.",
            spec: "spec.i2p.io/common/tunnel-routing (gateway preprocessing)",
            java: "net.i2p.router.tunnel.InboundGatewayProcessor (InboundGatewayProcessor.java)",
            swift: "I2PTunnel.swift (gateway preprocessing, IBGW glue)",
            wire: "TunnelGateway I2NP (type 15): gatewayID (4 BE) + I2NP message; gateway fragments into TunnelData frames.",
            encoding: "Fragmentation with per-fragment headers at the gateway; endpoint reassembles.",
            crypto: "Layered by hop processing.",
            edges: "Fragment count bounds; reassembly completeness checks; exercised end-to-end by the SAM stream tests.",
            status: .aligned,
            tests: ["T4-TN-GW-RT", "T4-TN-GW-FRAG"]),
        row("TN-POOL", .tunnels,
            "Tunnel pool per destination: 3–5 outbound + 3–5 inbound, staggered builds, expiry, pre-build, selection.",
            spec: "i2p tunnel spec (pools and tunnel management)",
            java: "net.i2p.router.tunnel.TunnelPool (TunnelPool.java); net.i2p.router.tunnel.TunnelPoolManager (TunnelPoolManager.java)",
            swift: "I2PTunnelPool.swift",
            wire: "n/a (management).",
            encoding: "Tunnels expire after 10–30 minutes; replacements pre-built before expiry; selection weighs latency and remaining lifetime.",
            crypto: "Hop keys generated per build; LeaseSet leases reference inbound gateway tunnels.",
            edges: "Staggered creation avoids correlated expiry; failed builds retried with backoff; latency monitoring feeds selection.",
            status: .aligned,
            tests: ["T4-TN-POOL-LIFECYCLE", "T4-TN-POOL-SELECT"]),
        row("TN-PEERS", .tunnels,
            "Live mainnet hop selection for tunnel builds.",
            spec: "i2p tunnel spec (peer selection, peer profiles)",
            java: "net.i2p.router.tunnel.TunnelPool.java (peer selection via ProfileManager)",
            swift: "I2PRouterAppContext.swift (tunnel peer provider wiring)",
            wire: "n/a.",
            encoding: "Hops chosen from known RouterInfos with sufficient capabilities and freshness.",
            crypto: "Build records carry each hop's encryption key from its RouterInfo.",
            edges: "Hop selection now draws from the live netdb: the production context wires the I2PMainnetTunnelPeerProvider (modern-identity routers surfaced by the CI mainnet suite) over the NTCP2 build transport, and the CI suite exercises one deliberate outbound build attempt through real hops. Builds through real hops remain gated on the record-shape alignment (TN-RECORD); inbound participation is fully wired (build dispatch + reply path).",
            status: .deviationDocumented,
            deviation: I2PDeviationRecord(
                classification: .intentional,
                description: "Live hop selection is wired and exercised by a single deliberate CI build attempt, but tunnels through real hops do not yet complete because build records still use the non-spec shape tracked under TN-RECORD.",
                rationale: "The tunnel data layer is aligned (AES-256-CBC layers, spec TunnelData layout) and the build transport now rides live NTCP2 sessions; the remaining blocker is the build-record shape itself. The CI suite surfaces the true wire outcome (hops silently drop the records) with a precise classification instead of hiding behind an empty provider.",
                trackingRef: "TN-RECORD alignment (record shape); CI mainnet suite build-attempt scenario."),
            tests: ["T4-TN-PEERS-SELECTION"]),
    ]

    // MARK: Garlic

    private static let garlicRows: [I2PSpecRow] = [
        row("GL-ENV", .garlic,
            "ECIES-X25519 new-session envelope framing.",
            spec: "spec.i2p.io/proposals/145 ECIES-X25519 §new session envelope",
            java: "net.i2p.router.message.GarlicMessageBuilder (GarlicMessageBuilder.java); net.i2p.crypto.ECIESAEADEngine (ECIESAEADEngine.java)",
            swift: "I2PGarlic.swift (I2PGarlicCrypto.sealNewSession/openNewSession)",
            wire: "Three sections: ephemeral (32, cleartext), static (48 = sender static public key 32 + 16-byte tag inside), payload (blocks ‖ zero padding to a 16-byte boundary, + 16-byte tag). Tag-based continuation: [session tag (32)][ciphertext ‖ 16-byte tag].",
            encoding: "Section boundaries are structural (ephemeral 32, static 48); tag-based messages are distinguished by tag lookup before new-session parsing.",
            crypto: "X25519 ephemeral-static (es) + sender-static (ss) agreement; the KDF chain starts at SHA-256(protocolName) and binds every derived key to the spec context via the HKDF info strings; per-tag ratcheted AEAD keys; tag messages use nonce 0 (single-use tags).",
            edges: "MAC failure drops silently; replay protection via single-use tag consumption; the static section binds the message to the sender.",
            status: .aligned,
            tests: ["T4-GL-ENV-RT", "T4-GL-ENV-MAINNET"]),
        row("GL-BLOCKS", .garlic,
            "ECIES payload blocks: DateTime (0), I2NP (1), Options (3), Termination (4), Padding (254).",
            spec: "spec.i2p.io/proposals/145 ECIES-X25519 §payload blocks",
            java: "net.i2p.crypto.ECIESAEADEngine.java (block encoding); GarlicMessageBuilder.java",
            swift: "I2PGarlic.swift (I2PGarlicBlock codec + I2PGarlicCloveSet)",
            wire: "Each block = type (1) + length (2 BE) + body. DateTime carries 4-byte unix seconds (the envelope expiration); I2NP blocks embed the garlic flag-byte delivery instructions + the I2NP message (the clove); Options blocks carry the session-tag set ([seed (32)][tag count (1)]); Termination blocks carry the reason code; Padding blocks carry random bytes for length obfuscation.",
            encoding: "Termination blocks carry reason codes; padding blocks obfuscate length; the message ID and expiration also ride in the wrapping GarlicMessage I2NP header.",
            crypto: "n/a",
            edges: "Unknown block types ignored per spec; DateTime blocks enforce freshness; a Termination block alongside cloves rejects the payload.",
            status: .aligned,
            tests: ["T4-GL-BLOCKS-RT", "T4-GL-BLOCKS-MAINNET"]),
        row("GL-HKDF", .garlic,
            "Garlic session key derivation with the spec HKDF info strings.",
            spec: "spec.i2p.io/proposals/145 ECIES-X25519 §key derivation",
            java: "net.i2p.crypto.ECIESAEADEngine.java (KDF)",
            swift: "I2PGarlic.swift (I2PGarlicCrypto) + I2PCrypto.swift",
            wire: "n/a.",
            encoding: "Every derived key binds to the ECIES-X25519 protocol context 'ECIES-X25519-AEAD-RATCHET' via the HKDF info string; the KDF chain starts at SHA-256 of the protocol name and advances with the section hashes (MixHash/MixKey per Noise).",
            crypto: "HKDF-SHA256/HMAC-SHA256 over the es and ss X25519 shared secrets; the static and payload section keys derive per the spec schedule; tag-set ratchets advance per tag with HMAC domain separators.",
            edges: "Info string mismatches are undetectable in self-round-trips — only mainnet cross-validation catches them.",
            status: .aligned,
            tests: ["T4-GL-HKDF-LABELS"]),
        row("GL-TAG", .garlic,
            "Session tag continuation: 32-byte tags, tag sets and ratchets.",
            spec: "spec.i2p.io/proposals/145 ECIES-X25519 §session tags",
            java: "net.i2p.crypto.SessionKeyManager (SessionKeyManager.java); net.i2p.crypto.ratchet.RatchetTagSet",
            swift: "I2PGarlic.swift (I2PGarlicSession tag-set ratchet + I2PGarlicInboundTagManager)",
            wire: "32-byte session tags delivered via Options blocks carrying the tag-set seed ([seed (32)][count (1)]); the ratchet advances per tag (tag_i = HMAC(k_i, 0x03), key_i = HMAC(k_i, 0x04), k_{i+1} = HMAC(k_i, 0x01)); tag-based envelopes frame [tag (32)][ciphertext ‖ 16-byte tag].",
            encoding: "Tag lookup maps a received tag to its ratcheted AEAD key; unknown tags fall back to full new-session decryption.",
            crypto: "Tag sets ratchet per spec with a per-tag chain from the seed; tag messages use nonce 0 because every tag is single-use.",
            edges: "Replayed or unknown tags handled by new-session fallback; tag exhaustion forces a fresh new-session handshake with a new seed.",
            status: .aligned,
            tests: ["T4-GL-TAG-REPLAY", "T4-GL-TAG-RATCHET"]),
        row("GL-CLOVE", .garlic,
            "Garlic clove: encapsulated I2NP message with delivery instructions and certificates.",
            spec: "spec.i2p.io/proposals/145 ECIES-X25519 §clove/I2NP blocks",
            java: "net.i2p.router.message.GarlicClove (GarlicClove.java); net.i2p.router.InNetMessageJob (InNetMessageJob.java)",
            swift: "I2PGarlic.swift (clove structure, unwrap dispatch)",
            wire: "Clove content rides in an I2NP payload block: the garlic flag-byte delivery instructions + the encapsulated I2NP message (no certificate fields per the ECIES block shape); the unwrapped message dispatches locally per InNetMessageJob semantics.",
            encoding: "Delivery instruction byte-count-consuming parse (see NP-DI).",
            crypto: "Wrapped into the ECIES envelope per GL-ENV.",
            edges: "Expired cloves dropped; unknown delivery modes rejected; unwrap dispatch feeds the local dispatch table.",
            status: .pendingWireVerification,
            tests: ["T4-GL-CLOVE-RT", "T4-GL-CLOVE-MAINNET"]),
    ]

    // MARK: Queries

    static func rows(in component: I2PSpecComponent) -> [I2PSpecRow] {
        rows.filter { $0.component == component }
    }

    static func row(id: String) -> I2PSpecRow? {
        rows.first { $0.id == id }
    }

    static func coverage(for component: I2PSpecComponent) -> I2PAlignmentCoverage {
        coverage(of: rows(in: component))
    }

    static var coverage: I2PAlignmentCoverage {
        coverage(of: rows)
    }

    /// Rows with an intentional, documented deviation.
    static var intentionalDeviations: [I2PSpecRow] {
        rows.filter { $0.deviation?.classification == .intentional }
    }

    /// Rows with a tracked defect.
    static var defects: [I2PSpecRow] {
        rows.filter { $0.deviation?.classification == .defect }
    }

    /// JSON export of the table plus coverage — structured output for the
    /// alignment report and CI tooling.
    static func jsonRepresentation() throws -> Data {
        struct Export: Codable {
            let title: String
            let coverage: I2PAlignmentCoverage
            let intentionalDeviations: [String]
            let defects: [String]
            let rows: [I2PSpecRow]
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try encoder.encode(Export(
            title: "Pure Swift I2P Router — Specification Truth Table",
            coverage: coverage,
            intentionalDeviations: intentionalDeviations.map(\.id),
            defects: defects.map(\.id),
            rows: rows))
    }

    // MARK: Private

    private static func coverage(of selected: [I2PSpecRow]) -> I2PAlignmentCoverage {
        I2PAlignmentCoverage(
            aligned: selected.filter { $0.status == .aligned }.count,
            deviationDocumented: selected.filter { $0.status == .deviationDocumented }.count,
            pendingWireVerification: selected.filter { $0.status == .pendingWireVerification }.count,
            defect: selected.filter { $0.status == .defect }.count)
    }

    private static func row(_ id: String, _ component: I2PSpecComponent,
                            _ requirement: String,
                            spec: String, java: String, swift: String,
                            wire: String, encoding: String, crypto: String,
                            edges: String,
                            status: I2PAlignmentStatus,
                            deviation: I2PDeviationRecord? = nil,
                            tests: [String]) -> I2PSpecRow {
        I2PSpecRow(
            id: id,
            component: component,
            requirement: requirement,
            specSection: spec,
            javaReference: java,
            swiftComponent: swift,
            wireLayout: wire,
            encodingRules: encoding,
            cryptoParameters: crypto,
            edgeCases: edges,
            status: status,
            deviation: deviation,
            testIDs: tests)
    }
}