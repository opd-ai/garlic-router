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
    case tunnels
    case garlic

    var displayName: String {
        switch self {
        case .crypto: return "Crypto"
        case .structures: return "Structures"
        case .netdb: return "NetDB"
        case .i2np: return "I2NP"
        case .ntcp2: return "NTCP2"
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
            swift: "I2NPMessages.swift (I2NPMessageHeader, 17 bytes)",
            wire: "Implemented: type (1) + messageID (4 BE) + expiration (8 BE ms) + size (4 BE) = 17 bytes. Spec long header: type (1) + messageID (4) + expiration (8) = 16 bytes with size carried by the transport frame; spec short (tunnel) header: type (1) + expiration (4 BE) = 5 bytes.",
            encoding: "Type codes per I2NPMessageImpl TYPE_* constants; expiration as milliseconds since epoch.",
            crypto: "n/a",
            edges: "Expired messages dropped on receipt; oversize payloads rejected; unsupported type codes rejected.",
            status: .defect,
            deviation: I2PDeviationRecord(
                classification: .defect,
                description: "The router uses a 17-byte internal header that embeds a 4-byte size field, and has no 5-byte short (tunnel) header; mainnet peers expect the 16-byte long header or the 5-byte short header.",
                rationale: "",
                trackingRef: "Cross-validation compliance suite (stage 4) — byte-for-byte I2NP header fidelity."),
            tests: ["T4-NP-HEADER-RT", "T4-NP-HEADER-SHORT", "T4-NP-HEADER-EXPIRY"]),
        row("NP-OPTIONS", .i2np,
            "Options message (router-internal status/bandwidth channel).",
            spec: "spec.i2p.io/common/i2np_spec#msg_Options (type 19)",
            java: "net.i2p.data.i2np.OptionsMessage (OptionsMessage.java)",
            swift: "I2NPMessages.swift (options type code 6, mapping payload)",
            wire: "Mapping payload of router status options.",
            encoding: "Implemented on type code 6 instead of the spec type 19.",
            crypto: "n/a",
            edges: "Only used router-internally; never sent to mainnet peers, so the non-standard code cannot reach the wire externally.",
            status: .deviationDocumented,
            deviation: I2PDeviationRecord(
                classification: .intentional,
                description: "The Options message uses type code 6 rather than the spec's 19.",
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
            "DatabaseLookup body and DatabaseSearchReply (type 99) response.",
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
            wire: "Implemented: tunnelID (4 BE) + IV (12) + ciphertext (1008 body + 16 tag) = 1040. Spec: tunnelID (4) + IV (16) + body (1008) = 1028 with AES-256-CBC and no AEAD tag.",
            encoding: "Fixed-size payload; mainnet bodies are 1008 bytes.",
            crypto: "Layer cipher deviates — see TN-HOP / TN-DATA.",
            edges: "Exact-size parse rejection; unknown tunnel IDs dropped.",
            status: .defect,
            deviation: I2PDeviationRecord(
                classification: .defect,
                description: "TunnelData carries a 12-byte AEAD nonce and a tagged ciphertext (1040 bytes total) instead of the spec's 16-byte IV with an untagged 1008-byte AES-CBC body (1028 total).",
                rationale: "",
                trackingRef: "Tunnel layer alignment item (AES-256-CBC + TunnelData layout)."),
            tests: ["T4-NP-TUNDATA-RT", "T4-NP-TUNDATA-MAINNET"]),
        row("NP-TUNGW", .i2np,
            "TunnelGateway body: gateway tunnel ID plus the encapsulated I2NP message.",
            spec: "spec.i2p.io/common/i2np_spec#msg_TunnelGateway",
            java: "net.i2p.data.i2np.TunnelGatewayMessage (TunnelGatewayMessage.java)",
            swift: "I2NPMessages.swift (I2PTunnelGatewayPayload)",
            wire: "gatewayID (4 BE) + message bytes (I2NP message to deliver).",
            encoding: "Type code 15 per spec; delivered at the inbound gateway to the endpoint router.",
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
            encoding: "GarlicMessage is the only carrier for end-to-end garlic; envelope framing deviates (see GL-ENV).",
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
            wire: "messageID (4 BE) + record count (1, 1–8) + per-hop encrypted records. Implemented on type codes 123/124 (classic TunnelBuild codes); mainnet VariableTunnelBuild uses 23/24.",
            encoding: "Classic type 123/124 implies fixed 1024-byte ElGamal records; variable 528-byte ECIES records belong on 23/24.",
            crypto: "Per-hop ECIES-X25519 record encryption — see TN-RECORD rows.",
            edges: "Record count bounds 1–8; trailing data rejected; reply travels back hop by hop with each hop appending its encrypted record.",
            status: .defect,
            deviation: I2PDeviationRecord(
                classification: .defect,
                description: "528-byte variable records are carried on the classic TunnelBuild type codes 123/124 instead of VariableTunnelBuild 23/24, which mainnet peers interpret as fixed 1024-byte records.",
                rationale: "",
                trackingRef: "Cross-validation compliance suite (stage 4) + tunnel alignment item (record shape)."),
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
            swift: "I2PNTCP2Handshake.swift",
            wire: "Spec message 1: obfuscated X (32) via AES-256-CBC keystream from the spec KDF, then a 2-byte options length prefix + options + padding. Implemented: ephemeral key obfuscated via a ChaCha20-Poly1305 substitution and no options length prefix; message 2 obfuscates Y the same way.",
            encoding: "Obfuscation key and IV derive from the initiator static/ephemeral material per the NTCP2 KDF.",
            crypto: "Spec: AES-256-CBC keystream; implemented: ChaCha20-Poly1305 (excluded substitution).",
            edges: "Real mainnet routers fail to parse our message 1 — visible in the CI mainnet handshake rows until aligned.",
            status: .defect,
            deviation: I2PDeviationRecord(
                classification: .defect,
                description: "Ephemeral-key obfuscation uses a ChaCha20-Poly1305 substitution instead of the spec's AES-256-CBC keystream, and message 1 lacks the 2-byte options length prefix.",
                rationale: "",
                trackingRef: "NTCP2 alignment item (obfuscation KDF + options length prefix)."),
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
            swift: "I2PNTCP2.swift (frame codec)",
            wire: "Spec: 2-byte big-endian length obfuscated with SipHash-24-2 keystream keys from the data-phase KDF, then encrypted payload + 16-byte Poly1305 tag. Implemented: length framing without the spec SipHash obfuscation keys.",
            encoding: "Maximum frame size per spec; zero-length frames carry keepalive blocks.",
            crypto: "Per-direction ChaCha20-Poly1305 streams with nonce96 (4-byte AD counter || 8-byte message counter).",
            edges: "MAC failure closes the session; length bounds enforced; SipHash keys per direction.",
            status: .defect,
            deviation: I2PDeviationRecord(
                classification: .defect,
                description: "Data-phase length obfuscation does not implement the spec's SipHash-24-2 keys derived by the data-phase KDF.",
                rationale: "",
                trackingRef: "NTCP2 alignment item (data-phase KDF for SipHash length-obfuscation keys)."),
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
            edges: "Chain key advancement must byte-match the spec; SipHash sub-key derivation tracked under NT-FRAME.",
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
                trackingRef: "Tunnel alignment item (record layout + flags + hop processing)."),
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
                trackingRef: "Tunnel alignment item (record encryption shape)."),
            tests: ["T4-TN-RECORD-ECIES-RT", "T4-TN-RECORD-ECIES-MAINNET"]),
        row("TN-HOP", .tunnels,
            "Hop processing: each hop decrypts one layer and forwards the tunnel message.",
            spec: "spec.i2p.io/common/tunnel-routing (layer encryption per hop)",
            java: "net.i2p.router.tunnel.HopProcessor (HopProcessor.java)",
            swift: "I2PTunnel.swift (data processor, hop processing)",
            wire: "n/a (processing).",
            encoding: "Spec: AES-256-CBC layer encryption with 16-byte tunnel IVs, per-hop layer and IV keys, IV-doubled-and-XORed chaining. Implemented: ChaCha20-Poly1305 AEAD layers with 12-byte per-message nonces from the ivKey material.",
            crypto: "Layer + IV keys distributed in build records; spec cipher AES-256-CBC (excluded substitution ChaChaPoly).",
            edges: "Unknown receive tunnel IDs dropped; duplicate IV detection; message-path-end hops unwrap and deliver.",
            status: .defect,
            deviation: I2PDeviationRecord(
                classification: .defect,
                description: "Tunnel layer encryption uses ChaCha20-Poly1305 with 12-byte nonces instead of AES-256-CBC with 16-byte IVs and the spec's IV chaining.",
                rationale: "",
                trackingRef: "Tunnel layer alignment item (AES-256-CBC data processor + hop processing)."),
            tests: ["T4-TN-HOP-LAYER", "T4-TN-HOP-MAINNET"]),
        row("TN-DATA", .tunnels,
            "TunnelData payload layout through the tunnel path.",
            spec: "spec.i2p.io/common/i2np_spec#msg_TunnelData + tunnel-routing",
            java: "net.i2p.router.tunnel tunnel package TunnelData handling",
            swift: "I2PTunnel.swift + I2NPMessages.swift",
            wire: "Spec: 4-byte tunnel ID + 16-byte IV + 1008-byte body = 1028. Implemented: 4 + 12 + (1008 + 16 tag) = 1040.",
            encoding: "Fixed-size messages; gateways fragment larger I2NP messages into multiple TunnelData frames.",
            crypto: "See TN-HOP.",
            edges: "Fragmentation/reassembly at the gateway; padding of the final fragment.",
            status: .defect,
            deviation: I2PDeviationRecord(
                classification: .defect,
                description: "TunnelData payload layout deviates from the spec's 4/16/1008 shape (see NP-TUNDATA).",
                rationale: "",
                trackingRef: "Tunnel layer alignment item."),
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
            edges: "The production app context currently wires an empty/local peer provider; the CI verification rig builds tunnels over in-memory router nodes.",
            status: .deviationDocumented,
            deviation: I2PDeviationRecord(
                classification: .intentional,
                description: "The production context wires an empty tunnel peer provider, so no tunnels are built through mainnet hops yet.",
                rationale: "Until the tunnel layer crypto is aligned (AES-256-CBC layers, spec record layout), tunnels built through real hops would not be interpretable by them and would pollute the live network. Live hop selection is gated on the tunnel alignment item; the netdb itself is already bootstrapped from live reseed data.",
                trackingRef: "Tunnel layer alignment item."),
            tests: ["T4-TN-PEERS-SELECTION"]),
    ]

    // MARK: Garlic

    private static let garlicRows: [I2PSpecRow] = [
        row("GL-ENV", .garlic,
            "ECIES-X25519 new-session envelope framing.",
            spec: "spec.i2p.io/proposals/145 ECIES-X25519 §new session envelope",
            java: "net.i2p.router.message.GarlicMessageBuilder (GarlicMessageBuilder.java); net.i2p.crypto.ECIESAEADEngine (ECIESAEADEngine.java)",
            swift: "I2PGarlic.swift (wrap/unwrap)",
            wire: "Spec: three sections — ephemeral key section (32 + 16), static key section, payload section — each ChaChaPoly-encrypted with HKDF-derived keys, or the existing-session tag framing. Implemented: single-shot ChaCha20-Poly1305 envelope with clove-set framing (message ID + expiration header).",
            encoding: "Section lengths implicit from total size per spec.",
            crypto: "X25519 ephemeral-static agreement; HKDF info strings per GL-HKDF; one-time and stored session keys.",
            edges: "MAC failure drops silently; replay protection via tag/message caches.",
            status: .defect,
            deviation: I2PDeviationRecord(
                classification: .defect,
                description: "The envelope uses a single ChaChaPoly box with clove-set framing instead of the ECIES-X25519 three-section new-session framing (or tag-based existing-session framing).",
                rationale: "",
                trackingRef: "Garlic alignment item (envelope framing)."),
            tests: ["T4-GL-ENV-RT", "T4-GL-ENV-MAINNET"]),
        row("GL-BLOCKS", .garlic,
            "ECIES payload blocks: DateTime (0), I2NP (1), Options (3), Termination (4), Padding (254).",
            spec: "spec.i2p.io/proposals/145 ECIES-X25519 §payload blocks",
            java: "net.i2p.crypto.ECIESAEADEngine.java (block encoding); GarlicMessageBuilder.java",
            swift: "I2PGarlic.swift",
            wire: "Spec: each block = type (1) + length (2 BE) + body; I2NP blocks embed delivery instructions + the I2NP message. Implemented: clove list with delivery instructions and certificate fields under a message-ID/expiration header.",
            encoding: "Termination blocks carry reason codes; padding blocks obfuscate length.",
            crypto: "n/a",
            edges: "Unknown block types ignored per spec; DateTime blocks enforce freshness.",
            status: .defect,
            deviation: I2PDeviationRecord(
                classification: .defect,
                description: "Payload is framed as a clove list rather than the spec's typed payload blocks.",
                rationale: "",
                trackingRef: "Garlic alignment item (payload blocks)."),
            tests: ["T4-GL-BLOCKS-RT", "T4-GL-BLOCKS-MAINNET"]),
        row("GL-HKDF", .garlic,
            "Garlic session key derivation with the spec HKDF info strings.",
            spec: "spec.i2p.io/proposals/145 ECIES-X25519 §key derivation",
            java: "net.i2p.crypto.ECIESAEADEngine.java (KDF)",
            swift: "I2PGarlic.swift + I2PCrypto.swift",
            wire: "n/a.",
            encoding: "Spec info strings bind derived keys to the ECIES-X25519 garlic context (new session vs stored key).",
            crypto: "HKDF-SHA256 over the X25519 shared secret; separate one-time and stored-session key paths.",
            edges: "Info string mismatches are undetectable in self-round-trips — only mainnet cross-validation catches them.",
            status: .defect,
            deviation: I2PDeviationRecord(
                classification: .defect,
                description: "HKDF info strings for garlic session key derivation do not match the spec values.",
                rationale: "",
                trackingRef: "Garlic alignment item (spec HKDF info strings)."),
            tests: ["T4-GL-HKDF-LABELS"]),
        row("GL-TAG", .garlic,
            "Session tag continuation: 32-byte tags, tag sets and ratchets.",
            spec: "spec.i2p.io/proposals/145 ECIES-X25519 §session tags",
            java: "net.i2p.crypto.SessionKeyManager (SessionKeyManager.java); net.i2p.crypto.ratchet.RatchetTagSet",
            swift: "I2PGarlic.swift (session tag management)",
            wire: "32-byte session tags delivered in Options blocks; next-session tags ratchet forward; one-time tags for low-traffic destinations.",
            encoding: "Tag lookup maps a received tag to the session key; unknown tags fall back to full new-session decryption.",
            crypto: "Tag sets ratchet per spec; replay cache prevents tag reuse.",
            edges: "Replayed or unknown tags handled by new-session fallback; tag exhaustion forces a new session.",
            status: .defect,
            deviation: I2PDeviationRecord(
                classification: .defect,
                description: "Tag-based continuation does not implement the spec's 32-byte tag delivery in Options blocks and tag-set ratchet rules.",
                rationale: "",
                trackingRef: "Garlic alignment item (tag-based continuation rules)."),
            tests: ["T4-GL-TAG-REPLAY", "T4-GL-TAG-RATCHET"]),
        row("GL-CLOVE", .garlic,
            "Garlic clove: encapsulated I2NP message with delivery instructions and certificates.",
            spec: "spec.i2p.io/proposals/145 ECIES-X25519 §clove/I2NP blocks",
            java: "net.i2p.router.message.GarlicClove (GarlicClove.java); net.i2p.router.InNetMessageJob (InNetMessageJob.java)",
            swift: "I2PGarlic.swift (clove structure, unwrap dispatch)",
            wire: "Clove = delivery instructions + encapsulated I2NP message (+ certificate fields in the implemented framing); the unwrapped message dispatches locally per InNetMessageJob semantics.",
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