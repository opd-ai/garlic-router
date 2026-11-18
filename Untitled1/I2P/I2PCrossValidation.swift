//
//  I2PCrossValidation.swift
//  Stage 4 of the alignment program: the cross-validation compliance suite.
//
//  Unit-level tests runnable in the app:
//    • byte-for-byte round-trip fidelity — serialize → parse → reserialize must
//      produce identical bytes — for Destination, RouterInfo, LeaseSet, the I2NP
//      header and each message body, tunnel build records and NTCP2 payload blocks;
//    • cryptographic cross-checks — pure Ed25519 vs CryptoKit, Ed25519ph dom2
//      behavior, BLAKE2b known-answer vector, ChaChaPoly/HKDF determinism,
//      nonce96 layout;
//    • edge cases — expired RouterInfo/LeaseSet rejection, unsigned entry
//      rejection, replayed session tags, short and oversized payloads, tampered
//      frame MACs.
//
//  Every test is tagged with a truth-table test ID and its row ID (from
//  I2PSpecTruthTable) so a failure pinpoints the violated requirement; each
//  result's tag is verified against the table at run time. Results surface in
//  the self-test card and feed the alignment report (per-row pass counts,
//  last-run timestamp, JSON export).
//

import Foundation
import CryptoKit

// MARK: - Result model

/// One cross-validation test outcome, tagged with its truth-table coordinates.
struct I2PCrossValidationResult: Identifiable, Codable {
    var id: String { testID }
    /// Truth-table test tag, e.g. "T4-ST-RINFO-RT".
    let testID: String
    /// Truth-table row the test verifies, e.g. "ST-RINFO".
    let rowID: String
    let name: String
    let passed: Bool
    let detail: String
}

/// Per-row pass counts for the alignment report.
struct I2PCrossValidationRowSummary: Codable {
    let rowID: String
    let passing: Int
    let total: Int
}

// MARK: - Suite

enum I2PCrossValidationError: Error {
    case unexpectedSuccess
    case notTraceable(testID: String, rowID: String)
    case failed(String)
}

enum I2PCrossValidation {

    private static let stateLock = NSLock()
    private static var storedResults: [I2PCrossValidationResult] = []
    private static var storedRunAt: Date?

    // MARK: Run

    @discardableResult
    static func runAll() async -> [I2PCrossValidationResult] {
        var results: [I2PCrossValidationResult] = []

        func run(_ testID: String, rowID: String, _ name: String, _ body: () throws -> String) {
            do {
                append(&results, testID: testID, rowID: rowID, name: name,
                       passed: true, detail: try body())
            } catch {
                append(&results, testID: testID, rowID: rowID, name: name,
                       passed: false, detail: String(describing: error))
            }
        }

        func runAsync(_ testID: String, rowID: String, _ name: String,
                      _ body: () async throws -> String) async {
            do {
                append(&results, testID: testID, rowID: rowID, name: name,
                       passed: true, detail: try await body())
            } catch {
                append(&results, testID: testID, rowID: rowID, name: name,
                       passed: false, detail: String(describing: error))
            }
        }

        // MARK: Structures — byte-for-byte round trips

        run("T4-ST-DEST-RT", rowID: "ST-DEST", "Destination: serialize → parse → reserialize identical") {
            try destinationRoundTrip()
        }
        run("T4-ST-RINFO-RT", rowID: "ST-RINFO", "RouterInfo: serialize → parse → reserialize identical") {
            try routerInfoRoundTrip()
        }
        run("T4-ST-RINFO-SIG", rowID: "ST-RINFO", "RouterInfo: unsigned, tampered and wrong-key signatures rejected") {
            try routerInfoSignatureRejection()
        }
        await runAsync("T4-ST-RINFO-EXPIRY", rowID: "ST-RINFO", "RouterInfo: entry expires after routerInfoLifetime, then rejected") {
            try await routerInfoExpiryLifecycle()
        }
        run("T4-ST-LSET-RT", rowID: "ST-LSET", "LeaseSet: serialize → parse → reserialize identical") {
            try leaseSetRoundTrip()
        }
        run("T4-ST-LSET-SIG", rowID: "ST-LSET", "LeaseSet: unsigned, tampered and wrong-key signatures rejected") {
            try leaseSetSignatureRejection()
        }
        await runAsync("T4-ST-LSET-EXPIRY", rowID: "ST-LSET", "LeaseSet: expired leases rejected at ingest; grace-bounded lifetime") {
            try await leaseSetExpiryRejection()
        }
        run("T4-ST-LS2-PARSE", rowID: "ST-LS2", "LeaseSet2 plain (type 2): serialize → parse → reserialize identical; 46-byte leases with cost intact; signature over type+length+data verified") {
            try leaseSet2RoundTrip()
        }
        run("T4-ST-LS2-OFFLINE", rowID: "ST-LS2", "LeaseSet2 offline signing: transient delegation block signed by the permanent key; body signed by the transient key; forged delegation rejected") {
            try leaseSet2OfflineSignatureRoundTrip()
        }
        run("T4-ST-LS2-ELS2", rowID: "ST-LS2", "Encrypted LeaseSet2 (type 3): envelope round trip with the encrypted body preserved byte-exact; destination ECIES key survives; tampering rejected") {
            try encryptedLeaseSet2RoundTrip()
        }
        run("T4-ST-LS2-META", rowID: "ST-LS2", "Meta LeaseSet2 (type 5): entries carry complete inner LeaseSet2s; nested plain LS2 leases recoverable for delivery") {
            try metaLeaseSet2RoundTrip()
        }
        await runAsync("T4-ST-LS2-RESOLVE", rowID: "ST-LS2", "NetDB resolution: LeaseSet2 store types 2/3/5 ingest after verification and resolve through lookup; tampered and expired entries rejected") {
            try await leaseSet2NetdbResolution()
        }
        run("T4-ST-PRIM-EDGE", rowID: "ST-PRIM", "Primitives: truncated and oversized reads rejected; nil dates") {
            try primitivesEdgeCases()
        }
        run("T4-ST-MAPPING-ORDER", rowID: "ST-MAPPING", "Mapping: canonical sorted-key encoding, insertion-order independent") {
            try mappingCanonicalOrder()
        }

        // MARK: I2NP — header and message bodies

        run("T4-NP-HEADER-RT", rowID: "NP-HEADER", "I2NP header + message: round trip identical; short/oversize payload rejected") {
            try i2npRoundTrip()
        }
        run("T4-NP-HEADER-SHORT", rowID: "NP-HEADER", "Short tunnel header (5 bytes, seconds-level expiry): the wire framing NTCP2 data blocks carry; seconds truncation and type validation verified") {
            try i2npShortHeaderSpec()
        }
        run("T4-NP-HEADER-EXPIRY", rowID: "NP-HEADER", "I2NP expiry enforcement: fresh accepted, stale flagged dropped") {
            try i2npExpiryEnforcement()
        }
        run("T4-NP-OPTIONS-RT", rowID: "NP-OPTIONS", "Options channel: the I2NP type table is exactly the spec's (no Options type, slot 12 rejected, 19 = TunnelGateway); RouterInfo options round-trip with the signature intact; the NTCP2 Options block round-trips") {
            try routerOptionsChannel()
        }
        run("T4-NP-DBSTORE-RT", rowID: "NP-DBSTORE", "DatabaseStore: round trip with and without reply token; RouterInfo entry") {
            try databaseStoreRoundTrip()
        }
        run("T4-NP-DBSTORE-EDGE", rowID: "NP-DBSTORE", "DatabaseStore: unknown entry type, short payload and trailing data rejected") {
            try databaseStoreEdgeCases()
        }
        run("T4-NP-DBLOOKUP-RT", rowID: "NP-DBLOOKUP", "DatabaseLookup + DatabaseSearchReply: round trip identical") {
            try databaseLookupRoundTrip()
        }
        run("T4-NP-DI-RT", rowID: "NP-DI", "Delivery instructions: local/tunnel/router × delay round trips") {
            try deliveryInstructionsRoundTrip()
        }
        run("T4-NP-TUNGW-RT", rowID: "NP-TUNGW", "TunnelGateway: the spec's golden layout [tunnelID (4)][length (2)][message] parses and serializes byte-for-byte; short and trailing bodies rejected") {
            try tunnelGatewayRoundTrip()
        }
        run("T4-NP-DATA-RT", rowID: "NP-DATA", "Data message body: the spec's [length (4)][payload] golden layout parses and serializes byte-for-byte; short and trailing bodies rejected") {
            try dataMessageRoundTrip()
        }
        run("T4-NP-TUNDATA-RT", rowID: "NP-TUNDATA", "TunnelData payload: fixed-shape round trip; short payload rejected") {
            try tunnelDataRoundTrip()
        }
        run("T4-NP-BUILD-RT", rowID: "NP-BUILD", "VariableTunnelBuild/Reply messages: round trip; records decrypt; count bounds") {
            try buildMessagesRoundTrip()
        }

        // MARK: NTCP2 — blocks, KDF, frames

        run("T4-NT-BLOCKS-RT", rowID: "NT-BLOCKS", "NTCP2 payload blocks: encode → decode → encode identical; padding alignment") {
            try ntcp2BlocksRoundTrip()
        }
        run("T4-NT-KDF-CHAINS", rowID: "NT-KDF", "Noise chain: deterministic MixKey/MixHash; split yields distinct direction keys") {
            try ntcp2KDFChains()
        }
        run("T4-NT-KDF-LABELS", rowID: "NT-KDF", "48-byte protocol name hashed per Noise; HKDF chain expansion deterministic and distinct") {
            try ntcp2KDFLabels()
        }
        run("T4-CR-NONCE96", rowID: "CR-CHACHAPOLY", "nonce96 layout: 4 zero bytes ‖ little-endian counter") {
            try nonce96Layout()
        }
        run("T4-NT-FRAME-RT", rowID: "NT-FRAME", "Frame codec: round trip, incremental delivery, tampered MAC rejected") {
            try ntcp2FrameRoundTrip()
        }
        run("T4-NT-FRAME-SIPHASH", rowID: "NT-FRAME", "SipHash length obfuscation: keys from the data-phase KDF; deterministic per counter; frame math verified") {
            try sipHashDeterminism()
        }
        run("T4-NT-M1-OBFS", rowID: "NT-M1", "SessionRequest/Created: AES-256-CBC ephemeral-key obfuscation per the spec KDF; full handshake round trip") {
            try ntcp2KeyObfuscationSpec()
        }
        run("T4-NT-M1-OPTIONS", rowID: "NT-M1", "Messages 1 and 2: fixed 64-byte envelopes with the spec's option-block layout and no length prefix; m3p2len is the part-2 frame size") {
            try ntcp2OptionsLayoutSpec()
        }

        // MARK: Crypto cross-checks

        run("T4-CR-CHACHAPOLY-DET", rowID: "CR-CHACHAPOLY", "ChaCha20-Poly1305: deterministic; tampered MAC/AAD/ciphertext rejected") {
            try chachaPolyDeterminism()
        }
        run("T4-CR-HKDF-RFC5869", rowID: "CR-HKDF", "HKDF-SHA256: RFC 5869 test cases 1 and 3; deterministic") {
            try hkdfRFC5869()
        }
        run("T4-CR-SHA256-VECTOR", rowID: "CR-SHA256", "SHA-256: known-answer vectors for \"\" and \"abc\"") {
            try sha256Vectors()
        }
        run("T4-CR-BLAKE2B-KAT", rowID: "CR-BLAKE2B", "BLAKE2b: RFC 7693 empty-input vector; digest-length parameterization") {
            try blake2bKAT()
        }
        run("T4-CR-ED25519-CRYPTOKIT", rowID: "CR-ED25519", "Pure Ed25519 ↔ CryptoKit: keys equal, signatures interoperate both ways") {
            try pureEd25519CrossCheck()
        }
        run("T4-CR-ED25519PH-DOM2", rowID: "CR-ED25519PH", "Ed25519ph dom2: context bytes, domain separation from plain Ed25519") {
            try ed25519phDom2()
        }
        run("T4-CR-POLICY-REGISTRY", rowID: "CR-POLICY", "Modern-only policy: registries pinned to SigType 7/11 + EncType 4/5; no legacy type code constructs a case") {
            try modernCryptoPolicyRegistry()
        }
        run("T4-CR-POLICY-LEGACY-REJECT", rowID: "CR-POLICY", "Modern-only policy: null certificates, legacy sig type codes and legacy identities rejected at parse, while the spec's unused EncType 0 field parses with no crypto key — no silent fallbacks") {
            try legacyWireRejection()
        }

        // MARK: Tunnels — build records

        run("T4-TN-RECORD-RT", rowID: "TN-RECORD", "Build request record: 154-byte short plaintext round trip identical") {
            try buildRecordRoundTrip()
        }
        run("T4-TN-RECORD-FLAGS", rowID: "TN-RECORD", "Short record flags and end marker round trip; reserved bytes rejected") {
            try buildRecordFlags()
        }
        run("T4-TN-RECORD-ECIES-RT", rowID: "TN-RECORD-ECIES", "218-byte short record box: encrypt/decrypt round trip; wrong key/hop/tamper rejected") {
            try buildRecordEncryption()
        }
        run("T4-TN-BREPLY-RT", rowID: "TN-BREPLY", "Short build reply record: round trip across return codes; wrong hop/index rejected") {
            try buildReplyRecordRoundTrip()
        }
        run("T4-TN-DATA-RT", rowID: "TN-DATA", "TunnelData layering: spec 4/16/1008 layout, AES-256-CBC layers with IV-key chaining, block-aligned per-hop region ladder") {
            try tunnelDataLayerSpec()
        }
        run("T4-TN-HOP-LAYER", rowID: "TN-HOP", "Hop processing: 3-hop layered pipeline forwards ciphertext regions byte-for-byte and delivers the gateway payload byte-exact") {
            try tunnelHopLayerSpec()
        }
        run("T4-TN-PEERS-SELECTION", rowID: "TN-PEERS", "Hop selection: live netdb candidates filtered for freshness, reachable transport and modern identity; distinct hops; floodfill fallback; failing hops benched with backoff and cleared on success") {
            try tunnelPeerSelection()
        }

        // MARK: NetDB — ingestion, lookup, selection, expiry

        await runAsync("T4-ND-STORE-SIGREJECT", rowID: "ND-STORE", "NetDB: unsigned and invalid-signature entries rejected; valid accepted") {
            try await netdbUnsignedRejection()
        }
        await runAsync("T4-ND-LOOKUP-RT", rowID: "ND-LOOKUP", "NetDB: lookup answered over the loopback transport round trip") {
            try await netdbLoopbackLookup()
        }
        await runAsync("T4-ND-DHT-SELECT", rowID: "ND-DHT", "NetDB: floodfill selection XOR-ordered, non-floodfills excluded") {
            try await netdbFloodfillSelection()
        }
        await runAsync("T4-ND-EXPIRY-LIFETIME", rowID: "ND-EXPIRY", "NetDB: entry lifetime ≈ 1h from ingest; prune removes expired") {
            try await netdbExpiryLifetime()
        }

        run("T4-ND-SU3-CONTAINER", rowID: "ND-SU3", "SU3 reseed container: the 40-byte header parses field-exact, the signature covers the whole prefix (header included), and header/content/signature tamps, truncation and trailing bytes all reject") {
            try su3ContainerSignature()
        }
        run("T4-ND-SU3-SIGNER", rowID: "ND-SU3", "SU3 signer trust: the bundled reseed certificates load as signers, '@'-style IDs normalize, and unknown or wrong-key signers fail closed") {
            try su3SignerTrust()
        }

        // MARK: Garlic — envelope, blocks, clove, tags, HKDF

        run("T4-GL-ENV-RT", rowID: "GL-ENV", "ECIES-X25519 envelope: three-section new-session and tag-based wraps round-trip byte-for-byte") {
            try garlicEnvelopeRoundTrip()
        }
        run("T4-GL-BLOCKS-RT", rowID: "GL-BLOCKS", "Payload blocks: DateTime/I2NP/Options/Termination/Padding round trip; unknown types skipped per spec") {
            try garlicBlocksRoundTrip()
        }
        run("T4-GL-CLOVE-RT", rowID: "GL-CLOVE", "Garlic clove: garlic delivery instructions + I2NP message round trip byte-for-byte") {
            try garlicCloveRoundTrip()
        }
        run("T4-GL-TAG-REPLAY", rowID: "GL-TAG", "Session tags: ratcheted per-tag keys strictly single-use; replayed and tampered payloads rejected") {
            try garlicTagReplay()
        }
        run("T4-GL-TAG-RATCHET", rowID: "GL-TAG", "Tag-set ratchet: chain advances per tag; exhausted sets re-handshake with a fresh seed") {
            try garlicTagRatchetSpec()
        }
        run("T4-GL-HKDF-LABELS", rowID: "GL-HKDF", "Garlic HKDF: spec protocol-context info strings pinned; section key schedule and tag ratchets verified") {
            try garlicHKDFChecks()
        }

        // MARK: SSU2 — headers, header protection, handshake, tokens, data phase

        run("T4-SS-HEADER-RT", rowID: "SS-HEADER", "SSU2 packet headers: long/short round trips with version/networkID/connection-ID validation") {
            try ssu2HeaderRoundTrip()
        }
        run("T4-SS-HPROTECT-PHASES", rowID: "SS-HPROTECT", "Header protection: 7 phases, tail-IV ChaCha20 masking, receiver-side phase detection") {
            try ssu2HeaderProtectionPhases()
        }
        run("T4-SS-NOISE-LOOPBACK", rowID: "SS-NOISE", "Noise XK handshake: token-request loopback completes with mirrored split keys") {
            try ssu2HandshakeLoopback()
        }
        run("T4-SS-STATE-HANDSHAKE", rowID: "SS-STATE", "Session state machine: both sides established with mirrored conn IDs and the RouterInfo exchanged") {
            try ssu2StateMachine()
        }
        run("T4-SS-TOKEN-MGMT", rowID: "SS-TOKEN", "Tokens: issue, validate, expiry and per-requester rate limiting") {
            try ssu2TokenManagement()
        }
        run("T4-SS-DATA-REPLAY", rowID: "SS-DATA", "Data phase: AEAD round trip, replay window, size bounds, tamper rejection") {
            try ssu2DataPhase()
        }
        run("T4-SS-FRAG-SC", rowID: "SS-FRAG", "SessionConfirmed fragmentation: 3-fragment reassembly; bounds and stale reassembly rejected") {
            try ssu2ConfirmedFragmentation()
        }
        run("T4-SS-PEERTEST-RT", rowID: "SS-PEERTEST", "Peer test: nonce correlation, observed-address extraction, reachability classification, result cache") {
            try ssu2PeerTest()
        }
        run("T4-SS-RELAY-HOLEPUNCH", rowID: "SS-RELAY", "Relay: request/response round trip and the type-11 hole punch datagram") {
            try ssu2RelayHolePunch()
        }
        run("T4-SS-MIGRATE-RT", rowID: "SS-MIGRATE", "Connection migration: new-address challenge, validated response, immutable conn IDs") {
            try ssu2Migration()
        }
        run("T4-SS-TERM-IDLE", rowID: "SS-TERM", "Termination: terminal block delivery, bounded retransmission, idle teardown") {
            try ssu2Termination()
        }
        await runAsync("T4-SS-UDP-LOOPBACK", rowID: "SS-STATE", "UDP transport: real loopback handshake and I2NP delivery over datagram sockets") {
            try await I2PSSU2SelfTest.udpLoopbackTest()
        }

        commit(results)
        return results
    }

    /// Stores the run's outcomes. Kept synchronous so the lock is never taken
    /// from an async context.
    private static func commit(_ results: [I2PCrossValidationResult]) {
        stateLock.lock()
        defer { stateLock.unlock() }
        storedResults = results
        storedRunAt = Date()
    }

    // MARK: Structured access for the alignment report

    /// The last run's outcomes (empty before the first run).
    static var results: [I2PCrossValidationResult] {
        stateLock.lock()
        defer { stateLock.unlock() }
        return storedResults
    }

    /// Timestamp of the last full run (feeds the report's last-run field).
    static var lastRunAt: Date? {
        stateLock.lock()
        defer { stateLock.unlock() }
        return storedRunAt
    }

    /// Per-truth-table-row pass counts, for the alignment report's coverage.
    static func rowSummaries() -> [I2PCrossValidationRowSummary] {
        let grouped = Dictionary(grouping: results, by: \.rowID)
        return grouped.keys.sorted().map { rowID in
            let group = grouped[rowID] ?? []
            return I2PCrossValidationRowSummary(
                rowID: rowID,
                passing: group.filter(\.passed).count,
                total: group.count)
        }
    }

    /// Self-test card entries (row-ID-prefixed names, test-ID-prefixed details).
    static func selfTestEntries() -> [I2PSelfTestResult] {
        results.map { result in
            I2PSelfTestResult(
                name: "[\(result.rowID)] \(result.name)",
                passed: result.passed,
                detail: "[\(result.testID)] \(result.detail)")
        }
    }

    /// JSON export of the last run — structured output for the report and CI.
    static func jsonRepresentation() throws -> Data {
        struct Export: Codable {
            let ranAt: Date?
            let passed: Int
            let failed: Int
            let rows: [I2PCrossValidationRowSummary]
            let results: [I2PCrossValidationResult]
        }
        let all = results
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(Export(
            ranAt: lastRunAt,
            passed: all.filter(\.passed).count,
            failed: all.filter { !$0.passed }.count,
            rows: rowSummaries(),
            results: all))
    }

    // MARK: Harness internals

    /// Every appended result's tag is verified against the truth table so a
    /// mistagged test can never masquerade as coverage.
    private static func append(_ results: inout [I2PCrossValidationResult],
                               testID: String, rowID: String, name: String,
                               passed: Bool, detail: String) {
        guard let row = I2PSpecTruthTable.row(id: rowID), row.testIDs.contains(testID) else {
            results.append(I2PCrossValidationResult(
                testID: testID, rowID: rowID, name: name, passed: false,
                detail: "test tag (\(testID) @ \(rowID)) is not traceable to the truth table"))
            return
        }
        results.append(I2PCrossValidationResult(
            testID: testID, rowID: rowID, name: name, passed: passed, detail: detail))
    }

    private static func expectThrow(_ body: () throws -> Void) -> Bool {
        do { try body(); return false } catch { return true }
    }

    private static func expectThrowAsync(_ body: () async throws -> Void) async -> Bool {
        do { try await body(); return false } catch { return true }
    }

    private static func makeNetDB(_ name: String = UUID().uuidString) throws -> I2PNetworkDatabase {
        let hub = I2PNetDBLoopbackHub()
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("i2p-cv-\(name)", isDirectory: true)
        let storage = try I2PNetDBStorage(directory: directory)
        let hash = I2PCrypto.randomBytes(32)
        let netdb = I2PNetworkDatabase(
            localRouterHash: hash,
            transport: I2PNetDBLoopbackTransport(hub: hub),
            storage: storage)
        hub.add(netdb, at: hash)
        return netdb
    }

    /// Hop selection over live netdb candidates: eligibility gating (self,
    /// freshness, transport reachability, modern identity), distinct hops, the
    /// caller's exclusion set, floodfill fallback and profile backoff.
    private static func tunnelPeerSelection() throws -> String {
        let now = Date()

        func address(host: String, port: Int, style: String = "NTCP2",
                     expired: Bool = false) -> I2PRouterAddress {
            I2PRouterAddress(cost: 5,
                             transportStyle: style,
                             expiration: expired ? now.addingTimeInterval(-60) : nil,
                             options: ["host": host, "port": String(port)])
        }

        func makeInfo(encryptionKey: Data, published: Date,
                      addresses: [I2PRouterAddress],
                      floodfill: Bool) throws -> (hash: Data, info: I2PRouterInfo) {
            let signing = Curve25519.Signing.PrivateKey()
            let identity = I2PRouterIdentity(encryptionPublicKey: encryptionKey,
                                             signingPublicKey: signing.publicKey.rawRepresentation)
            var info = I2PRouterInfo(identity: identity,
                                     published: published,
                                     addresses: addresses,
                                     options: ["caps": floodfill ? "f" : ""])
            try info.sign(withSeed: signing.rawRepresentation)
            return (identity.hash, info)
        }

        func freshKey() -> Data {
            Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation
        }

        // Our own router as it appears in our own cache: never its own hop.
        let local = try makeInfo(encryptionKey: freshKey(), published: now,
                                 addresses: [address(host: "127.0.0.1", port: 9151)],
                                 floodfill: false)
        let localHash = local.hash

        var candidates: [(hash: Data, info: I2PRouterInfo)] = [local]
        var ordinary: [Data] = []
        for index in 0..<6 {
            let entry = try makeInfo(encryptionKey: freshKey(),
                                     published: now.addingTimeInterval(-60),
                                     addresses: [address(host: "10.1.0.\(index + 1)",
                                                         port: 20000 + index)],
                                     floodfill: false)
            ordinary.append(entry.hash)
            candidates.append(entry)
        }
        var floodfills: [Data] = []
        for index in 0..<3 {
            let entry = try makeInfo(encryptionKey: freshKey(),
                                     published: now.addingTimeInterval(-60),
                                     addresses: [address(host: "10.2.1.\(index + 1)",
                                                         port: 21000 + index,
                                                         style: "SSU2")],
                                     floodfill: true)
            floodfills.append(entry.hash)
            candidates.append(entry)
        }
        // Ineligible peers the selector must refuse: stale RouterInfo,
        // address-less/expired address, degenerate identity key.
        let stale = try makeInfo(encryptionKey: freshKey(),
                                 published: now.addingTimeInterval(-5 * 3600),
                                 addresses: [address(host: "10.3.0.1", port: 22000)],
                                 floodfill: false)
        let addressless = try makeInfo(encryptionKey: freshKey(), published: now,
                                       addresses: [address(host: "0.0.0.0", port: 0)],
                                       floodfill: false)
        let expiredAddress = try makeInfo(encryptionKey: freshKey(), published: now,
                                          addresses: [address(host: "10.3.0.2", port: 22001,
                                                              expired: true)],
                                          floodfill: false)
        let degenerate = try makeInfo(encryptionKey: Data(repeating: 0, count: 32),
                                      published: now,
                                      addresses: [address(host: "10.3.0.3", port: 22002)],
                                      floodfill: false)
        candidates += [stale, addressless, expiredAddress, degenerate]

        let selector = I2PTunnelPeerSelector()
        let picks = selector.select(count: 3, excluding: [], from: candidates,
                                    localRouterHash: localHash, now: now)
        guard picks.count == 3,
              Set(picks.map(\.routerHash)).count == 3 else {
            throw I2PCrossValidationError.failed(
                "hop selection returned \(picks.count) hops for a 3-hop build")
        }
        let ineligible: Set<Data> = [localHash, stale.hash, addressless.hash,
                                     expiredAddress.hash, degenerate.hash]
        guard picks.allSatisfy({ !ineligible.contains($0.routerHash) }) else {
            throw I2PCrossValidationError.failed(
                "selection returned our own router, a stale RouterInfo, an unreachable address or a degenerate key")
        }
        guard picks.allSatisfy({ ordinary.contains($0.routerHash) }) else {
            throw I2PCrossValidationError.failed(
                "floodfills were chosen as hops while ordinary routers were available")
        }
        guard picks.allSatisfy({ $0.encryptionPublicKey.count == 32 }) else {
            throw I2PCrossValidationError.failed("a hop carries no X25519 encryption key")
        }

        // Hops already inside a tunnel (the caller's exclusion set) are avoided.
        let excluded = Set(ordinary.prefix(2))
        let avoiding = selector.select(count: 3, excluding: excluded, from: candidates,
                                       localRouterHash: localHash, now: now)
        guard avoiding.count == 3,
              avoiding.allSatisfy({ !excluded.contains($0.routerHash) }) else {
            throw I2PCrossValidationError.failed("selection ignored the caller's exclusion set")
        }

        // Floodfills back the netdb but still fill a tunnel when no ordinary
        // peer is left.
        let floodfillOnly = candidates.filter { floodfills.contains($0.hash) }
        let fallback = selector.select(count: 2, excluding: [], from: floodfillOnly,
                                       localRouterHash: localHash, now: now)
        guard fallback.count == 2,
              fallback.allSatisfy({ floodfills.contains($0.routerHash) }) else {
            throw I2PCrossValidationError.failed("the floodfill fallback did not fill a thin hop pool")
        }

        // Two failed builds bench the hop; a success clears the streak.
        let config = I2PTunnelPeerSelector.Config()
        let target = ordinary[0]
        let failureAt = now.addingTimeInterval(30)
        for _ in 0..<2 {
            selector.recordBuildOutcome(I2PTunnelPeerBuildOutcome(
                peers: [target], succeeded: false, latency: nil), now: failureAt)
        }
        guard let benched = selector.profile(for: target),
              benched.consecutiveFailures == 2,
              benched.isBackedOff(now: failureAt.addingTimeInterval(1), config: config) else {
            throw I2PCrossValidationError.failed("two failed builds did not bench the hop")
        }
        for _ in 0..<12 {
            let sample = selector.select(count: 2, excluding: [], from: candidates,
                                         localRouterHash: localHash,
                                         now: failureAt.addingTimeInterval(1))
            guard !sample.contains(where: { $0.routerHash == target }) else {
                throw I2PCrossValidationError.failed(
                    "a benched hop was selected again inside its backoff window")
            }
        }
        let recoveredAt = failureAt.addingTimeInterval(config.maxBackoff + 60)
        let recovered = selector.select(count: 6, excluding: [], from: candidates,
                                        localRouterHash: localHash, now: recoveredAt)
        guard recovered.contains(where: { $0.routerHash == target }) else {
            throw I2PCrossValidationError.failed(
                "the hop never returned after its backoff window passed")
        }
        selector.recordBuildOutcome(I2PTunnelPeerBuildOutcome(
            peers: [target], succeeded: true, latency: 1.2), now: recoveredAt)
        guard let healed = selector.profile(for: target),
              healed.consecutiveFailures == 0 else {
            throw I2PCrossValidationError.failed(
                "a successful build did not clear the hop's failure streak")
        }

        return "3 distinct ordinary hops out of \(candidates.count) candidates; self/stale/unreachable/degenerate excluded; exclusion set honored; floodfills used only as fallback; 2 failures benched the hop for \(Int(config.baseBackoff))s and a success cleared it"
    }

    private static func sampleCloveSet(messageID: UInt32,
                                       tagSetSeed: Data? = nil,
                                       tagCount: Int = 0) throws -> I2PGarlicCloveSet {
        let local = I2PDeliveryInstructions(mode: .local)
        let tunnel = I2PDeliveryInstructions(mode: .tunnel, tunnelID: 0x0BAD_F00D,
                                             routerHash: I2PCrypto.randomBytes(32))
        let messageA = I2NPMessage(type: .dataMessage, payload: Data("clove-set sample".utf8))
        let messageB = I2NPMessage(type: .deliveryStatus, messageID: 7, payload: I2PCrypto.randomBytes(24))
        return try I2PGarlicCloveSet(
            expiration: Date(timeIntervalSince1970: 1_800_000_000),
            messageID: messageID,
            cloves: [
                I2PGarlicClove(deliveryInstructions: local, message: messageA),
                I2PGarlicClove(deliveryInstructions: tunnel, message: messageB),
            ],
            tagSetSeed: tagSetSeed, tagCount: tagCount)
    }

    // MARK: Structures

    private static func destinationRoundTrip() throws -> String {
        let destination = I2PSamples.sampleDestination()
        var reader = I2PReader(destination.raw)
        let parsed = try I2PKeysAndCert.parse(&reader)
        guard reader.remaining == 0 else { throw I2PWireError.trailingData }
        var writer = I2PWriter()
        parsed.serialize(into: &writer)
        guard writer.data == destination.raw, parsed.raw == destination.raw else {
            throw I2PWireError.invalidFormat
        }
        // Reserializing the parsed bytes must parse back to the same identity hash.
        var secondReader = I2PReader(writer.data)
        let reparsed = try I2PKeysAndCert.parse(&secondReader)
        guard reparsed.hash == destination.hash else { throw I2PWireError.invalidFormat }
        return "\(destination.raw.count) bytes; serialize→parse→reserialize identical; SHA-256 hash stable"
    }

    private static func routerInfoRoundTrip() throws -> String {
        let info = try I2PSamples.sampleRouterInfo()
        let encoded = info.serialize()
        let parsed = try I2PRouterInfo.parse(encoded)
        guard parsed.serialize() == encoded else { throw I2PWireError.invalidFormat }
        guard parsed.identity.hash == info.identity.hash else { throw I2PWireError.invalidFormat }
        guard parsed.addresses.count == 1, parsed.addresses[0].transportStyle == "NTCP2",
              parsed.addresses[0].options["port"] == "8887" else {
            throw I2PWireError.invalidFormat
        }
        guard parsed.options["netid"] == "2" else { throw I2PWireError.invalidFormat }
        return "\(encoded.count) bytes; byte-for-byte round trip, addresses and options intact"
    }

    private static func routerInfoSignatureRejection() throws -> String {
        let info = try I2PSamples.sampleRouterInfo()
        let encoded = info.serialize()
        // (a) unsigned: zeroed signature
        let unsigned = encoded.prefix(encoded.count - 64) + Data(repeating: 0, count: 64)
        guard expectThrow({ _ = try I2PRouterInfo.parse(unsigned) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        // (b) tampered body (inside the identity region covered by the signature)
        var tampered = encoded
        tampered[60] ^= 0xff
        guard expectThrow({ _ = try I2PRouterInfo.parse(tampered) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        // (c) a valid signature made by a different key
        let (_, otherSeed) = I2PSamples.sampleIdentity()
        var wrongKey = info
        wrongKey.signature = try I2PCrypto.ed25519Sign(info.serializedBody(), seed: otherSeed)
        guard expectThrow({ _ = try I2PRouterInfo.parse(wrongKey.serialize()) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        return "unsigned, tampered and cross-key signatures all rejected on parse"
    }

    private static func routerInfoExpiryLifecycle() async throws -> String {
        let netdb = try makeNetDB()
        let info = try I2PSamples.sampleRouterInfo()
        try await netdb.ingestRouterInfo(info.serialize())
        guard await netdb.hasEntry(info.identity.hash) else { throw I2PWireError.invalidFormat }
        // After routerInfoLifetime the entry is expired and purged; lookups then fail.
        let removed = await netdb.pruneExpired(
            now: Date().addingTimeInterval(I2PNetworkDatabase.routerInfoLifetime + 120))
        guard removed >= 1 else { throw I2PWireError.invalidFormat }
        guard !(await netdb.hasEntry(info.identity.hash)) else { throw I2PWireError.invalidFormat }
        let afterExpiry = await netdb.lookupRouterInfo(info.identity.hash, timeoutPerRound: 0.1, maxRounds: 1)
        guard afterExpiry == nil else { throw I2PWireError.invalidFormat }
        return "entry valid for routerInfoLifetime (\(Int(I2PNetworkDatabase.routerInfoLifetime))s), purged after expiry, lookups rejected"
    }

    private static func leaseSetRoundTrip() throws -> String {
        let leaseSet = try I2PSamples.sampleLeaseSet()
        let encoded = leaseSet.serialize()
        let parsed = try I2PLeaseSet.parse(encoded)
        guard parsed.serialize() == encoded else { throw I2PWireError.invalidFormat }
        guard parsed.leases.count == 2, parsed.leases[0].tunnelId == 0x1122_3344 else {
            throw I2PWireError.invalidFormat
        }
        guard parsed.destination.hash == leaseSet.destination.hash else {
            throw I2PWireError.invalidFormat
        }
        return "\(encoded.count) bytes; byte-for-byte round trip with both leases intact"
    }

    private static func leaseSetSignatureRejection() throws -> String {
        let leaseSet = try I2PSamples.sampleLeaseSet()
        let encoded = leaseSet.serialize()
        let unsigned = encoded.prefix(encoded.count - 64) + Data(repeating: 0, count: 64)
        guard expectThrow({ _ = try I2PLeaseSet.parse(unsigned) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        var tampered = encoded
        tampered[70] ^= 0xff
        guard expectThrow({ _ = try I2PLeaseSet.parse(tampered) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        let (_, otherSeed) = I2PSamples.sampleIdentity()
        var wrongKey = leaseSet
        wrongKey.signature = try I2PCrypto.ed25519Sign(leaseSet.serializedBody(), seed: otherSeed)
        guard expectThrow({ _ = try I2PLeaseSet.parse(wrongKey.serialize()) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        return "unsigned, tampered and cross-key signatures all rejected on parse"
    }

    private static func leaseSetExpiryRejection() async throws -> String {
        let netdb = try makeNetDB()

        // (a) leases expired beyond the grace period → ingest rejects the entry.
        let (expiredDestination, expiredSeed) = I2PSamples.sampleIdentity()
        var expired = I2PLeaseSet(
            destination: expiredDestination,
            published: Date(),
            leases: [I2PLease(gatewayHash: I2PCrypto.randomBytes(32), tunnelId: 1,
                              expiration: Date().addingTimeInterval(-700))])
        try expired.sign(withSeed: expiredSeed)
        guard await expectThrowAsync({ try await netdb.ingestLeaseSet(expired.serialize()) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }

        // (b) within the grace window the entry is accepted, with its lifetime
        // bounded by lease expiration + grace rather than the full hour.
        let (graceDestination, graceSeed) = I2PSamples.sampleIdentity()
        var grace = I2PLeaseSet(
            destination: graceDestination,
            published: Date(),
            leases: [I2PLease(gatewayHash: I2PCrypto.randomBytes(32), tunnelId: 2,
                              expiration: Date().addingTimeInterval(-300))])
        try grace.sign(withSeed: graceSeed)
        try await netdb.ingestLeaseSet(grace.serialize())
        let graceExpiry = await netdb.entryExpiration(grace.destination.hash)
        guard let graceExpiry, graceExpiry.timeIntervalSinceNow > 290,
              graceExpiry.timeIntervalSinceNow < 310 else {
            throw I2PWireError.invalidFormat
        }

        // (c) a far-future lease cannot extend the entry past the one-hour lifetime.
        let (futureDestination, futureSeed) = I2PSamples.sampleIdentity()
        var future = I2PLeaseSet(
            destination: futureDestination,
            published: Date(),
            leases: [I2PLease(gatewayHash: I2PCrypto.randomBytes(32), tunnelId: 3,
                              expiration: Date().addingTimeInterval(7200))])
        try future.sign(withSeed: futureSeed)
        try await netdb.ingestLeaseSet(future.serialize())
        let futureExpiry = await netdb.entryExpiration(future.destination.hash)
        guard let futureExpiry, futureExpiry.timeIntervalSinceNow < I2PNetworkDatabase.leaseSetLifetime + 5 else {
            throw I2PWireError.invalidFormat
        }
        return "expired leases rejected at ingest; accepted entries bounded by lease expiry + grace and the 1h lifetime"
    }

    // MARK: LeaseSet2 (proposal 123 store types 3/5/7)

    private static func leaseSet2Sample() throws -> (I2PLeaseSet2, Data) {
        let (destination, seed) = I2PSamples.sampleIdentity()
        let leases = [
            I2PLease2(gatewayHash: I2PCrypto.randomBytes(32), tunnelId: 0x1122_3344,
                      expiration: Date().addingTimeInterval(600)),
            I2PLease2(gatewayHash: I2PCrypto.randomBytes(32), tunnelId: 0x0BAD_F00D,
                      expiration: Date().addingTimeInterval(900)),
        ]
        let ls2 = try I2PLeaseSet2.build(
            storeType: .plain, destination: destination,
            published: Date(), expiresOffsetSeconds: 1800, flags: 0,
            leases: leases, signingSeed: seed)
        return (ls2, seed)
    }

    private static func leaseSet2RoundTrip() throws -> String {
        let (ls2, _) = try leaseSet2Sample()
        let encoded = ls2.serialize()
        // Spec layout: the payload starts with the Destination — the store type
        // lives in the DatabaseStore type byte, not a length-prefixed header.
        guard encoded.prefix(ls2.destination.raw.count) == ls2.destination.raw else {
            throw I2PWireError.invalidFormat
        }
        let parsed = try I2PLeaseSet2.parse(encoded, expectedType: .plain)
        guard parsed.serialize() == encoded else { throw I2PWireError.invalidFormat }
        guard parsed.storeType == .plain, parsed.leases.count == 2,
              parsed.leases[0].tunnelId == 0x1122_3344,
              parsed.leases[1].tunnelId == 0x0BAD_F00D,
              parsed.expiresAt > Date(), abs(parsed.expiresAt.timeIntervalSince(parsed.published) - 1800) < 1 else {
            throw I2PWireError.invalidFormat
        }
        // The published key list rides the entry: delivery keys to it rather
        // than to the destination's unused crypto field.
        guard parsed.encryptionKeys.count == 1,
              parsed.encryptionKeys[0].type == I2PEncType.x25519.rawValue,
              parsed.preferredEncryptionKey == ls2.destination.encryptionPublicKey else {
            throw I2PWireError.invalidFormat
        }
        guard parsed.verifySignature(), parsed.verifyTransientBlockSignature() else {
            throw I2PWireError.invalidSignature
        }
        // Tampered body (inside the signed type-byte + body range) rejected.
        var tampered = encoded
        tampered[60] ^= 0xff
        guard expectThrow({ _ = try I2PLeaseSet2.parse(tampered) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        // A body signature made by a different key is rejected on parse.
        let (_, otherSeed) = I2PSamples.sampleIdentity()
        let wrongKey = try I2PLeaseSet2.build(
            storeType: .plain, destination: ls2.destination,
            published: ls2.published, expiresOffsetSeconds: ls2.expiresOffsetSeconds,
            flags: 0, leases: ls2.leases, signingSeed: otherSeed)
        guard expectThrow({ _ = try I2PLeaseSet2.parse(wrongKey.serialize()) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        // The shape every long-lived mainnet destination publishes: a LeaseSet2
        // whose destination carries the spec's unused crypto field (EncType 0)
        // and whose key list is therefore empty. It must parse, verify and
        // resolve its leases — before the certificate accepted code 0 this entry
        // was rejected whole with `unsupportedAlgorithm`, which is why the live
        // DHT resolved no well-known destination at all.
        let legacySeed = I2PCrypto.generateEd25519Seed()
        let legacySigningKey = I2PCrypto.ed25519PublicKey(fromSeed: legacySeed)
        var unusedWriter = I2PWriter()
        unusedWriter.raw(Data(repeating: 0x11, count: 256)) // unused crypto field
        unusedWriter.raw(Data(repeating: 0x22, count: 96))  // signing-field padding
        unusedWriter.raw(legacySigningKey)                  // right-aligned signing key
        I2PCertificate(sigType: .ed25519, encTypeRawValue: 0).serialize(into: &unusedWriter)
        var unusedReader = I2PReader(unusedWriter.data)
        let unusedDestination = try I2PKeysAndCert.parse(&unusedReader)
        guard unusedDestination.encryptionPublicKey.isEmpty,
              unusedDestination.signingPublicKey == legacySigningKey else {
            throw I2PWireError.invalidFormat
        }
        let unusedLS2 = try I2PLeaseSet2.build(
            storeType: .plain, destination: unusedDestination,
            published: Date(), expiresOffsetSeconds: 600, flags: 0,
            leases: [I2PLease2(gatewayHash: I2PCrypto.randomBytes(32), tunnelId: 0x5EED_1234,
                               expiration: Date().addingTimeInterval(600))],
            signingSeed: legacySeed)
        let unusedParsed = try I2PLeaseSet2.parse(unusedLS2.serialize(), expectedType: .plain)
        guard unusedParsed.encryptionKeys.isEmpty,
              unusedParsed.preferredEncryptionKey == nil,
              unusedParsed.serialize() == unusedLS2.serialize(),
              let unusedResolved = unusedParsed.resolvedLeaseSet(),
              unusedResolved.leases.count == 1,
              unusedResolved.leases[0].tunnelId == 0x5EED_1234 else {
            throw I2PWireError.invalidFormat
        }
        return "\(encoded.count) bytes; DatabaseStore type byte + body signed; 40-byte Lease2 entries and the ECIES key list intact; tampered and cross-key signatures rejected; a destination with the spec's unused crypto field and no key list still resolves its leases"
    }

    private static func leaseSet2OfflineSignatureRoundTrip() throws -> String {
        let (destination, permanentSeed) = I2PSamples.sampleIdentity()
        let transientSeed = I2PCrypto.generateEd25519Seed()
        let transientPublicKey = I2PCrypto.ed25519PublicKey(fromSeed: transientSeed)
        let offline = try I2PLeaseSet2OfflineSignature.sign(
            sigType: .ed25519,
            transientExpiration: Date().addingTimeInterval(3600),
            transientPublicKey: transientPublicKey,
            permanentSeed: permanentSeed)
        let leases = [I2PLease2(gatewayHash: I2PCrypto.randomBytes(32), tunnelId: 7,
                                expiration: Date().addingTimeInterval(600))]
        let ls2 = try I2PLeaseSet2.build(
            storeType: .plain, destination: destination,
            published: Date(), expiresOffsetSeconds: 1800, flags: 0x0001,
            offlineSignature: offline, leases: leases, signingSeed: transientSeed)
        let encoded = ls2.serialize()
        let parsed = try I2PLeaseSet2.parse(encoded)
        guard parsed.serialize() == encoded, parsed.hasOfflineSignature,
              parsed.offlineSignature == offline,
              parsed.bodySigningPublicKey == transientPublicKey else {
            throw I2PWireError.invalidFormat
        }
        // Parse already enforced both verifications: the delegation block under
        // the permanent key and the body under the transient key. A delegation
        // block signed by a different (forged) permanent key is rejected.
        let (_, otherSeed) = I2PSamples.sampleIdentity()
        let forged = try I2PLeaseSet2OfflineSignature.sign(
            sigType: .ed25519,
            transientExpiration: offline.transientExpiration,
            transientPublicKey: offline.transientPublicKey,
            permanentSeed: otherSeed)
        let forgedLS2 = try I2PLeaseSet2.build(
            storeType: .plain, destination: destination,
            published: ls2.published, expiresOffsetSeconds: ls2.expiresOffsetSeconds,
            flags: 0x0001, offlineSignature: forged, leases: leases,
            signingSeed: transientSeed)
        guard expectThrow({ _ = try I2PLeaseSet2.parse(forgedLS2.serialize()) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        return "transient delegation block signed by the permanent key; body signed by the transient key; forged delegation rejected"
    }

    private static func encryptedLeaseSet2RoundTrip() throws -> String {
        let (destination, seed) = I2PSamples.sampleIdentity()
        let inner = I2PCrypto.randomBytes(240)
        let ls2 = try I2PLeaseSet2.build(
            storeType: .encrypted, destination: destination,
            published: Date(), expiresOffsetSeconds: 1800, flags: 0,
            encryptedBody: inner, signingSeed: seed)
        let encoded = ls2.serialize()
        let parsed = try I2PLeaseSet2.parse(encoded, expectedType: .encrypted)
        guard parsed.serialize() == encoded, parsed.storeType == .encrypted,
              parsed.encryptedBody == inner, parsed.leases.isEmpty else {
            throw I2PWireError.invalidFormat
        }
        // An EncryptedLeaseSet carries only the blinded signing key — no
        // destination — so the envelope's identity is that key.
        guard parsed.blindedSigningPublicKey == destination.signingPublicKey,
              parsed.destination.signingPublicKey == destination.signingPublicKey,
              parsed.destination.encryptionPublicKey == Data(repeating: 0, count: 32),
              parsed.destination.hash == I2PLeaseSet2.blindedDestination(destination.signingPublicKey).hash else {
            throw I2PWireError.invalidFormat
        }
        guard parsed.verifySignature(), parsed.verifyTransientBlockSignature() else {
            throw I2PWireError.invalidSignature
        }
        var tampered = encoded
        tampered[encoded.count - 70] ^= 0xff
        guard expectThrow({ _ = try I2PLeaseSet2.parse(tampered, expectedType: .encrypted) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        return "\(encoded.count) bytes; encrypted inner body preserved byte-exact; identity is the blinded signing key (spec carries no destination); tampered signature rejected"
    }

    private static func metaLeaseSet2RoundTrip() throws -> String {
        let (destination, seed) = I2PSamples.sampleIdentity()
        let metaLeases = [
            I2PMetaLease(gatewayHash: I2PCrypto.randomBytes(32), flags: 3,
                         cost: 7, expiration: Date().addingTimeInterval(600)),
            I2PMetaLease(gatewayHash: I2PCrypto.randomBytes(32), flags: 5,
                         cost: 2, expiration: Date().addingTimeInterval(900)),
        ]
        let meta = try I2PLeaseSet2.build(
            storeType: .meta, destination: destination,
            published: Date(), expiresOffsetSeconds: 1800, flags: 0,
            metaEntries: metaLeases, signingSeed: seed)
        let encoded = meta.serialize()
        let parsed = try I2PLeaseSet2.parse(encoded, expectedType: .meta)
        guard parsed.serialize() == encoded, parsed.metaEntries.count == 2,
              parsed.metaEntries[0].entryTypeCode == 3,
              parsed.metaEntries[1].entryTypeCode == 5,
              parsed.metaEntries[1].cost == 2,
              parsed.metaEntries[0].gatewayHash == metaLeases[0].gatewayHash,
              parsed.revocations.isEmpty else {
            throw I2PWireError.invalidFormat
        }
        // A MetaLease names another entry by hash, so the meta entry itself
        // publishes no delivery-usable leases.
        guard parsed.resolvedLeaseSet() == nil else { throw I2PWireError.invalidFormat }
        guard parsed.verifySignature() else { throw I2PWireError.invalidSignature }
        return "meta LS2 (store type 7) round trips; MetaLease flags/cost/end intact with the entry type in flags bits 3-0; signature verified"
    }

    private static func leaseSet2NetdbResolution() async throws -> String {
        let netdb = try makeNetDB()
        // (a) A plain LeaseSet2 ingests and resolves by destination hash with
        // delivery-usable lease entries.
        let (plain, _) = try leaseSet2Sample()
        try await netdb.ingestLeaseSet2(plain.serialize(), entryType: .leaseSet2)
        guard await netdb.hasEntry(plain.destination.hash) else { throw I2PWireError.invalidFormat }
        let resolved = await netdb.lookupLeaseSet2(plain.destination.hash, timeoutPerRound: 0.5, maxRounds: 1)
        guard let resolved, resolved.storeType == .plain, resolved.leases.count == 2,
              resolved.leases[0].tunnelId == 0x1122_3344 else {
            throw I2PWireError.invalidFormat
        }
        // (b) An encrypted LeaseSet2 envelope ingests (signature-verified) and
        // resolves; its inner body stays opaque per the b33 blinding/auth spec.
        let (dest, seed) = I2PSamples.sampleIdentity()
        let els2 = try I2PLeaseSet2.build(
            storeType: .encrypted, destination: dest,
            published: Date(), expiresOffsetSeconds: 1800, flags: 0,
            encryptedBody: I2PCrypto.randomBytes(100), signingSeed: seed)
        try await netdb.ingestLeaseSet2(els2.serialize(), entryType: .encryptedLeaseSet2)
        let resolvedEncrypted = await netdb.lookupLeaseSet2(els2.destination.hash, timeoutPerRound: 0.5, maxRounds: 1)
        guard let resolvedEncrypted, resolvedEncrypted.storeType == .encrypted,
              !resolvedEncrypted.encryptedBody.isEmpty else {
            throw I2PWireError.invalidFormat
        }
        // (c) Tampered LeaseSet2 payloads are rejected at ingest.
        var tampered = plain.serialize()
        tampered[60] ^= 0xff
        guard await expectThrowAsync({ try await netdb.ingestLeaseSet2(tampered, entryType: .leaseSet2) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        // (d) An entry whose expiry has lapsed beyond the grace period is rejected.
        let (expiredDest, expiredSeed) = I2PSamples.sampleIdentity()
        let expired = try I2PLeaseSet2.build(
            storeType: .plain, destination: expiredDest,
            published: Date(timeIntervalSince1970: 1_000_000),
            expiresOffsetSeconds: 60, flags: 0,
            leases: [I2PLease2(gatewayHash: I2PCrypto.randomBytes(32), tunnelId: 1,
                               expiration: Date(timeIntervalSince1970: 1_000_060))],
            signingSeed: expiredSeed)
        guard await expectThrowAsync({ try await netdb.ingestLeaseSet2(expired.serialize(), entryType: .leaseSet2) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        return "plain/encrypted LeaseSet2s ingest after signature verification and resolve through lookup; leases delivery-usable; tampered and expired entries rejected"
    }

    private static func primitivesEdgeCases() throws -> String {
        // Truncated reads throw for every primitive.
        var intWriter = I2PWriter()
        intWriter.integer(1)
        guard expectThrow({ var r = I2PReader(Data(intWriter.data.prefix(3))); _ = try r.integer() }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        var hashWriter = I2PWriter()
        hashWriter.hash(Data(repeating: 1, count: 32))
        guard expectThrow({ var r = I2PReader(Data(hashWriter.data.prefix(31))); _ = try r.hash() }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        // A string whose declared length exceeds the buffer is rejected.
        var stringWriter = I2PWriter()
        stringWriter.string("short")
        var shortString = stringWriter.data
        shortString[0] = 200 // declared length 200, only 5 bytes follow
        guard expectThrow({ var r = I2PReader(shortString); _ = try r.string() }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        // A mapping whose body length exceeds the buffer is rejected.
        var mappingWriter = I2PWriter()
        mappingWriter.mapping(["k": "v"])
        var shortMapping = mappingWriter.data
        shortMapping[0] = 0xFF
        shortMapping[1] = 0xFF
        guard expectThrow({ var r = I2PReader(shortMapping); _ = try r.mapping() }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        // A zero date decodes as "none".
        var dateWriter = I2PWriter()
        dateWriter.date(nil)
        var dateReader = I2PReader(dateWriter.data)
        guard try dateReader.date() == nil else { throw I2PWireError.invalidFormat }
        // Oversized whole structures: trailing data rejected.
        let info = try I2PSamples.sampleRouterInfo()
        guard expectThrow({ _ = try I2PRouterInfo.parse(info.serialize() + Data([0xFF])) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        return "truncated strings/mappings/hashes rejected, zero dates decode as none, trailing data rejected"
    }

    private static func mappingCanonicalOrder() throws -> String {
        var first = I2PWriter()
        first.mapping(["zulu": "1", "alpha": "2", "mike": "3"])
        var second = I2PWriter()
        second.mapping(["alpha": "2", "mike": "3", "zulu": "1"])
        guard first.data == second.data else { throw I2PWireError.invalidFormat }
        // Keys must appear in ascending byte order inside the body.
        let offsets = ["alpha", "mike", "zulu"].map { key in
            first.data.range(of: Data(key.utf8))!.lowerBound
        }
        guard offsets == offsets.sorted() else { throw I2PWireError.invalidFormat }
        var reader = I2PReader(first.data)
        let parsed = try reader.mapping()
        guard parsed == ["zulu": "1", "alpha": "2", "mike": "3"] else {
            throw I2PWireError.invalidFormat
        }
        return "insertion order irrelevant: bytes identical, keys encoded in sorted order"
    }

    // MARK: I2NP

    private static func i2npRoundTrip() throws -> String {
        let message = I2NPMessage(
            type: .databaseLookup,
            messageID: 0x0A11_B2C3,
            // The spec's parse-time expiry enforcement rejects lapsed messages,
            // so fixtures ride a live epoch instead of a pinned past one.
            expiration: Date().addingTimeInterval(300),
            payload: Data(repeating: 0x3C, count: 71))
        let encoded = message.serialize()
        let parsed = try I2NPMessage.parse(encoded)
        guard parsed.serialize() == encoded else { throw I2PWireError.invalidFormat }
        let header = try I2NPMessageHeader.parse(encoded)
        guard header.size == 71, header.type == .databaseLookup,
              I2NPMessageHeader.length == 16 else {
            throw I2PWireError.invalidFormat
        }
        // Oversize: declared payload larger than the buffer is rejected.
        var oversize = encoded
        for index in 13...14 { oversize[index] = 0xFF }
        guard expectThrow({ _ = try I2NPMessage.parse(oversize) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        // Short: buffer shorter than the header is rejected.
        guard expectThrow({ _ = try I2NPMessage.parse(Data(encoded.prefix(9))) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        return "16-byte spec full header (type + ID + ms expiry + size + checksum byte) round trip identical; oversize and truncated payloads rejected"
    }

    /// The spec's 9-byte short header carried by NTCP2/SSU2 data blocks:
    /// type (1) + message ID (4 BE) + expiration (4 BE seconds), with size and
    /// checksum provided by the transport frame. The message ID rides the wire,
    /// exactly as real routers frame it.
    private static func i2npShortHeaderSpec() throws -> String {
        let payload = I2PCrypto.randomBytes(180)
        let expiration = Date().addingTimeInterval(300)
        let message = I2NPMessage(type: .garlic, messageID: 0x0123_4567,
                                  expiration: expiration, payload: payload)
        let short = message.serializeShort()
        // Layout: type (1) + message ID (4 BE) + expiration seconds (4 BE) + payload.
        guard short.count == 9 + payload.count, short[0] == I2NPMessageType.garlic.rawValue else {
            throw I2PWireError.invalidFormat
        }
        let messageID = (UInt32(short[1]) << 24) | (UInt32(short[2]) << 16)
                        | (UInt32(short[3]) << 8) | UInt32(short[4])
        guard messageID == 0x0123_4567 else { throw I2PWireError.invalidFormat }
        let seconds = (UInt32(short[5]) << 24) | (UInt32(short[6]) << 16)
                      | (UInt32(short[7]) << 8) | UInt32(short[8])
        guard abs(TimeInterval(seconds) - expiration.timeIntervalSince1970.rounded()) < 1 else {
            throw I2PWireError.invalidFormat
        }
        let parsed = try I2NPMessage.parseShort(short)
        guard parsed.type == .garlic, parsed.payload == payload,
              parsed.messageID == message.messageID else {
            throw I2PWireError.invalidFormat
        }
        // The transport round trip: full internal framing → short wire framing
        // → parse back; the payload, type and message ID survive byte-for-byte.
        guard try I2NPMessage.parseShort(message.serializeShort()).payload == payload else {
            throw I2PWireError.invalidFormat
        }
        // Unknown type codes reject at the short-header boundary.
        var unknown = short
        unknown[0] = 200
        guard expectThrow({ _ = try I2NPMessage.parseShort(unknown) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        return "9-byte spec short header (type + message ID + seconds-level expiry) round-trips with the ID riding the wire; unknown types rejected"
    }

    private static func i2npExpiryEnforcement() throws -> String {
        let fresh = I2NPMessage(type: .dataMessage, expiration: Date().addingTimeInterval(60))
        guard !fresh.isExpired() else { throw I2PWireError.invalidFormat }
        let stale = I2NPMessage(type: .dataMessage, expiration: Date().addingTimeInterval(-60))
        guard stale.isExpired() else { throw I2PWireError.invalidFormat }
        return "fresh message accepted; stale message flagged dropped per spec"
    }

    /// Router options/status channel: the I2NP message table defines no Options
    /// type, so options ride RouterInfo options and the NTCP2 Options block.
    private static func routerOptionsChannel() throws -> String {
        let codes = I2NPMessageType.allCases.map(\.rawValue).sorted()
        guard codes == [1, 2, 3, 10, 11, 18, 19, 20, 25, 26],
              I2NPMessageType.tunnelGateway.rawValue == 19 else {
            throw I2PCrossValidationError.failed("the I2NP type table does not match the spec's message table")
        }
        // The obsolete type-12 slot the router once used for a made-up Options
        // message must reject at parse — fail closed, not a silent extra type.
        var obsolete = I2NPMessage(type: .dataMessage, payload: Data([0x7A])).serialize()
        obsolete[0] = 12
        guard expectThrow({ _ = try I2NPMessage.parse(obsolete) }) else {
            throw I2PCrossValidationError.failed("the obsolete type-12 Options slot still parses")
        }

        // RouterInfo options carry the router's capabilities and status, and
        // survive the signed wire form byte-for-byte.
        let signing = Curve25519.Signing.PrivateKey()
        let identity = I2PRouterIdentity(
            encryptionPublicKey: Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation,
            signingPublicKey: signing.publicKey.rawRepresentation)
        var info = I2PRouterInfo(
            identity: identity,
            published: Date(timeIntervalSince1970: 1_700_000_000),
            addresses: [I2PRouterAddress(cost: 5, transportStyle: "NTCP2",
                                         expiration: nil,
                                         options: ["host": "10.0.0.7", "port": "8887"])],
            options: ["caps": "XfR", "netid": "2", "router.version": "0.9.62"])
        try info.sign(withSeed: signing.rawRepresentation)
        let decoded = try I2PRouterInfo.parse(info.serialize())
        guard decoded.options["caps"] == "XfR",
              decoded.options["router.version"] == "0.9.62",
              decoded.serialize() == info.serialize() else {
            throw I2PWireError.invalidFormat
        }

        // The NTCP2 data-phase Options block (payload block type 1) round trips.
        let options = NTCP2Options(transmitMin: 0x01, transmitMax: 0x10,
                                   receiveMin: 0x00, receiveMax: 0x20,
                                   transmitDummy: 25, receiveDummy: 40,
                                   transmitDelay: 5, receiveDelay: 7)
        let decodedBlocks = try NTCP2Block.decode(try NTCP2Block.encode([.options(options)]))
        guard decodedBlocks.count == 1,
              case .options(let decodedOptions) = decodedBlocks[0],
              decodedOptions == options else {
            throw I2PWireError.invalidFormat
        }
        return "type table is exactly the spec's (12 rejected, 19 = TunnelGateway); RouterInfo options round-trip with the signature intact; NTCP2 Options block round-trips"
    }

    private static func databaseStoreRoundTrip() throws -> String {
        let key = I2PCrypto.sha256(Data("cv-store-key".utf8))
        let gateway = I2PCrypto.sha256(Data("cv-store-gateway".utf8))
        let entryPayload = try I2PSamples.sampleRouterInfo().serialize()

        // With reply token + gateway.
        let withReply = I2PDatabaseStore(
            key: key, entryType: .routerInfo, replyToken: 0x0FA1_7E57,
            replyTunnelId: 12, replyGateway: gateway, payload: entryPayload)
        let withReplyBytes = withReply.serialize()
        let parsedReply = try I2PDatabaseStore.parse(withReplyBytes)
        guard parsedReply.serialize() == withReplyBytes else { throw I2PWireError.invalidFormat }
        guard parsedReply.replyToken == 0x0FA1_7E57, parsedReply.replyGateway == gateway,
              parsedReply.payload == entryPayload else {
            throw I2PWireError.invalidFormat
        }

        // Without reply token (store acknowledgment path absent).
        let noReply = I2PDatabaseStore(key: key, entryType: .leaseSet, replyToken: 0,
                                       payload: Data(repeating: 0x21, count: 9))
        let noReplyBytes = noReply.serialize()
        let parsedNoReply = try I2PDatabaseStore.parse(noReplyBytes)
        guard parsedNoReply.serialize() == noReplyBytes,
              parsedNoReply.replyGateway.isEmpty, parsedNoReply.replyTunnelId == 0 else {
            throw I2PWireError.invalidFormat
        }
        return "reply-token and tokenless stores round trip byte-for-byte"
    }

    private static func databaseStoreEdgeCases() throws -> String {
        let key = I2PCrypto.randomBytes(32)
        // Unknown entry type code.
        var writer = I2PWriter()
        writer.hash(key)
        writer.byte(9)
        writer.integer(0)
        writer.short(0)
        guard expectThrow({ _ = try I2PDatabaseStore.parse(writer.data) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        // Declared payload size beyond the buffer. A type-0 store's 2-byte
        // compressed size sits at offset 32 (key) + 1 (type) + 4 (token) = 37.
        let store = I2PDatabaseStore(key: key, entryType: .routerInfo, replyToken: 0,
                                     payload: Data(repeating: 0x5A, count: 20))
        var short = store.serialize()
        short[37] = 0xFF
        short[38] = 0xFF
        guard expectThrow({ _ = try I2PDatabaseStore.parse(short) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        // Trailing data.
        guard expectThrow({ _ = try I2PDatabaseStore.parse(store.serialize() + Data([0x00])) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        return "unknown entry type, oversize payload and trailing data all rejected"
    }

    private static func databaseLookupRoundTrip() throws -> String {
        let queryKey = I2PCrypto.sha256(Data("cv-lookup".utf8))
        let fromHash = I2PCrypto.sha256(Data("cv-lookup-from".utf8))
        let gateway = I2PCrypto.sha256(Data("cv-lookup-gateway".utf8))
        let lookup = I2PDatabaseLookup(
            queryKey: queryKey, fromHash: fromHash,
            excludedPeers: [queryKey, gateway, fromHash],
            replyTunnels: [(gateway, 0x0000_0BEE)],
            replyToken: 0x1234_ABCD, replyTunnelId: 7, replyGateway: queryKey)
        let encoded = lookup.serialize()
        let parsed = try I2PDatabaseLookup.parse(encoded)
        guard parsed.serialize() == encoded else { throw I2PWireError.invalidFormat }
        guard parsed.excludedPeers.count == 3, parsed.replyTunnels.count == 1,
              parsed.replyTunnels[0].tunnelId == 0x0000_0BEE else {
            throw I2PWireError.invalidFormat
        }
        // Minimal lookup (no excludes, no tunnels, no reply token).
        let minimal = I2PDatabaseLookup(queryKey: queryKey, fromHash: fromHash, replyToken: 0)
        let minimalBytes = minimal.serialize()
        guard try I2PDatabaseLookup.parse(minimalBytes).serialize() == minimalBytes else {
            throw I2PWireError.invalidFormat
        }
        // SearchReply round trip.
        let reply = I2PDatabaseSearchReply(queryKey: queryKey, fromHash: fromHash,
                                           peerHashes: [queryKey, gateway, fromHash])
        let replyBytes = reply.serialize()
        guard try I2PDatabaseSearchReply.parse(replyBytes).serialize() == replyBytes else {
            throw I2PWireError.invalidFormat
        }
        return "lookup (full + minimal) and search replies round trip byte-for-byte"
    }

    private static func deliveryInstructionsRoundTrip() throws -> String {
        let routerHash = I2PCrypto.randomBytes(32)
        let cases: [I2PDeliveryInstructions] = [
            I2PDeliveryInstructions(mode: .local),
            I2PDeliveryInstructions(mode: .destination, routerHash: routerHash),
            I2PDeliveryInstructions(mode: .tunnel, tunnelID: 0x0102_0304, routerHash: routerHash),
            I2PDeliveryInstructions(mode: .router, routerHash: routerHash),
        ]
        let expectedFlags: [UInt8] = [0x00, 0x20, 0x60, 0x40]
        let expectedLengths = [1, 33, 37, 33]
        for (index, instructions) in cases.enumerated() {
            let encoded = instructions.serialize()
            guard encoded.count == expectedLengths[index],
                  encoded[0] == expectedFlags[index] else { throw I2PWireError.invalidFormat }
            let (parsed, consumed) = try I2PDeliveryInstructions.parse(encoded)
            guard consumed == encoded.count else { throw I2PWireError.invalidFormat }
            guard parsed.serialize() == encoded else { throw I2PWireError.invalidFormat }
            guard parsed.mode == instructions.mode,
                  parsed.tunnelID == instructions.tunnelID,
                  parsed.routerHash == instructions.routerHash else {
                throw I2PWireError.invalidFormat
            }
        }
        // A destination must be rejected without a 32-byte hash; a set session
        // key bit (0x80) is not part of the 1/33/37-byte forms.
        guard expectThrow({ _ = try I2PDeliveryInstructions.parse(Data([0x80])) }),
              expectThrow({ _ = try I2PDeliveryInstructions.parse(Data([0x20])) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        return "4 instruction shapes (LOCAL/DESTINATION/ROUTER/TUNNEL) with spec flags and 1/33/37-byte lengths"
    }

    private static func tunnelGatewayRoundTrip() throws -> String {
        // Golden layout hand-assembled from the I2NP spec's diagram:
        // tunnelId (4 BE) | length (2 BE) | that many message bytes. Asserting
        // literal bytes — not a round trip through this same codec — is what
        // catches a field the encoder and decoder both omit.
        let innerBytes = Data([0x0B, 0x00, 0x00, 0x00, 0x01])
        let golden = Data([0x11, 0x22, 0x33, 0x44, 0x00, 0x05, 0x0B, 0x00, 0x00, 0x00, 0x01])
        let payload = I2PTunnelGatewayPayload(gatewayID: 0x1122_3344, message: innerBytes).serialize()
        guard payload == golden else { throw I2PWireError.invalidFormat }
        let (goldenID, goldenMessage) = try I2PTunnelGatewayPayload.parse(golden)
        guard goldenID == 0x1122_3344, goldenMessage == innerBytes else {
            throw I2PWireError.invalidFormat
        }
        // The same shape with a real I2NP message inside, and the length field
        // counts exactly that message.
        let inner = I2NPMessage(type: .dataMessage, messageID: 0x0000_0042,
                                payload: Data("gateway payload".utf8))
        let framed = I2PTunnelGatewayPayload(gatewayID: 0x01_0203, message: inner.serialize()).serialize()
        let messageLength = inner.serialize().count
        guard framed.count == 4 + 2 + messageLength,
              Array(framed[4..<6]) == [UInt8(messageLength >> 8), UInt8(messageLength & 0xff)],
              framed[6..<(6 + messageLength)] == inner.serialize()[...] else {
            throw I2PWireError.invalidFormat
        }
        let (gatewayID, message) = try I2PTunnelGatewayPayload.parse(framed)
        guard gatewayID == 0x01_0203, message == inner.serialize() else {
            throw I2PWireError.invalidFormat
        }
        guard I2PTunnelGatewayPayload(gatewayID: gatewayID, message: message).serialize() == framed else {
            throw I2PWireError.invalidFormat
        }
        // A length that overruns the body is truncated; one that under-runs it
        // leaves trailing data. Both are rejected rather than guessed at.
        guard expectThrow({ _ = try I2PTunnelGatewayPayload.parse(framed.dropLast()) }),
              expectThrow({ _ = try I2PTunnelGatewayPayload.parse(framed + Data([0x00])) }),
              expectThrow({ _ = try I2PTunnelGatewayPayload.parse(Data([0x11, 0x22, 0x33, 0x44])) })
        else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        return "spec golden bytes [tunnelID][length][message] verified in both directions; short, trailing and header-only bodies rejected"
    }

    private static func dataMessageRoundTrip() throws -> String {
        // Golden layout per the I2NP spec: length (4 BE) then the payload.
        let golden = Data([0x00, 0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC])
        let payload = Data([0xAA, 0xBB, 0xCC])
        guard I2NPDataMessage(payload: payload).serialize() == golden,
              try I2NPDataMessage.parse(golden) == payload else {
            throw I2PWireError.invalidFormat
        }
        // A whole I2NP message framed as a Data body keeps its own header.
        let message = I2NPMessage(type: .dataMessage, messageID: 0x0000_0007,
                                  payload: Data("stream frame".utf8))
        let body = I2NPDataMessage(payload: message.serialize()).serialize()
        guard try I2NPDataMessage.parse(body) == message.serialize() else {
            throw I2PWireError.invalidFormat
        }
        // A length that disagrees with the body is rejected both ways.
        guard expectThrow({ _ = try I2NPDataMessage.parse(golden.dropLast()) }),
              expectThrow({ _ = try I2NPDataMessage.parse(golden + Data([0x00])) }),
              expectThrow({ _ = try I2NPDataMessage.parse(Data([0x00, 0x00])) })
        else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        return "spec golden bytes [length][payload] verified in both directions; short, trailing and header-only bodies rejected"
    }

    private static func tunnelDataRoundTrip() throws -> String {
        let payload = I2PTunnelDataPayload(
            tunnelID: 0x00C0_FFEE,
            iv: I2PCrypto.randomBytes(16),
            body: I2PCrypto.randomBytes(I2PTunnelDataPayload.bodySize))
        let encoded = payload.serialize()
        guard encoded.count == 4 + 16 + I2PTunnelDataPayload.bodySize else {
            throw I2PWireError.invalidFormat
        }
        let parsed = try I2PTunnelDataPayload.parse(encoded)
        guard parsed.serialize() == encoded else { throw I2PWireError.invalidFormat }
        // Short payload rejected.
        guard expectThrow({ _ = try I2PTunnelDataPayload.parse(Data(encoded.prefix(encoded.count - 1))) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        // Trailing data rejected.
        guard expectThrow({ _ = try I2PTunnelDataPayload.parse(encoded + Data([0x00])) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        return "\(encoded.count)-byte fixed-shape payload round trips; short and trailing payloads rejected"
    }

    private static func buildMessagesRoundTrip() throws -> String {
        let hopKey1 = Curve25519.KeyAgreement.PrivateKey()
        let hopKey2 = Curve25519.KeyAgreement.PrivateKey()
        let plaintext1 = I2PTunnelBuildRequestRecord(
            hopNumber: 0, receiveTunnelID: 0x0A0B_0C0D, nextHopHash: I2PCrypto.randomBytes(32),
            nextTunnelID: 55, isMessagePathEnd: false, nextHopIsOriginator: false,
            hasMoreRecords: true
        )
        let plaintext2 = I2PTunnelBuildRequestRecord(
            hopNumber: 1, receiveTunnelID: 0x0102_0304, nextHopHash: Data(repeating: 0, count: 32),
            nextTunnelID: 0, isMessagePathEnd: true, nextHopIsOriginator: true,
            hasMoreRecords: false
        )
        let encrypted1 = try I2PTunnelBuildCrypto.encryptRecordWithMaterial(
            plaintext1.serialize(), to: hopKey1.publicKey.rawRepresentation, hopHash: nil, recordIndex: 0)
        let encrypted2 = try I2PTunnelBuildCrypto.encryptRecordWithMaterial(
            plaintext2.serialize(), to: hopKey2.publicKey.rawRepresentation, hopHash: nil, recordIndex: 1)
        let record1 = encrypted1.wire
        let record2 = encrypted2.wire

        let build = I2PTunnelBuildMessage(messageID: 0x00BE_EF01, records: [record1, record2])
        let buildBytes = build.serialize()
        let parsedBuild = try I2PTunnelBuildMessage.parse(buildBytes)
        guard parsedBuild.serialize() == buildBytes, parsedBuild.records == [record1, record2] else {
            throw I2PWireError.invalidFormat
        }
        // Each addressed hop recovers exactly its record.
        guard try I2PTunnelBuildCrypto.decryptRecord(record1, localEncryptionKey: hopKey1, recordIndex: 0) == plaintext1.serialize(),
              try I2PTunnelBuildCrypto.decryptRecord(record2, localEncryptionKey: hopKey2, recordIndex: 1) == plaintext2.serialize() else {
            throw I2PWireError.invalidFormat
        }

        // Reply message round trip.
        let replyWire = try I2PTunnelBuildCrypto.encryptReplyRecord(
            I2PTunnelBuildReplyRecord(receiveTunnelID: 77, returnCode: 0),
            material: encrypted1.material, recordIndex: 0)
        guard replyWire.count == I2PTunnelBuildReply.encryptedRecordLength else {
            throw I2PWireError.invalidFormat
        }
        let reply = I2PTunnelBuildReply(messageID: 0x00BE_EF01, encryptedRecords: [replyWire])
        let replyBytes = reply.serialize()
        guard try I2PTunnelBuildReply.parse(replyBytes).serialize() == replyBytes else {
            throw I2PWireError.invalidFormat
        }

        // Record-count bounds: 9 records rejected.
        var oversizeWriter = I2PWriter()
        oversizeWriter.byte(9)
        oversizeWriter.raw(record1)
        guard expectThrow({ _ = try I2PTunnelBuildMessage.parse(oversizeWriter.data) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        return "short build + reply messages round trip; per-hop decryption exact; record count bounds enforced"
    }

    // MARK: NTCP2

    private static func ntcp2BlocksRoundTrip() throws -> String {
        let blocks: [NTCP2Block] = [
            .data(Data("i2np frame payload".utf8)),
            .time(Date(timeIntervalSince1970: 1_700_000_123)),
            .options(NTCP2Options(transmitMin: 1, receiveMax: 8)),
            .padding(23),
            .termination(reason: 3, validFrames: 42),
        ]
        let encoded = try NTCP2Block.encode(blocks)
        let decoded = try NTCP2Block.decode(encoded)
        let reencoded = try NTCP2Block.encode(decoded)
        guard reencoded == encoded else { throw I2PWireError.invalidFormat }
        // 16-byte alignment padding round trips too.
        let aligned = NTCP2Block.aligned(encoded)
        guard aligned.count % 16 == 0 else { throw I2PWireError.invalidFormat }
        let alignedDecoded = try NTCP2Block.decode(aligned)
        guard alignedDecoded.count == decoded.count + 1 else { throw I2PWireError.invalidFormat }
        guard case .padding = alignedDecoded.last! else { throw I2PWireError.invalidFormat }
        // A block whose declared length exceeds the payload is rejected.
        var short = Data([NTCP2BlockType.data.rawValue, 0xFF, 0xFF])
        short.append(Data("xy".utf8))
        guard expectThrow({ _ = try NTCP2Block.decode(short) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        return "5 block types round trip byte-for-byte; alignment padding verified; oversize block rejected"
    }

    private static func ntcp2KDFChains() throws -> String {
        let ikm = I2PCrypto.randomBytes(32)
        let material = Data("mix-hash material".utf8)
        let plaintext = Data("deterministic plaintext".utf8)

        func build() throws -> NTCP2NoiseChain {
            var chain = NTCP2NoiseChain()
            chain.mixHash(material)
            chain.mixKey(ikm)
            return chain
        }
        var first = try build()
        var second = try build()
        guard first.chainingKey == second.chainingKey, first.hash == second.hash,
              first.key == second.key, first.nonce == second.nonce else {
            throw I2PWireError.invalidFormat
        }
        let firstCiphertext = try first.encrypt(plaintext)
        let secondCiphertext = try second.encrypt(plaintext)
        guard firstCiphertext == secondCiphertext else {
            throw I2PWireError.invalidFormat
        }
        // Split(): deterministic, 32-byte AEAD keys, 24-byte SipHash key material
        // (two keys + IV), distinct directions.
        let (ab1, ba1) = first.split()
        let (ab2, ba2) = second.split()
        guard ab1 == ab2, ba1 == ba2 else { throw I2PWireError.invalidFormat }
        guard ab1.aeadKey.count == 32, ab1.sipKeys.count == 24,
              ab1.aeadKey != ba1.aeadKey, ab1.sipKeys != ba1.sipKeys else {
            throw I2PWireError.invalidFormat
        }
        // The AEAD nonce advances per message.
        var advancing = try build()
        _ = try advancing.encrypt(Data([1]))
        guard advancing.nonce == 1 else { throw I2PWireError.invalidFormat }
        _ = try advancing.encrypt(Data([2]))
        guard advancing.nonce == 2 else { throw I2PWireError.invalidFormat }
        return "identical chain inputs → identical chain state, ciphertexts and split keys; nonce advances per message"
    }

    private static func ntcp2KDFLabels() throws -> String {
        guard NTCP2NoiseChain.protocolName == "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256",
              NTCP2NoiseChain.protocolName.utf8.count == 48 else {
            throw I2PWireError.invalidFormat
        }
        // A 48-byte name is hashed (Noise §5): h = SHA256(name), ck = h, then
        // the null prologue gives h = SHA256(h).
        let chain = NTCP2NoiseChain()
        let nameHash = I2PCrypto.sha256(Data(NTCP2NoiseChain.protocolName.utf8))
        guard chain.chainingKey == nameHash,
              chain.hash == I2PCrypto.sha256(nameHash) else {
            throw I2PWireError.invalidFormat
        }
        // HKDF chain expansion: deterministic, correct count, all outputs distinct.
        let outputs = NTCP2NoiseChain.hkdf(Data(repeating: 7, count: 32),
                                           Data(repeating: 9, count: 32), outputs: 4)
        guard outputs.count == 4, Set(outputs.map(\.hex)).count == 4 else {
            throw I2PWireError.invalidFormat
        }
        guard outputs == NTCP2NoiseChain.hkdf(Data(repeating: 7, count: 32),
                                              Data(repeating: 9, count: 32), outputs: 4) else {
            throw I2PWireError.invalidFormat
        }
        return "protocol name hashed per Noise (48 bytes); HKDF chain expansion deterministic and distinct"
    }

    private static func nonce96Layout() throws -> String {
        let key = I2PCrypto.randomBytes(32)
        func seal(_ nonce: ChaChaPoly.Nonce) throws -> Data {
            try ChaChaPoly.seal(Data(), using: SymmetricKey(data: key), nonce: nonce).combined
        }
        // nonce96 = 4 zero bytes ‖ little-endian counter (Noise spec).
        let counter: UInt64 = 0x0001_0203_0405_0607
        let manual = try ChaChaPoly.Nonce(data: Data([0, 0, 0, 0, 7, 6, 5, 4, 3, 2, 1, 0]))
        let zeroManual = try ChaChaPoly.Nonce(data: Data(repeating: 0, count: 12))
        let withCounter = try seal(NTCP2NoiseChain.nonce96(counter))
        let withManual = try seal(manual)
        guard withCounter == withManual else { throw I2PWireError.invalidFormat }
        let withZero = try seal(NTCP2NoiseChain.nonce96(0))
        let withZeroManual = try seal(zeroManual)
        guard withZero == withZeroManual else { throw I2PWireError.invalidFormat }
        // Distinct counters produce distinct nonces.
        let otherCounter = try seal(NTCP2NoiseChain.nonce96(1))
        guard otherCounter != withZero else { throw I2PWireError.invalidFormat }
        return "nonce96 = 4 zero bytes ‖ little-endian counter, verified functionally against manual nonces"
    }

    private static func ntcp2FrameRoundTrip() throws -> String {
        let keys = NTCP2DirectionKeys(aeadKey: I2PCrypto.randomBytes(32),
                                      sipKeys: I2PCrypto.randomBytes(24))
        // A frame's length mask and nonce use the *sender's* frame counter, while
        // the receiver keeps its own. Using one codec for both sides advanced the
        // shared counter before the length was unmasked, so the decode produced a
        // bogus length and the force-unwrap trapped (SIGTRAP in the alignment run).
        let sender = NTCP2FrameCodec(directionKeys: keys)
        let receiver = NTCP2FrameCodec(directionKeys: keys)
        let payload = Data("frame payload with stable bytes".utf8)
        let framed = try sender.frame(payload)
        guard let decoded = try receiver.unframe(framed) else {
            throw I2PWireError.invalidFormat
        }
        guard decoded.payload == payload, decoded.consumed == framed.count else {
            throw I2PWireError.invalidFormat
        }
        // Multiple frames: the counter advances per frame.
        let framed2 = try sender.frame(Data("second frame".utf8))
        guard let decoded2 = try receiver.unframe(framed2) else {
            throw I2PWireError.invalidFormat
        }
        guard decoded2.payload == Data("second frame".utf8), decoded2.consumed == framed2.count else {
            throw I2PWireError.invalidFormat
        }
        // Incremental delivery: partial buffer yields nil, completion yields the payload.
        let incrementalSender = NTCP2FrameCodec(directionKeys: keys)
        let incrementalReceiver = NTCP2FrameCodec(directionKeys: keys)
        let full = try incrementalSender.frame(payload)
        guard try incrementalReceiver.unframe(Data(full.prefix(1))) == nil else {
            throw I2PWireError.invalidFormat
        }
        guard let incrementalDecoded = try incrementalReceiver.unframe(full),
              incrementalDecoded.payload == payload else {
            throw I2PWireError.invalidFormat
        }
        // Tampered MAC rejected.
        let tamperSender = NTCP2FrameCodec(directionKeys: keys)
        let tamperReceiver = NTCP2FrameCodec(directionKeys: keys)
        let tamperTarget = try tamperSender.frame(payload)
        var tampered = tamperTarget
        tampered[tampered.count - 1] ^= 0xff
        guard expectThrow({ _ = try tamperReceiver.unframe(tampered) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        return "frames round trip (sequential + incremental); tampered MAC rejected"
    }

    private static func sipHashDeterminism() throws -> String {
        // SipHash-2-4 is a pure function of the two 64-bit keys and the message.
        // Known-answer vector (the reference implementation's vectors_sip64[15]):
        // key bytes 00..0f over message bytes 00..0e give the little-endian
        // 64-bit output 0xa129ca6149be45e5 (wire bytes e5 45 be 49 61 ca 29 a1).
        // The key loader is little-endian, exactly as NTCP2's key material is read.
        guard SipHash24.hash(key: Data(0..<16), message: Data(0..<15)) == 0xa129_ca61_49be_45e5 else {
            throw I2PCrossValidationError.failed(
                "SipHash-2-4 known-answer vector failed (a129ca614abf5be expected family)")
        }
        let k0 = UInt64.random(in: 1...UInt64.max)
        let k1 = UInt64.random(in: 1...UInt64.max)
        let iv = I2PCrypto.randomBytes(8)
        guard SipHash24.hash(k0: k0, k1: k1, message: iv)
                == SipHash24.hash(k0: k0, k1: k1, message: iv) else {
            throw I2PWireError.invalidFormat
        }
        guard SipHash24.hash(k0: k0, k1: k1, message: iv)
                != SipHash24.hash(k0: k0, k1: k1, message: I2PCrypto.randomBytes(8)) else {
            throw I2PWireError.invalidFormat
        }
        // The data-phase KDF hands each direction 24 bytes: two SipHash keys and
        // the initial IV. The IV chains per frame, so two frames of equal length
        // still carry different obfuscated length fields.
        let keys = NTCP2DirectionKeys(aeadKey: I2PCrypto.randomBytes(32),
                                      sipKeys: I2PCrypto.randomBytes(24))
        guard keys.sipKeys.count == 24 else { throw I2PWireError.invalidFormat }
        let codec = NTCP2FrameCodec(directionKeys: keys)
        let payload = Data("obfuscation math".utf8)
        let first = try codec.frame(payload)
        let second = try codec.frame(payload)
        guard first.count == second.count,
              Data(first.prefix(2)) != Data(second.prefix(2)) else {
            throw I2PWireError.invalidFormat
        }
        // A length field that de-obfuscates below the 16-byte MAC floor is
        // rejected rather than treated as an incomplete frame.
        let zeroCodec = NTCP2FrameCodec(directionKeys: keys)
        let mask = zeroCodec.nextLengthMask()
        let zeroLengthFrame = Data([UInt8((mask >> 8) & 0xff), UInt8(mask & 0xff)])
        guard expectThrow({ _ = try zeroCodec.unframe(zeroLengthFrame) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        return "masks deterministic and chained per frame; frame length math verified; short frames rejected"
    }

    /// Fresh in-memory handshake engines over X25519 static keys.
    private static func ntcp2HandshakeEngines() throws -> (initiator: NTCP2InitiatorHandshake,
                                                            responder: NTCP2ResponderHandshake,
                                                            routerInfo: Data,
                                                            responderStatic: Data,
                                                            responderHash: Data,
                                                            responderIV: Data) {
        let alice = Curve25519.KeyAgreement.PrivateKey()
        let bob = Curve25519.KeyAgreement.PrivateKey()
        let routerInfo = try I2PSamples.sampleRouterInfo().serialize()
        // The responder's router hash keys the handshake obfuscation; its `i`
        // option supplies the IV.
        let bobHash = I2PCrypto.randomBytes(32)
        let bobIV = I2PCrypto.randomBytes(16)
        let bobStaticPublic = I2PCrypto.canonicalX25519PublicKey(bob.publicKey.rawRepresentation)
        let initiator = try NTCP2InitiatorHandshake(localStaticKey: alice,
                                                    remoteStaticKey: bobStaticPublic,
                                                    remoteRouterHash: bobHash,
                                                    remoteIV: bobIV)
        let responder = try NTCP2ResponderHandshake(localStaticKey: bob,
                                                    localStaticPublicKey: bobStaticPublic,
                                                    localRouterHash: bobHash,
                                                    localIV: bobIV)
        return (initiator, responder, routerInfo, bobStaticPublic, bobHash, bobIV)
    }

    /// The spec's AES-256-CBC ephemeral-key obfuscation end-to-end: messages 1
    /// and 2 are fixed-length frames under a CBC stream keyed by the responder's
    /// router hash, and the full handshake completes with mirrored direction keys.
    private static func ntcp2KeyObfuscationSpec() throws -> String {
        let engines = try ntcp2HandshakeEngines()
        let request = try engines.initiator.makeSessionRequest(routerInfo: engines.routerInfo, padding: 13)
        let created = try engines.responder.processSessionRequest(request, padding: 7)
        guard created.consumed == request.count else {
            throw NTCP2Error.handshakeFailed("message 1 consumed length mismatch")
        }
        let confirm = try engines.initiator.processSessionCreated(created.reply)
        guard confirm.consumed == created.reply.count else {
            throw NTCP2Error.handshakeFailed("message 2 consumed length mismatch")
        }
        _ = try engines.responder.processSessionConfirm(confirm.message)
        let aliceKeys = try engines.initiator.complete()
        let bobKeys = try engines.responder.complete()
        guard aliceKeys.sendKeys == bobKeys.recvKeys,
              aliceKeys.recvKeys == bobKeys.sendKeys else {
            throw NTCP2Error.handshakeFailed("direction keys disagree")
        }
        // Message 1's X de-obfuscates under RH_B and the published `i` IV, and
        // message 2 continues the same CBC chain rather than restarting it.
        var reader = try NTCP2HandshakeObfuscator(routerHash: engines.responderHash,
                                                  iv: engines.responderIV)
        let recovered = try reader.decrypt(Data(request.prefix(32)))
        _ = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: recovered)

        var chained = try NTCP2HandshakeObfuscator(routerHash: engines.responderHash,
                                                   iv: engines.responderIV)
        let firstBlock = try chained.encrypt(recovered)
        let nextBlock = try chained.encrypt(recovered)
        var restart = try NTCP2HandshakeObfuscator(routerHash: engines.responderHash,
                                                   iv: engines.responderIV)
        let restarted = try restart.encrypt(recovered)
        guard firstBlock == Data(request.prefix(32)),
              nextBlock != firstBlock,
              restarted == firstBlock else {
            throw NTCP2Error.handshakeFailed("obfuscation IV did not chain")
        }
        return "messages 1 and 2 framed per spec: AES-256-CBC ephemeral-key obfuscation keyed by RH_B with the published 'i' IV, handshake completes with mirrored direction keys"
    }

    /// Message 1 and message 2 framing: fixed 64-byte envelopes (obfuscated
    /// ephemeral key, 16-byte options block, MAC) with no length prefix, and
    /// m3p2len equal to the message-3 part-2 frame size.
    private static func ntcp2OptionsLayoutSpec() throws -> String {
        let engines = try ntcp2HandshakeEngines()
        let request = try engines.initiator.makeSessionRequest(routerInfo: engines.routerInfo, padding: 0)
        guard request.count == 64 else {
            throw NTCP2Error.handshakeFailed("message 1 is \(request.count) bytes, expected 64 (32-byte X + 16-byte options + 16-byte MAC)")
        }
        let created = try engines.responder.processSessionRequest(request, padding: 5)
        guard created.consumed == request.count else {
            throw NTCP2Error.handshakeFailed("message 1 consumed length mismatch")
        }
        guard created.reply.count == 69 else {
            throw NTCP2Error.handshakeFailed("message 2 is \(created.reply.count) bytes, expected 64 + 5 padding")
        }
        _ = try engines.initiator.processSessionCreated(created.reply)
        let expectedPart2 = (try NTCP2Block.encode([.routerInfo(engines.routerInfo)])).count + 16
        guard engines.initiator.announcedPart2Length == expectedPart2 else {
            throw NTCP2Error.handshakeFailed("m3p2len is not the message-3 part-2 frame size")
        }
        return "message 1: 32-byte obfuscated X + 16-byte options + MAC; message 2: the same envelope with padLen/tsB; m3p2len equals the message-3 part-2 frame size"
    }

    // MARK: Crypto cross-checks

    private static func chachaPolyDeterminism() throws -> String {
        let key = I2PCrypto.randomBytes(32)
        let nonce = I2PCrypto.randomBytes(12)
        let message = I2PCrypto.randomBytes(200)
        let aad = Data("frame".utf8)
        let sealed1 = try I2PCrypto.chacha20Poly1305Seal(key: key, nonce: nonce, plaintext: message, aad: aad)
        let sealed2 = try I2PCrypto.chacha20Poly1305Seal(key: key, nonce: nonce, plaintext: message, aad: aad)
        guard sealed1 == sealed2 else { throw I2PWireError.invalidFormat }
        guard try I2PCrypto.chacha20Poly1305Open(key: key, nonce: nonce, ciphertextAndTag: sealed1, aad: aad) == message else {
            throw I2PWireError.invalidFormat
        }
        // A different nonce changes the ciphertext.
        let other = try I2PCrypto.chacha20Poly1305Seal(key: key, nonce: I2PCrypto.randomBytes(12),
                                                       plaintext: message, aad: aad)
        guard other != sealed1 else { throw I2PWireError.invalidFormat }
        // Tampered MAC, ciphertext and AAD are all rejected.
        var badTag = sealed1
        badTag[badTag.count - 1] ^= 0xff
        guard expectThrow({ _ = try I2PCrypto.chacha20Poly1305Open(key: key, nonce: nonce, ciphertextAndTag: badTag, aad: aad) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        var badCiphertext = sealed1
        badCiphertext[5] ^= 0xff
        guard expectThrow({ _ = try I2PCrypto.chacha20Poly1305Open(key: key, nonce: nonce, ciphertextAndTag: badCiphertext, aad: aad) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        guard expectThrow({ _ = try I2PCrypto.chacha20Poly1305Open(key: key, nonce: nonce, ciphertextAndTag: sealed1, aad: Data("other".utf8)) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        return "deterministic sealing; MAC, ciphertext and AAD tampering all rejected"
    }

    private static func hkdfRFC5869() throws -> String {
        // RFC 5869 test case 1.
        let case1IKM = Data(repeating: 0x0b, count: 22)
        let case1Salt = Data((0x00...0x0c).map { UInt8($0) })
        let case1Info = Data((0xf0...0xf9).map { UInt8($0) })
        let case1 = I2PCrypto.hkdfSHA256(inputKeyMaterial: case1IKM, salt: case1Salt,
                                         info: case1Info, outputLength: 42)
        guard case1.hex == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865" else {
            throw I2PWireError.invalidFormat
        }
        // RFC 5869 test case 3: empty salt and info.
        let case3IKM = Data(repeating: 0x0b, count: 22)
        let case3 = I2PCrypto.hkdfSHA256(inputKeyMaterial: case3IKM, salt: Data(),
                                         info: Data(), outputLength: 42)
        guard case3.hex == "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8" else {
            throw I2PWireError.invalidFormat
        }
        // Determinism.
        let again = I2PCrypto.hkdfSHA256(inputKeyMaterial: case3IKM, salt: Data(),
                                         info: Data(), outputLength: 42)
        guard again == case3 else { throw I2PWireError.invalidFormat }
        return "RFC 5869 test cases 1 and 3 match byte-for-byte; derivation deterministic"
    }

    private static func sha256Vectors() throws -> String {
        guard I2PCrypto.sha256(Data()).hex
                == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" else {
            throw I2PWireError.invalidFormat
        }
        guard I2PCrypto.sha256(Data("abc".utf8)).hex
                == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" else {
            throw I2PWireError.invalidFormat
        }
        return "SHA-256(\"\") and SHA-256(\"abc\") match the FIPS 180 vectors"
    }

    private static func blake2bKAT() throws -> String {
        // RFC 7693 Appendix B, empty input: the digest begins 786a02f742015903.
        let empty = BLAKE2b.digest([], outLen: 64)
        guard empty.count == 64, Data(empty).hex.hasPrefix("786a02f742015903") else {
            // Name the digest this build actually produced — a pure function
            // failing a fixed vector is otherwise undiagnosable from a bare tag.
            throw SSU2Error.testFailed("empty-input digest \(Data(empty).hex.prefix(16))… diverges from the RFC 7693 vector 786a02f742015903…")
        }
        // Digest length is a parameter: distinct lengths give distinct digests,
        // each with its declared size.
        let short = BLAKE2b.digest([], outLen: 32)
        guard short.count == 32, Data(short) != Data(empty.prefix(32)) else {
            throw I2PWireError.invalidFormat
        }
        // Distinct inputs produce distinct digests.
        guard BLAKE2b.digest(Array("abc".utf8)) != BLAKE2b.digest(Array("abd".utf8)) else {
            throw I2PWireError.invalidFormat
        }
        guard BLAKE2b.digest(Array("abc".utf8), outLen: 32).count == 32 else {
            throw I2PWireError.invalidFormat
        }
        return "RFC 7693 empty-input vector verified; outLen parameterization and input sensitivity checked"
    }

    private static func pureEd25519CrossCheck() throws -> String {
        for _ in 0..<5 {
            let seed = I2PCrypto.generateEd25519Seed()
            let purePublic = I2PCrypto.ed25519PurePublicKey(fromSeed: seed)
            let kitPublic = I2PCrypto.ed25519PublicKey(fromSeed: seed)
            guard purePublic == kitPublic, purePublic.count == 32 else {
                throw I2PWireError.invalidFormat
            }
            let message = I2PCrypto.randomBytes(Int.random(in: 1...4096))
            guard let pureSignature = I2PCrypto.ed25519PureSign(message, seed: seed) else {
                throw I2PWireError.invalidFormat
            }
            guard pureSignature.count == 64 else { throw I2PWireError.invalidFormat }
            guard I2PCrypto.ed25519Verify(signature: pureSignature, message: message, publicKey: kitPublic) else {
                throw I2PWireError.invalidSignature
            }
            let kitSignature = try I2PCrypto.ed25519Sign(message, seed: seed)
            guard I2PCrypto.ed25519PureVerify(signature: kitSignature, message: message, publicKey: purePublic) else {
                throw I2PWireError.invalidSignature
            }
            // Ed25519 is deterministic: the same message/seed signs identically.
            guard I2PCrypto.ed25519PureSign(message, seed: seed) == pureSignature else {
                throw I2PWireError.invalidFormat
            }
            guard !I2PCrypto.ed25519Verify(signature: pureSignature, message: Data("other".utf8), publicKey: kitPublic) else {
                throw I2PWireError.invalidSignature
            }
        }
        return "5 seeds: public keys identical, signatures verify cross-implementation both ways, deterministic"
    }

    // MARK: Modern crypto policy

    /// The legacy-removal regression guard: the algorithm registries carry
    /// exactly the modern cases, so any reintroduction of a legacy enum value
    /// fails here — the Swift equivalent of a static-analyzer rule banning the
    /// deleted types.
    private static func modernCryptoPolicyRegistry() throws -> String {
        try I2PCryptoPolicy.audit()
        // The approved inventory is exactly the modern suite.
        guard I2PCryptoPolicy.approvedSignatureTypes == [.ed25519, .ed25519ph],
              I2PCryptoPolicy.approvedEncryptionTypes == [.x25519, .eciesX25519] else {
            throw I2PWireError.unsupportedAlgorithm
        }
        // Registries are the policy inventory: nothing else can be requested.
        guard I2PSigType.allCases == I2PCryptoPolicy.approvedSignatureTypes,
              I2PEncType.allCases == I2PCryptoPolicy.approvedEncryptionTypes else {
            throw I2PWireError.unsupportedAlgorithm
        }
        // The banned inventory is documentation-only and never intersects the
        // registries (every banned algorithm names a type code outside 7/11 and 4/5).
        let bannedNames = I2PCryptoPolicy.bannedAlgorithms.map { $0.lowercased() }
        guard !I2PCryptoPolicy.bannedAlgorithms.isEmpty,
              Set(bannedNames).count == I2PCryptoPolicy.bannedAlgorithms.count else {
            throw I2PWireError.unsupportedAlgorithm
        }
        return "\(I2PCryptoPolicy.bannedAlgorithms.count) legacy algorithms inventoried and banned; registries pinned to SigType 7/11 and EncType 4/5 with 32-byte keys and 64-byte signatures"
    }

    /// Legacy wire input is rejected at every parse boundary: null certificates
    /// (legacy identity shape), unapproved signature/encryption type codes and
    /// hand-built legacy identities all throw — no silent fallbacks.
    private static func legacyWireRejection() throws -> String {
        // Null certificate (type 0): the legacy identity shape.
        var nullWriter = I2PWriter()
        nullWriter.byte(0)
        nullWriter.short(0)
        guard expectThrow({ var r = I2PReader(nullWriter.data); _ = try I2PCertificate.parse(&r) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        // Unapproved signature and encryption type codes in a key certificate.
        // EncType 0 is deliberately absent from this list: proposal 123 pins a
        // LeaseSet2-era destination's crypto field to 0 ("the encryption type is
        // not specified in the Destination key certificate, it will remain 0"),
        // which is the shape every long-lived mainnet destination publishes — and
        // rejecting it made every real LeaseSet2 unparseable.
        for (sigCode, encCode) in [(UInt16(0), UInt16(4)), (UInt16(1), UInt16(4)),
                                   (UInt16(3), UInt16(4)), (UInt16(7), UInt16(2)),
                                   (UInt16(11), UInt16(6))] {
            var payload = I2PWriter()
            payload.short(sigCode)
            payload.short(encCode)
            var certWriter = I2PWriter()
            certWriter.byte(5)
            certWriter.short(UInt16(payload.data.count))
            certWriter.raw(payload.data)
            guard expectThrow({ var r = I2PReader(certWriter.data); _ = try I2PCertificate.parse(&r) }) else {
                throw I2PCrossValidationError.unexpectedSuccess
            }
        }
        // (SigType 7, EncType 0) parses — and yields no crypto key at all. The
        // signing key is what verifies the entry; a LeaseSet2 carries the real
        // encryption key in its own key list, so the field is never consulted.
        var unusedWriter = I2PWriter()
        unusedWriter.short(I2PSigType.ed25519.rawValue)
        unusedWriter.short(0)
        var unusedCertWriter = I2PWriter()
        unusedCertWriter.byte(5)
        unusedCertWriter.short(UInt16(unusedWriter.data.count))
        unusedCertWriter.raw(unusedWriter.data)
        var unusedReader = I2PReader(unusedCertWriter.data)
        let unusedCert = try I2PCertificate.parse(&unusedReader)
        var unusedReencoded = I2PWriter()
        unusedCert.serialize(into: &unusedReencoded)
        guard unusedCert.sigType == I2PSigType.ed25519,
              unusedCert.encType == nil,
              unusedCert.cryptoPublicKeyLength == 0,
              unusedReencoded.data == unusedCertWriter.data else {
            throw I2PWireError.invalidFormat
        }
        let unusedIdentity = Data(repeating: 0x43, count: 256)
            + Data(repeating: 0x44, count: 128) + unusedCertWriter.data
        var unusedIdentityReader = I2PReader(unusedIdentity)
        let unusedKeys = try I2PKeysAndCert.parse(&unusedIdentityReader)
        guard unusedKeys.encryptionPublicKey.isEmpty,
              unusedKeys.signingPublicKey.count == 32,
              unusedKeys.raw == unusedIdentity else {
            throw I2PWireError.invalidFormat
        }
        // A hand-built keysAndCert with a null certificate is rejected whole —
        // legacy identities cannot enter the netdb.
        let identity = Data(repeating: 0x41, count: 256) + Data(repeating: 0x42, count: 128) + nullWriter.data
        guard expectThrow({ var r = I2PReader(identity); _ = try I2PKeysAndCert.parse(&r) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        // Emission side: a modern identity serializes a type-5 key certificate
        // carrying exactly SigType 7 / EncType 4.
        let (_, seed) = I2PSamples.sampleIdentity()
        let keyPair = I2PCrypto.generateX25519KeyPair()
        let signingKey = I2PCrypto.ed25519PublicKey(fromSeed: seed)
        let destination = I2PDestination(encryptionPublicKey: keyPair.publicKey, signingPublicKey: signingKey)
        var reader = I2PReader(Data(destination.raw.suffix(from: 256 + 128)))
        let certificate = try I2PCertificate.parse(&reader)
        guard certificate.sigType == I2PSigType.ed25519,
              certificate.encType == I2PEncType.x25519 else {
            throw I2PWireError.unsupportedAlgorithm
        }
        return "null certificates, legacy sig type codes and unapproved enc type codes rejected at parse; the LeaseSet2-era unused crypto field (EncType 0) parses beside a modern signing key and yields no crypto key; modern identities emit type-5 key certificates only"
    }

    private static func ed25519phDom2() throws -> String {
        // dom2(prehashed) = "SigEd25519 no Ed25519 collisions" ‖ octet(1) ‖ octet(0).
        let dom = Ed25519Pure.dom2(prehashed: true)
        guard String(decoding: dom.dropLast(2), as: UTF8.self) == "SigEd25519 no Ed25519 collisions",
              dom.suffix(2) == [1, 0] else {
            throw I2PWireError.invalidFormat
        }
        guard Ed25519Pure.dom2(prehashed: false).isEmpty else { throw I2PWireError.invalidFormat }
        // Domain separation: a pre-hashed signature differs from the plain one and
        // neither verifies in the other's domain.
        let seed = I2PCrypto.generateEd25519Seed()
        let publicKey = I2PCrypto.ed25519PurePublicKey(fromSeed: seed)
        let message = I2PCrypto.randomBytes(700)
        guard let phSignature = I2PCrypto.ed25519phSign(message, seed: seed),
              let plainSignature = I2PCrypto.ed25519PureSign(message, seed: seed) else {
            throw I2PWireError.invalidFormat
        }
        guard phSignature != plainSignature else { throw I2PWireError.invalidFormat }
        guard I2PCrypto.ed25519phVerify(signature: phSignature, message: message, publicKey: publicKey) else {
            throw I2PWireError.invalidSignature
        }
        guard !I2PCrypto.ed25519phVerify(signature: plainSignature, message: message, publicKey: publicKey) else {
            throw I2PWireError.invalidSignature
        }
        guard !I2PCrypto.ed25519PureVerify(signature: phSignature, message: message, publicKey: publicKey) else {
            throw I2PWireError.invalidSignature
        }
        // A non-canonical S (top bit set) is rejected in the ph domain.
        var highS = phSignature
        highS[63] |= 0x80
        guard !I2PCrypto.ed25519phVerify(signature: highS, message: message, publicKey: publicKey) else {
            throw I2PWireError.invalidSignature
        }
        return "dom2 context bytes verified; pre-hash and plain domains fully separated; high-S rejected"
    }

    // MARK: Tunnel build records

    private static func sampleRecord(hop: UInt8, pathEnd: Bool, originator: Bool,
                                     more: Bool) -> I2PTunnelBuildRequestRecord {
        I2PTunnelBuildRequestRecord(
            hopNumber: hop,
            receiveTunnelID: 0x0A0B_0C0D,
            nextHopHash: I2PCrypto.randomBytes(32),
            nextTunnelID: 55,
            isMessagePathEnd: pathEnd,
            nextHopIsOriginator: originator,
            hasMoreRecords: more,
            padding: Data(repeating: UInt8(hop &* 7 &+ 1), count: 96))
    }

    private static func buildRecordRoundTrip() throws -> String {
        let record = sampleRecord(hop: 2, pathEnd: false, originator: false, more: true)
        let encoded = record.serialize()
        guard encoded.count == I2PTunnelBuildRequestRecord.plaintextLength else {
            throw I2PWireError.invalidFormat
        }
        let parsed = try I2PTunnelBuildRequestRecord.parse(encoded)
        guard parsed.serialize() == encoded else { throw I2PWireError.invalidFormat }
        guard parsed.receiveTunnelID == 0x0A0B_0C0D, parsed.nextTunnelID == 55,
              parsed.nextHopHash == record.nextHopHash,
              parsed.padding == record.padding else {
            throw I2PWireError.invalidFormat
        }
        return "154-byte short record round trips byte-for-byte; next hop and padding intact"
    }

    private static func buildRecordFlags() throws -> String {
        let combinations: [(end: Bool, originator: Bool, more: Bool)] = [
            (false, false, true), (true, false, false),
            (false, true, false), (true, true, false),
        ]
        for combination in combinations {
            let record = sampleRecord(hop: 0, pathEnd: combination.end,
                                      originator: combination.originator, more: combination.more)
            let parsed = try I2PTunnelBuildRequestRecord.parse(record.serialize())
            guard parsed.isMessagePathEnd == combination.end,
                  parsed.flags == record.flags else {
                throw I2PWireError.invalidFormat
            }
        }
        // The reserved bytes must stay zero.
        let record = sampleRecord(hop: 0, pathEnd: false, originator: false, more: false)
        var bytes = record.serialize()
        bytes[41] = 1
        guard expectThrow({ _ = try I2PTunnelBuildRequestRecord.parse(bytes) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        // Short padding is normalized to the remaining record budget.
        let shortPadded = I2PTunnelBuildRequestRecord(
            hopNumber: 0, receiveTunnelID: 1, nextHopHash: Data(repeating: 0, count: 32),
            nextTunnelID: 2, isMessagePathEnd: false, nextHopIsOriginator: false,
            hasMoreRecords: false, padding: Data(repeating: 0x33, count: 10))
        guard try I2PTunnelBuildRequestRecord.parse(shortPadded.serialize()).padding.count == 96 else {
            throw I2PWireError.invalidFormat
        }
        return "IBGW/OBEP flags and the end marker round trip; reserved bytes enforced zero; padding normalized"
    }

    private static func buildRecordEncryption() throws -> String {
        let hopKey = Curve25519.KeyAgreement.PrivateKey()
        let plaintext = sampleRecord(hop: 0, pathEnd: true, originator: false, more: false).serialize()
        let wire = try I2PTunnelBuildCrypto.encryptRecord(
            plaintext, to: hopKey.publicKey.rawRepresentation, recordIndex: 3)
        guard wire.count == I2PTunnelBuildRequestRecord.wireLength else { throw I2PWireError.invalidFormat }
        guard try I2PTunnelBuildCrypto.decryptRecord(wire, localEncryptionKey: hopKey, recordIndex: 3) == plaintext else {
            throw I2PWireError.invalidFormat
        }
        // Wrong hop key → the record is not addressed to us.
        let otherHop = Curve25519.KeyAgreement.PrivateKey()
        guard expectThrow({ _ = try I2PTunnelBuildCrypto.decryptRecord(wire, localEncryptionKey: otherHop, recordIndex: 3) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        // Tampered wire bytes → MAC failure.
        var tampered = wire
        tampered[100] ^= 0xff
        guard expectThrow({ _ = try I2PTunnelBuildCrypto.decryptRecord(tampered, localEncryptionKey: hopKey, recordIndex: 3) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        // A record addressed to another router hash is not opened.
        let hopHash = I2PCrypto.randomBytes(32)
        let addressed = try I2PTunnelBuildCrypto.encryptRecordWithMaterial(
            plaintext, to: hopKey.publicKey.rawRepresentation, hopHash: hopHash, recordIndex: 0).wire
        guard expectThrow({ _ = try I2PTunnelBuildCrypto.decryptRecordWithMaterial(
            addressed, localEncryptionKey: hopKey,
            localRouterHash: I2PCrypto.randomBytes(32), recordIndex: 0) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        return "\(wire.count)-byte short record box round trips; wrong key, wrong hop and tampered bytes rejected"
    }

    private static func buildReplyRecordRoundTrip() throws -> String {
        let hopKey = Curve25519.KeyAgreement.PrivateKey()
        let encrypted = try I2PTunnelBuildCrypto.encryptRecordWithMaterial(
            sampleRecord(hop: 0, pathEnd: true, originator: false, more: false).serialize(),
            to: hopKey.publicKey.rawRepresentation, hopHash: nil, recordIndex: 3)
        // Return codes across the transient/permanent boundary round trip faithfully.
        for code in [UInt8(0), 1, 29, 30, 255] {
            let wire = try I2PTunnelBuildCrypto.encryptReplyRecord(
                I2PTunnelBuildReplyRecord(receiveTunnelID: 0x1122_3344, returnCode: code),
                material: encrypted.material, recordIndex: 3)
            guard wire.count == I2PTunnelBuildReply.encryptedRecordLength else { throw I2PWireError.invalidFormat }
            let parsed = try I2PTunnelBuildCrypto.decryptReplyRecord(
                wire, material: encrypted.material, recordIndex: 3)
            guard parsed.returnCode == code else {
                throw I2PWireError.invalidFormat
            }
        }
        // Another hop's material and a different record index both fail.
        let otherKey = Curve25519.KeyAgreement.PrivateKey()
        let other = try I2PTunnelBuildCrypto.encryptRecordWithMaterial(
            sampleRecord(hop: 1, pathEnd: false, originator: false, more: true).serialize(),
            to: otherKey.publicKey.rawRepresentation, hopHash: nil, recordIndex: 4)
        let wire = try I2PTunnelBuildCrypto.encryptReplyRecord(
            I2PTunnelBuildReplyRecord(receiveTunnelID: 1, returnCode: 0),
            material: encrypted.material, recordIndex: 3)
        guard expectThrow({ _ = try I2PTunnelBuildCrypto.decryptReplyRecord(
            wire, material: other.material, recordIndex: 3) }),
              expectThrow({ _ = try I2PTunnelBuildCrypto.decryptReplyRecord(
            wire, material: encrypted.material, recordIndex: 4) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        return "reply records round trip across the return-code spectrum; wrong hop and record index rejected"
    }

    // MARK: Tunnel data layering

    /// TunnelData layering per the tunnel spec: the 4/16/1008 payload layout,
    /// AES-256-CBC layers with the IV-key-derived CBC IV, and the per-hop
    /// encrypted-region ladder.
    private static func tunnelDataLayerSpec() throws -> String {
        // The ladder: the outermost layer covers the full body; each deeper
        // layer's region shrinks by a block-aligned 32 bytes.
        let ladder = I2PTunnelDataProcessor.layerLengths(hopCount: 3)
        guard ladder == [1008, 976, 944] else { throw I2PWireError.invalidFormat }
        guard I2PTunnelDataProcessor.layerLengths(hopCount: 1) == [1008] else {
            throw I2PWireError.invalidFormat
        }

        // One layer: AES-256-CBC over the 1008-byte body with the CBC IV
        // derived from the IV field through the IV key.
        let layerKey = I2PCrypto.randomBytes(32)
        let ivKey = I2PCrypto.randomBytes(32)
        let ivField = I2PCrypto.randomBytes(16)
        let content = I2PCrypto.randomBytes(600)
        let body = try I2PTunnelLayerCipher.wrap(content: content, layerKey: layerKey,
                                                 ivField: ivField, ivKey: ivKey)
        guard body.count == I2PTunnelDataPayload.bodySize else { throw I2PWireError.invalidFormat }
        let payload = I2PTunnelDataPayload(tunnelID: 0x00C0_FFEE, iv: ivField, body: body)
        let wire = payload.serialize()
        guard wire.count == 1028, try I2PTunnelDataPayload.parse(wire).serialize() == wire else {
            throw I2PWireError.invalidFormat
        }

        // The CBC IV is exactly AES-ECB(IV_key, IV field) XOR IV field, and
        // manual CBC decryption with it recovers the padded content byte-for-byte.
        let derived = try I2PTunnelLayerCipher.deriveCBCIV(ivField: ivField, ivKey: ivKey)
        let expectedPlain = try I2PTunnelLayerCipher.padded(content)
        guard I2PAESCBC.decrypt(body, key: layerKey, iv: derived) == expectedPlain else {
            throw I2PWireError.invalidFormat
        }
        guard try I2PTunnelLayerCipher.unwrap(body: body, layerKey: layerKey,
                                              ivField: ivField, ivKey: ivKey) == content else {
            throw I2PWireError.invalidFormat
        }
        // A wrong IV key yields different plaintext: the IV-key transform is load-bearing.
        let otherKey = I2PCrypto.randomBytes(32)
        let wrongPlain = try? I2PTunnelLayerCipher.unwrap(body: body, layerKey: layerKey,
                                                          ivField: ivField, ivKey: otherKey)
        guard wrongPlain != content else { throw I2PWireError.invalidFormat }
        return "spec layout (4+16+1008) byte-for-byte; AES-256-CBC layer with ECB-keyed IV chaining verified; 3-hop ladder 1008/976/944"
    }

    /// Hop processing per the tunnel spec end-to-end: a 3-hop layered pipeline
    /// where every hop forwards the next hop's ciphertext region byte-for-byte
    /// (re-randomizing only the region its own key never covered) and the final
    /// hop delivers the original I2NP message with its gateway ID intact.
    private static func tunnelHopLayerSpec() throws -> String {
        let gatewayID: UInt32 = 0x1122_3344
        let receiveIDs = (0..<3).map { _ in UInt32.random(in: 1...UInt32.max) }
        let layerKeys = (0..<3).map { _ in I2PCrypto.randomBytes(32) }
        let ivKeys = (0..<3).map { _ in I2PCrypto.randomBytes(32) }
        let ladder = I2PTunnelDataProcessor.layerLengths(hopCount: 3)

        var hops: [I2PTunnelHop] = []
        for index in 0..<3 {
            hops.append(I2PTunnelHop(
                routerHash: I2PCrypto.randomBytes(32),
                receiveTunnelID: receiveIDs[index],
                nextTunnelID: index < 2 ? receiveIDs[index + 1] : 0x0BAD_F00D,
                isTunnelEndpoint: index == 2))
        }
        let tunnel = I2PTunnel(direction: .outbound, hops: hops,
                               gatewayTunnelID: receiveIDs[0], endpointTunnelID: receiveIDs[2],
                               layerKeys: layerKeys, ivKeys: ivKeys,
                               createdAt: Date(), expiresAt: Date().addingTimeInterval(600),
                               buildLatency: nil)
        let inner = I2NPMessage(type: .dataMessage, payload: I2PCrypto.randomBytes(280))
        // The message-path end delivers its payload under the gateway ID the
        // originator addressed, which is independent of the tunnel's own
        // gateway hop ID — pass it explicitly rather than let preprocess
        // default to the gateway tunnel ID.
        var current = try I2PTunnelDataProcessor.preprocess(inner.serialize(), via: tunnel,
                                                            gatewayID: gatewayID)
        guard current.tunnelID == receiveIDs[0],
              current.body.count == I2PTunnelDataPayload.bodySize else {
            throw I2PWireError.invalidFormat
        }

        for index in 0..<3 {
            let participant = I2PTunnelParticipant(
                localRouterHash: tunnel.hops[index].routerHash,
                localEncryptionKey: Curve25519.KeyAgreement.PrivateKey(),
                transport: TunnelLayerSpecTransport())
            participant.testInjectHopState(I2PTunnelHopState(
                receiveTunnelID: tunnel.hops[index].receiveTunnelID,
                nextHopHash: index < 2 ? tunnel.hops[index + 1].routerHash : I2PCrypto.randomBytes(32),
                nextTunnelID: tunnel.hops[index].nextTunnelID,
                isMessagePathEnd: index == 2,
                layerKey: layerKeys[index], ivKey: ivKeys[index], registeredAt: Date()))

            // The inbound ciphertext region decrypts with this hop's key and the
            // IV-key-chained CBC IV to the framed next-hop message.
            let regionLength = ladder[index]
            let plain = I2PAESCBC.decrypt(Data(current.body.prefix(regionLength)),
                                          key: layerKeys[index],
                                          iv: try I2PTunnelLayerCipher.deriveCBCIV(ivField: current.iv,
                                                                               ivKey: ivKeys[index]))
            let action = try participant.processTunnelData(current)
            if index < 2 {
                guard case .forward(_, let forwarded) = action else { throw I2PWireError.invalidFormat }
                // Routing: addressed to the next hop with its tunnel ID, full 1008-byte body.
                guard forwarded.tunnelID == tunnel.hops[index].nextTunnelID,
                      forwarded.body.count == I2PTunnelDataPayload.bodySize else {
                    throw I2PWireError.invalidFormat
                }
                // The frame inside this layer: [BE16 length][nextTunnelID (4)][nextIV (16)],
                // with the length exactly 20 + the next hop's covered region.
                let length = (Int(plain[0]) << 8) | Int(plain[1])
                guard length == 20 + ladder[index + 1] else { throw I2PWireError.invalidFormat }
                guard Data(plain[2..<6]) == I2PTunnelLayerCipher.tunnelIDBytes(tunnel.hops[index + 1].receiveTunnelID) else {
                    throw I2PWireError.invalidFormat
                }
                // The forwarded region is byte-identical to this hop's decrypted
                // ciphertext bytes — the next hop decrypts the very same bytes.
                guard forwarded.body.prefix(ladder[index + 1]) == Data(plain[22..<(22 + ladder[index + 1])]) else {
                    throw I2PWireError.invalidFormat
                }
                current = forwarded
            } else {
                guard case .deliverGateway(_, let gatewayPayload) = action else { throw I2PWireError.invalidFormat }
                // The delivered payload is [gatewayID][the original I2NP bytes].
                guard gatewayPayload == I2PTunnelGatewayPayload(gatewayID: gatewayID,
                                                                message: inner.serialize()).serialize() else {
                    throw I2PWireError.invalidFormat
                }
            }
        }
        return "3-hop pipeline: ciphertext regions forwarded byte-for-byte, uncovered regions re-randomized, gateway payload delivered byte-exact"
    }

    /// No-op build transport for pipeline participants under test.
    private final class TunnelLayerSpecTransport: I2PTunnelBuildTransport {
        func sendBuild(_ message: I2PTunnelBuildMessage, to routerHash: Data) {}
        func sendBuildReply(_ body: Data, to routerHash: Data) {}
    }

    // MARK: NetDB

    private static func netdbUnsignedRejection() async throws -> String {
        let netdb = try makeNetDB()
        let info = try I2PSamples.sampleRouterInfo()
        let encoded = info.serialize()
        let unsigned = encoded.prefix(encoded.count - 64) + Data(repeating: 0, count: 64)
        guard await expectThrowAsync({ try await netdb.ingestRouterInfo(unsigned) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        var tampered = encoded
        tampered[400] ^= 0xff
        guard await expectThrowAsync({ try await netdb.ingestRouterInfo(tampered) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        try await netdb.ingestRouterInfo(encoded)
        guard await netdb.hasEntry(info.identity.hash) else { throw I2PWireError.invalidFormat }
        // The same holds for LeaseSets.
        let leaseSet = try I2PSamples.sampleLeaseSet()
        let leaseSetBytes = leaseSet.serialize()
        let unsignedLeaseSet = leaseSetBytes.prefix(leaseSetBytes.count - 64) + Data(repeating: 0, count: 64)
        guard await expectThrowAsync({ try await netdb.ingestLeaseSet(unsignedLeaseSet) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        try await netdb.ingestLeaseSet(leaseSetBytes)
        guard await netdb.hasEntry(leaseSet.destination.hash) else { throw I2PWireError.invalidFormat }
        return "unsigned and tampered RouterInfos/LeaseSets rejected at ingest; verified entries accepted"
    }

    private static func netdbLoopbackLookup() async throws -> String {
        let hub = I2PNetDBLoopbackHub()
        let hashA = I2PCrypto.randomBytes(32)
        let hashB = I2PCrypto.randomBytes(32)
        let storageA = try I2PNetDBStorage(
            directory: FileManager.default.temporaryDirectory
                .appendingPathComponent("i2p-cv-lookup-a", isDirectory: true))
        let storageB = try I2PNetDBStorage(
            directory: FileManager.default.temporaryDirectory
                .appendingPathComponent("i2p-cv-lookup-b", isDirectory: true))
        let nodeA = I2PNetworkDatabase(localRouterHash: hashA,
                                       transport: I2PNetDBLoopbackTransport(hub: hub),
                                       storage: storageA)
        let nodeB = I2PNetworkDatabase(localRouterHash: hashB,
                                       transport: I2PNetDBLoopbackTransport(hub: hub),
                                       storage: storageB)
        hub.add(nodeA, at: hashA)
        hub.add(nodeB, at: hashB)

        // B holds a RouterInfo; A asks for it through the netdb messaging path.
        let info = try I2PSamples.sampleRouterInfo()
        try await nodeB.ingestRouterInfo(info.serialize())
        await nodeA.registerFloodfill(hashB)
        let found = await nodeA.lookupRouterInfo(info.identity.hash, timeoutPerRound: 3, maxRounds: 2)
        guard let found, found.identity.hash == info.identity.hash,
              found.addresses.count == 1, found.options["netid"] == "2" else {
            throw I2PWireError.invalidFormat
        }
        return "DatabaseLookup answered by the holding node; verified entry returned over the transport"
    }

    private static func netdbFloodfillSelection() async throws -> String {
        let netdb = try makeNetDB()
        var entries: [(hash: Data, isFloodfill: Bool)] = []
        for index in 0..<5 {
            let (identity, seed) = I2PSamples.sampleIdentity()
            let caps = index < 4 ? "f" : ""
            var info = I2PRouterInfo(
                identity: identity,
                published: Date(),
                addresses: [],
                options: caps.isEmpty ? ["netid": "2"] : ["caps": caps, "netid": "2"])
            try info.sign(withSeed: seed)
            try await netdb.ingestRouterInfo(info.serialize())
            entries.append((info.identity.hash, !caps.isEmpty))
        }
        let target = I2PCrypto.randomBytes(32)
        let selected = await netdb.selectFloodfills(for: target, count: 10)
        guard !selected.isEmpty else { throw I2PWireError.invalidFormat }
        // Only floodfill-capped routers are selected.
        for hash in selected {
            guard let entry = entries.first(where: { $0.hash == hash }), entry.isFloodfill else {
                throw I2PWireError.invalidFormat
            }
            guard await netdb.isFloodfill(hash) else { throw I2PWireError.invalidFormat }
        }
        // Selection is XOR-ordered: closest first.
        for index in 1..<selected.count {
            guard I2PNetworkDatabase.isCloser(selected[index - 1], than: selected[index], to: target) else {
                throw I2PWireError.invalidFormat
            }
        }
        return "\(selected.count) floodfills selected in XOR-distance order; non-floodfill router excluded"
    }

    private static func netdbExpiryLifetime() async throws -> String {
        let netdb = try makeNetDB()
        let info = try I2PSamples.sampleRouterInfo()
        let ingestedAt = Date()
        try await netdb.ingestRouterInfo(info.serialize())
        let expiry = await netdb.entryExpiration(info.identity.hash)
        guard let expiry else { throw I2PWireError.invalidFormat }
        let observed = expiry.timeIntervalSince(ingestedAt)
        guard abs(observed - I2PNetworkDatabase.routerInfoLifetime) < 5 else {
            throw I2PWireError.invalidFormat
        }
        // The entry is valid up to the expiry boundary and rejected after it.
        let removedBefore = await netdb.pruneExpired(now: expiry.addingTimeInterval(-1))
        guard removedBefore == 0, await netdb.hasEntry(info.identity.hash) else {
            throw I2PWireError.invalidFormat
        }
        let removedAfter = await netdb.pruneExpired(now: expiry)
        guard removedAfter == 1, !(await netdb.hasEntry(info.identity.hash)) else {
            throw I2PWireError.invalidFormat
        }
        return "entry lifetime = routerInfoLifetime (\(Int(I2PNetworkDatabase.routerInfoLifetime))s) from ingest; prune drops it exactly at expiry"
    }

    // MARK: NetDB — SU3 reseed container

    /// Builds a spec-shaped SU3 container: the 40-byte header, version, signer
    /// ID, content, then an Ed25519 signature over the whole prefix (header
    /// included), which is what SU3File signs.
    private static func makeSU3Container(signerID: String, content: Data, seed: Data,
                                         signatureType: I2PSU3SignatureType,
                                         version: String = "0.9.62") throws -> Data {
        guard signatureType == .ed25519 else {
            throw I2PWireError.unsupportedAlgorithm
        }
        let versionBytes = Array(version.utf8)
        let signerBytes = Array(signerID.utf8)
        let versionLength = max(16, versionBytes.count)
        guard versionLength <= 255, !signerBytes.isEmpty, signerBytes.count <= 255 else {
            throw I2PWireError.invalidFormat
        }
        var writer = I2PWriter()
        writer.raw(Data(Array("I2Psu3".utf8)))        // magic
        writer.byte(0)                                // unused
        writer.byte(0)                                // file format version
        writer.short(signatureType.rawValue)          // signature type
        writer.short(UInt16(signatureType.signatureLength))
        writer.byte(0)                                // unused
        writer.byte(UInt8(versionLength))
        writer.byte(0)                                // unused
        writer.byte(UInt8(signerBytes.count))
        writer.long(UInt64(content.count))            // content length
        writer.byte(0)                                // unused
        writer.byte(0)                                // file type: zip
        writer.byte(0)                                // unused
        writer.byte(3)                                // content type: reseed data
        writer.raw(Data(repeating: 0, count: 12))     // reserved
        writer.raw(Data(versionBytes))
        if versionBytes.count < versionLength {
            writer.raw(Data(repeating: 0, count: versionLength - versionBytes.count))
        }
        writer.raw(Data(signerBytes))
        writer.raw(content)
        let region = writer.data
        let signature = try I2PCrypto.ed25519Sign(signatureType.digest(region), seed: seed)
        writer.raw(signature)
        return writer.data
    }

    /// True when the container is rejected, either at parse or at verification.
    private static func su3Rejected(_ data: Data, trust: I2PSU3TrustStore) -> Bool {
        guard let parsed = try? I2PSU3Container.parse(data) else { return true }
        do {
            try parsed.verify(using: trust)
            return false
        } catch {
            return true
        }
    }

    private static func su3ContainerSignature() throws -> String {
        let seed = I2PCrypto.generateEd25519Seed()
        let publicKey = I2PCrypto.ed25519PublicKey(fromSeed: seed)
        let signerID = "cross-validation_at_mail.i2p"
        let content = Data((0..<517).map { UInt8($0 & 0xff) })
        let container = try makeSU3Container(signerID: signerID, content: content,
                                             seed: seed, signatureType: .ed25519)
        let trust = I2PSU3TrustStore(signers: [
            I2PSU3Signer(id: signerID, keyMaterial: .ed25519PublicKey(publicKey))
        ])

        let parsed = try I2PSU3Container.parse(container)
        guard parsed.signerID == signerID,
              parsed.version == "0.9.62",
              parsed.fileType == 0,
              parsed.contentType == 3,
              parsed.signatureType == .ed25519,
              parsed.content == content,
              parsed.signature.count == 64,
              parsed.signedRegion.count == container.count - 64 else {
            throw I2PWireError.invalidFormat
        }
        try parsed.verify(using: trust)

        // The signature covers the header, the signer ID and the content: a
        // single flipped byte in any of them must reject the container.
        var tamperedVersion = container
        tamperedVersion[I2PSU3Container.headerLength + 1] ^= 0x01
        var tamperedContent = container
        tamperedContent[container.count - 65] ^= 0x01
        var tamperedSignature = container
        tamperedSignature[container.count - 1] ^= 0x01
        guard su3Rejected(tamperedVersion, trust: trust),
              su3Rejected(tamperedContent, trust: trust),
              su3Rejected(tamperedSignature, trust: trust) else {
            throw I2PWireError.invalidSignature
        }

        // Structural rejections: magic, declared signature length, truncation
        // (named as a truncated transfer so the reseed retries it) and data
        // trailing the signature.
        var badMagic = container
        badMagic[0] = 0x00
        guard (try? I2PSU3Container.parse(badMagic)) == nil else {
            throw I2PWireError.invalidFormat
        }
        var badSignatureLength = container
        badSignatureLength[11] = 0x20 // 32 bytes declared for a 64-byte type
        guard (try? I2PSU3Container.parse(badSignatureLength)) == nil else {
            throw I2PWireError.invalidFormat
        }
        let truncated = Data(container.dropLast())
        do {
            _ = try I2PSU3Container.parse(truncated)
            throw I2PWireError.invalidFormat
        } catch let error as I2PSU3Error {
            guard String(describing: error).contains("truncated transfer") else {
                throw I2PWireError.invalidFormat
            }
        }
        guard (try? I2PSU3Container.parse(container + Data([0x00]))) == nil else {
            throw I2PWireError.invalidFormat
        }

        return "\(container.count)-byte container: header field-exact, 64-byte Ed25519 signature verified over the \(parsed.signedRegion.count)-byte prefix; header, content, signature, magic, length, truncation and trailing-data tamps rejected"
    }

    private static func su3SignerTrust() throws -> String {
        let bundled = I2PSU3TrustStore.bundled
        guard !bundled.signerIDs.isEmpty else {
            throw I2PCrossValidationError.failed(
                "no bundled reseed certificates found in the app bundle (Resources/reseed-certs)")
        }
        // The certificate files are named in the "_at_" form; the header of a
        // real container names the same signer in mail form.
        guard bundled.signer(id: "reseed@diva.exchange") != nil else {
            throw I2PCrossValidationError.failed(
                "bundled reseed signer set is missing reseed@diva.exchange (found \(bundled.signerIDs.count) signers)")
        }
        // PEM bodies decode to DER; raw DER passes through.
        let pem = "-----BEGIN CERTIFICATE-----\n"
            + Data(repeating: 0x30, count: 40).base64EncodedString()
            + "\n-----END CERTIFICATE-----\n"
        guard I2PSU3BundledReseedSigners.derBytes(from: Data(pem.utf8))?.first == 0x30 else {
            throw I2PWireError.invalidFormat
        }

        // A genuinely signed container whose signer we do not trust must fail
        // closed even though the signature itself is good.
        let seed = I2PCrypto.generateEd25519Seed()
        let publicKey = I2PCrypto.ed25519PublicKey(fromSeed: seed)
        let signerID = "unbundled-signer_at_mail.i2p"
        let container = try makeSU3Container(signerID: signerID,
                                             content: Data("reseed-archive".utf8),
                                             seed: seed, signatureType: .ed25519)
        let parsed = try I2PSU3Container.parse(container)
        let ownTrust = I2PSU3TrustStore(signers: [
            I2PSU3Signer(id: signerID, keyMaterial: .ed25519PublicKey(publicKey))
        ])
        try parsed.verify(using: ownTrust)
        do {
            try parsed.verify(using: bundled)
            throw I2PCrossValidationError.failed(
                "an unbundled SU3 signer verified against the bundled trust store")
        } catch is I2PSU3Error {
            // expected: unknown signer
        }
        // Known signer ID, wrong key: the signature must reject.
        let wrongKey = I2PCrypto.ed25519PublicKey(fromSeed: I2PCrypto.generateEd25519Seed())
        let wrongTrust = I2PSU3TrustStore(signers: [
            I2PSU3Signer(id: signerID, keyMaterial: .ed25519PublicKey(wrongKey))
        ])
        guard su3Rejected(container, trust: wrongTrust),
              su3Rejected(container, trust: I2PSU3TrustStore(signers: [])) else {
            throw I2PWireError.invalidSignature
        }

        return "\(bundled.signerIDs.count) bundled reseed signers loaded from Resources/reseed-certs; mail-form signer IDs resolve; unknown signer and wrong-key signatures rejected"
    }

    // MARK: Garlic

    /// The ECIES-X25519 three-section envelope and tag-based continuation
    /// round-trip the clove-set payload blocks byte-for-byte.
    private static func garlicEnvelopeRoundTrip() throws -> String {
        let aliceKey = Curve25519.KeyAgreement.PrivateKey()
        let alice = I2PGarlicInboundSessionManager(localKey: aliceKey)
        let bob = I2PGarlicSession(peerPublicKey: aliceKey.publicKey, tagsPerHandshake: 4)

        // First send: ECIES-X25519 three-section new-session envelope carrying
        // the tag-set seed in its Options block.
        let tagSet = bob.prepareHandshakeTags()
        guard let tagSet else { throw I2PWireError.invalidFormat }
        let firstSet = try sampleCloveSet(messageID: 0x00CA_FE01,
                                          tagSetSeed: tagSet.seed, tagCount: tagSet.count)
        let firstBytes = try firstSet.serialize()
        let wrapped1 = try bob.wrapCloveSet(firstBytes)
        guard wrapped1 != firstBytes else { throw I2PWireError.invalidFormat }

        // Section layout: ephemeral (32) + static (32 plaintext + 16 tag = 48)
        // + payload section; the first 32 bytes are a valid X25519 curve point.
        guard wrapped1.count > 32 + 48 + 16 else { throw I2PWireError.invalidFormat }
        _ = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data(wrapped1.prefix(32)))

        let unwrapped1 = try alice.unwrapPayload(wrapped1, messageID: firstSet.messageID)
        guard try unwrapped1.serialize() == firstBytes else { throw I2PWireError.invalidFormat }
        // The Options block registered the tag set: 4 ratcheted tags now bound.
        guard alice.tagManager.count == 4 else { throw I2PWireError.invalidFormat }

        // Second send: tag-based continuation with the first ratcheted tag.
        let secondBytes = try sampleCloveSet(messageID: 0x00CA_FE02).serialize()
        let wrapped2 = try bob.wrapCloveSet(secondBytes)
        // Tag framing: [tag (32)][ciphertext ‖ 16-byte tag].
        guard wrapped2.count == 32 + secondBytes.count + 16 else { throw I2PWireError.invalidFormat }
        let unwrapped2 = try alice.unwrapPayload(wrapped2, messageID: 0x00CA_FE02)
        guard try unwrapped2.serialize() == secondBytes else { throw I2PWireError.invalidFormat }
        return "three-section new-session envelope round-trips byte-for-byte (tag set in its Options block); tag-based continuation round-trips"
    }

    private static func garlicCloveRoundTrip() throws -> String {
        let instructions = I2PDeliveryInstructions(mode: .tunnel, tunnelID: 0x0000_55AA,
                                                   routerHash: I2PCrypto.randomBytes(32))
        let message = I2NPMessage(type: .deliveryStatus, messageID: 42,
                                  payload: Data("clove payload".utf8))
        let clove = I2PGarlicClove(deliveryInstructions: instructions, message: message)
        let blockBody = try clove.serialize()
        let parsed = try I2PGarlicClove.parse(blockBody)
        guard parsed.deliveryInstructions.tunnelID == 0x0000_55AA,
              parsed.message.messageID == 42 else {
            throw I2PWireError.invalidFormat
        }
        guard try parsed.serialize() == blockBody else { throw I2PWireError.invalidFormat }
        return "cloves (garlic flag-byte delivery instructions + I2NP message) round-trip byte-for-byte"
    }

    /// Tag sets ratchet per-tag keys that are strictly single-use; replayed and
    /// tampered payloads rejected; the Options-block tag delivery round trips.
    private static func garlicTagReplay() throws -> String {
        // Single-use tags at the manager level, registered from a tag-set seed.
        let manager = I2PGarlicInboundTagManager()
        let seed = I2PCrypto.randomBytes(I2PGarlicCrypto.tagLength)
        manager.register(tagSetSeed: seed, count: 2)
        let chain = I2PGarlicCrypto.tagSet(seed: seed, count: 2)
        guard manager.consume(chain[0].tag) == chain[0].key else { throw I2PWireError.invalidFormat }
        guard manager.consume(chain[0].tag) == nil else { throw I2PWireError.invalidFormat } // replayed tag rejected
        guard manager.consume(chain[1].tag) == chain[1].key else { throw I2PWireError.invalidFormat }

        // End-to-end: a replayed tag-based payload fails to decrypt.
        let aliceKey = Curve25519.KeyAgreement.PrivateKey()
        let alice = I2PGarlicInboundSessionManager(localKey: aliceKey)
        let bob = I2PGarlicSession(peerPublicKey: aliceKey.publicKey, tagsPerHandshake: 4)
        let handshake = bob.prepareHandshakeTags()
        guard let handshake else { throw I2PWireError.invalidFormat }
        _ = try alice.unwrapPayload(
            try bob.wrapCloveSet(try sampleCloveSet(messageID: 1,
                                                    tagSetSeed: handshake.seed,
                                                    tagCount: handshake.count).serialize()))
        let tagBytes = try sampleCloveSet(messageID: 2).serialize()
        let tagged = try bob.wrapCloveSet(tagBytes)
        guard try alice.unwrapPayload(tagged).serialize() == tagBytes else { throw I2PWireError.invalidFormat }
        guard expectThrow({ _ = try alice.unwrapPayload(tagged) }) else {
            throw I2PCrossValidationError.unexpectedSuccess // the tag was consumed
        }
        // A tampered payload is rejected too.
        var tampered = tagged
        tampered[tampered.count - 3] ^= 0xff
        guard expectThrow({ _ = try alice.unwrapPayload(tampered) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        // The Options-block tag delivery round trips; malformed bodies rejected.
        let encoded = try I2PGarlicBlock.encode([.options(tagSetSeed: seed, tagCount: 2)])
        guard case .options(let seedBack, let countBack) = try I2PGarlicBlock.decode(encoded)[0],
              seedBack == seed, countBack == 2 else {
            throw I2PWireError.invalidFormat
        }
        guard expectThrow({ _ = try I2PGarlicBlock.encode([.options(tagSetSeed: Data(repeating: 0, count: 8), tagCount: 2)]) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        return "ratcheted per-tag keys strictly single-use; replayed and tampered payloads rejected; Options-block delivery round trips"
    }

    private static func garlicHKDFChecks() throws -> String {
        // The spec protocol context: every garlic HKDF binds its output to the
        // ECIES-X25519 protocol name, and the tag length is 32 bytes.
        guard I2PGarlicCrypto.protocolName == "ECIES-X25519-AEAD-RATCHET",
              I2PGarlicCrypto.infoStaticSection == Data("ECIES-X25519-AEAD-RATCHET".utf8),
              I2PGarlicCrypto.infoPayloadSection == I2PGarlicCrypto.infoStaticSection,
              I2PGarlicCrypto.tagLength == 32 else {
            throw I2PWireError.invalidFormat
        }
        // Section key schedule cross-check: the static section decrypts (with
        // the KDF-derived key) to exactly the sender's static public key.
        let aliceKey = Curve25519.KeyAgreement.PrivateKey()
        let senderStatic = Curve25519.KeyAgreement.PrivateKey()
        let blocks = I2PCrypto.randomBytes(200)
        let envelope = try I2PGarlicCrypto.sealNewSession(blocks,
                                                          peerStatic: aliceKey.publicKey,
                                                          senderStatic: senderStatic)
        let ephemeralPublic = Data(envelope.prefix(32))
        let h0 = I2PCrypto.sha256(Data(I2PGarlicCrypto.protocolName.utf8))
        // `es` is the ephemeral × receiver-static agreement (the sender static
        // key does not enter this section's KDF); derive it from the receiver's
        // side, exactly as the opening side does.
        let es = try aliceKey.sharedSecretFromKeyAgreement(
            with: Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephemeralPublic))
        let temp = Data(HMAC<SHA256>.authenticationCode(for: es.withUnsafeBytes { Data($0) },
                                                        using: SymmetricKey(data: h0)))
        let ck1 = Data(HMAC<SHA256>.authenticationCode(for: Data([0x01]),
                                                       using: SymmetricKey(data: temp)))
        let staticSectionKey = Data(HMAC<SHA256>.authenticationCode(for: ck1,
                                                                    using: SymmetricKey(data: temp)))
        let staticPlain = try I2PCrypto.chacha20Poly1305Open(
            key: staticSectionKey,
            nonce: I2PGarlicCrypto.zeroNonce,
            ciphertextAndTag: envelope.subdata(in: 32..<80))
        guard staticPlain == senderStatic.publicKey.rawRepresentation else {
            throw I2PWireError.invalidFormat
        }
        // Tag-set ratchets: deterministic from the seed, seed-sensitive, and
        // each tag is 32 bytes with its own distinct ratcheted key.
        let seed = I2PCrypto.randomBytes(32)
        let set = I2PGarlicCrypto.tagSet(seed: seed, count: 3)
        guard set.count == 3, set.allSatisfy({ $0.tag.count == 32 && $0.key.count == 32 }) else {
            throw I2PWireError.invalidFormat
        }
        guard set.map(\.tag) == I2PGarlicCrypto.tagSet(seed: seed, count: 3).map(\.tag),
              set.map(\.key) == I2PGarlicCrypto.tagSet(seed: seed, count: 3).map(\.key) else {
            throw I2PWireError.invalidFormat
        }
        guard set.map(\.tag) != I2PGarlicCrypto.tagSet(seed: I2PCrypto.randomBytes(32), count: 3).map(\.tag) else {
            throw I2PWireError.invalidFormat
        }
        guard Set(set.map(\.tag.hex)).count == 3 else { throw I2PWireError.invalidFormat }
        return "ECIES-X25519 info strings pinned to the spec protocol context; section keys derive per the spec schedule; tag-set ratchets deterministic and seed-bound"
    }

    // MARK: Garlic payload blocks + tag ratchet

    /// Typed payload blocks per the ECIES-X25519 spec: DateTime (0), I2NP (1),
    /// Options (3), Termination (4) and Padding (254) frame as
    /// [type (1)][length (2 BE)][body]; unknown types are skipped on decode.
    private static func garlicBlocksRoundTrip() throws -> String {
        let date = Date(timeIntervalSince1970: 1_800_000_123)
        let delivery = I2PDeliveryInstructions(mode: .tunnel, tunnelID: 0x0102_0304,
                                               routerHash: I2PCrypto.randomBytes(32))
        let message = I2NPMessage(type: .dataMessage, payload: I2PCrypto.randomBytes(60))
        let seed = I2PCrypto.randomBytes(32)
        let blocks: [I2PGarlicBlock] = [
            .dateTime(date),
            .i2np(deliveryInstructions: delivery, message: message),
            .options(tagSetSeed: seed, tagCount: 4),
            .termination(reason: 3),
            .padding(I2PCrypto.randomBytes(11)),
        ]
        let encoded = try I2PGarlicBlock.encode(blocks)
        let decoded = try I2PGarlicBlock.decode(encoded)
        guard decoded.count == 5 else { throw I2PWireError.invalidFormat }
        guard try I2PGarlicBlock.encode(decoded) == encoded else { throw I2PWireError.invalidFormat }
        guard case .dateTime(let dateBack) = decoded[0],
              abs(dateBack.timeIntervalSince1970.rounded() - date.timeIntervalSince1970.rounded()) < 1 else {
            throw I2PWireError.invalidFormat
        }
        guard case .i2np(let deliveryBack, let messageBack) = decoded[1],
              deliveryBack.mode == .tunnel, deliveryBack.tunnelID == 0x0102_0304,
              messageBack.serialize() == message.serialize() else {
            throw I2PWireError.invalidFormat
        }
        guard case .options(let seedBack, let countBack) = decoded[2],
              seedBack == seed, countBack == 4 else {
            throw I2PWireError.invalidFormat
        }
        guard case .termination(let reason) = decoded[3], reason == 3 else {
            throw I2PWireError.invalidFormat
        }
        // Unknown block types are skipped per spec.
        var withUnknown = I2PWriter()
        withUnknown.byte(0x7A)
        withUnknown.short(2)
        withUnknown.raw(Data([0xAA, 0xBB]))
        withUnknown.raw(encoded)
        guard try I2PGarlicBlock.decode(withUnknown.data).count == 5 else {
            throw I2PWireError.invalidFormat
        }
        return "5 block types round-trip byte-for-byte; unknown types skipped per spec"
    }

    /// Tag-set ratchet per the spec: the chain advances per tag, every tag
    /// binds to its own ratcheted key, and an exhausted set forces a fresh
    /// new-session handshake carrying a new seed.
    private static func garlicTagRatchetSpec() throws -> String {
        let aliceKey = Curve25519.KeyAgreement.PrivateKey()
        let alice = I2PGarlicInboundSessionManager(localKey: aliceKey)
        let bob = I2PGarlicSession(peerPublicKey: aliceKey.publicKey, tagsPerHandshake: 4)

        // First handshake: the tag-set seed rides in the Options block.
        guard let firstSet = bob.prepareHandshakeTags(), firstSet.seed.count == 32 else {
            throw I2PGarlicError.invalidPayload
        }
        let firstEnvelope = try bob.wrapCloveSet(
            try sampleCloveSet(messageID: 0x00D1_0001,
                               tagSetSeed: firstSet.seed, tagCount: firstSet.count).serialize())
        _ = try alice.unwrapPayload(firstEnvelope)
        guard alice.tagManager.count == 4 else { throw I2PWireError.invalidFormat }

        // Four tag-based sends consume the set in order; each decrypts with
        // its own ratcheted key.
        for index in 0..<4 {
            let messageID = UInt32(index + 0x00D1_0010)
            let envelope = try bob.wrapCloveSet(
                try sampleCloveSet(messageID: messageID).serialize())
            // The clove set's message ID rides the wrapping GarlicMessage's I2NP
            // header, so the receiver is told it rather than parsing it from the
            // payload blocks.
            let set = try alice.unwrapPayload(envelope, messageID: messageID)
            guard set.messageID == messageID else {
                throw I2PWireError.invalidFormat
            }
        }
        guard alice.tagManager.count == 0, bob.isEstablished == false else {
            throw I2PWireError.invalidFormat
        }

        // The exhausted set forces a new handshake: the next envelope carries
        // a FRESH seed and the receiver registers its new ratchet chain.
        guard let secondSet = bob.prepareHandshakeTags() else { throw I2PGarlicError.invalidPayload }
        guard secondSet.seed != firstSet.seed else { throw I2PWireError.invalidFormat }
        let secondEnvelope = try bob.wrapCloveSet(
            try sampleCloveSet(messageID: 0x00D1_0020,
                               tagSetSeed: secondSet.seed, tagCount: secondSet.count).serialize())
        let set = try alice.unwrapPayload(secondEnvelope)
        guard alice.tagManager.count == 4, set.tagSetSeed == secondSet.seed else {
            throw I2PWireError.invalidFormat
        }

        // Tag-based continuation resumes on the new ratchet chain.
        let resumed = try bob.wrapCloveSet(try sampleCloveSet(messageID: 0x00D1_0021).serialize())
        _ = try alice.unwrapPayload(resumed)
        guard alice.tagManager.count == 3 else { throw I2PWireError.invalidFormat }
        return "tag chain advances per tag over 4 single-use sends; exhausted sets re-handshake with a fresh seed and the ratchet resumes"
    }

    // MARK: SSU2

    private static func ssu2HeaderRoundTrip() throws -> String {
        let dst = SSU2PacketHeader.randomConnectionID()
        let src = SSU2PacketHeader.randomConnectionID(distinctFrom: dst)
        let header = SSU2PacketHeader(destinationConnectionID: dst, packetNumber: 42,
                                      type: .sessionRequest, sourceConnectionID: src,
                                      token: Data(repeating: 0x5A, count: 8))
        let bytes = header.serialize()
        guard bytes.count == 32 else { throw SSU2Error.invalidHeader }
        let parsed = try SSU2PacketHeader.parse(bytes)
        guard parsed.serialize() == bytes,
              parsed.destinationConnectionID == dst, parsed.packetNumber == 42,
              parsed.sourceConnectionID == src, parsed.token == Data(repeating: 0x5A, count: 8) else {
            throw SSU2Error.invalidHeader
        }
        // Version and network ID validation. Long-form versions are 2 (classical)
        // and 3/4 (the ML-KEM hybrids); anything else must fail closed.
        var bad = bytes
        bad[13] = 5
        guard expectThrow({ _ = try SSU2PacketHeader.parse(Data(bad)) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        var badNet = bytes
        badNet[14] = 9
        guard expectThrow({ _ = try SSU2PacketHeader.parse(Data(badNet)) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        // Short header fragment info round trip.
        let short = SSU2PacketHeader(shortDestinationConnectionID: dst, packetNumber: 7,
                                     type: .sessionConfirmed, fragmentIndex: 2, totalFragments: 5)
        let parsedShort = try SSU2PacketHeader.parse(short.serialize())
        guard parsedShort.fragmentIndex == 2, parsedShort.totalFragments == 5 else {
            throw SSU2Error.invalidHeader
        }
        // Connection ID pair rule: identical src/dst rejected.
        guard expectThrow({ try SSU2PacketHeader.validatePair(dst, dst) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        return "32-byte long + 16-byte short headers round-tripped; version/netID/connID rules enforced"
    }

    private static func ssu2HeaderProtectionPhases() throws -> String {
        let introKey = I2PCrypto.randomBytes(32)
        let packet = SSU2PacketHeader(destinationConnectionID: SSU2PacketHeader.randomConnectionID(),
                                      packetNumber: 9, type: .sessionRequest,
                                      sourceConnectionID: SSU2PacketHeader.randomConnectionID()).serialize()
            + I2PCrypto.randomBytes(60)
        for phase in SSU2HeaderPhase.allCases {
            var masked = Data(packet)
            try SSU2HeaderProtection.maskHeader(&masked, phase: phase, introKey: introKey)
            guard masked != packet else { throw SSU2Error.testFailed("\(phase) did not mask") }
            try SSU2HeaderProtection.unmaskHeader(&masked, phase: phase, introKey: introKey)
            guard masked == packet else { throw SSU2Error.testFailed("\(phase) unmask not an involution") }
        }
        // Receiver-side phase detection.
        let expectedDst = SSU2InitiatorHandshake.responderConnectionID(for: introKey)
        var request = SSU2PacketHeader(destinationConnectionID: expectedDst,
                                       packetNumber: 0, type: .sessionRequest,
                                       sourceConnectionID: SSU2PacketHeader.randomConnectionID()).serialize()
            + I2PCrypto.randomBytes(60)
        try SSU2HeaderProtection.maskHeader(&request, phase: .sessionRequest, introKey: introKey)
        guard SSU2HeaderProtection.detectPhase(request, introKey: introKey,
                                               expectedDestinationConnectionID: expectedDst) == .sessionRequest else {
            throw SSU2Error.testFailed("phase detection missed sessionRequest")
        }
        return "all 7 phases mask/unmask with tail-derived IVs; phase detection resolves the intro-key phases"
    }

    private static func ssu2HandshakeLoopback() throws -> String {
        let (aliceKeys, bobKeys) = try I2PSSU2SelfTest.handshakeKeySets()
        guard aliceKeys.send.aeadKey == bobKeys.recv.aeadKey,
              aliceKeys.recv.aeadKey == bobKeys.send.aeadKey else {
            throw SSU2Error.testFailed("split keys not mirrored")
        }
        return "token-request path completes with mirrored split keys"
    }

    private static func ssu2StateMachine() throws -> String {
        let (alice, bob) = try I2PSSU2SelfTest.loopbackPair(
            aliceKey: Curve25519.KeyAgreement.PrivateKey(),
            bobKey: Curve25519.KeyAgreement.PrivateKey())
        guard alice.state == .established, bob.state == .established else {
            throw SSU2Error.testFailed("state")
        }
        guard alice.remoteConnectionID == bob.localConnectionID,
              bob.remoteConnectionID == alice.localConnectionID else {
            throw SSU2Error.testFailed("conn IDs")
        }
        guard alice.remoteRouterInfo != nil else {
            throw SSU2Error.testFailed("RouterInfo exchange missing")
        }
        return "both sides established with mirrored conn IDs and the RouterInfo exchanged in the SessionConfirmed"
    }

    private static func ssu2TokenManagement() throws -> String {
        let manager = SSU2TokenManager(tokenLifetime: 600, maxRequestsPerWindow: 3, requestWindow: 60)
        let requester = Data(repeating: 7, count: 8)
        // One fixed clock for the whole case: validating an expired token prunes
        // the request window, so mixing simulated-future and wall-clock calls
        // would reset the rate-limit budget the case is about to check.
        let now = Date()
        guard let token = manager.issue(for: requester, now: now), token.count == 8,
              manager.validate(token, for: requester, now: now) else { throw SSU2Error.invalidToken }
        _ = manager.issue(for: requester, now: now)
        _ = manager.issue(for: requester, now: now)
        guard manager.issue(for: requester, now: now) == nil else {
            throw SSU2Error.testFailed("rate limit not enforced")
        }
        guard manager.issue(for: Data(repeating: 8, count: 8), now: now) != nil else {
            throw SSU2Error.testFailed("rate limit leaked across requesters")
        }
        guard !manager.validate(token, for: requester, now: now.addingTimeInterval(700)) else {
            throw SSU2Error.testFailed("expired token accepted")
        }
        return "8-byte tokens bound to the requester, expiring and rate-limited per window"
    }

    private static func ssu2DataPhase() throws -> String {
        let cipher = SSU2DataCipher(key: I2PCrypto.randomBytes(32))
        let header = SSU2PacketHeader(shortDestinationConnectionID: SSU2PacketHeader.randomConnectionID(),
                                      packetNumber: 5, type: .data)
        let packet = try cipher.seal(Data("i2np payload".utf8), header: header.serialize(), packetNumber: 5)
        guard try cipher.open(packet) == Data("i2np payload".utf8) else { throw SSU2Error.invalidPacket }
        let window = SSU2ReplayWindow()
        guard window.checkAndInsert(10), window.checkAndInsert(9),
              !window.checkAndInsert(9), !window.checkAndInsert(10),
              window.checkAndInsert(80) else { throw SSU2Error.replayedPacket }
        guard expectThrow({ _ = try cipher.seal(Data("tiny".utf8), header: header.serialize(), packetNumber: 6) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        guard expectThrow({
            _ = try cipher.seal(Data(repeating: 0, count: 1441), header: header.serialize(), packetNumber: 7)
        }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        var tampered = packet
        tampered[tampered.count - 20] ^= 0xff
        guard expectThrow({ _ = try cipher.open(tampered) }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        return "data phase sealed/opened; replay window, size bounds and MAC tamper rejection verified"
    }

    private static func ssu2ConfirmedFragmentation() throws -> String {
        let payload = I2PCrypto.randomBytes(2600)
        let chunks = try SSU2ConfirmedFragmenter.split(payload, maximumFragmentPayload: 1000)
        guard chunks.count == 3 else { throw SSU2Error.invalidPacket }
        let reassembler = SSU2ConfirmedReassembler()
        var complete: Data?
        for (index, chunk) in chunks.enumerated() {
            complete = try reassembler.add(fragmentIndex: index, totalFragments: chunks.count,
                                           payload: chunk, timeout: 30)
        }
        guard complete == payload else { throw SSU2Error.testFailed("reassembly mismatch") }
        guard expectThrow({
            _ = try SSU2ConfirmedFragmenter.split(I2PCrypto.randomBytes(15 * 1000 + 1),
                                                  maximumFragmentPayload: 1000)
        }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        return "3-fragment SessionConfirmed reassembled byte-exact; 16-fragment splits rejected"
    }

    private static func ssu2PeerTest() throws -> String {
        let published = SSU2Endpoint(host: "203.0.113.9", port: 8887)
        guard SSU2PeerTestCoordinator.classify(observed: published, published: published) == .direct,
              SSU2PeerTestCoordinator.classify(observed: SSU2Endpoint(host: "203.0.113.9", port: 54321),
                                               published: published) == .portMapped,
              SSU2PeerTestCoordinator.classify(observed: SSU2Endpoint(host: "198.51.100.2", port: 54321),
                                               published: published) == .symmetricNAT,
              SSU2PeerTestCoordinator.classify(observed: nil, published: published) == .unreachable else {
            throw SSU2Error.testFailed("classification matrix broken")
        }
        let (alice, alicePeer) = try I2PSSU2SelfTest.loopbackPair(
            aliceKey: Curve25519.KeyAgreement.PrivateKey(),
            bobKey: Curve25519.KeyAgreement.PrivateKey(),
            alicePublished: published)
        let nonce: UInt32 = 0xABCD_EF01
        try alice.startPeerTest(nonce: nonce)
        I2PSSU2SelfTest.pumpBoth(alice, alicePeer)
        guard let result = alice.peerTest.result(for: nonce),
              result.classification == .portMapped else {
            throw SSU2Error.testFailed("peer test result missing or misclassified")
        }
        guard alice.peerTest.result(for: nonce, now: Date().addingTimeInterval(7200)) == nil else {
            throw SSU2Error.testFailed("expired result still cached")
        }
        return "nonce-correlated request/response, reachability classified, cache expires"
    }

    private static func ssu2RelayHolePunch() throws -> String {
        let relayEntry = SSU2RelayEntry(introductionKey: I2PCrypto.randomBytes(32),
                                        host: "198.51.100.7", port: 9090,
                                        sessionID: 0x00C0_FFEE,
                                        supportsPeerTest: true, supportsHolePunch: true)
        let coordinator = SSU2RelayCoordinator()
        let targetHash = I2PCrypto.sha256(Data("bob-identity".utf8))
        let request = coordinator.buildRelayRequest(nonce: 7, targetHash: targetHash, targetPort: 8888)
        let parsedRequest = try SSU2RelayMessage.parseRequest(request)
        guard parsedRequest.nonce == 7, parsedRequest.targetHash == targetHash,
              parsedRequest.targetPort == 8888 else { throw SSU2Error.invalidPacket }
        guard try coordinator.handleRelayResponse(SSU2RelayMessage.response(nonce: 7, status: 0)) else {
            throw SSU2Error.testFailed("relay rejected")
        }
        let punch = try coordinator.buildHolePunch(nonce: 0x5150, packetNumber: 1,
                                                   destinationConnectionID: SSU2PacketHeader.randomConnectionID(),
                                                   sourceConnectionID: SSU2PacketHeader.randomConnectionID(),
                                                   introKey: relayEntry.introductionKey)
        // The header is protected on the wire, so read the type back through
        // the same unmasking the receiver performs.
        var unmarked = Data(punch)
        try SSU2HeaderProtection.unmaskHeader(&unmarked, phase: .holePunch,
                                              introKey: relayEntry.introductionKey)
        guard let punchHeader = try? SSU2PacketHeader.parse(unmarked),
              punchHeader.type == .holePunch, punchHeader.isLong else {
            throw SSU2Error.invalidPacket
        }
        let receiving = SSU2RelayCoordinator()
        guard try receiving.handleHolePunch(punch, introKey: relayEntry.introductionKey) == 0x5150,
              receiving.phase == .completed else {
            throw SSU2Error.testFailed("hole punch decode failed")
        }
        return "relay request/response round-tripped; type-11 hole punch masked, delivered and decoded"
    }

    private static func ssu2Migration() throws -> String {
        let (alice, bob) = try I2PSSU2SelfTest.loopbackPair(
            aliceKey: Curve25519.KeyAgreement.PrivateKey(),
            bobKey: Curve25519.KeyAgreement.PrivateKey())
        let localIDs = (alice.localConnectionID, bob.localConnectionID)
        let remoteIDs = (alice.remoteConnectionID, bob.remoteConnectionID)
        bob.handleDatagram(Data(), from: SSU2Endpoint(host: "10.6.0.9", port: 41234))
        I2PSSU2SelfTest.pumpBoth(alice, bob)
        guard bob.remoteEndpoint == SSU2Endpoint(host: "10.6.0.9", port: 41234) else {
            throw SSU2Error.testFailed("path not migrated")
        }
        guard alice.localConnectionID == localIDs.0, bob.localConnectionID == localIDs.1,
              alice.remoteConnectionID == remoteIDs.0, bob.remoteConnectionID == remoteIDs.1 else {
            throw SSU2Error.testFailed("conn IDs changed during migration")
        }
        return "new address challenged, validated by the echoed response, conn IDs untouched"
    }

    private static func ssu2Termination() throws -> String {
        let (alice, bob) = try I2PSSU2SelfTest.loopbackPair(
            aliceKey: Curve25519.KeyAgreement.PrivateKey(),
            bobKey: Curve25519.KeyAgreement.PrivateKey())
        try alice.close(reason: 0, detail: "bye")
        I2PSSU2SelfTest.pumpBoth(alice, bob)
        guard bob.state == .closed else { throw SSU2Error.testFailed("peer did not close") }
        guard alice.state == .terminating else { throw SSU2Error.testFailed("terminator state") }
        // Three whole-packet retransmissions are allowed; the fourth is refused.
        try alice.retransmitTermination()
        try alice.retransmitTermination()
        try alice.retransmitTermination()
        guard expectThrow({ try alice.retransmitTermination() }) else {
            throw I2PCrossValidationError.unexpectedSuccess
        }
        let quiet = try I2PSSU2SelfTest.loopbackPair(
            aliceKey: Curve25519.KeyAgreement.PrivateKey(),
            bobKey: Curve25519.KeyAgreement.PrivateKey()).0
        guard !quiet.checkIdle(timeout: 60) else { throw SSU2Error.testFailed("idle fired too early") }
        guard quiet.checkIdle(timeout: 60, now: Date().addingTimeInterval(3600)) else {
            throw SSU2Error.testFailed("idle teardown did not fire")
        }
        return "termination block delivered, 3 retransmissions bounded, idle timeout tears down"
    }
}