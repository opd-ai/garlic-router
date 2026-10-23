//
//  I2PSU3Reseed.swift
//  Mainnet bootstrapping: fetch an i2pseeds.su3 reseed file over HTTPS
//  from public reseed servers, unpack the embedded zip archive, and return
//  RouterInfo payloads for signature-verified ingestion into the network
//  database.
//
//  SU3 container layout: magic "I2Psu3" (6), format version (2), signature
//  type (2), signature length (2), padding length (1), version length (2),
//  signer ID length (2), content length (8), timestamp (8), then version,
//  signer, content (zip), padding and signature. The reseed container
//  signature is NOT verified — a documented deviation: the container signature
//  algorithms used in the wild sit outside the modern-only crypto policy.
//
//  Transport trust: reseed servers in the wild commonly present SELF-SIGNED
//  TLS certificates — which is why Java I2P and i2pd ship pinned copies of
//  every reseed server certificate, a pin set this build cannot embed. The
//  reseed session therefore accepts a self-signed leaf (single-certificate
//  chain) when default trust evaluation fails, and still rejects any chain
//  issued by a different CA (corporate MITM proxies carry two or more
//  certificates). Authenticity rests on the per-RouterInfo Ed25519 signature
//  verification the netdb ingest performs on every entry — the same bar
//  network-sourced RouterInfos already clear.
//
//  Reseed URL convention: every well-known reseed server serves its SU3
//  archive at "<base>/i2pseeds.su3" — Java I2P's ReseedHandler and i2pd
//  append exactly that filename to each configured base URL. Fetching the
//  bare base URL returns the server's HTML index page: HTTP 200, "bad SU3
//  magic" at parse. The hosts list therefore holds base URLs and the fetch
//  always targets the standard reseed path.
//
//  User-Agent convention: reseed servers deliberately filter agents to keep
//  browsers from accidentally downloading multi-megabyte archives through
//  their root, and they reject unrecognized agents with HTTP 403 on the data
//  path. The agent they expect is the wget-style one i2pd presents: Wget/1.14
//  (Java I2P sends its own reseed agent, which the same servers also accept).
//  Browser-grade or router-custom agents are refused — a browser UA retry was
//  tried and also 403'd, so the fetch presents Wget/1.14 from the first byte.
//
//  Zip layout: end-of-central-directory scan, central directory entries and
//  local headers; entries are stored (method 0) or raw-deflate (method 8),
//  decompressed through the Compression framework's zlib codec.
//
//  The reseed session aggregates every host's failure reason (connection
//  refused vs TLS rejection vs timeout) so a total reseed failure names each
//  host's refusal mode instead of exposing only the last raw URLError.

import Foundation
import Compression
import Security

struct I2PReseedReport {
    let fetchedFrom: String
    let totalEntries: Int
    let ingested: Int
    let rejected: Int
    let floodfillCount: Int
    /// RouterInfo identity hashes deliberately NOT ingested locally, so a live
    /// DatabaseLookup has a key the local cache cannot answer from — the
    /// mainnet round-trip target.
    let deferredHashes: [Data]
}

enum I2PReseedError: Error {
    case allHostsFailed
    /// The host answered the reseed path with HTTP 429: an explicit "later",
    /// not "never" — the host is skipped for the remainder of the run instead
    /// of being hammered into a longer limit.
    case rateLimited
    case invalidSU3(String)
    case invalidZip(String)
}

enum I2PReseedService {
    /// Well-known public reseed servers (HTTPS, SU3 reseed files), ordered
    /// most-reliable first. All are tried in sequence; the run only fails when
    /// every host refuses or times out.
    static let hosts = [
        "https://reseed.i2p-projekt.de/",
        "https://reseed-pl.i2p-projekt.de/",
        "https://uk.reseed.i2p-projekt.de/",
        "https://i2p.mooo.com/",
        "https://reseed.diva.exchange/",
        "https://reseed.stormycloud.org/",
        "https://banana.incognet.io/",
        "https://www.torontocrypto.org:8443/",
        "https://i2p.novg.net/",
        "https://i2pgit.org/",
        "https://kingfox.org/",
        "https://i2pseed.creativecowpat.net:8443/",
    ]

    /// The standard reseed filename every well-known reseed server serves off
    /// its base URL — the "latest reseed" archive, regenerated continuously by
    /// each server from the current netdb state.
    static let reseedPath = "i2pseeds.su3"

    /// The reseed session rides the documented transport-trust model: default
    /// certificate evaluation first, then a self-signed-leaf fallback (see
    /// I2PReseedTrustDelegate). Hosts with publicly-trusted certificates
    /// behave exactly as before.
    static let session: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 15
        config.waitsForConnectivity = false
        return URLSession(configuration: config, delegate: I2PReseedTrustDelegate(), delegateQueue: nil)
    }()

    /// Fetches the first working reseed host, parses the SU3 container,
    /// unpacks the RouterInfo entries and ingests them (signature verified)
    /// into the netdb.
    static func reseed(into netDB: I2PNetworkDatabase, deferCount: Int = 2) async throws -> I2PReseedReport {
        var failures: [String] = []
        var rateLimited: Set<String> = []
        // Two passes over the host list: cold-network TLS handshakes and
        // transit routes to these hosts frequently stall on the first attempt
        // and clear on the second, and a per-host retry would double the
        // worst-case wall time of the whole sweep for the same coverage.
        for pass in 1...2 {
            if pass == 2 {
                // A 429 is the server saying "later", not "never": give the
                // limit a moment before the second sweep (diva 429'd a request
                // arriving seconds after the first), and skip hosts that
                // already declared a limit this run instead of deepening it.
                try? await Task.sleep(nanoseconds: 5_000_000_000)
            }
            for host in hosts {
                if pass == 2, rateLimited.contains(host) { continue }
                do {
                    return try await reseed(from: host, into: netDB, deferCount: deferCount)
                } catch I2PReseedError.rateLimited {
                    rateLimited.insert(host)
                    failures.append("\(host) — rate limited (HTTP 429)")
                } catch {
                    // Aggregate every host outcome — a report that names each
                    // refusal mode (connection refused vs TLS rejection vs
                    // timeout) turns "all hosts failed" from a guess into a
                    // diagnosis instead of exposing only the last raw URLError.
                    failures.append("\(host) — \(summarize(error))")
                }
            }
        }
        throw I2PMainnetFailure(message: "all \(hosts.count) reseed hosts failed over two passes: \(failures.joined(separator: "; "))")
    }

    /// Collapses a host failure to its refusal mode: the URLError blob's
    /// security-relevant content is the code, not the trust-chain dump.
    static func summarize(_ error: Error) -> String {
        if let urlError = error as? URLError {
            switch urlError.code {
            case .cannotConnectToHost: return "connection refused"
            case .timedOut: return "timed out"
            case .cannotFindHost: return "dns resolution failed"
            case .networkConnectionLost: return "network connection lost"
            case .notConnectedToInternet: return "no internet connection"
            case .secureConnectionFailed: return "TLS rejected the server certificate"
            case .serverCertificateUntrusted: return "server certificate not trusted"
            case .serverCertificateHasBadDate: return "server certificate expired"
            case .serverCertificateHasUnknownRoot: return "server certificate from an unknown CA"
            case .serverCertificateNotYetValid: return "server certificate not yet valid"
            default: return urlError.localizedDescription.lowercased()
            }
        }
        return String(describing: error)
    }

    /// The user agent reseed servers require on the data path (see the header
    /// comment): the wget-style agent i2pd presents. Custom and browser agents
    /// are deliberately rejected with 403.
    static let userAgent = "Wget/1.14"

    static func reseed(from host: String, into netDB: I2PNetworkDatabase, deferCount: Int) async throws -> I2PReseedReport {
        // The SU3 archive lives at the standard reseed path off the base URL
        // (see the header comment). Some configured hosts omit the trailing
        // slash; normalize before appending the filename.
        let trimmed = host.hasSuffix("/") ? host : host + "/"
        guard let url = URL(string: trimmed + reseedPath) else {
            throw I2PReseedError.invalidSU3("invalid reseed host url")
        }
        return try await fetchAndIngest(url: url, host: host, netDB: netDB, deferCount: deferCount)
    }

    private static func fetchAndIngest(url: URL, host: String, netDB: I2PNetworkDatabase,
                                       deferCount: Int) async throws -> I2PReseedReport {
        var lastError: Error?
        for attempt in 1...2 {
            do {
                let (data, response) = try await fetch(url: url)
                guard let http = response as? HTTPURLResponse else {
                    throw I2PReseedError.invalidSU3("reseed host answered with a non-HTTP response")
                }
                guard (200...299).contains(http.statusCode) else {
                    if http.statusCode == 429 {
                        throw I2PReseedError.rateLimited
                    }
                    throw I2PReseedError.invalidSU3("reseed host returned HTTP status \(http.statusCode)")
                }

                let zipData = try parseSU3(data)
                let payloads = try routerInfoPayloads(fromZip: zipData)
                guard !payloads.isEmpty else {
                    throw I2PReseedError.invalidZip("no routerInfo entries in the reseed archive")
                }

                // Ingest everything except up to `deferCount` non-floodfill RouterInfos,
                // which are kept out of the local cache as live DHT lookup targets.
                var ingested = 0
                var rejected = 0
                var deferredHashes: [Data] = []
                for payload in payloads {
                    let parsed = try? I2PRouterInfo.parse(payload)
                    let isFloodfill = parsed?.options["caps"]?.contains("f") == true
                    if !isFloodfill, deferredHashes.count < deferCount {
                        if let parsed {
                            deferredHashes.append(parsed.identity.hash)
                        }
                        continue
                    }
                    do {
                        try await netDB.ingestRouterInfo(payload)
                        ingested += 1
                    } catch {
                        rejected += 1
                    }
                }
                let floodfills = await netDB.floodfillCount()
                return I2PReseedReport(
                    fetchedFrom: host,
                    totalEntries: payloads.count,
                    ingested: ingested,
                    rejected: rejected,
                    floodfillCount: floodfills,
                    deferredHashes: deferredHashes
                )
            } catch {
                // The ~100-200 KB SU3 archive can arrive cut short: an edge
                // closes the connection cleanly before the full body lands,
                // URLSession reports no error, and the SU3 header then
                // promises more content than arrived. A fresh connection
                // frequently carries the complete body, so transport
                // failures and truncation both get one retry before the
                // host is abandoned.
                let retriable = error is URLError || isTruncatedBody(error)
                guard attempt == 1, retriable else { throw error }
                lastError = error
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
        }
        throw lastError ?? I2PReseedError.invalidSU3("reseed fetch failed")
    }

    private static func isTruncatedBody(_ error: Error) -> Bool {
        guard case I2PReseedError.invalidSU3(let message) = error else { return false }
        return message.contains("content length") && message.contains("truncated transfer")
    }

    private static func fetch(url: URL) async throws -> (Data, URLResponse) {
        var request = URLRequest(url: url)
        // The full archive over a cold mobile link needs more than a 15s
        // window; the timeout is per-request idle time, not total duration.
        request.timeoutInterval = 30
        // Reseed servers require the wget-style agent on the data path (see
        // the header comment).
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        return try await session.data(for: request)
    }

    // MARK: SU3 container

    static func parseSU3(_ data: Data) throws -> Data {
        let bytes = [UInt8](data)
        guard bytes.count >= 33 else {
            throw I2PReseedError.invalidSU3("truncated SU3 header")
        }
        let magic = Array("I2Psu3".utf8)
        guard Array(bytes[0..<6]) == magic else {
            // Surface what actually arrived: a server that answers the reseed
            // path with an HTML page, a captive-portal block page, or garbage
            // shows up here as the payload's first bytes, not a bare refusal.
            let head = bytes.prefix(8).map { String(format: "%02x", $0) }.joined()
            throw I2PReseedError.invalidSU3("bad SU3 magic (payload begins \(head))")
        }
        // SU3 header numeric fields are BIG-endian (I2P wire convention) — the
        // little-endian helpers below belong to the ZIP container, whose fields
        // are little-endian per the zip spec. Reading the SU3 lengths with the
        // zip helpers byte-swapped every field: signature length 0x0040 (64)
        // parsed as 0x4000, and the 8-byte content length became astronomically
        // large — the exact "content length exceeds the file" failure real
        // archives produced while synthetic round-trips stayed green (the test
        // builder made the same byte swap, so parser and builder agreed).
        let signatureLength = Int(be16(bytes, 10))
        let paddingLength = Int(bytes[12])
        let versionLength = Int(be16(bytes, 13))
        let signerLength = Int(be16(bytes, 15))
        let contentLength = Int(be64(bytes, 17))
        let headerEnd = 33 + versionLength + signerLength
        let contentStart = headerEnd
        let contentEnd = contentStart + contentLength
        guard contentLength > 0 else {
            throw I2PReseedError.invalidSU3("empty SU3 content")
        }
        guard bytes.count >= contentEnd + signatureLength + paddingLength else {
            // Name the arithmetic: the header promises this much content, the
            // transfer delivered less. That is a cut-short response body, not
            // garbage — the message says so and carries the received size.
            throw I2PReseedError.invalidSU3(
                "content length \(contentLength) exceeds the file (received \(bytes.count) bytes — truncated transfer)")
        }
        return Data(bytes[contentStart..<contentEnd])
    }

    // MARK: Zip

    /// Returns the uncompressed payloads of every routerInfo-*.dat entry in the
    /// zip archive.
    static func routerInfoPayloads(fromZip zipData: Data) throws -> [Data] {
        let bytes = [UInt8](zipData)
        guard bytes.count >= 22 else {
            throw I2PReseedError.invalidZip("truncated zip")
        }

        // Locate the End Of Central Directory record (scan backwards, allowing
        // up to 64KB of archive comment).
        var eocd = -1
        let floor = max(0, bytes.count - 22 - 65536)
        var index = bytes.count - 22
        while index >= floor {
            if u32(bytes, index) == 0x06054b50 {
                eocd = index
                break
            }
            index -= 1
        }
        guard eocd >= 0 else {
            throw I2PReseedError.invalidZip("no end of central directory record")
        }
        let entryCount = Int(u16(bytes, eocd + 10))
        let centralSize = Int(u32(bytes, eocd + 12))
        let centralOffset = Int(u32(bytes, eocd + 16))
        guard centralOffset + centralSize <= bytes.count else {
            throw I2PReseedError.invalidZip("central directory out of bounds")
        }

        var payloads: [Data] = []
        var cursor = centralOffset
        for _ in 0..<entryCount {
            guard cursor + 46 <= bytes.count, u32(bytes, cursor) == 0x02014b50 else {
                break
            }
            let method = Int(u16(bytes, cursor + 10))
            let compressedSize = Int(u32(bytes, cursor + 20))
            let uncompressedSize = Int(u32(bytes, cursor + 24))
            let nameLength = Int(u16(bytes, cursor + 28))
            let extraLength = Int(u16(bytes, cursor + 30))
            let commentLength = Int(u16(bytes, cursor + 32))
            let localOffset = Int(u32(bytes, cursor + 42))
            let name = String(decoding: bytes[(cursor + 46)..<(cursor + 46 + nameLength)], as: UTF8.self)
            cursor += 46 + nameLength + extraLength + commentLength

            guard name.hasPrefix("routerInfo-"), name.hasSuffix(".dat") else { continue }
            guard method == 0 || method == 8 else { continue }
            if let payload = try? extract(bytes, localOffset: localOffset, method: method,
                                          compressedSize: compressedSize, uncompressedSize: uncompressedSize) {
                payloads.append(payload)
            }
        }
        return payloads
    }

    private static func extract(_ bytes: [UInt8], localOffset: Int, method: Int,
                                compressedSize: Int, uncompressedSize: Int) throws -> Data {
        guard localOffset + 30 <= bytes.count, u32(bytes, localOffset) == 0x04034b50 else {
            throw I2PReseedError.invalidZip("bad local header")
        }
        let localNameLength = Int(u16(bytes, localOffset + 26))
        let localExtraLength = Int(u16(bytes, localOffset + 28))
        let dataStart = localOffset + 30 + localNameLength + localExtraLength
        guard dataStart + compressedSize <= bytes.count else {
            throw I2PReseedError.invalidZip("entry data out of bounds")
        }
        let compressed = Data(bytes[dataStart..<(dataStart + compressedSize)])
        guard method == 8 else {
            return compressed // stored entry
        }
        guard uncompressedSize > 0 else { return Data() }
        var out = Data(count: uncompressedSize)
        var decoded = 0
        out.withUnsafeMutableBytes { dstPtr in
            compressed.withUnsafeBytes { srcPtr in
                decoded = compression_decode_buffer(dstPtr.baseAddress!, uncompressedSize,
                                                    srcPtr.baseAddress!, compressedSize,
                                                    nil, COMPRESSION_ZLIB)
            }
        }
        guard decoded == uncompressedSize else {
            throw I2PReseedError.invalidZip("deflate size mismatch")
        }
        return out
    }

    // SU3 header fields: big-endian, per the SU3 reseed spec.
    private static func be16(_ bytes: [UInt8], _ offset: Int) -> UInt16 {
        (UInt16(bytes[offset]) << 8) | UInt16(bytes[offset + 1])
    }

    private static func be64(_ bytes: [UInt8], _ offset: Int) -> UInt64 {
        var value: UInt64 = 0
        for i in 0..<8 { value = (value << 8) | UInt64(bytes[offset + i]) }
        return value
    }

    // ZIP container fields: little-endian, per the zip spec.
    private static func u16(_ bytes: [UInt8], _ offset: Int) -> UInt16 {
        UInt16(bytes[offset]) | (UInt16(bytes[offset + 1]) << 8)
    }

    private static func u32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        UInt32(bytes[offset])
            | (UInt32(bytes[offset + 1]) << 8)
            | (UInt32(bytes[offset + 2]) << 16)
            | (UInt32(bytes[offset + 3]) << 24)
    }

    private static func u64(_ bytes: [UInt8], _ offset: Int) -> UInt64 {
        UInt64(bytes[offset])
            | (UInt64(bytes[offset + 1]) << 8)
            | (UInt64(bytes[offset + 2]) << 16)
            | (UInt64(bytes[offset + 3]) << 24)
            | (UInt64(bytes[offset + 4]) << 32)
            | (UInt64(bytes[offset + 5]) << 40)
            | (UInt64(bytes[offset + 6]) << 48)
            | (UInt64(bytes[offset + 7]) << 56)
    }
}
/// Server-trust policy for reseed hosts ONLY. Reseed servers in the wild
/// commonly present SELF-SIGNED TLS certificates — Java I2P and i2pd ship
/// pinned copies of every reseed server certificate for exactly this reason,
/// and this build cannot embed that pin set. The policy:
///
///   1. Default evaluation runs first — publicly-trusted certificates behave
///      exactly as stock URLSession does.
///   2. When evaluation fails, the credential is accepted ONLY for a
///      single-certificate chain: a self-signed leaf presents no issuer chain,
///      while any CA-issued chain (including a corporate MITM proxy) carries
///      two or more certificates and stays rejected.
///   3. Authenticity rests downstream: every RouterInfo in the SU3 archive is
///      Ed25519 signature-verified again at netdb ingest — the same bar
///      network-sourced RouterInfos already clear — so a tampered reseed
///      stream cannot poison the netdb, only fail to bootstrap it.
final class I2PReseedTrustDelegate: NSObject, URLSessionDataDelegate {
    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        var evaluationError: CFError?
        if SecTrustEvaluateWithError(trust, &evaluationError) {
            completionHandler(.useCredential, URLCredential(trust: trust))
            return
        }
        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
              chain.count == 1 else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        completionHandler(.useCredential, URLCredential(trust: trust))
    }
}