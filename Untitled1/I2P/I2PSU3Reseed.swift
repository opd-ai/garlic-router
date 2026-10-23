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
//  path. The agents they accept are wget-style identifiers — the reseed spec
//  names the family, and the two reference routers present exactly two of
//  them: i2pd sends "Wget/1.14 (linux-gnu)" and Java I2P's ReseedHandler has
//  historically sent "Wget/1.11.4". The reseed carries BOTH and rotates per
//  pass: pass 1 presents the i2pd agent, the second pass retries whatever
//  failed with the Java agent — a different accepted identifier, not a
//  browser fallback. The live runs distinguish the two server responses:
//  diva answered the reseed path with HTTP 429 (an accepted agent hitting its
//  rate limit) rather than the 403 the agent filter returns, which pins the
//  wget agents as accepted. The hosts that still 403 both agents reject at
//  their edge (TLS fingerprint / bot-detection reputation), which no
//  User-Agent string can satisfy.
//
//  Content-Encoding: reseed archives can arrive GZIPPED, and the big ones are
//  streamed as MULTI-MEMBER gzip (RFC 1952 allows concatenated members).
//  URLSession's transparent decompressor stops at the END of the first member
//  and reports success — diva's ~17MB full-netdb reseed arrived as exactly its
//  first member (67,328 bytes, twice, cleanly) while the SU3 header honestly
//  promised the rest. The reseed therefore asks for identity encoding (honest
//  servers then send raw bytes) and inflates any gzip that still arrives
//  itself, member after member, so no archive loses its tail. The wire body
//  is also cross-checked against the server's own Content-Length before
//  parsing, so a genuinely cut-short transfer is named as such instead of
//  surfacing as a parse mystery.
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
        "https://i2p.mooo.com/",
        "https://reseed.diva.exchange/",
        "https://reseed.stormycloud.org/",
        "https://banana.incognet.io/",
        "https://www.torontocrypto.org:8443/",
        "https://i2p.novg.net/",
        "https://reseed2.i2pgit.org/",
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
                // Pass 1 presents the i2pd agent; the second pass retries
                // whatever failed with Java I2P's classic reseed agent — a
                // different accepted wget-style identifier, not the identical
                // request a third time.
                let agent = pass == 1 ? userAgent : alternateAgent
                do {
                    return try await reseed(from: host, into: netDB, deferCount: deferCount,
                                            userAgent: agent)
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

    /// The agents the reseed spec's server-side filter accepts: wget-style
    /// identifiers, not browsers. Both are carried and rotated per pass —
    /// pass 1 presents the i2pd agent, the second pass retries whatever
    /// failed with Java I2P's classic reseed agent. The 429-vs-403 split the
    /// live runs produced pins these as accepted (see the header comment).
    static let userAgent = "Wget/1.14 (linux-gnu)"
    static let alternateAgent = "Wget/1.11.4"

    static func reseed(from host: String, into netDB: I2PNetworkDatabase, deferCount: Int,
                       userAgent: String) async throws -> I2PReseedReport {
        // The SU3 archive lives at the standard reseed path off the base URL
        // (see the header comment). Some configured hosts omit the trailing
        // slash; normalize before appending the filename.
        let trimmed = host.hasSuffix("/") ? host : host + "/"
        guard let url = URL(string: trimmed + reseedPath) else {
            throw I2PReseedError.invalidSU3("invalid reseed host url")
        }
        return try await fetchAndIngest(url: url, host: host, netDB: netDB, deferCount: deferCount,
                                        userAgent: userAgent)
    }

    private static func fetchAndIngest(url: URL, host: String, netDB: I2PNetworkDatabase,
                                       deferCount: Int, userAgent: String) async throws -> I2PReseedReport {
        var lastError: Error?
        for attempt in 1...2 {
            do {
                let (rawData, http) = try await fetch(url: url, userAgent: userAgent)
                guard (200...299).contains(http.statusCode) else {
                    if http.statusCode == 429 {
                        throw I2PReseedError.rateLimited
                    }
                    throw I2PReseedError.invalidSU3("reseed host returned HTTP status \(http.statusCode)")
                }

                // Cross-check the wire body against the server's own
                // Content-Length before any parsing: a body cut short in
                // transport is a retriable transfer failure with a name, not a
                // parse mystery. Chunked responses report -1 and skip this.
                let expected = http.expectedContentLength
                if expected > 0, rawData.count < expected {
                    throw I2PReseedError.invalidSU3(
                        "server sent Content-Length \(expected) but the transfer delivered \(rawData.count) bytes — truncated transfer")
                }

                // Identity encoding was requested; if the server gzipped
                // anyway, inflate it ourselves with full multi-member support
                // (URLSession's transparent decompressor stops at the first
                // member and reports success — the exact diva failure mode).
                let raw = [UInt8](rawData)
                let encoding = (http.value(forHTTPHeaderField: "Content-Encoding") ?? "").lowercased()
                let body: Data
                if encoding.contains("gzip") || (raw.count >= 2 && raw[0] == 0x1f && raw[1] == 0x8b) {
                    body = try inflateGzip(Data(raw))
                } else {
                    body = Data(raw)
                }

                let zipData = try parseSU3(body)
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
        return message.contains("truncated transfer")
    }

    private static func fetch(url: URL, userAgent: String) async throws -> (Data, HTTPURLResponse) {
        var request = URLRequest(url: url)
        // The full archive over a cold mobile link needs more than a 15s
        // window; the timeout is per-request idle time, not total duration.
        request.timeoutInterval = 30
        // Reseed servers require a wget-style agent on the data path (see the
        // header comment); the caller picks which accepted agent this request
        // presents.
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        // wget also sends Accept: */* — carry the header so the request looks
        // like the accepted client end to end.
        request.setValue("*/*", forHTTPHeaderField: "Accept")
        // Identity encoding: with an explicit Accept-Encoding, URLSession does
        // not transparently decompress — so the body we receive is the wire
        // body, its Content-Length cross-check is meaningful, and any gzip
        // that still arrives is inflated by inflateGzip with multi-member
        // support instead of being silently cut at the first member.
        request.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw I2PReseedError.invalidSU3("reseed host answered with a non-HTTP response")
        }
        return (data, http)
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

    // MARK: Gzip

    /// Inflates a gzip body with FULL multi-member support (RFC 1952 allows
    /// concatenated members). URLSession's transparent decompressor stops at
    /// the END of the first member and reports success — diva's large reseed
    /// arrived as exactly its first member (~67KB of a 17MB archive) with no
    /// error. The reseed requests identity encoding first (honest servers then
    /// send raw bytes); any gzip that still arrives is walked member after
    /// member here, so no archive loses its tail.
    static func inflateGzip(_ raw: Data) throws -> Data {
        let bytes = [UInt8](raw)
        var output = Data()
        var position = 0
        while position + 2 <= bytes.count {
            guard bytes[position] == 0x1f, bytes[position + 1] == 0x8b else {
                // Trailing non-gzip bytes end the walk cleanly once output
                // exists; a non-gzip body with no output is a real refusal.
                if !output.isEmpty { break }
                let head = bytes.prefix(8).map { String(format: "%02x", $0) }.joined()
                throw I2PReseedError.invalidSU3("gzip body does not begin with a gzip member (payload begins \(head))")
            }
            let headerEnd = try gzipMemberHeaderEnd(bytes, position)
            let (member, consumed) = try inflateRawDeflate(Array(bytes[headerEnd...]))
            guard !member.isEmpty else {
                throw I2PReseedError.invalidSU3("gzip member inflated to nothing")
            }
            output.append(member)
            // Each member closes with CRC32 (4) + ISIZE (4).
            position = headerEnd + consumed + 8
        }
        guard !output.isEmpty else {
            throw I2PReseedError.invalidSU3("gzip body inflated to nothing")
        }
        return output
    }

    /// Walks one gzip member header (RFC 1952): magic(2) CM(1) FLG(1) MTIME(4)
    /// XFL(1) OS(1), then the optional FEXTRA/FNAME/FCOMMENT/FHCRC fields the
    /// FLG bits announce. Returns the offset where the raw DEFLATE stream
    /// starts.
    private static func gzipMemberHeaderEnd(_ bytes: [UInt8], _ start: Int) throws -> Int {
        var p = start + 10
        let flg = bytes[start + 3]
        if flg & 0x04 != 0 { // FEXTRA
            guard p + 2 <= bytes.count else { throw I2PReseedError.invalidSU3("truncated gzip header") }
            let xlen = Int(bytes[p]) | (Int(bytes[p + 1]) << 8)
            p += 2 + xlen
        }
        if flg & 0x08 != 0 { // FNAME
            while p < bytes.count, bytes[p] != 0 { p += 1 }
            p += 1
        }
        if flg & 0x10 != 0 { // FCOMMENT
            while p < bytes.count, bytes[p] != 0 { p += 1 }
            p += 1
        }
        if flg & 0x02 != 0 { p += 2 } // FHCRC
        guard p <= bytes.count else { throw I2PReseedError.invalidSU3("truncated gzip header") }
        return p
    }

    /// Raw-DEFLATE inflates one member through the Compression framework's
    /// streaming decoder and reports how many input bytes the member consumed,
    /// so the caller can locate the next member in a multi-member stream.
    private static func inflateRawDeflate(_ bytes: [UInt8]) throws -> (Data, Int) {
        let dstBufferSize = 65_536
        let dstBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: dstBufferSize)
        defer { dstBuffer.deallocate() }
        return try bytes.withUnsafeBufferPointer { srcBuffer -> (Data, Int) in
            guard let srcBase = srcBuffer.baseAddress, !bytes.isEmpty else {
                throw I2PReseedError.invalidSU3("empty gzip member")
            }
            var stream = compression_stream(dst_ptr: dstBuffer, dst_size: 0,
                                            src_ptr: srcBase, src_size: Int(bytes.count), state: nil)
            guard compression_stream_init(&stream, COMPRESSION_STREAM_DECODE, COMPRESSION_ZLIB)
                    == COMPRESSION_STATUS_OK else {
                throw I2PReseedError.invalidSU3("gzip decoder failed to initialize")
            }
            defer { compression_stream_destroy(&stream) }
            var output = Data()
            while true {
                stream.dst_ptr = dstBuffer
                stream.dst_size = dstBufferSize
                let status = compression_stream_process(&stream, 0)
                let produced = dstBufferSize - stream.dst_size
                if produced > 0 { output.append(dstBuffer, count: produced) }
                let consumed = bytes.count - Int(stream.src_size)
                switch status {
                case COMPRESSION_STATUS_END:
                    return (output, consumed)
                case COMPRESSION_STATUS_OK:
                    // No output produced with the input exhausted means the
                    // member's deflate stream never completed: truncated.
                    guard produced > 0 || stream.src_size > 0 else {
                        throw I2PReseedError.invalidSU3("truncated transfer (gzip member cut short)")
                    }
                default:
                    throw I2PReseedError.invalidSU3("gzip inflate failed")
                }
            }
        }
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