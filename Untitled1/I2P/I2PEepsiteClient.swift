//
//  I2PEepsiteClient.swift
//  The in-app eepsite client. An address (.i2p hostname, b32 host, b33 blinded
//  address or base64 destination) is resolved through the router's netdb —
//  plain LeaseSets, LeaseSet2 and the b33 blinding path for credentialled
//  hosts — then a garlic'd stream is opened over the browser's own outbound
//  tunnel pool to the resolved leases and an HTTP request travels through it.
//
//  Every step runs in a named stage so a failure can say exactly where the
//  path broke (lookup, blinding, tunnels, connect, request, response) and
//  a lease that expires mid-fetch is reported as such instead of as a silent
//  timeout.
//

import Foundation
import CryptoKit

// MARK: - Stages and failures

/// The named stages of one eepsite fetch, in the order they normally run.
enum I2PEepsiteStage: String, CaseIterable {
    case address = "Address"
    case lookup = "Lookup"
    case blinding = "Blinding"
    case leases = "Leases"
    case tunnels = "Tunnels"
    case connect = "Connect"
    case request = "Request"
    case response = "Response"

    /// The present-tense line the loading card shows for this stage.
    var summary: String {
        switch self {
        case .address:
            return "Reading the address"
        case .lookup:
            return "Resolving the destination through the netdb"
        case .blinding:
            return "Resolving the blinded b33 key"
        case .leases:
            return "Collecting the destination's live leases"
        case .tunnels:
            return "Filling the client's tunnel pool"
        case .connect:
            return "Opening the stream through the outbound tunnel"
        case .request:
            return "Sending the HTTP request"
        case .response:
            return "Reading the response"
        }
    }

    /// The line a completed stage leaves in the trail.
    var completedSummary: String {
        switch self {
        case .address: return "Address parsed"
        case .lookup: return "Destination resolved"
        case .blinding: return "Blinded key resolved"
        case .leases: return "Live leases collected"
        case .tunnels: return "Tunnel pool ready"
        case .connect: return "Stream opened"
        case .request: return "Request sent"
        case .response: return "Response read"
        }
    }
}

/// A failed fetch: the stage that broke and a human-readable reason.
struct I2PEepsiteFailure: Error {
    let stage: I2PEepsiteStage
    let message: String
}

/// How a destination's leases were found.
enum I2PEepsiteRoute: String {
    case leaseSet = "plain LeaseSet"
    case leaseSet2 = "LeaseSet2"
    case blinded = "b33 blinded LeaseSet2"
    case addressBook = "address book"
}

// MARK: - Address

/// A parsed eepsite address: what to resolve and which path to fetch.
struct I2PEepsiteAddress {
    enum Host {
        /// A 57-character b33 blinded address.
        case b33(String)
        /// A b32 hostname's 32-byte destination hash.
        case b32(Data)
        /// A base64 destination typed or pasted into the bar.
        case destination(I2PDestination)
        /// An address-book name (`site.i2p`).
        case name(String)
    }

    let host: Host
    /// The host as typed (lowercased, without path or port).
    let displayHost: String
    /// The request path, always starting with "/".
    let path: String

    static func parse(_ raw: String) throws -> I2PEepsiteAddress {
        func fail(_ message: String) -> I2PEepsiteFailure {
            I2PEepsiteFailure(stage: .address, message: message)
        }

        var text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else {
            throw fail("Enter an eepsite address — a .i2p hostname, a b32 host, a b33 address or a base64 destination.")
        }
        if let scheme = text.range(of: "://") {
            text = String(text[scheme.upperBound...])
        }
        var hostPart = text
        var path = "/"
        if let slash = text.firstIndex(of: "/") {
            hostPart = String(text[..<slash])
            path = String(text[slash...])
        } else if let question = text.firstIndex(of: "?") {
            hostPart = String(text[..<question])
            path = "/" + String(text[question...])
        }
        if hostPart.lowercased().hasPrefix("b33:") {
            hostPart = String(hostPart.dropFirst(4))
        }
        // Strip an explicit port ("site.i2p:80").
        if let colon = hostPart.lastIndex(of: ":") {
            let port = hostPart[hostPart.index(after: colon)...]
            if !port.isEmpty, port.count <= 5, port.allSatisfy(\.isNumber) {
                hostPart = String(hostPart[..<colon])
            }
        }
        let lowered = hostPart.lowercased()
        guard !lowered.isEmpty else { throw fail("The address has no host part.") }

        let b33Candidate = lowered.hasSuffix(".b33.i2p")
            ? String(lowered.dropLast(".b33.i2p".count))
            : lowered
        if I2PB33Blinding.b33Decode(b33Candidate) != nil {
            let display = lowered.hasSuffix(".b33.i2p") ? lowered : "\(b33Candidate).b33.i2p"
            return I2PEepsiteAddress(host: .b33(b33Candidate),
                                     displayHost: display,
                                     path: normalize(path))
        }

        if lowered.hasSuffix(".b32.i2p") {
            let base32 = String(lowered.dropLast(".b32.i2p".count))
            guard let hash = I2PSAMEncoding.base32Decode(base32), hash.count == 32 else {
                throw fail("That b32 hostname does not decode to a 32-byte destination hash.")
            }
            return I2PEepsiteAddress(host: .b32(hash),
                                     displayHost: lowered,
                                     path: normalize(path))
        }

        if let data = I2PSAMEncoding.normalizedBase64(hostPart), data.count >= 384 {
            var reader = I2PReader(data)
            if let destination = try? I2PKeysAndCert.parse(&reader), reader.remaining == 0 {
                return I2PEepsiteAddress(
                    host: .destination(destination),
                    displayHost: I2PSAMEncoding.base32Encode(destination.hash) + ".b32.i2p",
                    path: normalize(path))
            }
        }

        if lowered.hasSuffix(".i2p") {
            return I2PEepsiteAddress(host: .name(lowered),
                                     displayHost: lowered,
                                     path: normalize(path))
        }

        throw fail("Only .i2p hostnames, b32 hosts, b33 addresses and base64 destinations load here — clear-net names never leave the device.")
    }

    private static func normalize(_ path: String) -> String {
        guard !path.isEmpty else { return "/" }
        return path.hasPrefix("/") ? path : "/" + path
    }
}

// MARK: - Page

/// A fetched and rendered eepsite page.
struct I2PEepsitePage {
    let address: String
    let title: String?
    let blocks: [I2PReadBlock]
    let statusCode: Int
    let contentType: String
    let byteCount: Int
    let route: I2PEepsiteRoute
    let leaseCount: Int
    let elapsed: TimeInterval
    /// An inline diagnostic for a page that arrived but not cleanly.
    let note: String?
}

// MARK: - HTTP

/// A minimal HTTP/1.1 response read off the stream.
struct I2PHTTPResponse {
    static let maximumResponseBytes = 8 * 1024 * 1024
    private static let maximumHeaderBytes = 64 * 1024

    let statusCode: Int
    let reason: String
    let headers: [String: String]
    let body: Data

    var contentType: String { headers["content-type"] ?? "" }

    var isHTML: Bool {
        let type = contentType.lowercased()
        return type.contains("text/html") || type.contains("application/xhtml") || type.isEmpty
    }

    var isPlainText: Bool { contentType.lowercased().hasPrefix("text/plain") }

    var charset: String? {
        guard let range = contentType.range(of: "charset=", options: .caseInsensitive) else { return nil }
        let value = contentType[range.upperBound...]
            .split(separator: ";").first?
            .trimmingCharacters(in: .whitespaces.union(CharacterSet(charactersIn: "\"'")))
        return value?.isEmpty == false ? value : nil
    }

    /// True once the buffer holds everything the framing promises, so the
    /// read loop can stop before the peer closes the stream.
    static func isComplete(_ data: Data) -> Bool {
        // Let the caller stop reading so `parse` can report a bounded, explicit
        // error instead of buffering an untrusted response indefinitely.
        guard data.count <= maximumResponseBytes else { return true }
        guard let terminator = headerTerminator(in: data) else {
            return data.count > maximumHeaderBytes
        }
        guard terminator.lowerBound <= maximumHeaderBytes else { return true }
        let headerText = String(decoding: data[..<terminator.lowerBound], as: UTF8.self).lowercased()
        let body = Data(data[terminator.upperBound...])
        if headerText.contains("transfer-encoding:") && headerText.contains("chunked") {
            return decodeChunked(body).complete
        }
        let framing = contentLength(headerText)
        if framing.present {
            guard let length = framing.length, length <= maximumResponseBytes else { return true }
            return body.count >= length
        }
        // No framing: the page ends when the peer closes (FIN). A complete
        // HTML document is the reliable short-circuit.
        let tail = String(decoding: body.suffix(48), as: UTF8.self).lowercased()
        return tail.contains("</html>")
    }

    static func parse(_ data: Data) throws -> I2PHTTPResponse {
        func fail(_ message: String) -> I2PEepsiteFailure {
            I2PEepsiteFailure(stage: .response, message: message)
        }
        guard data.count <= maximumResponseBytes else {
            throw fail("The eepsite response exceeded the 8 MiB size limit.")
        }
        guard let terminator = headerTerminator(in: data) else {
            guard data.count <= maximumHeaderBytes else {
                throw fail("The HTTP headers exceeded the 64 KiB size limit.")
            }
            throw fail("The stream carried no complete HTTP header.")
        }
        guard terminator.lowerBound <= maximumHeaderBytes else {
            throw fail("The HTTP headers exceeded the 64 KiB size limit.")
        }
        let headerText = String(decoding: data[..<terminator.lowerBound], as: UTF8.self)
        let lines = headerText.components(separatedBy: .newlines).filter { !$0.isEmpty }
        guard let statusLine = lines.first else {
            throw fail("The stream carried an empty HTTP header.")
        }
        let statusParts = statusLine.split(separator: " ", maxSplits: 2)
        guard statusParts.count >= 2, statusParts[0].hasPrefix("HTTP/"),
              let code = Int(statusParts[1]) else {
            throw fail("The stream did not start with an HTTP status line (first line: \(statusLine.prefix(80))).")
        }
        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let key = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            headers[key] = value
        }
        let framing = contentLength(headerText)
        if framing.present, framing.length == nil {
            throw fail("The eepsite sent an invalid or conflicting Content-Length header.")
        }
        if let length = framing.length, length > maximumResponseBytes {
            throw fail("The eepsite declared a response larger than the 8 MiB size limit.")
        }

        let rawBody = Data(data[terminator.upperBound...])
        let body: Data
        if headers["transfer-encoding"]?.lowercased().contains("chunked") == true {
            body = decodeChunked(rawBody).data
        } else if let length = framing.length {
            body = rawBody.count > length ? Data(rawBody.prefix(length)) : rawBody
        } else {
            body = rawBody
        }
        return I2PHTTPResponse(statusCode: code,
                               reason: statusParts.count > 2 ? String(statusParts[2]) : "",
                               headers: headers,
                               body: body)
    }

    private static func headerTerminator(in data: Data) -> Range<Data.Index>? {
        if let range = data.range(of: Data([0x0D, 0x0A, 0x0D, 0x0A])) { return range }
        return data.range(of: Data([0x0A, 0x0A]))
    }

    private static func contentLength(_ headerText: String) -> (present: Bool, length: Int?) {
        var declaredLength: Int?
        var present = false
        for line in headerText.components(separatedBy: .newlines).filter { !$0.isEmpty } {
            guard let colon = line.firstIndex(of: ":"),
                  line[..<colon].trimmingCharacters(in: .whitespaces).lowercased() == "content-length" else {
                continue
            }
            present = true
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            guard let length = Int(value), length >= 0 else { return (true, nil) }
            if let declaredLength, declaredLength != length { return (true, nil) }
            declaredLength = length
        }
        return (present, declaredLength)
    }

    private static func decodeChunked(_ body: Data) -> (data: Data, complete: Bool) {
        var out = Data()
        var index = body.startIndex
        while index < body.endIndex {
            guard let lineEnd = body[index...].firstIndex(of: 0x0A) else {
                return (out, false)
            }
            var lineData = body[index..<lineEnd]
            if lineData.last == 0x0D { lineData = lineData.dropLast() }
            let line = String(decoding: lineData, as: UTF8.self)
            let sizeText = line.split(separator: ";").first.map(String.init) ?? ""
            guard let size = Int(sizeText.trimmingCharacters(in: .whitespaces), radix: 16) else {
                return (out, false)
            }
            index = body.index(after: lineEnd)
            if size == 0 { return (out, true) }
            guard body.distance(from: index, to: body.endIndex) >= size else {
                return (out, false)
            }
            let end = body.index(index, offsetBy: size)
            out.append(contentsOf: body[index..<end])
            index = end
            if index < body.endIndex, body[index] == 0x0D { index = body.index(after: index) }
            if index < body.endIndex, body[index] == 0x0A { index = body.index(after: index) }
        }
        return (out, false)
    }
}

// MARK: - HTTP response self-tests

enum I2PHTTPResponseSelfTest {
    static func runAll() -> [I2PSelfTestResult] {
        var results: [I2PSelfTestResult] = []
        func check(_ name: String, _ body: () -> String?) {
            if let detail = body() {
                results.append(I2PSelfTestResult(name: name, passed: true, detail: detail))
            } else {
                results.append(I2PSelfTestResult(
                    name: name, passed: false,
                    detail: "HTTP response framing did not match the expected bounded behavior"))
            }
        }
        func rejects(_ data: Data) -> Bool {
            do {
                _ = try I2PHTTPResponse.parse(data)
                return false
            } catch let error as I2PEepsiteFailure {
                return error.stage == .response
            } catch {
                return false
            }
        }

        check("eepsite HTTP response: invalid and negative Content-Length rejected") {
            let negative = Data("HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\nx".utf8)
            let malformed = Data("HTTP/1.1 200 OK\r\nContent-Length: nope\r\n\r\nx".utf8)
            let conflicting = Data("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nxy".utf8)
            guard I2PHTTPResponse.isComplete(negative), rejects(negative),
                  rejects(malformed), rejects(conflicting) else { return nil }
            return "negative, malformed and conflicting lengths fail as response errors without slicing or trapping"
        }

        check("eepsite HTTP response: oversized headers and bodies are bounded") {
            let header = Data("HTTP/1.1 200 OK\r\nX-Large: ".utf8)
                + Data(repeating: 0x61, count: 65 * 1024)
            let body = Data(repeating: 0x61, count: I2PHTTPResponse.maximumResponseBytes + 1)
            let oversizedLength = Data("HTTP/1.1 200 OK\r\nContent-Length: \(I2PHTTPResponse.maximumResponseBytes + 1)\r\n\r\n".utf8)
            guard I2PHTTPResponse.isComplete(header), rejects(header),
                  I2PHTTPResponse.isComplete(body), rejects(body),
                  I2PHTTPResponse.isComplete(oversizedLength), rejects(oversizedLength) else { return nil }
            return "header bytes and complete response bytes stay under explicit limits; oversized declarations stop reads early"
        }

        check("eepsite HTTP response: valid and partial Content-Length framing") {
            let complete = Data("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcignored".utf8)
            let partial = Data("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nab".utf8)
            guard I2PHTTPResponse.isComplete(complete),
                  (try? I2PHTTPResponse.parse(complete).body) == Data("abc".utf8),
                  !I2PHTTPResponse.isComplete(partial),
                  (try? I2PHTTPResponse.parse(partial).body) == Data("ab".utf8) else { return nil }
            return "valid declared bodies still trim extra bytes and preserve partial-response rendering"
        }

        return results
    }
}

// MARK: - Resolved site

/// A destination resolved to the leases a garlic stream can route to.
struct I2PEepsiteSite {
    let destination: I2PDestination
    let leases: [I2PLease]
    let route: I2PEepsiteRoute
}

// MARK: - Client

/// The browser's client: resolves destinations through the router's lookup
/// paths and fetches pages over a garlic'd stream. One client destination is
/// shared by every fetch (created lazily on the first load), so the browser
/// does not rebuild a tunnel pool per page.
final class I2PEepsiteClient {
    private let core: I2PSAMRouterCore
    /// The credentials the router holds for a b33 address (live encrypted
    /// publication sessions), keyed by the 57-character address.
    private let credentials: (String) -> I2PB33Credentials?
    /// The router's SAM address book, for `site.i2p` names.
    private let addressBook: (String) -> I2PDestination?

    private let lock = NSLock()
    private var session: I2PEepsiteClientSession?

    /// A netdb lookup round; two rounds give the DHT a chance to iterate.
    private static let lookupTimeout: TimeInterval = 2.0
    private static let lookupRounds = 2

    init(core: I2PSAMRouterCore,
         credentials: @escaping (String) -> I2PB33Credentials?,
         addressBook: @escaping (String) -> I2PDestination?) {
        self.core = core
        self.credentials = credentials
        self.addressBook = addressBook
    }

    /// Runs one full fetch: parse → resolve → tunnel pool → stream → HTTP →
    /// reader blocks. `onStage` reports each stage as it starts.
    func load(_ raw: String,
              onStage: @escaping (I2PEepsiteStage) -> Void) async throws -> I2PEepsitePage {
        let started = Date()
        let address = try I2PEepsiteAddress.parse(raw)
        onStage(.address)
        if Task.isCancelled { throw CancellationError() }

        let site = try await resolve(address, onStage: onStage)
        if Task.isCancelled { throw CancellationError() }

        onStage(.tunnels)
        let session = preparedSession()
        try await session.ensureReady()
        if Task.isCancelled { throw CancellationError() }

        onStage(.connect)
        let fetched = try await session.fetch(site: site,
                                              host: address.displayHost,
                                              path: address.path,
                                              onStage: onStage)
        onStage(.response)

        let http = try I2PHTTPResponse.parse(fetched.data)
        guard (200..<400).contains(http.statusCode) else {
            let reason = http.reason.isEmpty ? "(no reason)" : http.reason
            throw I2PEepsiteFailure(stage: .response,
                                    message: "The eepsite answered HTTP \(http.statusCode) \(reason).")
        }
        let text: String
        if http.isHTML || http.isPlainText {
            text = Self.decodeText(http.body)
        } else {
            throw I2PEepsiteFailure(stage: .response,
                                    message: "The response is \(http.contentType.isEmpty ? "a binary body" : http.contentType) — the reader renders HTML and plain text.")
        }

        let parsed = http.isPlainText
            ? (title: nil as String?, blocks: Self.plainTextBlocks(text))
            : I2PHTMLReader.parse(text, baseHost: address.displayHost)

        var notes: [String] = []
        if fetched.incomplete {
            notes.append("The response ended early — \(Self.byteText(http.body.count)) arrived before the fetch timeout, so the page may be truncated.")
        }
        if fetched.leaseExpiredMidFetch {
            notes.append("The destination's lease (tunnel \(fetched.lease.tunnelId)) expired during the fetch — the next load needs a fresh lookup.")
        }

        return I2PEepsitePage(
            address: address.displayHost,
            title: parsed.title ?? address.displayHost,
            blocks: parsed.blocks,
            statusCode: http.statusCode,
            contentType: http.contentType.isEmpty ? "text/html" : http.contentType,
            byteCount: http.body.count,
            route: site.route,
            leaseCount: site.leases.count,
            elapsed: Date().timeIntervalSince(started),
            note: notes.isEmpty ? nil : notes.joined(separator: " "))
    }

    // MARK: Resolution

    private func resolve(_ address: I2PEepsiteAddress,
                         onStage: (I2PEepsiteStage) -> Void) async throws -> I2PEepsiteSite {
        switch address.host {
        case .b33(let blinded):
            onStage(.blinding)
            guard let credentialSet = self.credentials(blinded) else {
                throw I2PEepsiteFailure(stage: .blinding,
                                        message: "This b33 host is a stranger: the router holds no credentials for its blinded key, so its encrypted LeaseSet2 can never be opened. Credentialled hosts come from a SAM session publishing an encrypted LeaseSet2 (see the b33 Hosts screen).")
            }
            onStage(.lookup)
            guard let resolved = await core.netDB.resolveEncryptedDestination(
                credentials: credentialSet,
                timeoutPerRound: Self.lookupTimeout,
                maxRounds: Self.lookupRounds) else {
                throw I2PEepsiteFailure(stage: .blinding,
                                        message: "No encrypted LeaseSet2 came back from the floodfills for this host's blinded netdb key. The host may not be publishing right now.")
            }
            onStage(.leases)
            let leases = Self.liveLeases(resolved.leases)
            guard !leases.isEmpty else { throw expiredFailure(resolved.leases) }
            return I2PEepsiteSite(destination: resolved.destination,
                                  leases: leases,
                                  route: .blinded)

        case .b32(let hash):
            return try await resolveByKey(hash, hint: nil, onStage: onStage)

        case .destination(let destination):
            return try await resolveByKey(destination.hash, hint: destination, onStage: onStage)

        case .name(let host):
            guard let destination = addressBook(host) else {
                throw I2PEepsiteFailure(stage: .lookup,
                                        message: "\(host) is not in the router's address book. I2P has no global name service — add the destination with NAMING ADD on the SAM screen, or load its b32 host or base64 destination here.")
            }
            return try await resolveByKey(destination.hash, hint: destination,
                                          onStage: onStage, route: .addressBook)
        }
    }

    /// Resolves a destination hash through the cache-first DHT path: a plain
    /// LeaseSet first, then a LeaseSet2 (types 2/3/5) through the same route.
    private func resolveByKey(_ key: Data,
                              hint: I2PDestination?,
                              onStage: (I2PEepsiteStage) -> Void,
                              route: I2PEepsiteRoute? = nil) async throws -> I2PEepsiteSite {
        onStage(.lookup)
        guard let entry = await core.netDB.lookup(key,
                                                  timeoutPerRound: Self.lookupTimeout,
                                                  maxRounds: Self.lookupRounds) else {
            throw I2PEepsiteFailure(stage: .lookup,
                                    message: "No netdb entry for \(Self.shortHash(key)) at any floodfill — the destination is not currently published, or the router has no floodfill sessions yet.")
        }
        onStage(.leases)
        if let leaseSet = entry.leaseSet {
            let leases = Self.liveLeases(leaseSet.leases)
            guard !leases.isEmpty else { throw expiredFailure(leaseSet.leases) }
            return I2PEepsiteSite(destination: hint ?? leaseSet.destination,
                                  leases: leases,
                                  route: route ?? .leaseSet)
        }
        if let leaseSet2 = entry.leaseSet2, let resolved = leaseSet2.resolvedLeaseSet() {
            let leases = Self.liveLeases(resolved.leases)
            guard !leases.isEmpty else { throw expiredFailure(resolved.leases) }
            return I2PEepsiteSite(destination: hint ?? resolved.destination,
                                  leases: leases,
                                  route: route ?? .leaseSet2)
        }
        throw I2PEepsiteFailure(stage: .lookup,
                                message: "The netdb entry for \(Self.shortHash(key)) carries no lease set the browser can route to.")
    }

    private func expiredFailure(_ leases: [I2PLease]) -> I2PEepsiteFailure {
        let newest = leases.map(\.expiration).max()
        let age = newest.map { Self.ageText(Date().timeIntervalSince($0)) } ?? "an unknown time"
        return I2PEepsiteFailure(stage: .leases,
                                 message: "Every lease in the destination's lease set has expired (the newest ran out \(age) ago) — the destination is not republishing, so a stream cannot reach it.")
    }

    // MARK: Session

    private func preparedSession() -> I2PEepsiteClientSession {
        lock.lock()
        defer { lock.unlock() }
        if let session { return session }
        let created = I2PEepsiteClientSession(core: core)
        session = created
        return created
    }

    // MARK: Formatting helpers

    private static func liveLeases(_ leases: [I2PLease], now: Date = Date()) -> [I2PLease] {
        leases.filter { $0.expiration > now }
            .sorted { $0.expiration > $1.expiration }
    }

    private static func shortHash(_ key: Data) -> String {
        let hex = key.hex
        guard hex.count > 12 else { return hex }
        return "\(hex.prefix(12))…"
    }

    private static func ageText(_ seconds: TimeInterval) -> String {
        let total = Int(max(0, seconds))
        if total < 60 { return "\(total)s" }
        if total < 3_600 { return "\(total / 60)m" }
        return "\(total / 3_600)h"
    }

    private static func byteText(_ bytes: Int) -> String {
        if bytes >= 1_048_576 { return String(format: "%.1f MB", Double(bytes) / 1_048_576) }
        if bytes >= 1_024 { return String(format: "%.1f KB", Double(bytes) / 1_024) }
        return "\(bytes) B"
    }

    private static func decodeText(_ data: Data) -> String {
        if let utf8 = String(data: data, encoding: .utf8) { return utf8 }
        if let latin = String(data: data, encoding: .isoLatin1) { return latin }
        return ""
    }

    /// Plain-text bodies render as one preformatted block.
    private static func plainTextBlocks(_ text: String) -> [I2PReadBlock] {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return [I2PReadBlock(kind: .paragraph,
                                 text: AttributedString("The document is empty."),
                                 plainText: "The document is empty.")]
        }
        return [I2PReadBlock(kind: .code,
                             text: AttributedString(trimmed),
                             plainText: trimmed)]
    }
}

// MARK: - Stream exchange

/// One in-flight stream: the SYN/SYN-ACK handshake flag, the response bytes
/// received so far, and the outbound sequence counter.
private final class I2PEepsiteExchange {
    struct State {
        let established: Bool
        let finished: Bool
        let failure: String?
        let data: Data
        let lastActivity: Date
    }

    let streamID: UInt32
    private let lock = NSLock()
    private var established = false
    private var finished = false
    private var failure: String?
    private var data = Data()
    private var sequence: UInt32 = 0
    private var lastActivity = Date()

    init(streamID: UInt32) {
        self.streamID = streamID
    }

    func markEstablished() {
        lock.lock()
        established = true
        lastActivity = Date()
        lock.unlock()
    }

    func append(_ chunk: Data) {
        lock.lock()
        defer { lock.unlock() }
        guard failure == nil else { return }
        guard chunk.count <= I2PHTTPResponse.maximumResponseBytes - data.count else {
            failure = "The eepsite response exceeded the 8 MiB size limit."
            return
        }
        data.append(chunk)
        lastActivity = Date()
    }

    func markFinished() {
        lock.lock()
        finished = true
        lastActivity = Date()
        lock.unlock()
    }

    func fail(_ message: String) {
        lock.lock()
        failure = message
        lock.unlock()
    }

    func nextSequence() -> UInt32 {
        lock.lock()
        defer { lock.unlock() }
        sequence += 1
        return sequence
    }

    func snapshot() -> State {
        lock.lock()
        defer { lock.unlock() }
        return State(established: established,
                     finished: finished,
                     failure: failure,
                     data: data,
                     lastActivity: lastActivity)
    }
}

// MARK: - Client session

/// The browser's own destination: a tunnel pool, a published LeaseSet so the
/// eepsite can reply, the garlic stream machinery and the inbound reassembler.
final class I2PEepsiteClientSession {
    struct FetchResult {
        let data: Data
        let lease: I2PLease
        /// True when the read loop stopped on the fetch budget, not on FIN or
        /// on a complete HTTP framing.
        let incomplete: Bool
        /// True when the remote lease ran out at some point during the fetch.
        let leaseExpiredMidFetch: Bool
    }

    private let core: I2PSAMRouterCore
    private let keys: I2PSAMDestinationKeys
    private let pool: I2PTunnelPool
    private let transport: I2PSAMGarlicTransport
    private let garlicHandler: I2PGarlicMessageHandler
    private let assembler: I2PSAMInboundAssembler

    private let lock = NSLock()
    private var exchanges: [UInt32: I2PEepsiteExchange] = [:]
    private var publishedAt = Date.distantPast

    private static let leaseWindow: TimeInterval = 600
    private static let republishInterval: TimeInterval = 240
    private static let poolWaitTimeout: TimeInterval = 45
    private static let handshakeTimeout: TimeInterval = 45
    private static let fetchTimeout: TimeInterval = 75
    private static let leaseStallWindow: TimeInterval = 6

    init(core: I2PSAMRouterCore) {
        self.core = core
        let keys = I2PSAMDestinationKeys.generate()
        self.keys = keys
        let pool = I2PTunnelPool(localRouterHash: core.routerHash,
                                 participant: core.participant,
                                 transport: core.buildTransport,
                                 peerProvider: core.peerProvider,
                                 config: .eepsiteDefault)
        self.pool = pool
        self.transport = I2PSAMGarlicTransport(core: core)
        self.garlicHandler = I2PGarlicMessageHandler(
            sessionManager: I2PGarlicInboundSessionManager(localKey: keys.encryptionKey),
            deliveryTransport: core.delivery)
        self.assembler = I2PSAMInboundAssembler(ordered: true)

        pool.start()
        assembler.onCompleted = { [weak self] completed in
            self?.handle(completed)
        }
        garlicHandler.addLocalConsumer { [weak self] message, _ in
            guard let self,
                  message.type == .dataMessage,
                  // A Data message body is a 4-byte length then the payload; a
                  // body whose length does not account for it is dropped here.
                  let body = try? I2NPDataMessage.parse(message.payload),
                  let frame = I2PSAMFrame.parse(body) else { return }
            self.assembler.ingest(frame)
        }
        // Inbound garlic for this destination arrives on the router's body
        // handlers; the handler fails closed for messages it cannot decrypt.
        core.i2npRouter.addBodyHandler { [weak self] message, source in
            self?.garlicHandler.handle(message, from: source)
        }
    }

    // MARK: Readiness

    /// Makes sure the pool has both directions, the browser's LeaseSet is
    /// published (so replies can come back) and its leases are current.
    func ensureReady() async throws {
        pool.start()
        if pool.outboundTunnels.isEmpty || pool.inboundTunnels.isEmpty {
            // Fail fast with a named stage instead of waiting out the pool
            // budget when the netdb has no hop candidates at all.
            let candidates = core.peerProvider.peers(count: 1, excluding: [core.routerHash])
            guard !candidates.isEmpty else {
                throw I2PEepsiteFailure(stage: .tunnels,
                                        message: "The router has no tunnel hops yet — its netdb holds no usable peer RouterInfos, so no tunnel can be built. Open the Router tab and let the bootstrap cycle connect to floodfills, then load the page again.")
            }
            await pool.fillPools()
        }
        // Builds are async (and the pool may already be filling): wait for
        // both directions to appear instead of assuming one fill completed.
        let deadline = Date().addingTimeInterval(Self.poolWaitTimeout)
        while Date() < deadline {
            if Task.isCancelled { throw CancellationError() }
            if !pool.outboundTunnels.isEmpty && !pool.inboundTunnels.isEmpty { break }
            try await Task.sleep(for: .milliseconds(250))
        }
        guard !pool.outboundTunnels.isEmpty else {
            throw I2PEepsiteFailure(stage: .tunnels,
                                    message: "No outbound tunnel could be built. The browser needs live peers — open the Router tab, let the pool fill, then load the page again.")
        }
        guard !pool.inboundTunnels.isEmpty else {
            throw I2PEepsiteFailure(stage: .tunnels,
                                    message: "The client has an outbound tunnel but no inbound tunnel, so the eepsite could not send its reply back. The pool keeps building; try again in a moment.")
        }
        if needsRepublish() {
            await publishLeases()
        }
        guard !currentLeases().isEmpty else {
            throw I2PEepsiteFailure(stage: .tunnels,
                                    message: "No inbound leases could be published for the browser's own destination — the reply path needs at least one live inbound tunnel.")
        }
    }

    /// Re-publishes on a cadence, or early when the published leases are about
    /// to run out.
    private func needsRepublish(now: Date = Date()) -> Bool {
        let leases = currentLeases(now: now)
        guard !leases.isEmpty else { return false }
        lock.lock()
        let last = publishedAt
        lock.unlock()
        if last == Date.distantPast { return true }
        if now.timeIntervalSince(last) >= Self.republishInterval { return true }
        let soonest = leases.map(\.expiration).min() ?? now
        return soonest.timeIntervalSince(now) < 60
    }

    /// The leases the browser publishes: one per live inbound tunnel, capped at
    /// a ten-minute window like any other destination's publication.
    private func currentLeases(now: Date = Date()) -> [I2PLease] {
        pool.inboundTunnels.filter { !$0.isExpired(now: now) }.compactMap { tunnel in
            guard let gateway = tunnel.hops.first else { return nil }
            return I2PLease(gatewayHash: gateway.routerHash,
                            tunnelId: tunnel.gatewayTunnelID,
                            expiration: min(tunnel.expiresAt,
                                            now.addingTimeInterval(Self.leaseWindow)))
        }
    }

    @discardableResult
    func publishLeases() async -> Bool {
        let now = Date()
        let leases = currentLeases(now: now)
        guard !leases.isEmpty else { return false }
        var leaseSet = I2PLeaseSet(destination: keys.destination, published: now, leases: leases)
        do {
            try leaseSet.sign(withSeed: keys.signingSeed)
        } catch {
            return false
        }
        await core.netDB.publish(leaseSet: leaseSet)
        lock.lock()
        publishedAt = now
        lock.unlock()
        return true
    }

    // MARK: Fetch

    func fetch(site: I2PEepsiteSite,
               host: String,
               path: String,
               onStage: (I2PEepsiteStage) -> Void) async throws -> FetchResult {
        guard let lease = site.leases.first else {
            throw I2PEepsiteFailure(stage: .leases,
                                    message: "The resolved lease set carried no usable lease.")
        }
        guard pool.selectOutboundTunnel() != nil else {
            throw I2PEepsiteFailure(stage: .tunnels,
                                    message: "The outbound tunnel pool drained before the request could be sent.")
        }
        let garlicLease = I2PGarlicLease(gatewayRouterHash: lease.gatewayHash,
                                         tunnelID: lease.tunnelId,
                                         expiration: lease.expiration)
        transport.registry.register(garlicLease)

        let garlic: I2PGarlicSession
        do {
            garlic = try I2PGarlicSession(
                peerPublicKey: Curve25519.KeyAgreement.PublicKey(
                    rawRepresentation: site.destination.encryptionPublicKey),
                tagsPerHandshake: 16)
        } catch {
            throw I2PEepsiteFailure(stage: .connect,
                                    message: "The destination advertises an encryption key the garlic pipeline cannot use: \(error)")
        }

        let streamID = UInt32.random(in: 1...UInt32.max)
        let exchange = I2PEepsiteExchange(streamID: streamID)
        lock.lock()
        exchanges[streamID] = exchange
        lock.unlock()
        defer {
            lock.lock()
            exchanges[streamID] = nil
            lock.unlock()
        }

        do {
            try await sendFrame(payload: Data(),
                                flags: [.syn],
                                streamID: streamID,
                                sequence: 0,
                                attached: keys.destination.raw,
                                to: garlicLease,
                                garlic: garlic)
        } catch {
            throw I2PEepsiteFailure(stage: .connect,
                                    message: "The stream SYN could not leave the outbound tunnel pool: \(Self.describe(error))")
        }

        try await waitForEstablished(exchange, lease: lease)

        onStage(.request)
        let request = Data(Self.httpRequest(host: host, path: path).utf8)
        do {
            try await sendFrame(payload: request,
                                flags: [],
                                streamID: streamID,
                                sequence: exchange.nextSequence(),
                                attached: Data(),
                                to: garlicLease,
                                garlic: garlic)
        } catch {
            throw I2PEepsiteFailure(stage: .request,
                                    message: "The HTTP request could not be sent over the stream: \(Self.describe(error))")
        }

        onStage(.response)
        return try await readResponse(exchange, lease: lease)
    }

    private func waitForEstablished(_ exchange: I2PEepsiteExchange,
                                    lease: I2PLease) async throws {
        let deadline = Date().addingTimeInterval(Self.handshakeTimeout)
        while Date() < deadline {
            if Task.isCancelled { throw CancellationError() }
            let state = exchange.snapshot()
            if state.established { return }
            if let failure = state.failure {
                throw I2PEepsiteFailure(stage: .connect, message: failure)
            }
            if Date() > lease.expiration {
                throw I2PEepsiteFailure(stage: .connect,
                                        message: "The destination's lease expired before it answered: lease \(lease.tunnelId) ran out \(Self.ageText(Date().timeIntervalSince(lease.expiration))) ago. Reload to re-resolve its lease set.")
            }
            try await Task.sleep(for: .milliseconds(100))
        }
        throw I2PEepsiteFailure(stage: .connect,
                                message: "The eepsite did not answer the stream SYN within \(Int(Self.handshakeTimeout))s. The request left through the outbound tunnel pool; either the destination is offline or its inbound tunnels are not forwarding.")
    }

    private func readResponse(_ exchange: I2PEepsiteExchange,
                              lease: I2PLease) async throws -> FetchResult {
        let deadline = Date().addingTimeInterval(Self.fetchTimeout)
        var leaseStalled = false
        while Date() < deadline {
            if Task.isCancelled { throw CancellationError() }
            let state = exchange.snapshot()
            if let failure = state.failure {
                throw I2PEepsiteFailure(stage: .response, message: failure)
            }
            if state.finished { break }
            if I2PHTTPResponse.isComplete(state.data) { break }
            if Date() > lease.expiration,
               Date().timeIntervalSince(state.lastActivity) > Self.leaseStallWindow {
                leaseStalled = true
                break
            }
            try await Task.sleep(for: .milliseconds(100))
        }

        let state = exchange.snapshot()
        if let failure = state.failure {
            throw I2PEepsiteFailure(stage: .response, message: failure)
        }
        let leaseExpiredMidFetch = Date() > lease.expiration
        if state.data.isEmpty {
            if leaseStalled || leaseExpiredMidFetch {
                throw I2PEepsiteFailure(stage: .response,
                                        message: "The destination's lease (tunnel \(lease.tunnelId)) expired mid-fetch and no response bytes came back — the reply path died with the lease. Reload to re-resolve and retry.")
            }
            if let failure = state.failure {
                throw I2PEepsiteFailure(stage: .response, message: failure)
            }
            throw I2PEepsiteFailure(stage: .response,
                                    message: "The stream opened but the eepsite sent no response bytes before the \(Int(Self.fetchTimeout))s fetch timeout.")
        }
        let complete = state.finished || I2PHTTPResponse.isComplete(state.data)
        return FetchResult(data: state.data,
                           lease: lease,
                           incomplete: !complete,
                           leaseExpiredMidFetch: leaseExpiredMidFetch)
    }

    // MARK: Frames

    /// Sends one logical message: chunked frames that all share `sequence`, so
    /// the peer's reassembler completes the message.
    private func sendFrame(payload: Data,
                           flags: I2PSAMFrame.Flags,
                           streamID: UInt32,
                           sequence: UInt32,
                           attached: Data,
                           to lease: I2PGarlicLease,
                           garlic: I2PGarlicSession) async throws {
        let chunks = I2PSAMChunker.split(payload)
        for (index, chunk) in chunks.enumerated() {
            let frame = I2PSAMFrame(streamID: streamID,
                                    flags: flags,
                                    sequence: sequence,
                                    fromPort: 0,
                                    toPort: 0,
                                    chunkIndex: UInt16(index),
                                    chunkCount: UInt16(chunks.count),
                                    chunk: chunk,
                                    attached: index == 0 ? attached : Data())
            try await transport.send(I2NPMessage(type: .dataMessage,
                                                 payload: I2NPDataMessage(
                                                    payload: frame.serialize()).serialize()),
                                     to: lease,
                                     garlicSession: garlic,
                                     pool: pool)
        }
    }

    private func handle(_ completed: I2PSAMInboundAssembler.Completed) {
        lock.lock()
        let exchange = exchanges[completed.streamID]
        lock.unlock()
        guard let exchange else { return }
        if completed.flags.contains(.rst) {
            exchange.fail("The eepsite reset the stream.")
            return
        }
        if completed.flags.contains(.syn) {
            exchange.markEstablished()
            return
        }
        if !completed.data.isEmpty { exchange.append(completed.data) }
        if completed.flags.contains(.fin) { exchange.markFinished() }
    }

    // MARK: Requests

    private static func httpRequest(host: String, path: String) -> String {
        let target = path.isEmpty ? "/" : path
        return "GET \(target) HTTP/1.1\r\n"
            + "Host: \(host)\r\n"
            + "User-Agent: Milq-I2P-Browser/1.0\r\n"
            + "Accept: text/html, text/plain;q=0.9, */*;q=0.1\r\n"
            + "Connection: close\r\n"
            + "\r\n"
    }

    // MARK: Formatting

    private static func ageText(_ seconds: TimeInterval) -> String {
        let total = Int(max(0, seconds))
        if total < 60 { return "\(total)s" }
        if total < 3_600 { return "\(total / 60)m" }
        return "\(total / 3_600)h"
    }

    private static func describe(_ error: Error) -> String {
        if let samError = error as? I2PSAMError {
            switch samError {
            case .noTunnels: return "the outbound tunnel pool is empty"
            case .timeout: return "the peer timed out"
            case .destinationNotFound: return "the lease could not be resolved"
            case .unreachable: return "the peer is unreachable"
            case .invalidCommand(let reason): return reason
            case .invalidDestination: return "the destination is malformed"
            case .duplicatedID: return "a duplicate session id"
            }
        }
        return String(describing: error)
    }
}

// MARK: - Browser pool

extension I2PTunnelPool.Config {
    /// The browser's pool: a small, fast-filling pair of one-hop tunnels. The
    /// inbound side exists so the eepsite's response has a path back.
    static var eepsiteDefault: I2PTunnelPool.Config {
        var config = I2PTunnelPool.Config()
        config.outboundTarget = 2
        config.inboundTarget = 2
        config.hopCount = 1
        config.staggerInterval = 0.2
        config.buildTimeout = 15
        config.maintenanceInterval = 5
        return config
    }
}
