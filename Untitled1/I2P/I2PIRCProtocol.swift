//
//  I2PIRCProtocol.swift
//  The IRC wire layer for the in-app client: server-address parsing, the IRC
//  line grammar (IRCv3 tags, prefix, command and params), the naming rules the
//  client relies on (channel prefixes, nick prefix stripping) and text shaping
//  for sends (line-break stripping, CTCP ACTION, IRC-sized splitting).
//
//  Everything here is pure: it runs without the router, so the grammar and the
//  address rules are verified by the self-test suite before a stream exists.
//

import Foundation

// MARK: - Stages and failures

/// The named stages of one IRC connection, in the order they normally run.
enum I2PIRCStage: String, CaseIterable {
    case address = "Address"
    case lookup = "Lookup"
    case blinding = "Blinding"
    case leases = "Leases"
    case tunnels = "Tunnels"
    case connect = "Stream"
    case register = "Register"
    case ready = "Ready"

    /// The present-tense line the connection card shows while this stage runs.
    var summary: String {
        switch self {
        case .address: return "Reading the server address"
        case .lookup: return "Resolving the server through the netdb"
        case .blinding: return "Resolving the blinded b33 key"
        case .leases: return "Collecting the server's live leases"
        case .tunnels: return "Filling the client's tunnel pool"
        case .connect: return "Opening the stream through the outbound tunnel"
        case .register: return "Registering with the server"
        case .ready: return "Connected"
        }
    }

    /// The line a completed stage leaves in the trail.
    var completedSummary: String {
        switch self {
        case .address: return "Address parsed"
        case .lookup: return "Server resolved"
        case .blinding: return "Blinded key resolved"
        case .leases: return "Live leases collected"
        case .tunnels: return "Tunnel pool ready"
        case .connect: return "Stream opened"
        case .register: return "Registration sent"
        case .ready: return "Connected"
        }
    }
}

/// A failed connection attempt: the stage that broke and a readable reason.
struct I2PIRCFailure: Error {
    let stage: I2PIRCStage
    let message: String
}

// MARK: - Reconnect policy

/// The retry schedule a live IRC stream follows when it ends on its own — the
/// server closing it, a send failing or the keep-alive declaring it dead. Four
/// attempts with a widening backoff, then the client stops and hands the reason
/// back to the user.
enum I2PIRCReconnectPolicy {
    /// The wait before each retry, in order.
    static let delays: [TimeInterval] = [5, 15, 30, 60]

    /// How many retries one outage gets before the client stops.
    static var attemptLimit: Int { delays.count }

    /// The wait before attempt `attempt` (counted from one), or nil when the
    /// attempt is past the budget.
    static func delay(forAttempt attempt: Int) -> TimeInterval? {
        guard attempt >= 1, attempt <= delays.count else { return nil }
        return delays[attempt - 1]
    }

    /// The line the header shows while a retry counts down.
    static func line(attempt: Int, seconds: Int) -> String {
        "Reconnecting in \(seconds)s · attempt \(attempt) of \(attemptLimit)"
    }
}

// MARK: - Server address

/// A parsed I2P IRC server address: what to resolve, how the UI shows it and
/// the port typed alongside it.
enum I2PIRCHost {
    /// What the address points at.
    enum Target {
        /// A 57-character b33 blinded address.
        case b33(String)
        /// A b32 hostname's 32-byte destination hash.
        case b32(Data)
        /// A base64 destination typed or pasted into the field.
        case destination(I2PDestination)
        /// An address-book name (`irc.example.i2p`).
        case name(String)
    }

    struct Parsed {
        let target: Target
        /// The host as the UI shows it: lowercased, no scheme, no path, no port.
        let displayHost: String
        /// The port typed into the address, when one was.
        let port: UInt16?
    }

    static func parse(_ raw: String) throws -> Parsed {
        func fail(_ message: String) -> I2PIRCFailure {
            I2PIRCFailure(stage: .address, message: message)
        }

        var text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else {
            throw fail("Enter an I2P IRC server — a .i2p hostname, a b32 host, a b33 address or a base64 destination, with an optional :port.")
        }
        if let scheme = text.range(of: "://") {
            text = String(text[scheme.upperBound...])
        }
        if text.lowercased().hasPrefix("b33:") {
            text = String(text.dropFirst(4))
        }
        // A base64 destination may itself contain "/" and "+", so it is tried
        // before the address is split into host and path.
        if let data = I2PSAMEncoding.normalizedBase64(text), data.count >= 384 {
            var reader = I2PReader(data)
            if let destination = try? I2PKeysAndCert.parse(&reader), reader.remaining == 0 {
                return Parsed(target: .destination(destination),
                              displayHost: I2PSAMEncoding.base32Encode(destination.hash) + ".b32.i2p",
                              port: nil)
            }
        }
        if let slash = text.firstIndex(of: "/") {
            text = String(text[..<slash])
        }
        var port: UInt16?
        if let colon = text.lastIndex(of: ":") {
            let portText = text[text.index(after: colon)...]
            if !portText.isEmpty, portText.count <= 5, portText.allSatisfy(\.isNumber) {
                guard let parsed = UInt16(portText), parsed > 0 else {
                    throw fail("\(portText) is not a usable TCP port — pick a number between 1 and 65535.")
                }
                port = parsed
                text = String(text[..<colon])
            }
        }
        let lowered = text.lowercased()
        guard !lowered.isEmpty else { throw fail("The address has no host part.") }

        let b33Candidate = lowered.hasSuffix(".b33.i2p")
            ? String(lowered.dropLast(".b33.i2p".count))
            : lowered
        if I2PB33Blinding.b33Decode(b33Candidate) != nil {
            let display = lowered.hasSuffix(".b33.i2p") ? lowered : "\(b33Candidate).b33.i2p"
            return Parsed(target: .b33(b33Candidate), displayHost: display, port: port)
        }

        if lowered.hasSuffix(".b32.i2p") {
            let base32 = String(lowered.dropLast(".b32.i2p".count))
            guard let hash = I2PSAMEncoding.base32Decode(base32), hash.count == 32 else {
                throw fail("That b32 hostname does not decode to a 32-byte destination hash.")
            }
            return Parsed(target: .b32(hash), displayHost: lowered, port: port)
        }

        if lowered.hasSuffix(".i2p") {
            return Parsed(target: .name(lowered), displayHost: lowered, port: port)
        }

        throw fail("Only .i2p hostnames, b32 hosts, b33 addresses and base64 destinations connect here — clear-net IRC servers never leave the device.")
    }
}

// MARK: - Line grammar

/// One IRC line: the optional IRCv3 tag map, the optional prefix, the command
/// and its params (the trailing param included, without its colon).
struct I2PIRCLine: Equatable {
    let tags: [String: String]
    let prefix: String?
    let command: String
    let params: [String]

    /// Parses a raw line as it came off the stream. Returns nil for a blank or
    /// unusable line so a malformed message is dropped rather than displayed.
    static func parse(_ raw: String) -> I2PIRCLine? {
        var text = raw
        while let last = text.last, last == "\r" || last == "\n" {
            text.removeLast()
        }
        text = text.trimmingCharacters(in: .whitespaces)
        guard !text.isEmpty else { return nil }

        var tags: [String: String] = [:]
        if text.hasPrefix("@") {
            guard let space = text.firstIndex(of: " ") else { return nil }
            let tagPart = text[text.index(after: text.startIndex)..<space]
            for entry in tagPart.split(separator: ";") {
                let pair = entry.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
                guard let key = pair.first, !key.isEmpty else { continue }
                let value = pair.count > 1 ? unescapeTag(String(pair[1])) : ""
                tags[String(key)] = value
            }
            text = String(text[text.index(after: space)...])
        }

        var prefix: String?
        if text.hasPrefix(":") {
            guard let space = text.firstIndex(of: " ") else { return nil }
            prefix = String(text[text.index(after: text.startIndex)..<space])
            text = String(text[text.index(after: space)...])
        }

        text = text.trimmingCharacters(in: .whitespaces)
        guard !text.isEmpty else { return nil }

        let command: String
        if let space = text.firstIndex(of: " ") {
            command = String(text[..<space]).uppercased()
            text = String(text[text.index(after: space)...])
        } else {
            command = text.uppercased()
            text = ""
        }
        guard !command.isEmpty else { return nil }

        var params: [String] = []
        while !text.isEmpty {
            if text.hasPrefix(":") {
                params.append(String(text.dropFirst()))
                break
            }
            if let space = text.firstIndex(of: " ") {
                params.append(String(text[..<space]))
                text = String(text[text.index(after: space)...])
                while text.hasPrefix(" ") {
                    text.removeFirst()
                }
            } else {
                params.append(text)
                break
            }
        }
        return I2PIRCLine(tags: tags, prefix: prefix, command: command, params: params)
    }

    /// Renders the line for the wire. The last param is sent as the trailing
    /// one when it is empty, holds a space or starts with a colon.
    func serialize() -> String {
        var out = ""
        if !tags.isEmpty {
            let rendered = tags
                .sorted { $0.key < $1.key }
                .map { "\($0.key)=\(Self.escapeTag($0.value))" }
                .joined(separator: ";")
            out += "@\(rendered) "
        }
        if let prefix {
            out += ":\(prefix) "
        }
        out += command
        for (index, param) in params.enumerated() {
            out += " "
            let isLast = index == params.count - 1
            if isLast, param.isEmpty || param.contains(" ") || param.hasPrefix(":") {
                out += ":\(param)"
            } else {
                out += param
            }
        }
        return out
    }

    // MARK: Readers

    /// The nick a prefixed line came from (its prefix without user/host).
    var nick: String? {
        guard let prefix else { return nil }
        let stop = prefix.firstIndex { $0 == "!" || $0 == "@" }
        let name = stop.map { String(prefix[..<$0]) } ?? prefix
        return name.isEmpty ? nil : name
    }

    var isNumeric: Bool {
        command.count == 3 && command.allSatisfy { $0.isASCII && $0.isNumber }
    }

    var numeric: Int? { isNumeric ? Int(command) : nil }

    /// The first param — a message's target or a numeric's addressee.
    var target: String? { params.first }

    /// The last param — a message's text or a numeric's sentence.
    var trailing: String? { params.last }

    // MARK: IRCv3 tag escaping

    static func escapeTag(_ value: String) -> String {
        var out = ""
        for character in value {
            switch character {
            case ";": out += "\\:"
            case " ": out += "\\s"
            case "\\": out += "\\\\"
            case "\r": out += "\\r"
            case "\n": out += "\\n"
            default: out.append(character)
            }
        }
        return out
    }

    static func unescapeTag(_ value: String) -> String {
        var out = ""
        var escaping = false
        for character in value {
            if escaping {
                switch character {
                case ":": out.append(";")
                case "s": out.append(" ")
                case "\\": out.append("\\")
                case "r": out.append("\r")
                case "n": out.append("\n")
                default: out.append(character)
                }
                escaping = false
            } else if character == "\\" {
                escaping = true
            } else {
                out.append(character)
            }
        }
        return out
    }
}

// MARK: - Naming rules

enum I2PIRCName {
    /// IRC channels start with a channel prefix; a target without one is a
    /// user (a query).
    static func isChannel(_ name: String) -> Bool {
        guard let first = name.first else { return false }
        return "#&+!".contains(first)
    }

    /// Drops the status prefixes a NAMES line puts in front of a nick.
    static func stripNickPrefixes(_ nick: String) -> String {
        var name = nick
        while let first = name.first, "~&@%+".contains(first) {
            name.removeFirst()
        }
        return name
    }

    /// Channel and nick lookups are case-insensitive in IRC.
    static func key(_ name: String) -> String {
        name.lowercased()
    }

    /// A channel name as the client sends it: a leading "#" is added when the
    /// typed name has no channel prefix at all.
    static func channel(_ raw: String) -> String? {
        var name = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, !name.contains(" "), !name.contains(",") else { return nil }
        if !isChannel(name) {
            name = "#" + name
        }
        guard name.count > 1 else { return nil }
        return name
    }
}

// MARK: - Text

enum I2PIRCText {
    /// The CTCP delimiter (a single 0x01 byte).
    static let ctcpDelimiter = "\u{01}"

    /// The largest text one PRIVMSG should carry: an IRC line is capped at 512
    /// bytes including the command and CRLF, so the text gets a safe ceiling.
    static let messageLimit = 400

    /// Removes the bytes that would break a line on the wire.
    static func stripLineBreaks(_ text: String) -> String {
        var out = ""
        for character in text {
            switch character {
            case "\r", "\n", "\u{00}", "\u{01}":
                out.append(" ")
            default:
                out.append(character)
            }
        }
        return out
    }

    /// Cleans text for display and for a send: control characters and line
    /// breaks collapse to single spaces, and both ends are trimmed.
    static func sanitize(_ text: String) -> String {
        var scalars: [Unicode.Scalar] = []
        var lastWasSpace = false
        for scalar in stripLineBreaks(text).unicodeScalars {
            if scalar.properties.generalCategory == .control {
                continue
            }
            if scalar.value == 0x20 || scalar.value == 0x09 {
                if !lastWasSpace, !scalars.isEmpty {
                    scalars.append(" ")
                }
                lastWasSpace = true
                continue
            }
            scalars.append(scalar)
            lastWasSpace = false
        }
        while let last = scalars.last, last.value == 0x20 {
            scalars.removeLast()
        }
        return String(String.UnicodeScalarView(scalars))
    }

    /// Splits a message into IRC-sized pieces on word boundaries where it can,
    /// so a long message arrives whole instead of being cut off by the server.
    static func split(_ text: String, limit: Int = I2PIRCText.messageLimit) -> [String] {
        let clean = sanitize(text)
        guard !clean.isEmpty, limit > 0 else { return [] }
        if clean.utf8.count <= limit { return [clean] }
        var out: [String] = []
        var current = ""
        for word in clean.split(separator: " ", omittingEmptySubsequences: true) {
            let candidate = current.isEmpty ? String(word) : current + " " + word
            if candidate.utf8.count <= limit {
                current = candidate
                continue
            }
            if !current.isEmpty {
                out.append(current)
                current = ""
            }
            if word.utf8.count <= limit {
                current = String(word)
                continue
            }
            // A single word longer than the limit is cut by characters.
            var piece = ""
            for character in word {
                if (piece + String(character)).utf8.count > limit {
                    out.append(piece)
                    piece = String(character)
                } else {
                    piece.append(character)
                }
            }
            current = piece
        }
        if !current.isEmpty { out.append(current) }
        return out
    }

    /// The body of a CTCP ACTION message (`/me`), or nil when the text is not
    /// one. Any other CTCP request returns nil too, so it is never shown.
    static func actionBody(_ text: String) -> String? {
        guard text.hasPrefix(ctcpDelimiter),
              text.hasSuffix(ctcpDelimiter),
              text.count >= 2 else { return nil }
        let inner = String(text.dropFirst().dropLast())
        guard inner.hasPrefix("ACTION") else { return nil }
        let body = inner.dropFirst("ACTION".count)
        return sanitize(String(body))
    }

    /// Whether the text is any CTCP request.
    static func isCTCP(_ text: String) -> Bool {
        text.hasPrefix(ctcpDelimiter)
    }

    /// The CTCP-encoded form of an action message.
    static func action(_ text: String) -> String {
        ctcpDelimiter + "ACTION " + sanitize(text) + ctcpDelimiter
    }
}

// MARK: - Self-test suite (IRC protocol)

enum I2PIRCProtocolSelfTest {
    static func runAll() -> [I2PSelfTestResult] {
        var results: [I2PSelfTestResult] = []
        func run(_ name: String, _ body: () throws -> String) {
            do {
                results.append(I2PSelfTestResult(name: name, passed: true, detail: try body()))
            } catch {
                results.append(I2PSelfTestResult(name: name, passed: false,
                                                 detail: String(describing: error)))
            }
        }

        run("irc · line grammar parses prefix, params and trailing text") {
            let line = try unwrap(I2PIRCLine.parse(":alice!a@host PRIVMSG #i2p :hello there"))
            guard line.prefix == "alice!a@host",
                  line.nick == "alice",
                  line.command == "PRIVMSG",
                  line.params == ["#i2p", "hello there"],
                  line.target == "#i2p",
                  line.trailing == "hello there" else {
                throw I2PWireError.invalidFormat
            }
            // A numeric carries our nick first; its sentence is the last param.
            let numeric = try unwrap(I2PIRCLine.parse(":irc.server 372 tester :  a motd line"))
            guard numeric.isNumeric, numeric.numeric == 372,
                  numeric.params == ["tester", "  a motd line"] else {
                throw I2PWireError.invalidFormat
            }
            // A trailling may be empty, and a line with no prefix has no nick.
            let emptyTrailing = try unwrap(I2PIRCLine.parse("PING :"))
            guard emptyTrailing.nick == nil, emptyTrailing.params == [""] else {
                throw I2PWireError.invalidFormat
            }
            guard I2PIRCLine.parse("") == nil, I2PIRCLine.parse("   ") == nil else {
                throw I2PWireError.invalidFormat
            }
            return "prefix, command, params and an empty trailing parse distinctly; blank lines are dropped"
        }

        run("irc · line grammar handles IRCv3 tags and serializes back") {
            let line = try unwrap(I2PIRCLine.parse("@time=2024-01-01T00:00:00.000Z;msgid=abc :n!u@h PRIVMSG #x :a;b c\\sd"))
            guard line.tags["msgid"] == "abc",
                  line.tags["time"] == "2024-01-01T00:00:00.000Z",
                  line.params == ["#x", "a;b c\\sd"] else {
                throw I2PWireError.invalidFormat
            }
            // Tag escaping round-trips through serialization.
            let encoded = I2PIRCLine(tags: ["k": "a;b c\\d"], prefix: "n!u@h",
                                     command: "PRIVMSG", params: ["#x", "hello there"])
            let reparsed = try unwrap(I2PIRCLine.parse(encoded.serialize()))
            guard reparsed.tags["k"] == "a;b c\\d",
                  reparsed.nick == "n",
                  reparsed.params == ["#x", "hello there"] else {
                throw I2PWireError.invalidFormat
            }
            // The last param gets its colon only when it needs one.
            guard I2PIRCLine(tags: [:], prefix: nil, command: "NICK", params: ["tester"]).serialize() == "NICK tester",
                  I2PIRCLine(tags: [:], prefix: nil, command: "PRIVMSG",
                             params: ["#x", "hi there"]).serialize() == "PRIVMSG #x :hi there" else {
                throw I2PWireError.invalidFormat
            }
            return "tags with escaping round-trip; the trailing colon appears only when needed"
        }

        run("irc · channel, nick-prefix and text rules") {
            guard I2PIRCName.isChannel("#i2p"),
                  I2PIRCName.isChannel("&local"),
                  !I2PIRCName.isChannel("alice"),
                  I2PIRCName.stripNickPrefixes("@+alice") == "alice",
                  I2PIRCName.stripNickPrefixes("alice") == "alice",
                  I2PIRCName.channel("i2p") == "#i2p",
                  I2PIRCName.channel("#i2p") == "#i2p",
                  I2PIRCName.channel("  #I2P  ") == "#I2P",
                  I2PIRCName.channel("") == nil,
                  I2PIRCName.channel("a b") == nil,
                  I2PIRCName.channel("#") == nil else {
                throw I2PWireError.invalidFormat
            }
            // A message split at the limit never exceeds it and loses no words.
            // The fixture is built past the 400-byte ceiling on purpose: a
            // shorter one arrives whole and proves nothing about splitting.
            let long = (0..<80).map { "word\($0)" }.joined(separator: " ")
            guard long.utf8.count > I2PIRCText.messageLimit else {
                throw I2PWireError.invalidFormat
            }
            let pieces = I2PIRCText.split(long)
            guard pieces.count > 1,
                  pieces.allSatisfy({ $0.utf8.count <= I2PIRCText.messageLimit }),
                  pieces.joined(separator: " ") == long else {
                throw I2PWireError.invalidFormat
            }
            // A single oversized word is cut by characters, never by bytes.
            let huge = String(repeating: "é", count: 600)
            let cut = I2PIRCText.split(huge)
            guard cut.count > 1,
                  cut.allSatisfy({ $0.utf8.count <= I2PIRCText.messageLimit }),
                  cut.joined() == huge else {
                throw I2PWireError.invalidFormat
            }
            // Line breaks and control characters never reach the wire.
            guard I2PIRCText.sanitize("  hello \r\n world\u{00}\u{01}  ") == "hello world",
                  !I2PIRCText.sanitize("a\nb").contains("\n") else {
                throw I2PWireError.invalidFormat
            }
            return "channel prefixes, status prefixes, splitting at the byte ceiling and line-break stripping all hold"
        }

        run("irc · CTCP action encoding and decoding") {
            let encoded = I2PIRCText.action("waves hello")
            guard encoded == "\u{01}ACTION waves hello\u{01}",
                  I2PIRCText.isCTCP(encoded),
                  I2PIRCText.actionBody(encoded) == "waves hello",
                  I2PIRCText.actionBody("\u{01}VERSION\u{01}") == nil,
                  I2PIRCText.actionBody("plain text") == nil,
                  I2PIRCText.actionBody("\u{01}ACTION\u{01}") == "" else {
                throw I2PWireError.invalidFormat
            }
            return "ACTION round-trips; other CTCP requests are recognised and never rendered as text"
        }

        run("irc · server addresses parse for every I2P host form") {
            // A named host with a port and a path.
            let named = try I2PIRCHost.parse("IRC.Postman.I2P:6667/some/path")
            guard named.displayHost == "irc.postman.i2p", named.port == 6667,
                  case .name(let name) = named.target, name == "irc.postman.i2p" else {
                throw I2PWireError.invalidFormat
            }
            // A b32 host decodes to its destination hash.
            let hash = I2PCrypto.sha256(Data("irc".utf8))
            let b32 = try I2PIRCHost.parse(I2PSAMEncoding.base32Encode(hash) + ".b32.i2p")
            guard case .b32(let decoded) = b32.target, decoded == hash else {
                throw I2PWireError.invalidFormat
            }
            // A b33 address is used in its 57-character form.
            let b33Address = try I2PB33Blinding.blind(
                destinationSeed: I2PCrypto.generateEd25519Seed(),
                encryptionPublicKey: I2PCrypto.generateX25519KeyPair().publicKey).b33Address
            let b33 = try I2PIRCHost.parse(b33Address)
            guard case .b33(let blinded) = b33.target, blinded == b33Address,
                  b33.displayHost == "\(b33Address).b33.i2p" else {
                throw I2PWireError.invalidFormat
            }
            // A typed base64 destination (which may contain "/") is not split
            // into a host and a path.
            let x25519 = I2PCrypto.generateX25519KeyPair()
            let signingSeed = I2PCrypto.generateEd25519Seed()
            let destination = I2PKeysAndCert(
                encryptionPublicKey: x25519.publicKey,
                signingPublicKey: I2PCrypto.ed25519PublicKey(fromSeed: signingSeed))
            let pasted = try I2PIRCHost.parse("  " + destination.raw.base64EncodedString() + "  ")
            guard case .destination(let parsedDestination) = pasted.target,
                  parsedDestination.hash == destination.hash else {
                throw I2PWireError.invalidFormat
            }
            // Clear-net names and unusable ports are refused.
            for bad in ["example.com", "", "   ", "irc.example.i2p:99999", "irc.example.i2p:0"] {
                do {
                    _ = try I2PIRCHost.parse(bad)
                    throw I2PWireError.invalidFormat
                } catch is I2PIRCFailure {}
            }
            return ".i2p name, b32, b33 and base64 destination parse; clear-net names and bad ports refused"
        }

        run("irc · a dropped stream retries on a 5, 15, 30 and 60 second backoff") {
            let expected: [TimeInterval?] = [5, 15, 30, 60]
            let schedule = (1...4).map { I2PIRCReconnectPolicy.delay(forAttempt: $0) }
            guard schedule == expected,
                  I2PIRCReconnectPolicy.attemptLimit == 4,
                  I2PIRCReconnectPolicy.delay(forAttempt: 0) == nil,
                  I2PIRCReconnectPolicy.delay(forAttempt: 5) == nil else {
                throw I2PWireError.invalidFormat
            }
            guard I2PIRCReconnectPolicy.line(attempt: 2, seconds: 15)
                    == "Reconnecting in 15s · attempt 2 of 4",
                  I2PIRCReconnectPolicy.line(attempt: 4, seconds: 1)
                    == "Reconnecting in 1s · attempt 4 of 4" else {
                throw I2PWireError.invalidFormat
            }
            return "four retries at 5, 15, 30 and 60 seconds — nothing before the first or after the fourth — and the header names the countdown with the attempt"
        }

        return results
    }

    private static func unwrap<T>(_ value: T?) throws -> T {
        guard let value else { throw I2PWireError.truncated }
        return value
    }
}
