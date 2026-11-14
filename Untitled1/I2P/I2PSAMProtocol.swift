//
//  I2PSAMProtocol.swift
//  SAMv3.3 protocol grammar: command parsing, reply formatting, and the
//  encoding helpers (base32 hosts, base64 normalization) used by the bridge.
//

import Foundation

/// SAM session styles.
enum I2PSAMStyle: String {
    case stream = "STREAM"
    case datagram = "DATAGRAM"
    case raw = "RAW"
}

/// Bridge errors; mapped onto SAM result codes by I2PSAMReply.
enum I2PSAMError: Error {
    case invalidCommand(String)
    case duplicatedID
    case destinationNotFound
    case invalidDestination
    case unreachable
    case noTunnels
    case timeout
}

enum I2PSAMLimits {
    /// Maximum SAM v3 datagram size (spec caps repliable datagrams ~11.5 KB).
    static let maxDatagramSize = 11_520
    /// Garlic payload budget per tunnel message: the stream/datagram chunk size.
    static let chunkSize = 512
    /// Client bytes buffered while a stream handshake completes.
    static let maxStreamBuffer = 65_536
    /// Stream handshake / accept timeouts (seconds).
    static let handshakeTimeout: TimeInterval = 30
}

/// Parsed SAM commands.
enum I2PSAMCommand {
    case hello(minVersion: String, maxVersion: String)
    case sessionCreate(style: I2PSAMStyle, id: String, destination: String, options: [String: String])
    case sessionQuit
    case streamConnect(id: String, destination: String, silent: Bool)
    case streamAccept(id: String, silent: Bool)
    case datagramSend(id: String, destination: String, size: Int)
    case namingLookup(name: String)
    case namingAdd(name: String, destination: String)
    case destGenerate
}

/// SAMv3.3 line grammar: `<VERB> [SUBVERB] KEY=VALUE ...`, newline terminated.
enum I2PSAMGrammar {
    static let version = "3.3"

    static func parse(_ line: String) throws -> I2PSAMCommand {
        let tokens = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
        guard !tokens.isEmpty else { throw I2PSAMError.invalidCommand("empty_line") }
        let options = Self.options(from: tokens)
        func require(_ key: String) throws -> String {
            guard let value = options[key], !value.isEmpty else {
                throw I2PSAMError.invalidCommand("missing_\(key.lowercased())")
            }
            return value
        }
        switch tokens[0] {
        case "HELLO":
            return .hello(minVersion: options["MIN"] ?? "", maxVersion: options["MAX"] ?? "")
        case "SESSION":
            guard tokens.count >= 2 else { throw I2PSAMError.invalidCommand("incomplete_session") }
            switch tokens[1] {
            case "CREATE":
                guard let style = options["STYLE"].flatMap(I2PSAMStyle.init(rawValue:)) else {
                    throw I2PSAMError.invalidCommand("unknown_style")
                }
                return .sessionCreate(style: style,
                                      id: try require("ID"),
                                      destination: try require("DESTINATION"),
                                      options: options)
            case "QUIT":
                return .sessionQuit
            default:
                throw I2PSAMError.invalidCommand("unknown_session_command")
            }
        case "STREAM":
            guard tokens.count >= 2 else { throw I2PSAMError.invalidCommand("incomplete_stream") }
            switch tokens[1] {
            case "CONNECT":
                return .streamConnect(id: try require("ID"),
                                      destination: try require("DESTINATION"),
                                      silent: options["SILENT"] == "true")
            case "ACCEPT":
                return .streamAccept(id: try require("ID"), silent: options["SILENT"] == "true")
            default:
                throw I2PSAMError.invalidCommand("unknown_stream_command")
            }
        case "DATAGRAM":
            guard tokens.count >= 2, tokens[1] == "SEND" else {
                throw I2PSAMError.invalidCommand("unknown_datagram_command")
            }
            guard let size = Int(options["SIZE"] ?? "") else {
                throw I2PSAMError.invalidCommand("missing_size")
            }
            return .datagramSend(id: try require("ID"),
                                 destination: try require("DESTINATION"),
                                 size: size)
        case "NAMING":
            guard tokens.count >= 2 else { throw I2PSAMError.invalidCommand("incomplete_naming") }
            switch tokens[1] {
            case "LOOKUP":
                return .namingLookup(name: try require("NAME"))
            case "ADD":
                return .namingAdd(name: try require("NAME"), destination: try require("DESTINATION"))
            default:
                throw I2PSAMError.invalidCommand("unknown_naming_command")
            }
        case "DEST":
            guard tokens.count >= 2, tokens[1] == "GENERATE" else {
                throw I2PSAMError.invalidCommand("unknown_dest_command")
            }
            return .destGenerate
        default:
            throw I2PSAMError.invalidCommand("unknown_command")
        }
    }

    static func options(from tokens: [String]) -> [String: String] {
        var out: [String: String] = [:]
        for token in tokens.dropFirst() {
            guard let equals = token.firstIndex(of: "=") else { continue }
            let key = String(token[token.startIndex..<equals])
            let value = String(token[token.index(after: equals)...])
            if !key.isEmpty { out[key] = value }
        }
        return out
    }
}

/// SAM reply formatting.
enum I2PSAMReply {
    static func hello(ok: Bool) -> String {
        ok ? "HELLO REPLY RESULT=OK VERSION=\(I2PSAMGrammar.version)"
           : "HELLO REPLY RESULT=NO_VERSION"
    }

    static func sessionStatus(result: String, destination: String? = nil,
                              b33: String? = nil, message: String? = nil) -> String {
        var line = "SESSION STATUS RESULT=\(result)"
        if let destination { line += " DESTINATION=\(destination)" }
        if let b33 { line += " B33=\(b33)" }
        if let message { line += " MESSAGE=\(message)" }
        return line
    }

    static func streamStatus(result: String, id: String? = nil, message: String? = nil) -> String {
        var line = "STREAM STATUS RESULT=\(result)"
        if let id { line += " ID=\(id)" }
        if let message { line += " MESSAGE=\(message)" }
        return line
    }

    static func namingReply(result: String, name: String, value: String? = nil) -> String {
        var line = "NAMING REPLY RESULT=\(result) NAME=\(name)"
        if let value { line += " VALUE=\(value)" }
        return line
    }

    static func destReply(pub: String, priv: String) -> String {
        "DEST REPLY PUB=\(pub) PRIV=\(priv)"
    }

    /// TCP-mode datagram delivery line (UDP-mode clients receive raw datagrams).
    static func datagramReceived(destination: String?, size: Int) -> String {
        var line = "DATAGRAM RECEIVED"
        if let destination, !destination.isEmpty { line += " DESTINATION=\(destination)" }
        line += " SIZE=\(size)"
        return line
    }

    static func resultCode(for error: Error) -> String {
        switch error {
        case I2PSAMError.duplicatedID: return "DUPLICATED_ID"
        case I2PSAMError.destinationNotFound: return "KEY_NOT_FOUND"
        case I2PSAMError.unreachable, I2PSAMError.noTunnels: return "CANT_REACH_PEER"
        case I2PSAMError.timeout: return "TIMEOUT"
        default: return "I2P_ERROR"
        }
    }

    static func error(_ error: Error, prefix: String) -> String {
        let code = resultCode(for: error)
        var message = ""
        if case I2PSAMError.invalidCommand(let reason) = error { message = reason }
        else if case I2PSAMError.invalidDestination = error { message = "invalid_destination" }
        else if case I2PSAMError.timeout = error { message = "timed_out" }
        var line = "\(prefix) RESULT=\(code)"
        if !message.isEmpty { line += " MESSAGE=\(message)" }
        return line
    }
}

/// Base32 (I2P hosts.b32.i2p form) plus tolerant base64 handling.
enum I2PSAMEncoding {
    private static let alphabet = Array("abcdefghijklmnopqrstuvwxyz234567")

    static func base32Encode(_ data: Data) -> String {
        var out = ""
        var value = 0
        var bits = 0
        for byte in data {
            value = (value << 8) | Int(byte)
            bits += 8
            while bits >= 5 {
                bits -= 5
                out.append(alphabet[(value >> bits) & 31])
            }
        }
        if bits > 0 { out.append(alphabet[(value << (5 - bits)) & 31]) }
        return out
    }

    static func base32Decode(_ string: String) -> Data? {
        var value = 0
        var bits = 0
        var out: [UInt8] = []
        for character in string.lowercased() {
            guard let index = alphabet.firstIndex(of: character) else { return nil }
            value = (value << 5) | index
            bits += 5
            if bits >= 8 {
                bits -= 8
                out.append(UInt8((value >> bits) & 0xff))
            }
        }
        return Data(out)
    }

    /// Accepts standard or URL-safe base64 with or without padding.
    static func normalizedBase64(_ text: String) -> Data? {
        var sanitized = text
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
            .replacingOccurrences(of: "\n", with: "")
            .trimmingCharacters(in: .whitespaces)
        while sanitized.count % 4 != 0 { sanitized += "=" }
        return Data(base64Encoded: sanitized)
    }
}