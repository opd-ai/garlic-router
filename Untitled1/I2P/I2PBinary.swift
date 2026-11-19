//
//  I2PBinary.swift
//  I2P big-endian binary wire format: encoder/decoder for all primitive types
//  (byte, short, integer, long, hash, string, mapping, date) per the I2P
//  common-structures specification.
//

import Foundation

enum I2PWireError: Error {
    case truncated
    case invalidFormat
    case unsupportedAlgorithm
    case invalidSignature
    case trailingData
}

struct I2PWriter {
    private(set) var data = Data()

    mutating func byte(_ value: UInt8) { data.append(value) }

    mutating func short(_ value: UInt16) {
        data.append(UInt8((value >> 8) & 0xff))
        data.append(UInt8(value & 0xff))
    }

    mutating func integer(_ value: UInt32) {
        for shift in stride(from: 24, through: 0, by: -8) {
            data.append(UInt8((value >> UInt32(shift)) & 0xff))
        }
    }

    mutating func long(_ value: UInt64) {
        for shift in stride(from: 56, through: 0, by: -8) {
            data.append(UInt8((value >> UInt64(shift)) & 0xff))
        }
    }

    mutating func raw(_ bytes: Data) { data.append(bytes) }

    /// I2P Hash: exactly 32 bytes.
    ///
    /// The precondition is a programmer-error detector, not an input check:
    /// every caller passes a computed SHA-256, and no value that came off the
    /// wire reaches it at another length (`I2PReader.hash()` always reads 32).
    mutating func hash(_ value: Data) {
        precondition(value.count == 32, "I2P hash is 32 bytes")
        data.append(value)
    }

    /// I2P String: 1-byte length prefix followed by UTF-8 data.
    ///
    /// The 255-byte precondition is likewise a programmer-error detector: a
    /// parsed string's length came from that one byte, so re-encoding a value
    /// read off the wire can never exceed it.
    mutating func string(_ value: String) {
        let utf8 = Array(value.utf8)
        precondition(utf8.count <= 255, "I2P string length exceeds 255 bytes")
        byte(UInt8(utf8.count))
        data.append(contentsOf: utf8)
    }

    /// I2P Mapping: 2-byte big-endian length of the body, then
    /// `[len][key]=[len][value];` pairs (keys sorted for deterministic
    /// encoding). The '=' and ';' separators are part of the wire format —
    /// without them every real RouterInfo/LeaseSet2 options mapping mis-parses.
    ///
    /// Keys and values are limited to 255 bytes and the body to 65,535 by those
    /// on-wire length fields, so a mapping parsed from the wire always
    /// re-encodes within them — pinned by `T4-ST-MAPPING-BOUNDS`. Only a
    /// locally built mapping that broke those limits could trap here.
    mutating func mapping(_ value: [String: String]) {
        var body = Data()
        for key in value.keys.sorted() {
            let k = Array(key.utf8)
            let v = Array(value[key]!.utf8)
            body.append(UInt8(k.count))
            body.append(contentsOf: k)
            body.append(0x3D) // '='
            body.append(UInt8(v.count))
            body.append(contentsOf: v)
            body.append(0x3B) // ';'
        }
        short(UInt16(body.count))
        raw(body)
    }

    /// 8-byte big-endian milliseconds since the Unix epoch; 0 encodes "none".
    mutating func date(_ value: Date?) {
        long(value.map { UInt64(($0.timeIntervalSince1970 * 1000).rounded()) } ?? 0)
    }
}

struct I2PReader {
    let bytes: [UInt8]
    var offset = 0

    init(_ data: Data) { bytes = Array(data) }

    var remaining: Int { bytes.count - offset }

    mutating func byte() throws -> UInt8 {
        guard remaining >= 1 else { throw I2PWireError.truncated }
        defer { offset += 1 }
        return bytes[offset]
    }

    mutating func raw(_ count: Int) throws -> Data {
        guard remaining >= count else { throw I2PWireError.truncated }
        defer { offset += count }
        return Data(bytes[offset..<(offset + count)])
    }

    mutating func short() throws -> UInt16 {
        let d = try raw(2)
        return (UInt16(d[0]) << 8) | UInt16(d[1])
    }

    mutating func integer() throws -> UInt32 {
        let d = try raw(4)
        return (UInt32(d[0]) << 24) | (UInt32(d[1]) << 16) | (UInt32(d[2]) << 8) | UInt32(d[3])
    }

    mutating func long() throws -> UInt64 {
        let d = try raw(8)
        var value: UInt64 = 0
        for b in d { value = (value << 8) | UInt64(b) }
        return value
    }

    mutating func hash() throws -> Data { try raw(32) }

    mutating func string() throws -> String {
        let length = Int(try byte())
        let d = try raw(length)
        return String(decoding: d, as: UTF8.self)
    }

    mutating func mapping() throws -> [String: String] {
        let length = Int(try short())
        let body = try raw(length)
        var inner = I2PReader(body)
        var result: [String: String] = [:]
        while inner.remaining > 0 {
            let key = try inner.string()
            guard try inner.byte() == 0x3D else { throw I2PWireError.invalidFormat } // '='
            let value = try inner.string()
            guard try inner.byte() == 0x3B else { throw I2PWireError.invalidFormat } // ';'
            result[key] = value
        }
        return result
    }

    mutating func date() throws -> Date? {
        let ms = try long()
        return ms == 0 ? nil : Date(timeIntervalSince1970: Double(ms) / 1000)
    }
}