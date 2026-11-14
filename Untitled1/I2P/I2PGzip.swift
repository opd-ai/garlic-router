//
//  I2PGzip.swift
//  RFC 1952 gzip framing over raw DEFLATE (Compression framework), used by
//  DatabaseStore: RouterInfo payloads are ALWAYS gzip-compressed and preceded
//  by a 2-byte compressed size; a receiver must not sniff or fall back.
//

import Foundation
import Compression

enum I2PGzipError: Error {
    case invalidHeader
    case compressionFailed
    case decompressionFailed
}

enum I2PGzip {
    /// Gzip-compresses with the header Java I2P emits (mtime 0, OS 0xFF, XFL 2).
    /// Falls back to RFC 1951 stored blocks if the compressor refuses, so a
    /// type-0 DatabaseStore always carries valid gzip rather than plain bytes.
    static func compress(_ data: Data) -> Data {
        var compressed = Data([0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xFF])
        compressed.append((try? rawDeflate(data)) ?? storedDeflate(data))
        var crc = crc32(data).littleEndian
        withUnsafeBytes(of: &crc) { compressed.append(contentsOf: $0) }
        var size = UInt32(truncatingIfNeeded: data.count).littleEndian
        withUnsafeBytes(of: &size) { compressed.append(contentsOf: $0) }
        return compressed
    }

    /// Uncompressed DEFLATE blocks (BTYPE 00), used only when the compressor
    /// fails: still a valid gzip body every reference router can inflate.
    private static func storedDeflate(_ data: Data) -> Data {
        let bytes = Array(data)
        var out = Data()
        if bytes.isEmpty {
            out.append(0x01)
            out.append(contentsOf: [0x00, 0x00, 0xFF, 0xFF])
            return out
        }
        var offset = 0
        while offset < bytes.count {
            let count = min(65_535, bytes.count - offset)
            let isFinal = offset + count >= bytes.count
            out.append(isFinal ? 0x01 : 0x00)
            var len = UInt16(count).littleEndian
            withUnsafeBytes(of: &len) { out.append(contentsOf: $0) }
            var nlen = UInt16(~count).littleEndian
            withUnsafeBytes(of: &nlen) { out.append(contentsOf: $0) }
            out.append(contentsOf: bytes[offset..<(offset + count)])
            offset += count
        }
        return out
    }

    /// Decompresses a gzip stream after validating the header; the 8-byte
    /// trailer (CRC32 + ISIZE) is verified after inflation.
    static func decompress(_ data: Data) throws -> Data {
        let bytes = Array(data)
        guard bytes.count >= 18,
              bytes[0] == 0x1F, bytes[1] == 0x8B, bytes[2] == 0x08 else {
            throw I2PGzipError.invalidHeader
        }
        let flags = bytes[3]
        var offset = 10
        if flags & 0x04 != 0 { // FEXTRA
            guard offset + 2 <= bytes.count else { throw I2PGzipError.invalidHeader }
            let extraLength = Int(bytes[offset]) | (Int(bytes[offset + 1]) << 8)
            offset += 2 + extraLength
        }
        if flags & 0x08 != 0 { // FNAME
            while offset < bytes.count, bytes[offset] != 0 { offset += 1 }
            offset += 1
        }
        if flags & 0x10 != 0 { // FCOMMENT
            while offset < bytes.count, bytes[offset] != 0 { offset += 1 }
            offset += 1
        }
        if flags & 0x02 != 0 { // FHCRC
            offset += 2
        }
        guard offset <= bytes.count - 8 else { throw I2PGzipError.invalidHeader }
        let body = Data(bytes[offset..<(bytes.count - 8)])
        let plain = try rawInflate(body)
        // Trailer integrity: CRC32 and ISIZE must match the inflated body.
        var expectedCRC: UInt32 = 0
        for index in 0..<4 { expectedCRC |= UInt32(bytes[bytes.count - 8 + index]) << (8 * UInt32(index)) }
        var expectedSize: UInt32 = 0
        for index in 0..<4 { expectedSize |= UInt32(bytes[bytes.count - 4 + index]) << (8 * UInt32(index)) }
        guard crc32(plain) == expectedCRC,
              UInt32(truncatingIfNeeded: plain.count) == expectedSize else {
            throw I2PGzipError.decompressionFailed
        }
        return plain
    }

    // MARK: DEFLATE

    private static func rawDeflate(_ data: Data) throws -> Data {
        var capacity = max(256, data.count + 1024)
        while capacity <= 4 * 1024 * 1024 {
            var output = Data(count: capacity)
            let written = output.withUnsafeMutableBytes { dst -> Int in
                data.withUnsafeBytes { src -> Int in
                    guard let dstBase = dst.bindMemory(to: UInt8.self).baseAddress,
                          let srcBase = src.bindMemory(to: UInt8.self).baseAddress else { return 0 }
                    return compression_encode_buffer(dstBase, capacity, srcBase, data.count,
                                                     nil, COMPRESSION_ZLIB)
                }
            }
            if written > 0 {
                output.removeSubrange(written..<output.count)
                return output
            }
            capacity *= 2
        }
        throw I2PGzipError.compressionFailed
    }

    private static func rawInflate(_ data: Data) throws -> Data {
        var capacity = max(4096, data.count * 8)
        while capacity <= 40 * 1024 * 1024 {
            var output = Data(count: capacity)
            let written = output.withUnsafeMutableBytes { dst -> Int in
                data.withUnsafeBytes { src -> Int in
                    guard let dstBase = dst.bindMemory(to: UInt8.self).baseAddress,
                          let srcBase = src.bindMemory(to: UInt8.self).baseAddress else { return 0 }
                    return compression_decode_buffer(dstBase, capacity, srcBase, data.count,
                                                     nil, COMPRESSION_ZLIB)
                }
            }
            if written > 0, written < capacity {
                output.removeSubrange(written..<output.count)
                return output
            }
            capacity *= 2
        }
        throw I2PGzipError.decompressionFailed
    }

    // MARK: CRC32

    private static let crcTable: [UInt32] = (0..<256).map { index -> UInt32 in
        var value = UInt32(index)
        for _ in 0..<8 {
            value = (value & 1) != 0 ? (0xEDB8_8320 ^ (value >> 1)) : (value >> 1)
        }
        return value
    }

    static func crc32(_ data: Data) -> UInt32 {
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in data {
            crc = crcTable[Int((crc ^ UInt32(byte)) & 0xFF)] ^ (crc >> 8)
        }
        return crc ^ 0xFFFF_FFFF
    }
}
