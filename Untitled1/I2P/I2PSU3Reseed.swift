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
//  signature is NOT verified — a documented deviation: RSA/ECDSA container
//  signatures sit outside the modern crypto stack. Integrity rides on the
//  HTTPS transport, and every RouterInfo inside is Ed25519 signature-verified
//  again when ingested into the netdb.
//
//  Zip layout: end-of-central-directory scan, central directory entries and
//  local headers; entries are stored (method 0) or raw-deflate (method 8),
//  decompressed through the Compression framework's zlib codec.
//

import Foundation
import Compression

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
    case invalidSU3(String)
    case invalidZip(String)
}

enum I2PReseedService {
    /// Well-known public reseed servers (HTTPS, SU3 reseed files).
    static let hosts = [
        "https://reseed.i2p-projekt.de/",
        "https://reseed.diva.exchange/",
        "https://reseed.milli.pe/",
        "https://www.torontocrypto.org:8443/",
        "https://banana.incognet.io/",
    ]

    /// Fetches the first working reseed host, parses the SU3 container,
    /// unpacks the RouterInfo entries and ingests them (signature verified)
    /// into the netdb.
    static func reseed(into netDB: I2PNetworkDatabase, deferCount: Int = 2) async throws -> I2PReseedReport {
        var lastError: Error = I2PReseedError.allHostsFailed
        for host in hosts {
            do {
                return try await reseed(from: host, into: netDB, deferCount: deferCount)
            } catch {
                lastError = error
            }
        }
        throw lastError
    }

    static func reseed(from host: String, into netDB: I2PNetworkDatabase, deferCount: Int) async throws -> I2PReseedReport {
        guard let url = URL(string: host) else {
            throw I2PReseedError.invalidSU3("invalid reseed host url")
        }
        var request = URLRequest(url: url)
        request.timeoutInterval = 8
        request.setValue("I2P-Swift-Router/0.1", forHTTPHeaderField: "User-Agent")
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            throw I2PReseedError.allHostsFailed
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
    }

    // MARK: SU3 container

    static func parseSU3(_ data: Data) throws -> Data {
        let bytes = [UInt8](data)
        guard bytes.count >= 33 else {
            throw I2PReseedError.invalidSU3("truncated SU3 header")
        }
        let magic = Array("I2Psu3".utf8)
        guard Array(bytes[0..<6]) == magic else {
            throw I2PReseedError.invalidSU3("bad SU3 magic")
        }
        let signatureLength = Int(u16(bytes, 10))
        let paddingLength = Int(bytes[12])
        let versionLength = Int(u16(bytes, 13))
        let signerLength = Int(u16(bytes, 15))
        let contentLength = Int(u64(bytes, 17))
        let headerEnd = 33 + versionLength + signerLength
        let contentStart = headerEnd
        let contentEnd = contentStart + contentLength
        guard contentLength > 0 else {
            throw I2PReseedError.invalidSU3("empty SU3 content")
        }
        guard bytes.count >= contentEnd + signatureLength + paddingLength else {
            throw I2PReseedError.invalidSU3("content length exceeds the file")
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