//
//  I2PNetDBStorage.swift
//  Persistent on-disk storage for Network Database entries. Entries are stored
//  as raw serialized RouterInfo/LeaseSet payloads; on restore they are re-parsed
//  (re-verifying signatures) and unverifiable or expired records are discarded.
//

import Foundation

final class I2PNetDBStorage {
    struct Record: Codable {
        let entryType: UInt8
        let storedAt: Date
        let expiresAt: Date
        let payload: Data
    }

    private let directory: URL

    /// - Parameter directory: explicit directory (used by tests); defaults to
    ///   Application Support/I2PNetDB.
    init(directory: URL? = nil) throws {
        if let directory {
            self.directory = directory
        } else {
            let base = try FileManager.default.url(
                for: .applicationSupportDirectory,
                in: .userDomainMask,
                appropriateFor: nil,
                create: true
            )
            self.directory = base.appendingPathComponent("I2PNetDB", isDirectory: true)
        }
        try FileManager.default.createDirectory(at: self.directory, withIntermediateDirectories: true)
    }

    func persist(key: Data, record: Record) throws {
        let data = try JSONEncoder().encode(record)
        try data.write(to: fileURL(key), options: [.atomic])
    }

    /// Loads every persisted record; corrupt or malformed files are removed.
    func loadAll() -> [(key: Data, record: Record)] {
        let fm = FileManager.default
        guard let names = try? fm.contentsOfDirectory(atPath: directory.path) else {
            return []
        }
        var out: [(key: Data, record: Record)] = []
        for name in names where name.hasSuffix(".json") {
            let url = directory.appendingPathComponent(name)
            guard let data = try? Data(contentsOf: url),
                  let record = try? JSONDecoder().decode(Record.self, from: data) else {
                try? fm.removeItem(at: url)
                continue
            }
            let hexName = String(name.dropLast(5)) // strip ".json"
            guard let key = Self.dataFromHex(keyName: hexName),
                  key.count == 32 else {
                // A decodable record whose file name is not a valid 32-byte hex
                // key can never be addressed again — remove() and every restore
                // key off the hex name — so it would survive every load forever
                // as unaddressable state. Fail closed: reclaim the orphan.
                try? fm.removeItem(at: url)
                continue
            }
            out.append((key, record))
        }
        return out
    }

    func remove(key: Data) {
        try? FileManager.default.removeItem(at: fileURL(key))
    }

    private func fileURL(_ key: Data) -> URL {
        directory.appendingPathComponent(key.hex + ".json")
    }

    private static func dataFromHex(keyName string: String) -> Data? {
        guard string.count % 2 == 0 else { return nil }
        var bytes: [UInt8] = []
        var index = string.startIndex
        while index < string.endIndex {
            // Two hex characters per byte: taking one character at a time
            // decoded a 64-character key into 64 bytes, so no restored record
            // ever matched its file name and every one was reclaimed as
            // unaddressable on the next launch.
            guard let end = string.index(index, offsetBy: 2, limitedBy: string.endIndex),
                  let byte = UInt8(string[index..<end], radix: 16) else { return nil }
            bytes.append(byte)
            index = end
        }
        return Data(bytes)
    }
}