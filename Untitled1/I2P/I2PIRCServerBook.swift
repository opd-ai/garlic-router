//
//  I2PIRCServerBook.swift
//  The IRC servers the user keeps: a display name, the I2P address, the port,
//  the nick to register with, the channels to join on connect and an optional
//  server password. Persisted across launches in user defaults, like the
//  browser's saved hosts.
//

import Foundation
import Combine

// MARK: - Entry

/// One saved IRC server.
struct I2PIRCServerEntry: Codable, Identifiable, Equatable {
    var id: UUID
    /// What the list calls the server; the host when it is left empty.
    var name: String
    /// The I2P address: a .i2p name, a b32 host, a b33 address or a base64
    /// destination. A typed :port is honoured by the connection too.
    var host: String
    var port: UInt16
    var nick: String
    /// Sent as PASS before the nick when it is not empty.
    var password: String
    /// Channels joined as soon as the server accepts the registration.
    var channels: [String]

    static let defaultPort: UInt16 = 6667

    init(id: UUID = UUID(),
         name: String = "",
         host: String = "",
         port: UInt16 = I2PIRCServerEntry.defaultPort,
         nick: String = "",
         password: String = "",
         channels: [String] = []) {
        self.id = id
        self.name = name
        self.host = host
        self.port = port
        self.nick = nick
        self.password = password
        self.channels = channels
    }

    var displayName: String {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? host : trimmed
    }

    var address: String {
        let trimmedPort = port == I2PIRCServerEntry.defaultPort ? "" : ":\(port)"
        return host + trimmedPort
    }

    /// Why the entry cannot be saved or connected, or nil when it is usable.
    var validationProblem: String? {
        let trimmedHost = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedHost.isEmpty else {
            return "Add the server's address — an .i2p name, a b32 host, a b33 address or a base64 destination."
        }
        do {
            _ = try I2PIRCHost.parse(trimmedHost)
        } catch let failure as I2PIRCFailure {
            return failure.message
        } catch {
            return "That server address cannot be used."
        }
        let trimmedNick = nick.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedNick.isEmpty else { return "Choose a nick — the server refuses a registration without one." }
        guard !trimmedNick.contains(" "),
              !trimmedNick.contains(","),
              !trimmedNick.contains("#"),
              !trimmedNick.contains(":"),
              !trimmedNick.contains("&") else {
            return "A nick cannot contain spaces, commas, #, : or &."
        }
        guard port > 0 else { return "Pick a port between 1 and 65535." }
        return nil
    }
}

// MARK: - Server book

/// The saved servers, newest first.
final class I2PIRCServerBook: ObservableObject {
    static let shared = I2PIRCServerBook()
    static let defaultsKey = "i2p.irc.servers"

    @Published private(set) var entries: [I2PIRCServerEntry] = []

    private let defaults: UserDefaults
    private let storageKey: String

    init(defaults: UserDefaults = .standard,
         storageKey: String = I2PIRCServerBook.defaultsKey) {
        self.defaults = defaults
        self.storageKey = storageKey
        self.entries = Self.load(defaults: defaults, key: storageKey)
    }

    func entry(_ id: UUID?) -> I2PIRCServerEntry? {
        guard let id else { return nil }
        return entries.first { $0.id == id }
    }

    func contains(host: String, nick: String) -> Bool {
        let hostKey = host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let nickKey = nick.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return entries.contains {
            $0.host.lowercased() == hostKey && $0.nick.lowercased() == nickKey
        }
    }

    /// Adds a server, or replaces the entry with the same id. A server that
    /// cannot pass validation is refused and false is returned.
    @discardableResult
    func save(_ entry: I2PIRCServerEntry) -> Bool {
        guard entry.validationProblem == nil else { return false }
        var cleaned = entry
        cleaned.name = entry.name.trimmingCharacters(in: .whitespacesAndNewlines)
        cleaned.host = entry.host.trimmingCharacters(in: .whitespacesAndNewlines)
        cleaned.nick = entry.nick.trimmingCharacters(in: .whitespacesAndNewlines)
        cleaned.channels = Self.channels(from: entry.channels.joined(separator: ","))
        if let index = entries.firstIndex(where: { $0.id == cleaned.id }) {
            entries[index] = cleaned
        } else {
            entries.insert(cleaned, at: 0)
        }
        persist()
        return true
    }

    func remove(_ id: UUID) {
        let before = entries.count
        entries.removeAll { $0.id == id }
        guard entries.count != before else { return }
        persist()
    }

    // MARK: Channel list

    /// Parses the channels field of the form: comma- or space-separated names,
    /// with the "#" added when a name lacks a channel prefix, de-duplicated
    /// case-insensitively in the order typed.
    static func channels(from raw: String) -> [String] {
        var out: [String] = []
        var seen: Set<String> = []
        let pieces = raw.split(whereSeparator: { $0 == "," || $0 == " " || $0 == "\n" || $0 == "\t" })
        for piece in pieces {
            guard let channel = I2PIRCName.channel(String(piece)) else { continue }
            let key = I2PIRCName.key(channel)
            guard !seen.contains(key) else { continue }
            seen.insert(key)
            out.append(channel)
        }
        return out
    }

    /// The channels field text for a saved server.
    static func channelListText(_ channels: [String]) -> String {
        channels.joined(separator: ", ")
    }

    // MARK: Persistence

    private func persist() {
        guard let data = try? JSONEncoder().encode(entries) else { return }
        defaults.set(data, forKey: storageKey)
    }

    private static func load(defaults: UserDefaults, key: String) -> [I2PIRCServerEntry] {
        guard let data = defaults.data(forKey: key),
              let decoded = try? JSONDecoder().decode([I2PIRCServerEntry].self, from: data) else {
            return []
        }
        return decoded
    }
}

// MARK: - Self-test suite (IRC server book)

enum I2PIRCServerBookSelfTest {
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

        run("irc · server book saves, validates and persists entries") {
            let suite = "i2p.irc.serverBook.selfTest"
            let defaults = UserDefaults(suiteName: suite) ?? .standard
            defaults.removePersistentDomain(forName: suite)
            let store = I2PIRCServerBook(defaults: defaults, storageKey: "servers")

            let valid = I2PIRCServerEntry(name: "  Postman  ",
                                          host: " irc.postman.i2p ",
                                          port: 6667,
                                          nick: " tester ",
                                          channels: ["#i2p"])
            guard store.save(valid) else { throw I2PWireError.invalidFormat }
            guard let saved = store.entries.first,
                  saved.name == "Postman",
                  saved.host == "irc.postman.i2p",
                  saved.nick == "tester",
                  saved.displayName == "Postman",
                  saved.address == "irc.postman.i2p",
                  store.entries.count == 1 else {
                throw I2PWireError.invalidFormat
            }
            // A custom port is part of the address line.
            var custom = I2PIRCServerEntry(name: "Local", host: "irc.example.i2p",
                                           port: 6697, nick: "tester")
            guard store.save(custom) else { throw I2PWireError.invalidFormat }
            guard store.entries.first?.address == "irc.example.i2p:6697" else {
                throw I2PWireError.invalidFormat
            }
            // An entry with no host, a clear-net host, a bad nick or port 0 is
            // refused and changes nothing.
            for bad in [
                I2PIRCServerEntry(host: "", nick: "tester"),
                I2PIRCServerEntry(host: "example.com", nick: "tester"),
                I2PIRCServerEntry(host: "irc.example.i2p", nick: "bad nick"),
                I2PIRCServerEntry(host: "irc.example.i2p", port: 0, nick: "tester")
            ] {
                guard bad.validationProblem != nil, store.save(bad) == false else {
                    throw I2PWireError.invalidFormat
                }
            }
            // Saving the same id edits in place; the list keeps its order.
            custom.name = "Renamed"
            guard store.save(custom), store.entries.count == 2,
                  store.entry(custom.id)?.name == "Renamed" else {
                throw I2PWireError.invalidFormat
            }
            // The list survives a relaunch, and removal sticks.
            let reopened = I2PIRCServerBook(defaults: defaults, storageKey: "servers")
            guard reopened.entries.count == 2,
                  reopened.entry(custom.id)?.name == "Renamed" else {
                throw I2PWireError.invalidFormat
            }
            reopened.remove(custom.id)
            guard I2PIRCServerBook(defaults: defaults, storageKey: "servers").entries.count == 1 else {
                throw I2PWireError.invalidFormat
            }
            defaults.removePersistentDomain(forName: suite)
            return "trimmed entry saved and persisted; an edit replaces in place; clear-net host, bad nick and port 0 refused"
        }

        run("irc · channel list parsing normalizes names") {
            let channels = I2PIRCServerStoreChannels.parse("i2p, #help  I2P ,, #I2P")
            guard channels == ["#i2p", "#help"] else { throw I2PWireError.invalidFormat }
            guard I2PIRCServerStoreChannels.parse("") == [],
                  I2PIRCServerStoreChannels.parse(", ,") == [],
                  I2PIRCServerStoreChannels.text(channels) == "#i2p, #help" else {
                throw I2PWireError.invalidFormat
            }
            return "channel names gain their #, fold case for de-duplication and keep the typed order"
        }

        return results
    }
}

/// Small accessor so the channel rules are testable by name.
enum I2PIRCServerStoreChannels {
    static func parse(_ raw: String) -> [String] {
        I2PIRCServerBook.channels(from: raw)
    }

    static func text(_ channels: [String]) -> String {
        I2PIRCServerBook.channelListText(channels)
    }
}
