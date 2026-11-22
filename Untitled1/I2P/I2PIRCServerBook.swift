//
//  I2PIRCServerBook.swift
//  The IRC servers the user keeps: a display name, the I2P address, the port,
//  the nick to register with, the channels to join on connect and an optional
//  server password. Server details live in user defaults; passwords live in the
//  device-only Keychain.
//

import Foundation
import Combine
import Security

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

    private enum CodingKeys: String, CodingKey {
        case id, name, host, port, nick, password, channels
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decode(UUID.self, forKey: .id)
        name = try values.decode(String.self, forKey: .name)
        host = try values.decode(String.self, forKey: .host)
        port = try values.decode(UInt16.self, forKey: .port)
        nick = try values.decode(String.self, forKey: .nick)
        password = try values.decodeIfPresent(String.self, forKey: .password) ?? ""
        channels = try values.decode([String].self, forKey: .channels)
    }

    func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(id, forKey: .id)
        try values.encode(name, forKey: .name)
        try values.encode(host, forKey: .host)
        try values.encode(port, forKey: .port)
        try values.encode(nick, forKey: .nick)
        try values.encode(channels, forKey: .channels)
        // Passwords are intentionally excluded; I2PIRCServerBook stores them in Keychain.
    }
}

protocol I2PIRCServerPasswordStore {
    func password(account: String) -> String?
    func setPassword(_ password: String, account: String) -> Bool
    func deletePassword(account: String) -> Bool
}

final class I2PIRCServerPasswordKeychain: I2PIRCServerPasswordStore {
    static let shared = I2PIRCServerPasswordKeychain()
    private let service = "i2p.irc.server-password"

    func password(account: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    func setPassword(_ password: String, account: String) -> Bool {
        let attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        guard let data = password.data(using: .utf8) else { return false }
        let update: [String: Any] = [kSecValueData as String: data]
        let status = SecItemUpdate(attributes as CFDictionary, update as CFDictionary)
        if status == errSecSuccess { return true }
        guard status == errSecItemNotFound else { return false }

        var query = attributes
        query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        return SecItemAdd(query as CFDictionary, nil) == errSecSuccess
    }

    func deletePassword(account: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }
}

// MARK: - Server book

/// The saved servers, newest first.
final class I2PIRCServerBook: ObservableObject {
    static let shared = I2PIRCServerBook()
    static let defaultsKey = "i2p.irc.servers"

    @Published private(set) var entries: [I2PIRCServerEntry] = []
    @Published private(set) var didDiscardLegacyPasswords = false

    private let defaults: UserDefaults
    private let storageKey: String
    private let passwordStore: I2PIRCServerPasswordStore

    init(defaults: UserDefaults = .standard,
         storageKey: String = I2PIRCServerBook.defaultsKey,
         passwordStore: I2PIRCServerPasswordStore = I2PIRCServerPasswordKeychain.shared) {
        self.defaults = defaults
        self.storageKey = storageKey
        self.passwordStore = passwordStore
        let loaded = Self.load(defaults: defaults, key: storageKey, passwordStore: passwordStore)
        self.entries = loaded.entries
        self.didDiscardLegacyPasswords = loaded.discardedLegacyPasswords
    }

    func entry(_ id: UUID?) -> I2PIRCServerEntry? {
        guard let id else { return nil }
        return entries.first { $0.id == id }
    }

    func dismissPasswordMigrationWarning() {
        didDiscardLegacyPasswords = false
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
        let account = cleaned.id.uuidString
        if cleaned.password.isEmpty {
            if entries.contains(where: { $0.id == cleaned.id }) {
                guard passwordStore.deletePassword(account: account) else { return false }
            }
        } else {
            guard passwordStore.setPassword(cleaned.password, account: account) else { return false }
        }
        if let index = entries.firstIndex(where: { $0.id == cleaned.id }) {
            entries[index] = cleaned
        } else {
            entries.insert(cleaned, at: 0)
        }
        persist()
        return true
    }

    @discardableResult
    func remove(_ id: UUID) -> Bool {
        guard entries.contains(where: { $0.id == id }),
              passwordStore.deletePassword(account: id.uuidString) else { return false }
        entries.removeAll { $0.id == id }
        persist()
        return true
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
        Self.persist(entries, defaults: defaults, key: storageKey)
    }

    private static func persist(_ entries: [I2PIRCServerEntry], defaults: UserDefaults, key: String) {
        guard let data = try? JSONEncoder().encode(entries) else { return }
        defaults.set(data, forKey: key)
    }

    private static func load(defaults: UserDefaults,
                             key: String,
                             passwordStore: I2PIRCServerPasswordStore) -> (entries: [I2PIRCServerEntry], discardedLegacyPasswords: Bool) {
        guard let data = defaults.data(forKey: key),
              var decoded = try? JSONDecoder().decode([I2PIRCServerEntry].self, from: data) else {
            return ([], false)
        }
        var migratedLegacyPasswords = false
        var discardedLegacyPasswords = false
        for index in decoded.indices {
            let account = decoded[index].id.uuidString
            let legacyPassword = decoded[index].password
            if legacyPassword.isEmpty {
                decoded[index].password = passwordStore.password(account: account) ?? ""
            } else {
                let stored = passwordStore.setPassword(legacyPassword, account: account)
                decoded[index].password = stored
                    ? legacyPassword
                    : (passwordStore.password(account: account) ?? "")
                migratedLegacyPasswords = true
                if !stored { discardedLegacyPasswords = true }
            }
        }
        // Always scrub legacy values from defaults, even when Keychain is
        // unavailable. In that case the credential is discarded rather than
        // retained as plaintext; the next save can store a new value securely.
        if migratedLegacyPasswords {
            persist(decoded, defaults: defaults, key: key)
        }
        return (decoded, discardedLegacyPasswords)
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
            let passwordStore = I2PIRCServerBookMemoryPasswordStore()
            let store = I2PIRCServerBook(defaults: defaults,
                                         storageKey: "servers",
                                         passwordStore: passwordStore)

            let valid = I2PIRCServerEntry(name: "  Postman  ",
                                          host: " irc.postman.i2p ",
                                          port: 6667,
                                          nick: " tester ",
                                          password: "test-only-password",
                                          channels: ["#i2p"])
            guard store.save(valid) else { throw I2PWireError.invalidFormat }
            guard let saved = store.entries.first,
                  saved.name == "Postman",
                  saved.host == "irc.postman.i2p",
                  saved.nick == "tester",
                   saved.password == "test-only-password",
                  saved.displayName == "Postman",
                  saved.address == "irc.postman.i2p",
                  store.entries.count == 1,
                   passwordStore.password(account: valid.id.uuidString) == "test-only-password",
                   let persisted = defaults.data(forKey: "servers"),
                   String(data: persisted, encoding: .utf8)?.contains("test-only-password") == false else {
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
            let reopened = I2PIRCServerBook(defaults: defaults,
                                           storageKey: "servers",
                                           passwordStore: passwordStore)
            guard reopened.entries.count == 2,
                  reopened.entry(custom.id)?.name == "Renamed",
                   reopened.entry(valid.id)?.password == "test-only-password" else {
                throw I2PWireError.invalidFormat
            }
            reopened.remove(custom.id)
            guard I2PIRCServerBook(defaults: defaults,
                                  storageKey: "servers",
                                  passwordStore: passwordStore).entries.count == 1 else {
                throw I2PWireError.invalidFormat
            }
            defaults.removePersistentDomain(forName: suite)
            return "trimmed entry saved and persisted; an edit replaces in place; clear-net host, bad nick and port 0 refused"
        }

        run("irc · legacy server passwords migrate out of user defaults") {
            let suite = "i2p.irc.serverBook.migration.\(UUID().uuidString)"
            guard let defaults = UserDefaults(suiteName: suite) else {
                throw I2PWireError.invalidFormat
            }
            defer { defaults.removePersistentDomain(forName: suite) }

            let id = UUID()
            let secret = "legacy-test-password"
            let legacy: [[String: Any]] = [[
                "id": id.uuidString,
                "name": "Legacy",
                "host": "irc.legacy.i2p",
                "port": 6667,
                "nick": "tester",
                "password": secret,
                "channels": ["#i2p"]
            ]]
            defaults.set(try JSONSerialization.data(withJSONObject: legacy), forKey: "servers")
            let passwordStore = I2PIRCServerBookMemoryPasswordStore()
            let migrated = I2PIRCServerBook(defaults: defaults,
                                             storageKey: "servers",
                                             passwordStore: passwordStore)
            guard migrated.entry(id)?.password == secret,
                  passwordStore.password(account: id.uuidString) == secret,
                  let scrubbed = defaults.data(forKey: "servers"),
                  let scrubbedText = String(data: scrubbed, encoding: .utf8),
                  !scrubbedText.contains(secret),
                  !scrubbedText.contains("\"password\"") else {
                throw I2PWireError.invalidFormat
            }
            let reopened = I2PIRCServerBook(defaults: defaults,
                                             storageKey: "servers",
                                             passwordStore: passwordStore)
            guard reopened.entry(id)?.password == secret,
                  reopened.remove(id),
                  passwordStore.password(account: id.uuidString) == nil else {
                throw I2PWireError.invalidFormat
            }

            let blockedSuite = "i2p.irc.serverBook.blocked.\(UUID().uuidString)"
            guard let blockedDefaults = UserDefaults(suiteName: blockedSuite) else {
                throw I2PWireError.invalidFormat
            }
            defer { blockedDefaults.removePersistentDomain(forName: blockedSuite) }
            blockedDefaults.set(try JSONSerialization.data(withJSONObject: legacy), forKey: "servers")
            let blockedStore = I2PIRCServerBookMemoryPasswordStore(acceptsWrites: false)
            let blocked = I2PIRCServerBook(defaults: blockedDefaults,
                                            storageKey: "servers",
                                            passwordStore: blockedStore)
            guard blocked.entry(id)?.password.isEmpty == true,
                  blocked.didDiscardLegacyPasswords,
                  let scrubbedAfterFailure = blockedDefaults.data(forKey: "servers"),
                  String(data: scrubbedAfterFailure, encoding: .utf8)?.contains(secret) == false,
                  blocked.save(I2PIRCServerEntry(host: "irc.new.i2p",
                                                 nick: "tester",
                                                 password: "blocked-write")) == false,
                  blocked.entries.count == 1 else {
                throw I2PWireError.invalidFormat
            }
            blocked.dismissPasswordMigrationWarning()
            guard !blocked.didDiscardLegacyPasswords else { throw I2PWireError.invalidFormat }
            return "legacy password moved to Keychain, omitted from defaults, restored after reopen and removed with its server; failed migration scrubs plaintext, warns the user and failed writes are refused"
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

private final class I2PIRCServerBookMemoryPasswordStore: I2PIRCServerPasswordStore {
    private var values: [String: String] = [:]
    private let acceptsWrites: Bool

    init(acceptsWrites: Bool = true) {
        self.acceptsWrites = acceptsWrites
    }

    func password(account: String) -> String? {
        values[account]
    }

    func setPassword(_ password: String, account: String) -> Bool {
        guard acceptsWrites else { return false }
        values[account] = password
        return true
    }

    func deletePassword(account: String) -> Bool {
        values.removeValue(forKey: account)
        return true
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
