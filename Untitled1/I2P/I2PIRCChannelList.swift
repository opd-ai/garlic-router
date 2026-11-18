//
//  I2PIRCChannelList.swift
//  The server's channel directory: the rows one LIST listing returns (a channel
//  name, its member count and its topic), the numerics they arrive in, and the
//  filter the channel-list sheet applies.
//
//  Pure state and string handling, like the rest of the IRC layer, so the
//  parsing and the filtering are covered by the self-test suite without a router.
//

import Foundation

// MARK: - Row

/// One channel a server advertises, as the channel-list sheet shows it.
struct I2PIRCChannelEntry: Identifiable, Equatable {
    let name: String
    let memberCount: Int
    let topic: String?

    var id: String { I2PIRCName.key(name) }

    /// What the row shows under the name: the topic, or a quiet line when the
    /// server listed none.
    var topicLine: String {
        guard let topic, !topic.isEmpty else { return "No topic set." }
        return topic
    }

    /// The member count as the row shows it.
    var memberLine: String { "\(memberCount)" }

    /// The whole row in one sentence, for VoiceOver.
    var accessibilityLabel: String {
        var parts = [name]
        if let topic, !topic.isEmpty { parts.append(topic) }
        parts.append(memberCount == 1 ? "1 member" : "\(memberCount) members")
        return parts.joined(separator: ", ")
    }
}

// MARK: - Listing

/// The listing of one connection: the rows the server has sent so far, and how
/// far the listing got. It is dropped when the session ends, since a server's
/// channels say nothing about the next server's.
struct I2PIRCChannelList: Equatable {
    enum Status: Equatable {
        /// Nothing has been asked for yet.
        case idle
        /// LIST is out and the rows are arriving.
        case loading
        /// The server sent its end of list.
        case loaded
        /// The server refused the listing, with the reason it gave.
        case failed(String)
    }

    private(set) var entries: [I2PIRCChannelEntry] = []
    private(set) var status: Status = .idle

    var isLoading: Bool { status == .loading }
    var isEmpty: Bool { entries.isEmpty }

    /// The reason the server gave for refusing the listing, when it did.
    var failure: String? {
        if case .failed(let message) = status { return message }
        return nil
    }

    /// Whether opening the sheet should ask the server again: nothing has been
    /// asked for yet, or the last attempt was refused.
    var needsRequest: Bool {
        switch status {
        case .idle, .failed: return true
        case .loading, .loaded: return false
        }
    }

    mutating func beginLoading() {
        status = .loading
    }

    mutating func fail(_ message: String) {
        status = .failed(message)
    }

    /// Throws the listing away — done when the session it belongs to ends.
    mutating func reset() {
        self = I2PIRCChannelList()
    }

    // MARK: Numerics

    /// The numerics one LIST listing is made of: 321 opens it, 322 carries a
    /// channel and 323 closes it.
    static func handles(_ line: I2PIRCLine) -> Bool {
        guard let numeric = line.numeric else { return false }
        return (321...323).contains(numeric)
    }

    /// Applies one channel-list numeric. Returns false for a line the listing
    /// does not own, so it is left to the chat state.
    @discardableResult
    mutating func apply(_ line: I2PIRCLine) -> Bool {
        guard let numeric = line.numeric else { return false }
        switch numeric {
        case 321:
            // A new listing starts: the previous one's rows are not part of it.
            entries.removeAll()
            status = .loading
        case 322:
            if let entry = Self.entry(from: line) {
                entries.append(entry)
            }
        case 323:
            status = .loaded
        default:
            return false
        }
        return true
    }

    /// One RPL_LIST line: our nick, the channel, its member count and then the
    /// topic — which may hold spaces, so every remaining param belongs to it.
    /// A server that leaves the count out puts the topic in its place.
    static func entry(from line: I2PIRCLine) -> I2PIRCChannelEntry? {
        guard line.params.count >= 3 else { return nil }
        let name = line.params[1]
        guard I2PIRCName.isChannel(name) else { return nil }
        let countText = line.params[2]
        var memberCount = 0
        var topicStart = 3
        if let parsed = Int(countText) {
            memberCount = max(0, parsed)
        } else {
            topicStart = 2
        }
        let topic = I2PIRCText.sanitize(
            line.params.dropFirst(topicStart).joined(separator: " "))
        return I2PIRCChannelEntry(name: name,
                                  memberCount: memberCount,
                                  topic: topic.isEmpty ? nil : topic)
    }

    // MARK: Filtering

    /// The rows matching the sheet's filter field, case-insensitively across
    /// the channel name and its topic, in the order the server listed them.
    func filtered(_ query: String) -> [I2PIRCChannelEntry] {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !needle.isEmpty else { return entries }
        return entries.filter { entry in
            entry.name.lowercased().contains(needle)
                || (entry.topic?.lowercased().contains(needle) ?? false)
        }
    }

    /// The count line above the rows: "14 channels", "1 channel".
    static func countLine(_ count: Int) -> String {
        count == 1 ? "1 channel" : "\(count) channels"
    }
}

// MARK: - Self-test suite (IRC channel list)

enum I2PIRCChannelListSelfTest {
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

        run("irc · a LIST listing parses into channel rows") {
            var list = I2PIRCChannelList()
            list.beginLoading()
            try apply(&list, [
                ":irc.example.i2p 321 tester Channel :Users Name",
                ":irc.example.i2p 322 tester #i2p 248 :The main I2P network channel. Be kind, stay on topic.",
                ":irc.example.i2p 322 tester #help 123",
                ":irc.example.i2p 323 tester :End of /LIST"
            ])
            guard list.status == .loaded, list.entries.count == 2 else {
                throw I2PWireError.invalidFormat
            }
            let first = list.entries[0]
            guard first.name == "#i2p",
                  first.memberCount == 248,
                  first.topic == "The main I2P network channel. Be kind, stay on topic.",
                  first.topicLine == first.topic,
                  first.memberLine == "248",
                  first.id == "#i2p" else {
                throw I2PWireError.invalidFormat
            }
            // A server that leaves the topic out leaves no topic behind.
            let second = list.entries[1]
            guard second.name == "#help",
                  second.memberCount == 123,
                  second.topic == nil,
                  second.topicLine == "No topic set." else {
                throw I2PWireError.invalidFormat
            }
            // A server that leaves the count out still lists the channel, its
            // topic starting where the count would have been.
            let withoutCount = try unwrap(
                I2PIRCLine.parse(":irc.example.i2p 322 tester #quiet :Off topic, links and quiet conversation."))
            let entry = try unwrap(I2PIRCChannelList.entry(from: withoutCount))
            guard entry.name == "#quiet",
                  entry.memberCount == 0,
                  entry.topic == "Off topic, links and quiet conversation." else {
                throw I2PWireError.invalidFormat
            }
            guard I2PIRCChannelList.countLine(0) == "0 channels",
                  I2PIRCChannelList.countLine(1) == "1 channel",
                  I2PIRCChannelList.countLine(14) == "14 channels" else {
                throw I2PWireError.invalidFormat
            }
            return "321, 322 and 323 build the rows with name, count and a spaced topic; a missing count still lists the channel"
        }

        run("irc · the listing only owns its own numerics and drops on reset") {
            var list = I2PIRCChannelList()
            try apply(&list, [
                ":irc.example.i2p 322 tester #i2p 248 :a topic",
                ":irc.example.i2p 323 tester :End of /LIST"
            ])
            guard list.entries.count == 1, list.status == .loaded, !list.needsRequest else {
                throw I2PWireError.invalidFormat
            }
            // A topic reply and a chat message are not the listing's.
            for raw in [":irc.example.i2p 332 tester #i2p :Welcome to #i2p",
                        ":alice!a@host PRIVMSG #i2p :hello there"] {
                let line = try unwrap(I2PIRCLine.parse(raw))
                guard !I2PIRCChannelList.handles(line), list.apply(line) == false else {
                    throw I2PWireError.invalidFormat
                }
            }
            guard I2PIRCChannelList.handles(try unwrap(I2PIRCLine.parse(":s 323 tester :End"))),
                  I2PIRCChannelList.handles(try unwrap(I2PIRCLine.parse(":s 321 tester Channel"))) else {
                throw I2PWireError.invalidFormat
            }
            // A fresh listing starts empty, and the end of a session drops it.
            list.beginLoading()
            guard list.isLoading, list.entries.count == 1 else { throw I2PWireError.invalidFormat }
            try apply(&list, [":irc.example.i2p 321 tester Channel :Users Name"])
            guard list.entries.isEmpty else { throw I2PWireError.invalidFormat }
            list.fail("The server refused the listing.")
            guard list.failure == "The server refused the listing.", list.needsRequest else {
                throw I2PWireError.invalidFormat
            }
            list.reset()
            guard list.entries.isEmpty, list.status == .idle, list.failure == nil,
                  list.needsRequest, !list.isLoading else {
                throw I2PWireError.invalidFormat
            }
            return "other numerics and chat lines are left to the chat state; 321 starts a clean listing and reset drops it"
        }

        run("irc · the channel filter matches names and topics") {
            var list = I2PIRCChannelList()
            try apply(&list, [
                ":irc.example.i2p 322 tester #i2p 248 :The main I2P network channel.",
                ":irc.example.i2p 322 tester #i2p-dev 31 :Router and SAM development — patch review on Sundays.",
                ":irc.example.i2p 322 tester #random 96 :Off-topic, links and quiet conversation.",
                ":irc.example.i2p 323 tester :End of /LIST"
            ])
            guard list.filtered("").count == 3,
                  list.filtered("   ").count == 3 else {
                throw I2PWireError.invalidFormat
            }
            // A name match is case-insensitive and keeps the server's order.
            guard list.filtered("I2P-DEV").map(\.name) == ["#i2p-dev"],
                  list.filtered("#i2p").map(\.name) == ["#i2p", "#i2p-dev"] else {
                throw I2PWireError.invalidFormat
            }
            // A topic match finds the channel the name would not.
            guard list.filtered("quiet").map(\.name) == ["#random"],
                  list.filtered("SAM").map(\.name) == ["#i2p-dev"],
                  list.filtered("nothing here").isEmpty else {
                throw I2PWireError.invalidFormat
            }
            let entry = try unwrap(list.filtered("#random").first)
            guard entry.accessibilityLabel
                    == "#random, Off-topic, links and quiet conversation., 96 members" else {
                throw I2PWireError.invalidFormat
            }
            return "the filter matches name and topic case-insensitively in listing order, and names nothing rather than everything"
        }

        return results
    }

    private static func apply(_ list: inout I2PIRCChannelList, _ lines: [String]) throws {
        for raw in lines {
            guard let line = I2PIRCLine.parse(raw), list.apply(line) else {
                throw I2PWireError.invalidFormat
            }
        }
    }

    private static func unwrap<T>(_ value: T?) throws -> T {
        guard let value else { throw I2PWireError.invalidFormat }
        return value
    }
}
