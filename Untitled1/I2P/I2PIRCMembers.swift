//
//  I2PIRCMembers.swift
//  The channel roster: how each nick in a channel stands (operator, voiced or
//  an ordinary participant), how a NAMES burst and a MODE change move a nick
//  between those groups, and the groups, order and filter the member list
//  screen renders.
//
//  Pure state and string handling, like the rest of the IRC layer, so the
//  roster rules are covered by the self-test suite without a router.
//

import Foundation

// MARK: - Role

/// How one nick stands in a channel. The member list groups by this.
enum I2PIRCMemberRole: String, Codable, Equatable {
    /// Someone in the channel with no status prefix.
    case participant
    /// `+` — voiced.
    case voiced
    /// `@` — a channel operator (owner, admin and half-op fold in here, since
    /// the roster groups by the three sections the member list shows).
    case op

    /// The badge the member list draws beside the nick, or nil for none.
    var badgeSymbol: String? {
        switch self {
        case .participant: return nil
        case .voiced: return "plus"
        case .op: return "at"
        }
    }

    /// The role as a person would name it.
    var title: String {
        switch self {
        case .participant: return "Member"
        case .voiced: return "Voiced"
        case .op: return "Operator"
        }
    }
}

/// The three sections the member list shows, in display order.
enum I2PIRCChannelGroup: String, CaseIterable, Identifiable {
    case operators
    case voiced
    case members

    var id: String { rawValue }

    var title: String {
        switch self {
        case .operators: return "Operators"
        case .voiced: return "Voiced"
        case .members: return "Everyone"
        }
    }

    /// The roster role that belongs in this section.
    var role: I2PIRCMemberRole {
        switch self {
        case .operators: return .op
        case .voiced: return .voiced
        case .members: return .participant
        }
    }
}

// MARK: - Member

/// One nick in a channel, as the member list shows it.
struct I2PIRCMember: Identifiable, Equatable {
    let nick: String
    let role: I2PIRCMemberRole
    /// True for our own nick, which the row marks as "you".
    let isUs: Bool

    var id: String { I2PIRCName.key(nick) }

    /// The letter the row's avatar shows.
    var initial: String {
        guard let first = nick.first else { return "?" }
        return String(first).uppercased()
    }
}

/// One section of the member list: a group and the nicks in it.
struct I2PIRCMemberSection: Identifiable, Equatable {
    let group: I2PIRCChannelGroup
    let members: [I2PIRCMember]

    var id: String { group.id }
    var title: String { group.title }
}

// MARK: - Roster rules

enum I2PIRCMemberList {
    /// Splits a NAMES entry into the nick and the status its prefixes carry:
    /// `@+nick` is an operator, `+nick` is voiced, `@%nick` is an operator
    /// (half-op and up all land in the operators section).
    static func parse(namesEntry entry: String) -> (nick: String, role: I2PIRCMemberRole)? {
        let nick = I2PIRCName.stripNickPrefixes(entry)
        guard !nick.isEmpty else { return nil }
        let prefixCount = entry.count - nick.count
        var role = I2PIRCMemberRole.participant
        for prefix in entry.prefix(prefixCount) {
            switch prefix {
            case "~", "&", "@", "%":
                role = .op
            case "+":
                if role == .participant { role = .voiced }
            default:
                break
            }
        }
        return (nick, role)
    }

    /// Applies one MODE line's flags to a roster. `parameters` is the line's
    /// params from the channel on: the channel, the flag string, then the
    /// flags' arguments. Nicks that are not in the channel are left alone.
    static func apply(modes parameters: [String],
                      to roles: inout [String: I2PIRCMemberRole],
                      members: [String]) {
        guard parameters.count >= 2 else { return }
        let flags = parameters[1]
        var arguments = Array(parameters.dropFirst(2))
        let known = Set(members.map { I2PIRCName.key($0) })
        var adding = true

        for flag in flags {
            switch flag {
            case "+":
                adding = true
            case "-":
                adding = false
            case "o", "q", "a", "h":
                guard !arguments.isEmpty else { continue }
                let key = I2PIRCName.key(arguments.removeFirst())
                guard known.contains(key) else { continue }
                roles[key] = adding ? .op : .participant
            case "v":
                guard !arguments.isEmpty else { continue }
                let key = I2PIRCName.key(arguments.removeFirst())
                guard known.contains(key) else { continue }
                if adding {
                    // An operator who is given voice stays an operator.
                    if roles[key] != .op { roles[key] = .voiced }
                } else if roles[key] != .op {
                    roles[key] = .participant
                }
            case "b", "e", "I", "k", "l", "j", "f", "J", "X":
                // These take an argument when they are applied; consume it so
                // the nick after a flag is read against the right mode.
                if !arguments.isEmpty { arguments.removeFirst() }
            default:
                break
            }
        }
        // A participant needs no entry: the roster's default is enough.
        roles = roles.filter { $0.value != .participant }
    }

    /// The sections the member list shows, in order, with a nick filter
    /// applied. Our own nick sorts first inside its group and the rest sort
    /// case-insensitively; a group with nobody in it is left out.
    static func sections(members: [String],
                         roles: [String: I2PIRCMemberRole],
                         ourNick: String,
                         filter: String = "") -> [I2PIRCMemberSection] {
        let needle = filter.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let ourKey = I2PIRCName.key(ourNick)
        var grouped: [I2PIRCChannelGroup: [I2PIRCMember]] = [:]

        for name in members {
            guard !name.isEmpty else { continue }
            let key = I2PIRCName.key(name)
            if !needle.isEmpty, !key.contains(needle) { continue }
            let role = roles[key] ?? .participant
            let member = I2PIRCMember(nick: name, role: role, isUs: key == ourKey)
            let group: I2PIRCChannelGroup
            switch role {
            case .op: group = .operators
            case .voiced: group = .voiced
            case .participant: group = .members
            }
            grouped[group, default: []].append(member)
        }

        return I2PIRCChannelGroup.allCases.compactMap { group in
            guard var list = grouped[group], !list.isEmpty else { return nil }
            list.sort { lhs, rhs in
                if lhs.isUs != rhs.isUs { return lhs.isUs }
                return lhs.nick.lowercased() < rhs.nick.lowercased()
            }
            return I2PIRCMemberSection(group: group, members: list)
        }
    }
}

// MARK: - Self-test suite (channel roster)

enum I2PIRCMemberListSelfTest {
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

        run("irc · NAMES groups operators, voiced and everyone with us first") {
            var state = I2PIRCChatState(serverName: "irc.example.i2p", nick: "tester")
            try applyAll(&state, [
                ":irc.example.i2p 001 tester :Welcome",
                ":tester!t@client JOIN #i2p",
                ":irc.example.i2p 353 tester = #i2p :@orbital +velvet @nightHawk tester marisol @%halfy",
                ":irc.example.i2p 366 tester #i2p :End of /NAMES list"
            ])
            let channel = try unwrap(state.conversation("#i2p"))
            guard channel.members.count == 6 else { throw I2PWireError.invalidFormat }
            let sections = channel.memberSections(ourNick: "tester")
            guard sections.map(\.group) == [.operators, .voiced, .members],
                  sections[0].members.map(\.nick) == ["halfy", "nightHawk", "orbital"],
                  sections[1].members.map(\.nick) == ["velvet"],
                  sections[2].members.map(\.nick) == ["tester", "marisol"],
                  sections[2].members.first?.isUs == true,
                  sections[0].members.first?.isUs == false else {
                throw I2PWireError.invalidFormat
            }
            // A NAMES burst that repeats a nick never duplicates the row, and
            // a status carried the second time is the one kept.
            try applyAll(&state, [":irc.example.i2p 353 tester = #i2p :velvet +velvet"])
            let widened = try unwrap(state.conversation("#i2p"))
            guard widened.members.count == 6,
                  widened.role(of: "velvet") == .voiced,
                  widened.role(of: "marisol") == .participant else {
                throw I2PWireError.invalidFormat
            }
            return "owner, admin and half-op symbols join @ in the operators section, + is voiced, plain nicks follow with ours first, and a repeated NAMES entry adds no second row"
        }

        run("irc · MODE moves nicks between groups and part, quit, kick and nick changes keep the roster honest") {
            var state = I2PIRCChatState(serverName: "irc.example.i2p", nick: "tester")
            try applyAll(&state, [
                ":irc.example.i2p 001 tester :Welcome",
                ":tester!t@client JOIN #i2p",
                ":irc.example.i2p 353 tester = #i2p :@orbital +velvet tester alice",
                ":irc.example.i2p 366 tester #i2p :End of /NAMES list",
                ":orbital!o@h MODE #i2p +v alice",
                ":orbital!o@h MODE #i2p -o orbital",
                ":nighthawk!n@h JOIN #i2p",
                ":orbital!o@h MODE #i2p +ov orbital nighthawk",
                ":orbital!o@h MODE #i2p +o ghost"
            ])
            let afterModes = try unwrap(state.conversation("#i2p"))
            guard afterModes.role(of: "alice") == .voiced,
                  afterModes.role(of: "orbital") == .op,
                  afterModes.role(of: "nighthawk") == .voiced,
                  !afterModes.members.contains(where: { I2PIRCName.key($0) == "ghost" }) else {
                throw I2PWireError.invalidFormat
            }
            // The mode line itself is still announced in the channel.
            guard afterModes.messages.contains(where: {
                $0.kind == .system && $0.text.contains("+ov orbital nighthawk")
            }) else {
                throw I2PWireError.invalidFormat
            }

            try applyAll(&state, [
                ":alice!a@h PART #i2p :bye",
                ":velvet!v@h QUIT :gone",
                ":orbital!o@h KICK #i2p nighthawk :out",
                ":tester!t@client NICK tester2"
            ])
            let afterLeaves = try unwrap(state.conversation("#i2p"))
            // The roster keeps insertion order; the member list sorts it for
            // display, so the rule under test is membership, not order.
            guard afterLeaves.members.map({ I2PIRCName.key($0) }).sorted()
                    == ["orbital", "tester2"],
                  afterLeaves.memberRoles["alice"] == nil,
                  afterLeaves.memberRoles["velvet"] == nil,
                  afterLeaves.memberRoles["nighthawk"] == nil else {
                throw I2PWireError.invalidFormat
            }
            let sections = afterLeaves.memberSections(ourNick: "tester2")
            guard sections.map(\.group) == [.operators, .members],
                  sections[0].members.map(\.nick) == ["orbital"],
                  sections[1].members.map(\.nick) == ["tester2"],
                  sections[1].members.first?.isUs == true else {
                throw I2PWireError.invalidFormat
            }
            return "MODE applies +o/-o and +v/-v to nicks in the channel only, and part, quit, kick and a nick change leave no stale member or status behind"
        }

        run("irc · the filter narrows the roster and empty groups drop out") {
            var state = I2PIRCChatState(serverName: "s", nick: "tester")
            try applyAll(&state, [
                ":irc.example.i2p 001 tester :Welcome",
                ":tester!t@client JOIN #i2p",
                ":irc.example.i2p 353 tester = #i2p :@orbital +velvet tester marisol",
                ":irc.example.i2p 366 tester #i2p :End of /NAMES list"
            ])
            let channel = try unwrap(state.conversation("#i2p"))
            guard channel.memberSections(ourNick: "tester").count == 3 else {
                throw I2PWireError.invalidFormat
            }
            // Case-insensitive, on any part of the nick.
            let voiced = channel.memberSections(ourNick: "tester", filter: " VELV ")
            guard voiced.map(\.group) == [.voiced],
                  voiced.first?.members.map(\.nick) == ["velvet"] else {
                throw I2PWireError.invalidFormat
            }
            let operators = channel.memberSections(ourNick: "tester", filter: "or")
            guard operators.map(\.group) == [.operators],
                  operators.first?.members.map(\.nick) == ["orbital"] else {
                throw I2PWireError.invalidFormat
            }
            guard channel.memberSections(ourNick: "tester", filter: "zzz").isEmpty else {
                throw I2PWireError.invalidFormat
            }
            // An empty filter shows the whole roster again.
            guard channel.memberSections(ourNick: "tester", filter: "   ").count == 3 else {
                throw I2PWireError.invalidFormat
            }
            return "a fragment matches any part of a nick regardless of case, sections with no match are omitted, and an empty filter restores the whole roster"
        }

        return results
    }

    private static func applyAll(_ state: inout I2PIRCChatState, _ lines: [String]) throws {
        for raw in lines {
            guard let line = I2PIRCLine.parse(raw) else { throw I2PWireError.invalidFormat }
            state.apply(line)
        }
    }

    private static func unwrap<T>(_ value: T?) throws -> T {
        guard let value else { throw I2PWireError.invalidFormat }
        return value
    }
}
