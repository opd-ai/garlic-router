//
//  I2PIRCChannel.swift
//  The IRC chat state: the conversations a connection holds (the server
//  buffer, the channels joined and the queries opened) and the rules that turn
//  a parsed server line into visible state — joins, parts, quits, nick
//  changes, topics, NAMES bursts, actions, notices and numeric errors.
//
//  The state is a value type with no networking in it, so the whole IRC
//  behaviour is exercised by the self-test suite without a router.
//

import Foundation

// MARK: - Message

/// One line in a conversation, as the chat view renders it.
struct I2PIRCMessage: Identifiable, Equatable {
    enum Kind: String, Equatable, Codable {
        case message
        case action
        case notice
        case system
        case error
    }

    let id = UUID()
    let date: Date
    /// The nick that spoke, when the line came from someone.
    let nick: String?
    let text: String
    let kind: Kind
    /// True for a line this client sent, so it renders on the right.
    let isLocal: Bool
    /// True when the line named us — our nick as a whole word. The mark is
    /// dropped once the conversation has been read, and is never saved.
    var mentionsUs: Bool = false
    /// The user's keywords this line holds, in the Highlights list's order.
    /// Empty for a line no switched-on word matches; the mark is dropped once
    /// the conversation has been read, and is recomputed on a restore.
    var keywordHits: [String] = []

    /// A stable ordering key for the view's scroll target.
    var sortKey: String { "\(date.timeIntervalSince1970)-\(id.uuidString)" }
}

// MARK: - Conversation

/// One conversation: the server buffer, a channel or a private query.
struct I2PIRCConversation: Identifiable, Equatable {
    enum Kind: String, Equatable, Codable {
        case server
        case channel
        case query
    }

    let name: String
    let kind: Kind
    var topic: String?
    var members: [String]
    /// Each nick's channel status, keyed by `I2PIRCName.key(nick)`. An ordinary
    /// participant has no entry, so the dictionary only holds operators and
    /// voiced nicks.
    var memberRoles: [String: I2PIRCMemberRole]
    var messages: [I2PIRCMessage]
    var unread: Int
    /// How many lines in here currently name us. The chip shows it, and it
    /// falls to zero when the conversation is read.
    var mentionCount: Int
    /// How many lines in here wear a keyword edge and have not been read past
    /// yet. The chip shows it beside the mention badge, and it falls to zero
    /// when the conversation is read.
    var keywordCount: Int
    /// Whether this client is in the channel (or the query is open).
    var joined: Bool
    var lastActivity: Date

    var id: String { I2PIRCName.key(name) }

    init(name: String,
         kind: Kind,
         topic: String? = nil,
         members: [String] = [],
         memberRoles: [String: I2PIRCMemberRole] = [:],
         messages: [I2PIRCMessage] = [],
         unread: Int = 0,
         mentionCount: Int = 0,
         keywordCount: Int = 0,
         joined: Bool = false,
         at date: Date = Date()) {
        self.name = name
        self.kind = kind
        self.topic = topic
        self.members = members
        self.memberRoles = memberRoles
        self.messages = messages
        self.unread = unread
        self.mentionCount = mentionCount
        self.keywordCount = keywordCount
        self.joined = joined
        self.lastActivity = date
    }

    /// The members in the order the roster shows them: sorted case-insensitively
    /// with our own nick first.
    func sortedMembers(ourNick: String) -> [String] {
        let ourKey = I2PIRCName.key(ourNick)
        return members.sorted { lhs, rhs in
            let leftIsUs = I2PIRCName.key(lhs) == ourKey
            let rightIsUs = I2PIRCName.key(rhs) == ourKey
            if leftIsUs != rightIsUs { return leftIsUs }
            return lhs.lowercased() < rhs.lowercased()
        }
    }

    /// How a nick stands in this channel: operator, voiced or plain member.
    func role(of nick: String) -> I2PIRCMemberRole {
        memberRoles[I2PIRCName.key(nick)] ?? .participant
    }

    /// The groups the member list shows — operators, voiced, then everyone
    /// else — with a nick filter applied and our own nick first.
    func memberSections(ourNick: String, filter: String = "") -> [I2PIRCMemberSection] {
        I2PIRCMemberList.sections(members: members,
                                  roles: memberRoles,
                                  ourNick: ourNick,
                                  filter: filter)
    }
}

// MARK: - Chat state

/// The state of one IRC connection's chat: what is being talked in and what has
/// been said. A value type, so a caller can hand a copy to the view and keep
/// mutating the original without races.
struct I2PIRCChatState {
    /// The id of the server buffer conversation.
    static let serverBufferName = "server"
    /// The most messages kept per conversation, oldest dropped first.
    static let messageLimit = 400

    private(set) var serverName: String
    private(set) var nick: String
    private(set) var registered = false
    private(set) var conversations: [I2PIRCConversation]
    /// The words that mark a line when it holds one: the Highlights list's
    /// switched-on entries, in the order the list keeps them.
    private(set) var enabledKeywords: [String] = []
    /// The conversations the user has silenced, by `I2PIRCName.key`. A muted
    /// conversation adds no unread badge, no mention count and no keyword count,
    /// while the marks stay painted on its lines.
    private(set) var mutedConversations: Set<String> = []

    init(serverName: String, nick: String, at date: Date = Date()) {
        self.serverName = serverName
        self.nick = nick
        self.conversations = [
            I2PIRCConversation(name: Self.serverBufferName, kind: .server,
                               joined: true, at: date)
        ]
    }

    // MARK: Lookups

    func conversation(_ id: String) -> I2PIRCConversation? {
        conversations.first { $0.id == I2PIRCName.key(id) }
    }

    /// The conversations in the order the strip shows them: the server buffer
    /// first, then joined channels by name, then queries by recent activity.
    var orderedConversations: [I2PIRCConversation] {
        let server = conversations.filter { $0.kind == .server }
        let channels = conversations
            .filter { $0.kind == .channel }
            .sorted { lhs, rhs in
                if lhs.joined != rhs.joined { return lhs.joined }
                return lhs.name.lowercased() < rhs.name.lowercased()
            }
        let queries = conversations
            .filter { $0.kind == .query }
            .sorted { $0.lastActivity > $1.lastActivity }
        return server + channels + queries
    }

    /// The number of unread messages across every conversation.
    var totalUnread: Int {
        conversations.reduce(0) { $0 + $1.unread }
    }

    // MARK: Client-side notes

    /// Adds a line this client generated (a stage note, an error).
    mutating func noteSystem(_ text: String,
                             in conversationID: String? = nil,
                             kind: I2PIRCMessage.Kind = .system,
                             at date: Date = Date()) {
        let target = conversationID ?? Self.serverBufferName
        let name = conversationName(for: target) ?? target
        let conversationKind = kindFor(target)
        ensure(target, name: name, kind: conversationKind, at: date)
        append(to: target, nick: nil, text: text, kind: kind, isLocal: false, at: date)
    }

    /// Echoes a message this client sent, so it appears the moment it leaves.
    /// Returns the conversation id it was filed under.
    @discardableResult
    mutating func noteOutgoing(_ text: String, to target: String, at date: Date = Date()) -> String {
        let conversationID = I2PIRCName.key(target)
        if let action = I2PIRCText.actionBody(text) {
            ensure(conversationID, name: target,
                   kind: I2PIRCName.isChannel(target) ? .channel : .query, at: date)
            append(to: conversationID, nick: nick, text: action, kind: .action,
                   isLocal: true, at: date)
        } else {
            ensure(conversationID, name: target,
                   kind: I2PIRCName.isChannel(target) ? .channel : .query, at: date)
            append(to: conversationID, nick: nick, text: I2PIRCText.sanitize(text),
                   kind: .message, isLocal: true, at: date)
        }
        return conversationID
    }

    /// Starts a channel conversation at the moment it is asked for, so the
    /// channel shows up before the server's JOIN comes back.
    mutating func requestJoin(_ channel: String, at date: Date = Date()) {
        let conversationID = I2PIRCName.key(channel)
        ensure(conversationID, name: channel, kind: .channel, at: date)
        append(to: conversationID, nick: nil, text: "Joining \(channel)…",
               kind: .system, isLocal: false, at: date)
    }

    /// The conversation a target lives in, created when the client is about to
    /// talk there for the first time. Returns the conversation id.
    @discardableResult
    mutating func openConversation(_ target: String, at date: Date = Date()) -> String {
        let conversationID = I2PIRCName.key(target)
        ensure(conversationID, name: target,
               kind: I2PIRCName.isChannel(target) ? .channel : .query, at: date)
        return conversationID
    }

    /// Records the nick the server assigned.
    mutating func setNick(_ newNick: String) {
        guard !newNick.isEmpty else { return }
        nick = newNick
    }

    /// Clears a conversation's unread badge.
    mutating func markRead(_ conversationID: String) {
        guard let index = indexOf(conversationID), conversations[index].unread != 0 else { return }
        conversations[index].unread = 0
    }

    /// Clears a conversation's mention marks: the violet edges go and the chip's
    /// count with them, so the lines are shown plainly from then on. Called when
    /// the conversation has been read and left.
    mutating func markMentionsRead(_ conversationID: String) {
        guard let index = indexOf(conversationID), conversations[index].mentionCount != 0 else { return }
        for messageIndex in conversations[index].messages.indices {
            conversations[index].messages[messageIndex].mentionsUs = false
        }
        conversations[index].mentionCount = 0
    }

    /// Empties every transcript while keeping the conversations and their
    /// rosters, so the chat and what is saved start over together.
    mutating func clearHistory() {
        for index in conversations.indices {
            conversations[index].messages.removeAll()
            conversations[index].unread = 0
            conversations[index].mentionCount = 0
            conversations[index].keywordCount = 0
        }
    }

    // MARK: Mute

    /// Whether a conversation is silenced. The name is matched the way IRC
    /// matches a conversation, so "#i2p" and "#I2P" are the same one.
    func isMuted(_ conversationID: String) -> Bool {
        mutedConversations.contains(I2PIRCName.key(conversationID))
    }

    /// Sets the conversations that are silenced, from the mutes the user saved
    /// for this server. A conversation that has just been muted loses the badges
    /// it had — and keeps the marks on its lines. Unmuting adds nothing back:
    /// the lines said while it was silent were never counted.
    mutating func setMutedConversations(_ conversationIDs: [String]) {
        let keys = Set(conversationIDs.map { I2PIRCName.key($0) })
        guard keys != mutedConversations else { return }
        let muted = keys.subtracting(mutedConversations)
        mutedConversations = keys
        for key in muted {
            guard let index = indexOf(key) else { continue }
            conversations[index].unread = 0
            conversations[index].mentionCount = 0
            conversations[index].keywordCount = 0
        }
    }

    // MARK: Keywords

    /// Sets the words that mark a line. The transcript on screen is re-marked,
    /// which is what makes a word added in the Highlights sheet apply to the
    /// lines already there and a paused word stop matching at once, without a
    /// reconnect.
    mutating func setKeywords(_ keywords: [String]) {
        enabledKeywords = keywords
        for index in conversations.indices {
            markKeywords(in: index, counting: true)
        }
    }

    /// Clears a conversation's keyword marks: the edges go and the chip's count
    /// with them, exactly as a mention's do when the conversation is read.
    mutating func markKeywordsRead(_ conversationID: String) {
        guard let index = indexOf(conversationID) else { return }
        guard conversations[index].keywordCount != 0
                || conversations[index].messages.contains(where: { !$0.keywordHits.isEmpty })
        else { return }
        for messageIndex in conversations[index].messages.indices {
            conversations[index].messages[messageIndex].keywordHits = []
        }
        conversations[index].keywordCount = 0
    }

    /// Re-marks one conversation against the enabled words. `counting` adds the
    /// marked lines to the chip's count; a transcript restored from saved
    /// history is marked without counting, so a relaunch does not light up the
    /// chips with lines the user read long ago.
    private mutating func markKeywords(in index: Int, counting: Bool) {
        for messageIndex in conversations[index].messages.indices {
            let message = conversations[index].messages[messageIndex]
            conversations[index].messages[messageIndex].keywordHits =
                I2PIRCKeywordRule.hits(in: message.text,
                                       kind: message.kind,
                                       isLocal: message.isLocal,
                                       keywords: enabledKeywords)
        }
        guard counting else { return }
        // A muted conversation keeps its edges but counts nothing on the chip.
        guard !mutedConversations.contains(conversations[index].id) else {
            conversations[index].keywordCount = 0
            return
        }
        conversations[index].keywordCount =
            conversations[index].messages.reduce(0) { $0 + ($1.keywordHits.isEmpty ? 0 : 1) }
    }

    // MARK: Restoring a transcript

    /// Puts a server's saved transcript in front of the fresh state, so a
    /// reconnecting server picks up where it left off. Channels start unjoined
    /// again — the server's JOIN is what puts us in them — and no restored line
    /// counts as unread.
    mutating func restore(_ restored: [I2PIRCHistoryConversation]) {
        for saved in restored {
            let lines = saved.messages.suffix(I2PIRCHistoryStore.lineLimit).map { $0.message() }
            guard !lines.isEmpty else { continue }
            let name: String
            let kind: I2PIRCConversation.Kind
            if saved.kind == .server {
                name = Self.serverBufferName
                kind = .server
            } else {
                name = saved.name
                kind = saved.kind
            }
            let conversationID = I2PIRCName.key(name)
            ensure(conversationID, name: name, kind: kind, at: lines[0].date)
            guard let index = indexOf(conversationID) else { continue }
            // Saved lines go before whatever the fresh state already holds, so
            // the transcript reads oldest first.
            conversations[index].messages = Array(lines) + conversations[index].messages
            if conversations[index].messages.count > Self.messageLimit {
                let overflow = conversations[index].messages.count - Self.messageLimit
                conversations[index].messages.removeFirst(overflow)
            }
            // A restored line wears the edges of the words switched on now, but
            // never adds to the chip's count: those lines were read in an
            // earlier session.
            markKeywords(in: index, counting: false)
            if let last = lines.last {
                conversations[index].lastActivity = last.date
            }
        }
    }

    // MARK: Reconnecting

    /// Puts the state back to what a fresh stream starts with — nobody
    /// registered yet, and the rosters empty because the server has not sent
    /// them again — while keeping every line said so far, so the transcript of
    /// the session that dropped stays on screen while it is retried.
    mutating func beginReconnection() {
        registered = false
        for index in conversations.indices {
            conversations[index].members.removeAll()
            conversations[index].memberRoles.removeAll()
            conversations[index].joined = conversations[index].kind == .server
        }
    }

    // MARK: Applying a server line

    /// Applies one parsed server line to the chat state.
    mutating func apply(_ line: I2PIRCLine, at date: Date = Date()) {
        let sender = line.nick
        switch line.command {
        case "001":
            registered = true
            if let name = line.params.first, !name.isEmpty {
                nick = name
            }
            append(to: Self.serverBufferName, nick: nil,
                   text: "Connected to \(serverName) as \(nick).",
                   kind: .system, isLocal: false, at: date)

        case "002", "003", "004":
            if let text = line.params.dropFirst().joined(separator: " ").nilIfEmpty {
                append(to: Self.serverBufferName, nick: nil, text: text,
                       kind: .system, isLocal: false, at: date)
            }

        case "375", "372", "376", "422":
            // The message of the day, kept in the server buffer.
            if let text = line.params.last, !text.isEmpty {
                append(to: Self.serverBufferName, nick: nil, text: text,
                       kind: .system, isLocal: false, at: date)
            }

        case "433", "431", "432":
            let detail = line.params.dropFirst().joined(separator: " ")
            append(to: Self.serverBufferName, nick: nil,
                   text: detail.isEmpty ? "The server refused the nick." : detail,
                   kind: .error, isLocal: false, at: date)

        case "PING":
            // Answered by the caller; nothing to show.
            break

        case "PRIVMSG":
            handlePrivmsg(line, sender: sender, at: date)

        case "NOTICE":
            handleNotice(line, sender: sender, at: date)

        case "JOIN":
            handleJoin(line, sender: sender, at: date)

        case "PART":
            let channelName = line.params.first ?? ""
            guard let index = indexOf(channelName) else { return }
            let leaving = sender.map { I2PIRCName.key($0) == I2PIRCName.key(nick) } ?? false
            if let sender {
                drop(sender, from: index)
            }
            if leaving { conversations[index].joined = false }
            let reason = line.params.count > 2 ? line.params.last : nil
            let suffix = reason.map { " (\($0))" } ?? ""
            append(to: channelName, nick: nil,
                   text: "\(sender ?? "Someone") parted\(suffix)",
                   kind: .system, isLocal: false, at: date)

        case "QUIT":
            let reason = line.params.last
            let suffix = reason.map { " (\($0))" } ?? ""
            guard let sender else { return }
            let shared = conversations.filter { conversation in
                conversation.kind == .channel && conversation.members.contains {
                    I2PIRCName.key($0) == I2PIRCName.key(sender)
                }
            }
            for conversation in shared {
                guard let index = indexOf(conversation.id) else { continue }
                drop(sender, from: index)
                append(to: conversation.id, nick: nil,
                       text: "\(sender) quit\(suffix)",
                       kind: .system, isLocal: false, at: date)
            }

        case "NICK":
            guard let sender, let newNick = line.params.last, !newNick.isEmpty else { return }
            if I2PIRCName.key(sender) == I2PIRCName.key(nick) {
                nick = newNick
            }
            for index in conversations.indices {
                let renamed = conversations[index].members.map { member in
                    I2PIRCName.key(member) == I2PIRCName.key(sender) ? newNick : member
                }
                conversations[index].members = renamed
                // The status travels with the nick, so the member list keeps
                // an operator an operator after the rename.
                if let role = conversations[index].memberRoles.removeValue(
                    forKey: I2PIRCName.key(sender)),
                   role != .participant {
                    conversations[index].memberRoles[I2PIRCName.key(newNick)] = role
                }
            }
            for conversation in conversations where conversation.kind == .channel {
                guard let index = indexOf(conversation.id) else { continue }
                let inChannel = conversations[index].members.contains {
                    I2PIRCName.key($0) == I2PIRCName.key(newNick)
                }
                guard inChannel else { continue }
                append(to: conversation.id, nick: nil,
                       text: "\(sender) is now known as \(newNick)",
                       kind: .system, isLocal: false, at: date)
            }

        case "KICK":
            guard line.params.count >= 2 else { return }
            let channelName = line.params[0]
            let victim = line.params[1]
            let reason = line.params.count > 2 ? line.params[2] : nil
            guard let index = indexOf(channelName) else { return }
            drop(victim, from: index)
            if I2PIRCName.key(victim) == I2PIRCName.key(nick) {
                conversations[index].joined = false
            }
            let suffix = reason.map { " (\($0))" } ?? ""
            append(to: channelName, nick: nil,
                   text: "\(sender ?? "Someone") kicked \(victim)\(suffix)",
                   kind: .system, isLocal: false, at: date)

        case "TOPIC":
            guard line.params.count >= 2 else { return }
            let channelName = line.params[0]
            let topic = line.params[1]
            guard let index = indexOf(channelName) else { return }
            conversations[index].topic = topic.isEmpty ? nil : topic
            append(to: channelName, nick: nil,
                   text: "\(sender ?? "Someone") set the topic: \(topic.isEmpty ? "(cleared)" : topic)",
                   kind: .system, isLocal: false, at: date)

        case "332":
            // RPL_TOPIC: our nick, the channel, the topic.
            guard line.params.count >= 3 else { return }
            let channelName = line.params[1]
            guard let index = indexOf(channelName) else { return }
            let topic = line.params[2]
            conversations[index].topic = topic.isEmpty ? nil : topic

        case "353":
            // RPL_NAMREPLY: our nick, the channel symbol, the channel, names.
            guard line.params.count >= 4 else { return }
            let channelName = line.params[2]
            let names = line.params[3]
            ensure(channelName, name: channelName, kind: .channel, at: date)
            guard let index = indexOf(channelName) else { return }
            for entry in names.split(separator: " ") {
                guard let parsed = I2PIRCMemberList.parse(namesEntry: String(entry)) else {
                    continue
                }
                assign(parsed.nick, role: parsed.role, to: index)
            }

        case "366":
            // RPL_ENDOFNAMES carries nothing worth a line.
            break

        case "MODE":
            guard line.params.count > 1, let channelName = line.params.first,
                  let index = indexOf(channelName) else { return }
            // The status flags move nicks between the member list's groups;
            // the names the flags name are the line's remaining params.
            I2PIRCMemberList.apply(modes: line.params,
                                   to: &conversations[index].memberRoles,
                                   members: conversations[index].members)
            let detail = line.params.dropFirst().joined(separator: " ")
            append(to: channelName, nick: nil,
                   text: "\(sender ?? "Server") set mode \(detail)",
                   kind: .system, isLocal: false, at: date)

        case "ERROR":
            let text = line.params.last.flatMap { $0.isEmpty ? nil : $0 }
                ?? "The server reported an error."
            append(to: Self.serverBufferName, nick: nil, text: text,
                   kind: .error, isLocal: false, at: date)

        default:
            guard let numeric = line.numeric, (400...599).contains(numeric) else { return }
            // A channel-scoped numeric puts our nick first and the channel
            // second ("403 tester #i2p :No such channel"): file it in that
            // channel when we hold it, with our nick and the channel's name
            // dropped from the sentence. Everything else — and a numeric naming
            // a channel we are not in — stays in the server buffer, so nothing
            // ever lands in a conversation the user cannot see.
            let channelTarget = line.params.dropFirst().first.flatMap { candidate in
                I2PIRCName.isChannel(candidate) && indexOf(candidate) != nil ? candidate : nil
            }
            let detail = line.params.dropFirst(channelTarget == nil ? 1 : 2)
                .joined(separator: " ")
            let text = detail.isEmpty ? "Error \(numeric)" : detail
            append(to: channelTarget ?? Self.serverBufferName, nick: nil, text: text,
                   kind: .error, isLocal: false, at: date)
        }
    }

    // MARK: Line handlers

    private mutating func handlePrivmsg(_ line: I2PIRCLine, sender: String?, at date: Date) {
        guard line.params.count >= 2 else { return }
        let target = line.params[0]
        let body = line.params[line.params.count - 1]
        guard let sender else { return }
        if I2PIRCText.isCTCP(body), I2PIRCText.actionBody(body) == nil {
            // Any other CTCP request is never rendered as chat text.
            return
        }
        let isChannel = I2PIRCName.isChannel(target)
        let conversationName = isChannel
            ? target
            : (I2PIRCName.key(target) == I2PIRCName.key(nick) ? sender : target)
        let conversationID = I2PIRCName.key(conversationName)
        ensure(conversationID, name: conversationName,
               kind: isChannel ? .channel : .query, at: date)
        if let action = I2PIRCText.actionBody(body) {
            append(to: conversationID, nick: sender, text: action,
                   kind: .action, isLocal: false, at: date)
        } else {
            append(to: conversationID, nick: sender, text: I2PIRCText.sanitize(body),
                   kind: .message, isLocal: false, at: date)
        }
    }

    private mutating func handleNotice(_ line: I2PIRCLine, sender: String?, at date: Date) {
        guard let text = line.params.last, !text.isEmpty else { return }
        let target = line.params.first ?? ""
        if I2PIRCName.isChannel(target), indexOf(target) != nil {
            append(to: target, nick: sender, text: I2PIRCText.sanitize(text),
                   kind: .notice, isLocal: false, at: date)
        } else {
            append(to: Self.serverBufferName, nick: sender,
                   text: I2PIRCText.sanitize(text), kind: .notice, isLocal: false, at: date)
        }
    }

    private mutating func handleJoin(_ line: I2PIRCLine, sender: String?, at date: Date) {
        guard let sender, let channelName = line.params.first, !channelName.isEmpty else { return }
        let conversationID = I2PIRCName.key(channelName)
        ensure(conversationID, name: channelName, kind: .channel, at: date)
        guard let index = indexOf(conversationID) else { return }
        let isUs = I2PIRCName.key(sender) == I2PIRCName.key(nick)
        if isUs { conversations[index].joined = true }
        let known = conversations[index].members.contains {
            I2PIRCName.key($0) == I2PIRCName.key(sender)
        }
        if !known {
            conversations[index].members.append(sender)
        }
        append(to: conversationID, nick: nil, text: "\(sender) joined",
               kind: .system, isLocal: false, at: date)
    }

    // MARK: Mutation helpers

    private func indexOf(_ conversationID: String) -> Int? {
        let key = I2PIRCName.key(conversationID)
        return conversations.firstIndex { $0.id == key }
    }

    private func conversationName(for conversationID: String) -> String? {
        indexOf(conversationID).map { conversations[$0].name }
    }

    private func kindFor(_ conversationID: String) -> I2PIRCConversation.Kind {
        indexOf(conversationID).map { conversations[$0].kind } ?? .server
    }

    private mutating func ensure(_ conversationID: String,
                                 name: String,
                                 kind: I2PIRCConversation.Kind,
                                 at date: Date) {
        let key = I2PIRCName.key(conversationID)
        guard !conversations.contains(where: { $0.id == key }) else { return }
        conversations.append(I2PIRCConversation(name: name, kind: kind, at: date))
    }

    /// Puts a nick in a channel's roster with the status it holds there: added
    /// when it is new, and its status set to what the server just said.
    private mutating func assign(_ nick: String,
                                 role: I2PIRCMemberRole,
                                 to index: Int) {
        let key = I2PIRCName.key(nick)
        guard !key.isEmpty else { return }
        if !conversations[index].members.contains(where: { I2PIRCName.key($0) == key }) {
            conversations[index].members.append(nick)
        }
        if role == .participant {
            // A plain member needs no entry: the roster's default is enough.
            conversations[index].memberRoles.removeValue(forKey: key)
        } else {
            conversations[index].memberRoles[key] = role
        }
    }

    /// Takes a nick out of a channel's roster, its status with it.
    private mutating func drop(_ nick: String, from index: Int) {
        let key = I2PIRCName.key(nick)
        conversations[index].members.removeAll { I2PIRCName.key($0) == key }
        conversations[index].memberRoles.removeValue(forKey: key)
    }

    private mutating func append(to conversationID: String,
                                 nick: String?,
                                 text: String,
                                 kind: I2PIRCMessage.Kind,
                                 isLocal: Bool,
                                 at date: Date) {
        let key = I2PIRCName.key(conversationID)
        guard let index = conversations.firstIndex(where: { $0.id == key }) else { return }
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        // A line from somebody else that names us is marked, so the chat can
        // edge it in violet, count it on the chip and step through it.
        let marked = !isLocal && I2PIRCMention.counts(kind: kind)
            && I2PIRCMention.names(trimmed, nick: self.nick)
        // A line that holds one of the user's words wears the keyword edge and
        // counts on the chip beside the mention badge, the same way.
        let hits = I2PIRCKeywordRule.hits(in: trimmed, kind: kind,
                                          isLocal: isLocal, keywords: enabledKeywords)
        conversations[index].messages.append(
            I2PIRCMessage(date: date, nick: nick, text: trimmed, kind: kind,
                          isLocal: isLocal, mentionsUs: marked, keywordHits: hits))
        // A muted conversation keeps the marks on its lines but adds none of
        // the badges that go with them.
        let silent = mutedConversations.contains(key)
        if marked, !silent {
            conversations[index].mentionCount += 1
        }
        if !hits.isEmpty, !silent {
            conversations[index].keywordCount += 1
        }
        if conversations[index].messages.count > Self.messageLimit {
            let overflow = conversations[index].messages.count - Self.messageLimit
            // Lines dropping off the front take their marks with them, so the
            // counts never outstrip what is left on screen.
            let dropped = conversations[index].messages.prefix(overflow)
                .filter { $0.mentionsUs }.count
            let droppedKeywords = conversations[index].messages.prefix(overflow)
                .filter { !$0.keywordHits.isEmpty }.count
            conversations[index].messages.removeFirst(overflow)
            conversations[index].mentionCount = max(0, conversations[index].mentionCount - dropped)
            conversations[index].keywordCount = max(0, conversations[index].keywordCount - droppedKeywords)
        }
        conversations[index].lastActivity = date
        if !isLocal, !silent, kind == .message || kind == .action || kind == .notice {
            conversations[index].unread = min(conversations[index].unread + 1, Self.messageLimit)
        }
    }
}

private extension String {
    var nilIfEmpty: String? { isEmpty ? nil : self }
}

// MARK: - Self-test suite (IRC chat state)

enum I2PIRCChatStateSelfTest {
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

        run("irc · registration, joins, messages and unread badges") {
            var state = I2PIRCChatState(serverName: "irc.example.i2p", nick: "tester")
            try applyAll(&state, [
                ":irc.example.i2p 001 tester :Welcome to the network",
                ":tester!t@client JOIN #i2p",
                ":alice!a@host JOIN #i2p",
                ":bob!b@host JOIN #i2p",
                ":alice!a@host PRIVMSG #i2p :hello there"
            ])
            guard state.registered, state.nick == "tester" else { throw I2PWireError.invalidFormat }
            let channel = try unwrap(state.conversation("#i2p"))
            guard channel.kind == .channel, channel.joined,
                  channel.members.count == 3,
                  channel.sortedMembers(ourNick: "tester").first == "tester",
                  channel.unread == 1,
                  channel.messages.last?.kind == .message,
                  channel.messages.last?.nick == "alice",
                  channel.messages.last?.text == "hello there" else {
                throw I2PWireError.invalidFormat
            }
            state.markRead("#i2p")
            guard state.conversation("#i2p")?.unread == 0, state.totalUnread == 0 else {
                throw I2PWireError.invalidFormat
            }
            // Our own echo never badges and renders as local.
            state.noteOutgoing("hi alice", to: "#i2p")
            guard let echoed = state.conversation("#i2p")?.messages.last,
                  echoed.isLocal, echoed.nick == "tester", echoed.text == "hi alice",
                  state.conversation("#i2p")?.unread == 0 else {
                throw I2PWireError.invalidFormat
            }
            return "welcome, joins and a channel message build the conversation; the badge clears on read and a local echo never counts"
        }

        run("irc · notices, actions, topics, names and numeric errors") {
            var state = I2PIRCChatState(serverName: "irc.example.i2p", nick: "tester")
            try applyAll(&state, [
                ":irc.example.i2p 001 tester :Welcome",
                ":tester!t@client JOIN #i2p",
                ":irc.example.i2p 332 tester #i2p :Welcome to #i2p",
                ":irc.example.i2p 353 tester = #i2p :@tester +alice bob",
                ":irc.example.i2p 366 tester #i2p :End of /NAMES list",
                ":alice!a@host NOTICE #i2p :be right back",
                ":bob!b@host PRIVMSG #i2p :\u{01}ACTION waves hello\u{01}",
                ":irc.example.i2p 403 tester #i2p :No such channel"
            ])
            let channel = try unwrap(state.conversation("#i2p"))
            guard channel.topic == "Welcome to #i2p",
                  channel.members.sorted() == ["alice", "bob", "tester"] else {
                throw I2PWireError.invalidFormat
            }
            guard channel.messages.contains(where: { $0.kind == .notice && $0.nick == "alice" }),
                  channel.messages.contains(where: {
                      $0.kind == .action && $0.text == "waves hello" && $0.nick == "bob"
                  }),
                  channel.messages.contains(where: { $0.kind == .error && $0.text.contains("No such channel") }) else {
                throw I2PWireError.invalidFormat
            }
            // Other CTCP requests are never rendered as chat text.
            try applyAll(&state, [":alice!a@host PRIVMSG #i2p :\u{01}VERSION\u{01}"])
            guard !(state.conversation("#i2p")?.messages.contains { $0.text.contains("VERSION") } ?? true) else {
                throw I2PWireError.invalidFormat
            }
            // A channel-scoped numeric names a channel we do not hold: it stays
            // in the server buffer and keeps the channel's name in its sentence,
            // so nothing appears in a channel we are not in.
            try applyAll(&state, [":irc.example.i2p 403 tester #nope :No such channel either"])
            guard state.conversation("#i2p")?.messages.contains(where: {
                      $0.text.contains("No such channel either")
                  }) == false,
                  state.conversation(I2PIRCChatState.serverBufferName)?.messages.contains(where: {
                      $0.kind == .error && $0.text.contains("#nope")
                          && $0.text.contains("No such channel either")
                  }) == true else {
                throw I2PWireError.invalidFormat
            }
            return "topic, NAMES, notice, ACTION and channel numerics all land in the channel; other CTCP is suppressed; a numeric for a channel we do not hold stays in the server buffer"
        }

        run("irc · private queries, nick changes, parts and quits") {
            var state = I2PIRCChatState(serverName: "irc.example.i2p", nick: "tester")
            try applyAll(&state, [
                ":irc.example.i2p 001 tester :Welcome",
                ":tester!t@client JOIN #i2p",
                ":alice!a@host JOIN #i2p",
                ":alice!a@host PRIVMSG tester :psst, private",
                ":alice!a@host NICK alicia"
            ])
            let query = try unwrap(state.conversation("alice"))
            guard query.kind == .query, query.messages.last?.text == "psst, private",
                  state.conversation("#i2p")?.members.contains(where: {
                      I2PIRCName.key($0) == "alicia"
                  }) == true else {
                throw I2PWireError.invalidFormat
            }
            // The nick change is announced, and a part and a quit each take
            // their nick out of the roster.
            try applyAll(&state, [
                ":bob!b@host JOIN #i2p",
                ":bob!b@host PART #i2p :later",
                ":alicia!a@host QUIT :bye"
            ])
            guard state.conversation("#i2p")?.members.contains(where: {
                      I2PIRCName.key($0) == "alicia"
                  }) == false,
                  state.conversation("#i2p")?.members.contains(where: {
                      I2PIRCName.key($0) == "bob"
                  }) == false else {
                throw I2PWireError.invalidFormat
            }
            // Channel names are case-insensitive: one conversation, not two.
            try applyAll(&state, [
                ":tester!t@client JOIN #I2P",
                ":bob!b@host JOIN #i2p"
            ])
            guard state.conversations.filter { $0.kind == .channel }.count == 1,
                  state.conversation("#I2P")?.members.count == 2 else {
                throw I2PWireError.invalidFormat
            }
            // The server buffer orders first; channels follow.
            guard state.orderedConversations.first?.kind == .server else {
                throw I2PWireError.invalidFormat
            }
            return "private messages open a query; nick change, part and quit keep the roster honest; channel casing folds to one conversation"
        }

        run("irc · messages are bounded and join requests show immediately") {
            var state = I2PIRCChatState(serverName: "s", nick: "tester")
            state.requestJoin("#i2p")
            guard state.conversation("#i2p")?.joined == false,
                  state.conversation("#i2p")?.messages.last?.kind == .system else {
                throw I2PWireError.invalidFormat
            }
            try applyAll(&state, [":tester!t@c JOIN #i2p"])
            guard state.conversation("#i2p")?.joined == true else { throw I2PWireError.invalidFormat }
            let burst = (0..<(I2PIRCChatState.messageLimit + 50)).map { index in
                ":alice!a@h PRIVMSG #i2p :line \(index)"
            }
            try applyAll(&state, burst)
            let channel = try unwrap(state.conversation("#i2p"))
            guard channel.messages.count == I2PIRCChatState.messageLimit,
                  channel.messages.last?.text == "line \(I2PIRCChatState.messageLimit + 49)",
                  channel.messages.first?.text != "line 0",
                  channel.unread == I2PIRCChatState.messageLimit else {
                throw I2PWireError.invalidFormat
            }
            return "join requests create the channel at once; the buffer is capped at \(I2PIRCChatState.messageLimit) lines from the oldest end"
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
