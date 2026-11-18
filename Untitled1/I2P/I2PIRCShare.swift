//
//  I2PIRCShare.swift
//  One conversation as the share sheet gets it: its name as the subject and its
//  lines, oldest first, as the body. Nothing else travels with it — no server
//  password, no destination, no host or peer details — since the transcript is
//  the only thing being shared.
//

import Foundation

// MARK: - Payload

struct I2PIRCSharePayload: Equatable {
    /// The conversation's name, which the share sheet shows as its subject.
    let name: String
    /// The transcript's lines, one per line, in the order they were said.
    let body: String

    /// What the share sheet shows as its subject: the conversation's name.
    var subject: String { name }
}

// MARK: - Transcript

enum I2PIRCShare {
    /// The payload for a conversation, or nil when it holds no lines — which is
    /// how the share control knows to stay disabled.
    static func payload(for conversation: I2PIRCConversation,
                        ourNick: String,
                        serverName: String) -> I2PIRCSharePayload? {
        guard !conversation.messages.isEmpty else { return nil }
        let body = conversation.messages
            .map { line(for: $0, ourNick: ourNick) }
            .joined(separator: "\n")
        guard !body.isEmpty else { return nil }
        return I2PIRCSharePayload(name: displayName(for: conversation, serverName: serverName),
                                  body: body)
    }

    /// The name the conversation goes by on screen and in the share sheet: the
    /// channel or the nick, and the server's name for the server buffer, which
    /// has no name of its own.
    static func displayName(for conversation: I2PIRCConversation, serverName: String) -> String {
        guard conversation.kind == .server else { return conversation.name }
        let trimmed = serverName.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? "Server buffer" : "\(trimmed) server buffer"
    }

    /// One line as the shared text carries it: 'HH:mm nick: text' for what was
    /// said, 'HH:mm * nick text' for an action, and the stage notes — system,
    /// error and notice lines — in brackets, since nobody said them.
    static func line(for message: I2PIRCMessage, ourNick: String) -> String {
        let time = timeFormatter.string(from: message.date)
        switch message.kind {
        case .message:
            let nick = speaker(of: message, ourNick: ourNick)
            return "\(time) \(nick): \(message.text)"
        case .action:
            let nick = speaker(of: message, ourNick: ourNick)
            return "\(time) * \(nick) \(message.text)"
        case .notice, .system, .error:
            return "\(time) [\(message.text)]"
        }
    }

    /// The nick a line belongs to, or nil for a line nobody said — a notice, a
    /// server line or a stage note, which the shared text carries in brackets
    /// instead of naming a speaker.
    static func nick(of message: I2PIRCMessage, ourNick: String) -> String? {
        switch message.kind {
        case .message, .action:
            return speaker(of: message, ourNick: ourNick)
        case .notice, .system, .error:
            return nil
        }
    }

    /// Who the line belongs to: its own nick, our nick for the lines we sent,
    /// and our nick as the last resort so a line never shares without a name.
    private static func speaker(of message: I2PIRCMessage, ourNick: String) -> String {
        if let nick = message.nick, !nick.isEmpty { return nick }
        return ourNick.isEmpty ? "you" : ourNick
    }

    /// Hours and minutes, 24-hour and fixed, so a shared transcript reads the
    /// same wherever it is opened.
    private static let timeFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "HH:mm"
        return formatter
    }()
}
