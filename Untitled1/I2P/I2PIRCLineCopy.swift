//
//  I2PIRCLineCopy.swift
//  One transcript line on the clipboard. It goes in the same shape the share
//  sheet prints it — 'HH:mm nick: text', an action with an asterisk and a stage
//  note in brackets — so a pasted line reads exactly like a shared one. Nothing
//  about the connection, the server or the peer travels with it: the line is
//  the only thing copied.
//

import Foundation

// MARK: - Menu item

/// One choice a long press on a line offers: the line as text, and for a line
/// someone said, the same line with its nick named.
struct I2PIRCLineCopyOption: Identifiable, Equatable {
    enum Kind: String, Equatable {
        /// The line on its own.
        case text
        /// The same line, offered with the nick that said it.
        case nickAndText
    }

    let kind: Kind
    /// The menu item's label.
    let title: String
    /// What the confirmation above the composer calls the copy.
    let confirmation: String
    /// Exactly what goes on the clipboard.
    let text: String
    /// The nick the line belongs to; nil for a line nobody said.
    let nick: String?

    var id: String { kind.rawValue }

    /// What the chat shows for a moment after this copy.
    var notice: I2PIRCLineCopyNotice {
        I2PIRCLineCopyNotice(title: confirmation, line: text)
    }
}

/// The short confirmation the chat shows above the composer: what was taken,
/// and the line it took — never the connection or the peer.
struct I2PIRCLineCopyNotice: Equatable {
    let title: String
    let line: String
}

// MARK: - Choices

enum I2PIRCLineCopy {
    /// The menu a long press on a line opens: Copy text for every line, and Copy
    /// nick and text as well when the line has a nick to name. Both carry the
    /// line in the share sheet's shape, so what is pasted matches what Share
    /// would have printed.
    static func options(for message: I2PIRCMessage, ourNick: String) -> [I2PIRCLineCopyOption] {
        let line = I2PIRCShare.line(for: message, ourNick: ourNick)
        let text = I2PIRCLineCopyOption(kind: .text,
                                        title: "Copy text",
                                        confirmation: "Copied text",
                                        text: line,
                                        nick: I2PIRCShare.nick(of: message, ourNick: ourNick))
        guard let nick = text.nick else { return [text] }
        let withNick = I2PIRCLineCopyOption(kind: .nickAndText,
                                            title: "Copy nick and text",
                                            confirmation: "Copied nick and text",
                                            text: line,
                                            nick: nick)
        return [text, withNick]
    }
}
