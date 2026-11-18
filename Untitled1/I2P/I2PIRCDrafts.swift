//
//  I2PIRCDrafts.swift
//  The composer's drafts: one per conversation, so typing in #i2p, stepping
//  over to a query and coming back puts exactly what was typed in the field
//  again — whitespace and all. They live in memory for the session and are
//  never written to disk.
//
//  The rule is pure text and conversation keys, so the switching and the
//  clearing are verified by the self-test suite without a connection.
//

import Foundation

// MARK: - Draft store

/// The drafts the composer keeps, keyed by `I2PIRCName.key` of the conversation
/// they were typed in.
struct I2PIRCDrafts: Equatable {
    /// Draft text per conversation key. A conversation with no entry has no
    /// draft: an empty draft is no draft at all, so a conversation typed into
    /// and cleared again looks untouched.
    private var texts: [String: String] = [:]

    /// How many conversations hold a draft.
    var count: Int { texts.count }

    /// The conversations holding a draft, in a stable order.
    var conversationKeys: [String] { texts.keys.sorted() }

    /// The draft of a conversation exactly as it was typed, or "" when nothing
    /// was. The name is matched the way IRC matches a conversation, so "#i2p"
    /// and "#I2P" are the same conversation.
    func draft(for conversationID: String) -> String {
        texts[I2PIRCName.key(conversationID)] ?? ""
    }

    /// Whether the conversation holds a draft at all.
    func hasDraft(for conversationID: String) -> Bool {
        texts[I2PIRCName.key(conversationID)] != nil
    }

    /// Records what the composer holds for a conversation. Whitespace is kept
    /// as typed; an empty text drops the conversation's draft.
    mutating func store(_ text: String, for conversationID: String) {
        let key = I2PIRCName.key(conversationID)
        guard !key.isEmpty else { return }
        if text.isEmpty {
            texts.removeValue(forKey: key)
        } else {
            texts[key] = text
        }
    }

    /// Sending clears only the conversation it was sent from.
    mutating func clear(_ conversationID: String) {
        texts.removeValue(forKey: I2PIRCName.key(conversationID))
    }

    /// Puts another conversation on screen: what the field holds is kept for
    /// the conversation being left, verbatim, and the conversation arriving
    /// hands back its own draft. Returns the text the field shows next.
    mutating func switchDraft(from previous: String,
                              holding text: String,
                              to next: String) -> String {
        store(text, for: previous)
        return draft(for: next)
    }
}

// MARK: - Self-test suite (IRC drafts)

enum I2PIRCDraftsSelfTest {
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

        run("irc · each conversation keeps its own draft") {
            var drafts = I2PIRCDrafts()
            guard drafts.count == 0,
                  drafts.draft(for: "#i2p").isEmpty,
                  !drafts.hasDraft(for: "#i2p") else {
                throw I2PWireError.invalidFormat
            }
            drafts.store("what about the tunnels", for: "#i2p")
            drafts.store("  psst,\nprivate  ", for: "bob")
            guard drafts.draft(for: "#i2p") == "what about the tunnels",
                  drafts.draft(for: "#I2P") == "what about the tunnels",
                  drafts.draft(for: "bob") == "  psst,\nprivate  ",
                  drafts.hasDraft(for: "bob"),
                  drafts.count == 2,
                  drafts.conversationKeys == ["#i2p", "bob"] else {
                throw I2PWireError.invalidFormat
            }
            // A conversation never typed in has no draft, and the key is the
            // IRC name match: the same channel typed in another case is one
            // conversation, not two.
            guard drafts.draft(for: "server").isEmpty,
                  !drafts.hasDraft(for: "server") else {
                throw I2PWireError.invalidFormat
            }
            // A draft that is only whitespace is still a draft, exactly as
            // typed.
            drafts.store("   ", for: "alma")
            guard drafts.draft(for: "alma") == "   ",
                  drafts.count == 3 else {
                throw I2PWireError.invalidFormat
            }
            return "each conversation holds its own draft verbatim, looked up case-insensitively, and a never-typed conversation holds none"
        }

        run("irc · switching conversations puts each draft back in the field") {
            var drafts = I2PIRCDrafts()
            var field = "hi there"
            drafts.store(field, for: "#i2p")
            // Over to a query: the field shows that conversation's draft,
            // which is nothing yet.
            field = drafts.switchDraft(from: "#i2p", holding: field, to: "bob")
            guard field.isEmpty else { throw I2PWireError.invalidFormat }
            // Typing in the query, whitespace and all.
            field = "  psst, private\r\n  "
            // Back to the channel: exactly what was typed there.
            field = drafts.switchDraft(from: "bob", holding: field, to: "#i2p")
            guard field == "hi there" else { throw I2PWireError.invalidFormat }
            // And back to the query: its own text, verbatim.
            field = drafts.switchDraft(from: "#i2p", holding: field, to: "bob")
            guard field == "  psst, private\r\n  " else { throw I2PWireError.invalidFormat }
            // Coming back to the conversation already on screen changes
            // nothing, however the name is cased.
            guard drafts.switchDraft(from: "bob", holding: field, to: "BOB") == field else {
                throw I2PWireError.invalidFormat
            }
            return "leaving a conversation keeps what was typed there and the one arriving hands back its own draft, whitespace and all"
        }

        run("irc · sending clears only the open conversation's draft") {
            var drafts = I2PIRCDrafts()
            drafts.store("half a thought", for: "#i2p")
            drafts.store("hello bob", for: "bob")
            drafts.clear("#i2p")
            guard drafts.draft(for: "#i2p").isEmpty,
                  !drafts.hasDraft(for: "#i2p"),
                  drafts.draft(for: "bob") == "hello bob",
                  drafts.count == 1 else {
                throw I2PWireError.invalidFormat
            }
            // Clearing a conversation that holds nothing changes nothing, and
            // a draft edited down to nothing is no draft at all.
            drafts.clear("nobody")
            guard drafts.count == 1 else { throw I2PWireError.invalidFormat }
            drafts.store("", for: "bob")
            guard drafts.count == 0,
                  drafts.draft(for: "bob").isEmpty else {
                throw I2PWireError.invalidFormat
            }
            return "a send drops one conversation's draft and leaves every other one where it was"
        }

        return results
    }
}
