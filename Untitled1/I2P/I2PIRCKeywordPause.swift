//
//  I2PIRCKeywordPause.swift
//  The master switch at the top of the Highlights sheet: every keyword turned
//  off for a set time — 15 minutes, an hour or until tomorrow — without
//  touching the list, and switched back on by itself when the time runs out.
//
//  A pause is a moment, not an edit: the words keep their own switches and
//  their place in the list, and the book's `enabledWords` reads as nothing while
//  the pause runs. The rule is pure arithmetic, so the whole behaviour is
//  verified by the self-test suite without a connection.
//

import Foundation

// MARK: - Duration

/// How long the master switch pauses highlighting for, as the one row of
/// choices in the Highlights sheet offers it.
enum I2PIRCKeywordPauseDuration: String, CaseIterable, Identifiable {
    /// A short pause: the rest of a build, a call, a meeting.
    case quarterHour
    /// The default: the next hour.
    case hour
    /// Until the next day starts, whatever the hour is now.
    case tomorrow

    var id: String { rawValue }

    /// What the chip reads.
    var label: String {
        switch self {
        case .quarterHour: return "15 minutes"
        case .hour: return "1 hour"
        case .tomorrow: return "Until tomorrow"
        }
    }

    /// What the chip tells VoiceOver it does.
    var actionLabel: String {
        switch self {
        case .quarterHour: return "Pause highlighting for 15 minutes"
        case .hour: return "Pause highlighting for 1 hour"
        case .tomorrow: return "Pause highlighting until tomorrow"
        }
    }

    /// When a pause chosen at `now` ends: the fixed span from now, or the start
    /// of the next day for the rest of this one.
    func end(from now: Date = Date(), calendar: Calendar = .current) -> Date {
        switch self {
        case .quarterHour:
            return now.addingTimeInterval(15 * 60)
        case .hour:
            return now.addingTimeInterval(60 * 60)
        case .tomorrow:
            let midnight = calendar.startOfDay(for: now)
            return calendar.date(byAdding: .day, value: 1, to: midnight)
                ?? now.addingTimeInterval(12 * 60 * 60)
        }
    }
}

// MARK: - Pause rule

enum I2PIRCKeywordPause {
    /// Whether the pause that ends at `endsAt` is still running, which is the
    /// master switch being off. A pause with no end date is no pause at all.
    static func isPaused(until endsAt: Date?, at now: Date = Date()) -> Bool {
        guard let endsAt else { return false }
        return endsAt > now
    }

    /// The line under the master switch: how much of the pause is left, or that
    /// highlighting is on.
    static func summary(until endsAt: Date?, at now: Date = Date()) -> String {
        guard isPaused(until: endsAt, at: now), let endsAt else {
            return "Highlighting is on"
        }
        return "Highlighting paused for \(remaining(until: endsAt, from: now))"
    }

    /// What is left of the pause in words: "42 minutes", "1 hour", "1 hour 5
    /// minutes". Rounded up, so a pause with a few seconds to run never reads as
    /// no time at all.
    static func remaining(until endsAt: Date, from now: Date = Date()) -> String {
        let minutes = max(1, Int((endsAt.timeIntervalSince(now) / 60).rounded(.up)))
        guard minutes >= 60 else {
            return "\(minutes) minute\(minutes == 1 ? "" : "s")"
        }
        let hours = minutes / 60
        let rest = minutes % 60
        let hoursText = "\(hours) hour\(hours == 1 ? "" : "s")"
        guard rest > 0 else { return hoursText }
        return "\(hoursText) \(rest) minute\(rest == 1 ? "" : "s")"
    }
}

// MARK: - Self-test suite (IRC keyword pause)

enum I2PIRCKeywordPauseSelfTest {
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

        run("irc · a pause runs for the length it was set for") {
            var calendar = Calendar(identifier: .gregorian)
            calendar.timeZone = TimeZone(secondsFromGMT: 0) ?? .current
            let noon = calendar.date(from: DateComponents(year: 2024, month: 5, day: 17,
                                                          hour: 12, minute: 30)) ?? Date()
            let tomorrow = calendar.date(from: DateComponents(year: 2024, month: 5, day: 18))
                ?? noon
            let dayAfter = calendar.date(from: DateComponents(year: 2024, month: 5, day: 19))
                ?? noon

            // The three choices the sheet offers, in the order it shows them.
            guard I2PIRCKeywordPauseDuration.allCases.map(\.label)
                    == ["15 minutes", "1 hour", "Until tomorrow"],
                  I2PIRCKeywordPauseDuration.quarterHour.end(from: noon, calendar: calendar)
                    == noon.addingTimeInterval(15 * 60),
                  I2PIRCKeywordPauseDuration.hour.end(from: noon, calendar: calendar)
                    == noon.addingTimeInterval(60 * 60),
                  // "Until tomorrow" ends when the next day starts, whatever the
                  // hour is now — a pause taken just after midnight lasts the
                  // whole of that day.
                  I2PIRCKeywordPauseDuration.tomorrow.end(from: noon, calendar: calendar)
                    == tomorrow,
                  I2PIRCKeywordPauseDuration.tomorrow
                    .end(from: tomorrow.addingTimeInterval(30), calendar: calendar)
                    == dayAfter else {
                throw I2PWireError.invalidFormat
            }

            // The summary names the state and the time left in it.
            guard I2PIRCKeywordPause.summary(until: nil, at: noon) == "Highlighting is on",
                  I2PIRCKeywordPause.summary(until: noon.addingTimeInterval(-1), at: noon)
                    == "Highlighting is on",
                  I2PIRCKeywordPause.summary(until: noon.addingTimeInterval(42 * 60), at: noon)
                    == "Highlighting paused for 42 minutes",
                  I2PIRCKeywordPause.summary(until: noon.addingTimeInterval(60 * 60), at: noon)
                    == "Highlighting paused for 1 hour",
                  I2PIRCKeywordPause.summary(until: noon.addingTimeInterval(120 * 60), at: noon)
                    == "Highlighting paused for 2 hours",
                  I2PIRCKeywordPause.summary(until: noon.addingTimeInterval(65 * 60), at: noon)
                    == "Highlighting paused for 1 hour 5 minutes",
                  // A second or two left still reads as a minute, never as none.
                  I2PIRCKeywordPause.summary(until: noon.addingTimeInterval(20), at: noon)
                    == "Highlighting paused for 1 minute",
                  I2PIRCKeywordPause.isPaused(until: noon.addingTimeInterval(1), at: noon),
                  !I2PIRCKeywordPause.isPaused(until: noon, at: noon) else {
                throw I2PWireError.invalidFormat
            }
            return "the three durations end when they should, and the summary reads the pause left in minutes or hours, or that highlighting is on"
        }

        run("irc · a pause leaves the list alone and comes back on its own") {
            let suite = "i2p.irc.keywordPause.selfTest"
            let defaults = UserDefaults(suiteName: suite) ?? .standard
            defaults.removePersistentDomain(forName: suite)
            let now = Date()

            let book = I2PIRCKeywordBook(defaults: defaults, storageKey: "keywords")
            guard book.add("Release"), book.add("i2pd"),
                  !book.isPaused,
                  book.enabledWords == ["Release", "i2pd"] else {
                throw I2PWireError.invalidFormat
            }

            // The master switch off turns every word off, and the list — and
            // each word's own switch — stays exactly as it was.
            book.pause(for: .quarterHour, at: now)
            guard book.isPaused,
                  book.enabledWords.isEmpty,
                  book.entries.map(\.word) == ["Release", "i2pd"],
                  book.entries.allSatisfy(\.isEnabled),
                  book.lastPauseDuration == .quarterHour,
                  I2PIRCKeywordPause.summary(until: book.pauseEndsAt, at: now)
                    == "Highlighting paused for 15 minutes" else {
                throw I2PWireError.invalidFormat
            }

            // A relaunch reads the pause back, and the words with it.
            let reopened = I2PIRCKeywordBook(defaults: defaults, storageKey: "keywords")
            guard reopened.isPaused,
                  reopened.enabledWords.isEmpty,
                  reopened.entries.map(\.word) == ["Release", "i2pd"],
                  reopened.lastPauseDuration == .quarterHour else {
                throw I2PWireError.invalidFormat
            }

            // Switching it back on is instant and sticks.
            reopened.resume()
            guard !reopened.isPaused,
                  reopened.enabledWords == ["Release", "i2pd"],
                  !I2PIRCKeywordBook(defaults: defaults, storageKey: "keywords").isPaused else {
                throw I2PWireError.invalidFormat
            }

            // A pause that ran out while the app was closed is over the next
            // time the book is read: the switch comes back on by itself.
            reopened.pause(for: .hour, at: now)
            defaults.set(now.addingTimeInterval(-60), forKey: "keywords.pause.endsAt")
            let expired = I2PIRCKeywordBook(defaults: defaults, storageKey: "keywords")
            guard !expired.isPaused,
                  expired.pauseEndsAt == nil,
                  expired.enabledWords == ["Release", "i2pd"],
                  defaults.object(forKey: "keywords.pause.endsAt") == nil else {
                throw I2PWireError.invalidFormat
            }

            defaults.removePersistentDomain(forName: suite)
            return "the master switch pauses every word without editing the list, the pause survives a relaunch, and a pause that ran out comes back on by itself"
        }

        run("irc · a pause marks no line and zeroes the chip counts") {
            let suite = "i2p.irc.keywordPause.state.selfTest"
            let defaults = UserDefaults(suiteName: suite) ?? .standard
            defaults.removePersistentDomain(forName: suite)

            var state = I2PIRCChatState(serverName: "irc.example.i2p", nick: "tester")
            try applyAll(&state, [
                ":tester!t@client JOIN #i2p",
                ":alice!a@host JOIN #i2p",
                ":alice!a@host PRIVMSG #i2p :the release is out",
                ":bob!b@host PRIVMSG #i2p :nothing to see here",
                ":bob!b@host PRIVMSG #i2p :i2pd release notes are up",
                ":alice!a@host PRIVMSG tester :a private release word"
            ])

            let book = I2PIRCKeywordBook(defaults: defaults, storageKey: "keywords")
            guard book.add("release") else { throw I2PWireError.invalidFormat }
            state.setKeywords(book.enabledWords)
            guard state.conversation("#i2p")?.keywordCount == 2,
                  state.conversation("alice")?.keywordCount == 1,
                  I2PIRCHighlightMatches.matches(in: state.orderedConversations,
                                                 words: book.enabledWords).count == 3 else {
                throw I2PWireError.invalidFormat
            }

            // Paused: no line is marked anywhere and every chip count is zero,
            // while the lines themselves stay where they are.
            book.pause(for: .hour)
            state.setKeywords(book.enabledWords)
            let paused = try unwrap(state.conversation("#i2p"))
            guard paused.keywordCount == 0,
                  !paused.messages.contains(where: { !$0.keywordHits.isEmpty }),
                  paused.messages.contains(where: { $0.text == "the release is out" }),
                  state.conversation("alice")?.keywordCount == 0,
                  !state.conversation("alice").map({ conv in
                      conv.messages.contains(where: { !$0.keywordHits.isEmpty })
                  })!,
                  I2PIRCHighlightMatches.matches(in: state.orderedConversations,
                                                 words: book.enabledWords).isEmpty else {
                throw I2PWireError.invalidFormat
            }

            // Back on, the lines wear their edges again and the counts return.
            book.resume()
            state.setKeywords(book.enabledWords)
            guard state.conversation("#i2p")?.keywordCount == 2,
                  state.conversation("alice")?.keywordCount == 1,
                  state.conversation("#i2p")?.messages.first(where: {
                      $0.text == "the release is out"
                  })?.keywordHits == ["release"] else {
                throw I2PWireError.invalidFormat
            }

            defaults.removePersistentDomain(forName: suite)
            return "while the pause runs every keyword line loses its edge and every chip reads zero, and the lines take their edges back when it is over"
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
