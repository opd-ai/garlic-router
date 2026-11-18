//
//  I2PIRCDayGrouping.swift
//  The day rule for the IRC transcript: the lines on screen are broken into
//  days, each one opening with a small separator that reads "Today",
//  "Yesterday" and then the date, and a separator only ever sits over a day
//  that has a line under it.
//
//  The rule is pure date work over the lines already loaded, so a saved
//  history, a restored transcript and a filtered search are grouped the same
//  way, and the self-test suite verifies it without a connection.
//

import Foundation

// MARK: - Day separator

/// One day of the transcript: its first instant, which is what identifies it,
/// and the quiet word or date its capsule reads.
struct I2PIRCDaySeparator: Identifiable, Equatable {
    let dayStart: Date
    let label: String

    var id: Date { dayStart }
}

// MARK: - A row of the transcript

/// One row of the transcript: either a day's separator, a line of chat, or an
/// ignored nick's lines folded into one quiet row. The rows are built from
/// whatever lines are on screen, so a day with no line in them — a search's
/// filtered view, an empty transcript — never gets one.
enum I2PIRCTranscriptRow: Identifiable, Equatable {
    case day(I2PIRCDaySeparator)
    case message(I2PIRCMessage)
    case ignored(I2PIRCIgnoredGroup)

    var id: String {
        switch self {
        case .day(let separator): return "day-\(separator.dayStart.timeIntervalSince1970)"
        case .message(let message): return "line-\(message.id.uuidString)"
        case .ignored(let group): return group.id
        }
    }
}

// MARK: - Grouping rule

enum I2PIRCDayGrouping {
    /// The instant a line belongs to: the start of its day.
    static func dayStart(for date: Date, calendar: Calendar = Calendar.current) -> Date {
        calendar.startOfDay(for: date)
    }

    /// The transcript as rows: a day's separator above the first line of each
    /// day, then its lines in the order they arrived. A day that holds no line
    /// gets no separator at all.
    static func rows(messages: [I2PIRCMessage],
                     now: Date = Date(),
                     calendar: Calendar = Calendar.current,
                     locale: Locale = Locale.current) -> [I2PIRCTranscriptRow] {
        var rows: [I2PIRCTranscriptRow] = []
        rows.reserveCapacity(messages.count + 2)
        var currentDay: Date?
        for message in messages {
            let day = dayStart(for: message.date, calendar: calendar)
            if day != currentDay {
                currentDay = day
                rows.append(.day(I2PIRCDaySeparator(
                    dayStart: day,
                    label: label(for: message.date, now: now, calendar: calendar, locale: locale)
                )))
            }
            rows.append(.message(message))
        }
        return rows
    }

    /// What a day reads: "Today", "Yesterday", and the date for anything older.
    static func label(for date: Date,
                      now: Date = Date(),
                      calendar: Calendar = Calendar.current,
                      locale: Locale = Locale.current) -> String {
        let day = dayStart(for: date, calendar: calendar)
        let today = dayStart(for: now, calendar: calendar)
        if day == today { return "Today" }
        if let yesterday = calendar.date(byAdding: .day, value: -1, to: today), day == yesterday {
            return "Yesterday"
        }
        return dateText(for: date, calendar: calendar, locale: locale)
    }

    /// The date a day older than yesterday shows: the weekday and the day of
    /// the month, in the reader's own language and order.
    static func dateText(for date: Date, calendar: Calendar, locale: Locale) -> String {
        let formatter = DateFormatter()
        // The locale goes first: setting it resets the calendar it carries.
        formatter.locale = locale
        formatter.calendar = calendar
        formatter.timeZone = calendar.timeZone
        formatter.setLocalizedDateFormatFromTemplate("EEE d MMM")
        return formatter.string(from: date)
    }
}

// MARK: - Self-test suite (IRC transcript days)

enum I2PIRCDayGroupingSelfTest {
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

        run("irc · a day reads Today, Yesterday and then its date") {
            let calendar = utcCalendar()
            let locale = Locale(identifier: "en_US_POSIX")
            let now = date(2025, 3, 12, 18)

            guard I2PIRCDayGrouping.label(for: date(2025, 3, 12, 0, 5),
                                          now: now, calendar: calendar, locale: locale) == "Today",
                  I2PIRCDayGrouping.label(for: now,
                                          now: now, calendar: calendar, locale: locale) == "Today",
                  I2PIRCDayGrouping.label(for: date(2025, 3, 11, 23, 55),
                                          now: now, calendar: calendar, locale: locale) == "Yesterday",
                  // Just after midnight yesterday is still yesterday, whatever
                  // the hour of the line.
                  I2PIRCDayGrouping.label(for: date(2025, 3, 11, 0, 1),
                                          now: date(2025, 3, 12, 0, 5),
                                          calendar: calendar, locale: locale) == "Yesterday" else {
                throw I2PWireError.invalidFormat
            }

            let older = I2PIRCDayGrouping.label(for: date(2025, 3, 10, 21, 30),
                                                now: now, calendar: calendar, locale: locale)
            let olderSameDay = I2PIRCDayGrouping.label(for: date(2025, 3, 10, 1, 0),
                                                       now: now, calendar: calendar, locale: locale)
            let another = I2PIRCDayGrouping.label(for: date(2025, 3, 9, 9, 0),
                                                  now: now, calendar: calendar, locale: locale)
            guard older != "Today", older != "Yesterday", !older.isEmpty,
                  // The label belongs to the day, not to the hour the line came in.
                  older == olderSameDay,
                  // A different day reads differently.
                  older != another,
                  // Anything older carries the date itself.
                  older == I2PIRCDayGrouping.dateText(for: date(2025, 3, 10, 21, 30),
                                                      calendar: calendar, locale: locale) else {
                throw I2PWireError.invalidFormat
            }
            return "Today and Yesterday follow the line's own day; older days carry the date, at any hour"
        }

        run("irc · a separator opens each day and only days with a line get one") {
            let calendar = utcCalendar()
            let locale = Locale(identifier: "en_US_POSIX")
            let now = date(2025, 3, 12, 15)
            let messages = [
                line(date(2025, 3, 10, 21, 30), "two days back"),
                line(date(2025, 3, 11, 8, 5), "yesterday morning"),
                line(date(2025, 3, 11, 23, 59), "yesterday night"),
                line(date(2025, 3, 12, 9, 0), "today morning"),
                line(date(2025, 3, 12, 14, 0), "today afternoon")
            ]
            let rows = I2PIRCDayGrouping.rows(messages: messages, now: now,
                                              calendar: calendar, locale: locale)
            let days = separators(in: rows)
            guard rows.count == messages.count + 3,
                  days.count == 3,
                  days.map(\.label) == [
                    I2PIRCDayGrouping.dateText(for: date(2025, 3, 10, 21, 30),
                                               calendar: calendar, locale: locale),
                    "Yesterday",
                    "Today"
                  ],
                  // Each separator sits directly above its day's first line…
                  isDay(rows[0]), messageText(rows[1]) == "two days back",
                  isDay(rows[2]), messageText(rows[3]) == "yesterday morning",
                  isDay(rows[5]), messageText(rows[6]) == "today morning",
                  // …and a second line of the same day gets none.
                  messageText(rows[4]) == "yesterday night",
                  messageText(rows[7]) == "today afternoon",
                  // No row is drawn twice.
                  Set(rows.map(\.id)).count == rows.count else {
                throw I2PWireError.invalidFormat
            }
            // An empty transcript has nowhere to put a separator.
            guard I2PIRCDayGrouping.rows(messages: [], now: now,
                                         calendar: calendar, locale: locale).isEmpty else {
                throw I2PWireError.invalidFormat
            }
            return "3 days over 5 lines: one separator per day, none between two lines of the same day, none over an empty day"
        }

        run("irc · a search keeps the separator of a day it has matches in") {
            let calendar = utcCalendar()
            let locale = Locale(identifier: "en_US_POSIX")
            let now = date(2025, 3, 12, 15)
            let messages = [
                line(date(2025, 3, 10, 21, 30), "two days back"),
                line(date(2025, 3, 11, 8, 5), "yesterday morning"),
                line(date(2025, 3, 11, 23, 59), "yesterday night"),
                line(date(2025, 3, 12, 9, 0), "today morning"),
                line(date(2025, 3, 12, 14, 0), "today afternoon")
            ]

            // One day matched: only that day's separator comes with it.
            let yesterdayRows = I2PIRCDayGrouping.rows(
                messages: I2PIRCSearch.results(in: messages, query: "yesterday"),
                now: now, calendar: calendar, locale: locale
            )
            guard separators(in: yesterdayRows).map(\.label) == ["Yesterday"],
                  yesterdayRows.count == 3 else {
                throw I2PWireError.invalidFormat
            }

            // Two days matched, the day between them has no match: it gets no
            // separator, and neither does the first day of the transcript.
            let morningRows = I2PIRCDayGrouping.rows(
                messages: I2PIRCSearch.results(in: messages, query: "morning"),
                now: now, calendar: calendar, locale: locale
            )
            guard separators(in: morningRows).map(\.label) == ["Yesterday", "Today"],
                  morningRows.count == 4,
                  messageText(morningRows[1]) == "yesterday morning",
                  messageText(morningRows[3]) == "today morning" else {
                throw I2PWireError.invalidFormat
            }

            // A search with no match, and an empty one, never add a day.
            guard I2PIRCDayGrouping.rows(
                messages: I2PIRCSearch.results(in: messages, query: "zzz"),
                now: now, calendar: calendar, locale: locale
            ).isEmpty,
                  I2PIRCDayGrouping.rows(
                    messages: I2PIRCSearch.results(in: messages, query: ""),
                    now: now, calendar: calendar, locale: locale
                  ).count == messages.count + 3 else {
                throw I2PWireError.invalidFormat
            }
            return "the filtered lines carry their own days' separators only: 2 days matched, the day between them stays out"
        }

        return results
    }

    // MARK: Helpers

    private static func utcCalendar() -> Calendar {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0) ?? TimeZone.current
        return calendar
    }

    private static func date(_ year: Int, _ month: Int, _ day: Int,
                             _ hour: Int = 12, _ minute: Int = 0) -> Date {
        var calendar = utcCalendar()
        let components = DateComponents(year: year, month: month, day: day,
                                        hour: hour, minute: minute)
        return calendar.date(from: components) ?? Date(timeIntervalSince1970: 0)
    }

    private static func line(_ date: Date, _ text: String) -> I2PIRCMessage {
        I2PIRCMessage(date: date, nick: "alice", text: text, kind: .message, isLocal: false)
    }

    private static func separators(in rows: [I2PIRCTranscriptRow]) -> [I2PIRCDaySeparator] {
        rows.compactMap { row in
            if case .day(let separator) = row { return separator }
            return nil
        }
    }

    private static func isDay(_ row: I2PIRCTranscriptRow) -> Bool {
        if case .day = row { return true }
        return false
    }

    private static func messageText(_ row: I2PIRCTranscriptRow) -> String? {
        if case .message(let message) = row { return message.text }
        return nil
    }
}
