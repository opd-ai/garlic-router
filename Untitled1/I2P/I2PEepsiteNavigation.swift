//
//  I2PEepsiteNavigation.swift
//  The eepsite browser's navigation model: the visit an address bar names, the
//  back/forward stack, and the page as the share sheet receives it, plus their
//  self-test suites.
//
//  These types sit in I2P/ rather than beside the browser's SwiftUI view because
//  the off-device harness compiles `Untitled1/I2P/*.swift` with `swiftc` and
//  cannot compile a view file. Keeping them here means their suites run in that
//  harness for real instead of being stubbed out, and they still run in the app
//  and in the unit test target.
//

import Foundation

// MARK: - Visit

/// One visited page: the host to resolve and the path to request. The visible
/// form drops the implicit "/" so a host's root page reads as just its name.
struct I2PEepsiteVisit: Equatable {
    /// The host as the browser loads it: a .i2p name, a b32 hostname or a b33
    /// address.
    let host: String
    /// The request path, always starting with "/".
    let path: String

    init(host: String, path: String) {
        self.host = host
        self.path = path.hasPrefix("/") ? path : "/" + path
    }

    /// The visit an address bar's text points at, or nil when the text does not
    /// parse into an eepsite address.
    init?(rawValue: String) {
        guard let address = try? I2PEepsiteAddress.parse(rawValue) else { return nil }
        self.init(host: address.displayHost, path: address.path)
    }

    /// What the address bar shows while this is the entry being viewed.
    var display: String {
        path == "/" ? host : host + path
    }
}

/// The browser's visit stack. Every load pushes an entry; back and forward move
/// the cursor and hand the entry back to be re-loaded, never pushing a
/// duplicate. A fresh load after going back drops the entries that were ahead
/// of the cursor, and an empty stack offers neither direction.
struct I2PEepsiteVisitStack: Equatable {
    /// The visits, oldest first.
    private(set) var entries: [I2PEepsiteVisit] = []
    /// The entry being viewed; -1 while the stack is empty.
    private(set) var index = -1

    /// The entry the browser is showing.
    var current: I2PEepsiteVisit? {
        entries.indices.contains(index) ? entries[index] : nil
    }

    var count: Int { entries.count }
    var isEmpty: Bool { entries.isEmpty }
    var canGoBack: Bool { index > 0 }
    var canGoForward: Bool { index >= 0 && index < entries.count - 1 }

    /// Whether the cursor already sits on the newest entry.
    var isAtEnd: Bool { !entries.isEmpty && index == entries.count - 1 }

    /// Pushes a newly loaded entry. Loading the entry already at the end of the
    /// stack leaves it alone, and a load after going back drops the entries that
    /// were ahead of the cursor.
    mutating func push(_ visit: I2PEepsiteVisit) {
        if isAtEnd, entries[index] == visit { return }
        if index >= 0, index < entries.count - 1 {
            entries.removeSubrange((index + 1)...)
        }
        entries.append(visit)
        index = entries.count - 1
    }

    /// Steps to the previous entry and hands it back to be re-loaded.
    mutating func goBack() -> I2PEepsiteVisit? {
        guard canGoBack else { return nil }
        index -= 1
        return entries[index]
    }

    /// Steps to the next entry and hands it back to be re-loaded.
    mutating func goForward() -> I2PEepsiteVisit? {
        guard canGoForward else { return nil }
        index += 1
        return entries[index]
    }

    /// Starts the stack fresh.
    mutating func reset() {
        entries = []
        index = -1
    }
}

// MARK: - Share payload

/// One page as the share sheet gets it: the address the reader is showing and
/// the plain text of its blocks. Nothing else travels with it — no request or
/// response data, no peer details and none of the destination's leases — since
/// the reader's text is the only thing being shared.
struct I2PEepsiteShare: Equatable {
    /// The address the page is being read at: the host and, when it had one,
    /// the path.
    let address: String
    /// The host the share control names.
    let host: String
    /// The reader's plain text, its blocks separated by a blank line.
    let text: String

    /// What the share sheet shows as its subject: the page's address.
    var subject: String { address }

    /// What it shares as its body: the address, then the reader's plain text.
    /// A page that rendered no text shares its address alone.
    var body: String {
        text.isEmpty ? address : address + "\n\n" + text
    }

    /// The payload for a page on screen, or nil when there is no address to
    /// share — which is how the share control knows to stay disabled.
    static func make(address: String, blocks: [I2PReadBlock]) -> I2PEepsiteShare? {
        let trimmed = address.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        let host = I2PEepsiteVisit(rawValue: trimmed)?.host ?? trimmed
        return I2PEepsiteShare(address: trimmed, host: host, text: plainText(blocks))
    }

    /// The reader blocks as one plain text: each block trimmed, the ones that
    /// carry nothing (a rule, a blank heading) dropped, and the rest separated
    /// by a blank line so paragraphs keep their shape in the shared text.
    static func plainText(_ blocks: [I2PReadBlock]) -> String {
        blocks
            .map { $0.plainText.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
            .joined(separator: "\n\n")
    }
}

// MARK: - Self-test suite (visit stack)

enum I2PEepsiteVisitStackSelfTest {
    static func runAll() -> [I2PSelfTestResult] {
        var results: [I2PSelfTestResult] = []
        func run(_ name: String, _ body: () throws -> String) {
            do {
                let detail = try body()
                results.append(I2PSelfTestResult(name: name, passed: true, detail: detail))
            } catch {
                results.append(I2PSelfTestResult(name: name, passed: false,
                                                 detail: String(describing: error)))
            }
        }

        run("eepsite browser · visit stack pushes, steps back and forward") {
            // An address bar's text becomes a canonical host plus path, and the
            // root page drops the implicit slash.
            guard let withPath = I2PEepsiteVisit(rawValue: "HTTPS://I2PWiki.i2p:8080/wiki/Main_Page"),
                  withPath.host == "i2pwiki.i2p",
                  withPath.path == "/wiki/Main_Page",
                  withPath.display == "i2pwiki.i2p/wiki/Main_Page",
                  let root = I2PEepsiteVisit(rawValue: "I2PWiki.i2p/"),
                  root.host == "i2pwiki.i2p",
                  root.path == "/",
                  root.display == "i2pwiki.i2p",
                  I2PEepsiteVisit(rawValue: "example.com") == nil,
                  I2PEepsiteVisit(rawValue: "   ") == nil else {
                throw I2PWireError.invalidFormat
            }

            // An empty stack offers neither direction.
            var stack = I2PEepsiteVisitStack()
            guard stack.isEmpty, stack.count == 0, stack.current == nil,
                  !stack.canGoBack, !stack.canGoForward,
                  stack.goBack() == nil, stack.goForward() == nil else {
                throw I2PWireError.invalidFormat
            }

            let a = I2PEepsiteVisit(host: "a.i2p", path: "/")
            let b = I2PEepsiteVisit(host: "a.i2p", path: "/two")
            let c = I2PEepsiteVisit(host: "b.i2p", path: "/")
            stack.push(a)
            stack.push(b)
            stack.push(c)
            guard stack.count == 3, stack.current == c,
                  stack.canGoBack, !stack.canGoForward else {
                throw I2PWireError.invalidFormat
            }

            // Back walks without changing the stack's shape.
            guard stack.goBack() == b, stack.current == b, stack.count == 3,
                  stack.canGoBack, stack.canGoForward,
                  stack.goBack() == a, stack.current == a, stack.count == 3,
                  !stack.canGoBack,
                  stack.goBack() == nil, stack.current == a, stack.count == 3 else {
                throw I2PWireError.invalidFormat
            }
            // Forward walks back up to the newest entry and stops there.
            guard stack.goForward() == b, stack.goForward() == c, stack.current == c,
                  stack.goForward() == nil, !stack.canGoForward, stack.count == 3 else {
                throw I2PWireError.invalidFormat
            }
            // Re-loading the entry already at the end adds no duplicate.
            stack.push(c)
            guard stack.count == 3, stack.current == c else {
                throw I2PWireError.invalidFormat
            }
            // A load after going back drops the entries that were ahead.
            _ = stack.goBack()
            let d = I2PEepsiteVisit(host: "c.i2p", path: "/deep/page")
            stack.push(d)
            guard stack.count == 3, stack.current == d,
                  !stack.canGoForward, stack.canGoBack else {
                throw I2PWireError.invalidFormat
            }
            // The same host with another path is another visit.
            let e = I2PEepsiteVisit(host: "c.i2p", path: "/other")
            stack.push(e)
            guard stack.count == 4, stack.current == e, stack.canGoForward == false else {
                throw I2PWireError.invalidFormat
            }
            // Closing the browser starts the stack fresh.
            stack.reset()
            guard stack.isEmpty, stack.count == 0, stack.current == nil,
                  !stack.canGoBack, !stack.canGoForward else {
                throw I2PWireError.invalidFormat
            }
            return "typed URL canonicalized to host and path; back and forward walk without pushing; duplicate at the end ignored; forward entries dropped by a fresh load; reset empties the stack"
        }

        return results
    }
}

// MARK: - Self-test suite (share payload)

enum I2PEepsiteShareSelfTest {
    static func runAll() -> [I2PSelfTestResult] {
        var results: [I2PSelfTestResult] = []
        func run(_ name: String, _ body: () throws -> String) {
            do {
                let detail = try body()
                results.append(I2PSelfTestResult(name: name, passed: true, detail: detail))
            } catch {
                results.append(I2PSelfTestResult(name: name, passed: false,
                                                 detail: String(describing: error)))
            }
        }

        run("eepsite browser · share payload is the address and the reader's text") {
            let blocks = [
                I2PReadBlock(kind: .title, text: AttributedString("Welcome"),
                             plainText: "Welcome"),
                I2PReadBlock(kind: .rule, text: AttributedString(), plainText: ""),
                I2PReadBlock(kind: .paragraph, text: AttributedString("  Hello  "),
                             plainText: "  Hello  ")
            ]
            guard let payload = I2PEepsiteShare.make(
                address: "i2pwiki.i2p/wiki/Main_Page", blocks: blocks) else {
                throw I2PWireError.invalidFormat
            }
            // The subject is the page's address, the control names its host,
            // and the body is the address followed by the trimmed, blank-line
            // separated text — nothing from the fetch travels with it.
            guard payload.host == "i2pwiki.i2p",
                  payload.subject == "i2pwiki.i2p/wiki/Main_Page",
                  payload.body == "i2pwiki.i2p/wiki/Main_Page\n\nWelcome\n\nHello",
                  !payload.body.contains("lease"),
                  !payload.body.contains("tunnel") else {
                throw I2PWireError.invalidFormat
            }

            // A page whose reader rendered nothing shares its address alone.
            guard let bare = I2PEepsiteShare.make(address: "example.i2p",
                                                  blocks: [I2PReadBlock(
                                                    kind: .rule,
                                                    text: AttributedString(),
                                                    plainText: "")]),
                  bare.host == "example.i2p",
                  bare.subject == "example.i2p",
                  bare.body == "example.i2p" else {
                throw I2PWireError.invalidFormat
            }

            // Nothing on screen is nothing to share, so the control disables.
            guard I2PEepsiteShare.make(address: "   ", blocks: blocks) == nil,
                  I2PEepsiteShare.make(address: "", blocks: []) == nil else {
                throw I2PWireError.invalidFormat
            }

            // A kept copy shares from the address it was kept from, which
            // carries the path the live page's own address drops.
            guard let kept = I2PEepsiteShare.make(
                address: "i2pwiki.i2p/wiki/Kept",
                blocks: [I2PReadBlock(kind: .paragraph,
                                      text: AttributedString("Kept text"),
                                      plainText: "Kept text")]),
                  kept.host == "i2pwiki.i2p",
                  kept.body == "i2pwiki.i2p/wiki/Kept\n\nKept text" else {
                throw I2PWireError.invalidFormat
            }
            return "subject is the address; body is the address then the plain text; empty page shares its address; empty address disables; kept copy shares its kept address"
        }

        return results
    }
}
