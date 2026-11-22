//
//  I2PEepsiteTabs.swift
//  The eepsite browser's open pages: what the browser holds for one tab — its
//  address, its own visit stack and the page it fetched — and the set of them
//  with the page on screen marked. Memory only, exactly like the visit stack:
//  the browser screen owns the set, so closing the browser closes every tab
//  with it.
//
//  These types sit in I2P/ rather than beside the browser's SwiftUI view because
//  the off-device harness compiles `Untitled1/I2P/*.swift` with `swiftc` and
//  cannot compile a view file. Keeping them here means the tabs suite runs in
//  that harness for real instead of being stubbed out, and it still runs in the
//  app and in the unit test target.
//

import Foundation

// MARK: - What one page shows

/// What one page of the browser holds: a fetch in flight, the page it produced,
/// the failure it came to, a copy read from the offline library, or nothing yet.
/// The browser model's `phase` is this same type, so switching tabs is a plain
/// copy in either direction rather than a translation.
enum I2PEepsiteLoadState {
    case idle
    case loading
    case loaded(I2PEepsitePage)
    case failed(I2PEepsiteFailure)
    case offline(I2PKeptPage)

    var isLoading: Bool { if case .loading = self { return true }; return false }
    var isLoaded: Bool { if case .loaded = self { return true }; return false }
    var isFailed: Bool { if case .failed = self { return true }; return false }
    var isOffline: Bool { if case .offline = self { return true }; return false }
}

// MARK: - How a page's last fetch ended

/// How a tab's last fetch ended, as the Tabs sheet names it on the row.
enum I2PBrowserTabFetch: Equatable {
    /// A page that has not been loaded since it opened.
    case notLoaded
    /// A fetch is running in this page.
    case reading
    /// The page is loaded; the time it arrived, when it is known.
    case fetched(Date?)
    /// The last fetch broke at this stage.
    case failed(I2PEepsiteStage)
    /// The page was read from a copy kept on the device at this time.
    case kept(Date)

    var isReading: Bool { self == .reading }

    /// The row's status line: "reading", "fetched 14:02", "failed at connect",
    /// "kept copy · 14:02", "not loaded yet". The time follows the device's own
    /// clock settings.
    func line() -> String {
        switch self {
        case .notLoaded:
            return "not loaded yet"
        case .reading:
            return "reading"
        case .fetched(let date):
            guard let date else { return "fetched" }
            return "fetched \(I2PBrowserTabFetch.timeText(date))"
        case .failed(let stage):
            return "failed at \(stage.rawValue.lowercased())"
        case .kept(let date):
            return "kept copy · \(I2PBrowserTabFetch.timeText(date))"
        }
    }

    static func timeText(_ date: Date) -> String {
        date.formatted(date: .omitted, time: .shortened)
    }
}

// MARK: - One page

/// One page the browser has open: the address in the bar while it is on screen,
/// its own visit stack, and what its last fetch left behind. The fetched page
/// itself is held here, so switching back to a tab puts it on screen without a
/// second fetch.
struct I2PBrowserTab: Identifiable {
    /// The page's identity for as long as the browser stays open.
    let id: Int
    /// The address the bar shows while this page is on screen.
    var addressText: String
    /// Back and forward belong to the page, not to the browser.
    var visits: I2PEepsiteVisitStack
    /// What the page holds.
    var state: I2PEepsiteLoadState
    /// The stage a running fetch is in, for the sheet's row and the loading card.
    var stage: I2PEepsiteStage?
    /// The stages the running fetch has already come through.
    var trail: [I2PEepsiteStage]
    /// The copy a failing host kept, shown under that failure.
    var keptCopy: I2PKeptPage?
    /// When the page on screen arrived, for the row's "fetched 14:02".
    var fetchedAt: Date?

    init(id: Int, address: String = "") {
        self.id = id
        self.addressText = address
        self.visits = I2PEepsiteVisitStack()
        self.state = .idle
        self.stage = nil
        self.trail = []
        self.keptCopy = nil
        self.fetchedAt = nil
    }

    /// The host the row names, in the browser's own canonical form.
    var host: String? {
        I2PSavedHostsStore.host(in: addressText)?.host
            ?? I2PEepsiteVisit(rawValue: addressText)?.host
    }

    /// What the row shows for the page: its host, or the raw text of an address
    /// the browser cannot parse yet, or nothing for a page that has not been
    /// given one.
    var displayHost: String { host ?? addressText }

    /// Whether the page's host is a b33 blinded address, which the row marks
    /// with a key rather than a globe.
    var isB33Host: Bool { displayHost.hasSuffix(".b33.i2p") }

    /// The page's own title, when it has one.
    var title: String? {
        switch state {
        case .loaded(let page):
            return page.title
        case .offline(let kept):
            return kept.title
        case .idle, .loading, .failed:
            return nil
        }
    }

    /// How the last fetch ended.
    var fetch: I2PBrowserTabFetch {
        switch state {
        case .idle:
            return .notLoaded
        case .loading:
            return .reading
        case .loaded:
            return .fetched(fetchedAt)
        case .failed(let failure):
            return .failed(failure.stage)
        case .offline(let kept):
            return .kept(kept.keptAt)
        }
    }

    var isLoaded: Bool { state.isLoaded }
}

// MARK: - The set of pages

/// The pages one browser has open in this session, in the order they were
/// opened, with the one on screen marked.
struct I2PBrowserTabs {
    /// The open pages, oldest first.
    private(set) var pages: [I2PBrowserTab] = []
    /// The page on screen; nil while no page is open.
    private(set) var activeID: Int?
    private var nextID = 1

    var count: Int { pages.count }
    var isEmpty: Bool { pages.isEmpty }

    var active: I2PBrowserTab? { pages.first { $0.id == activeID } }
    var activeIndex: Int? { pages.firstIndex { $0.id == activeID } }

    /// The line under the sheet's title: "3 pages open".
    var summary: String {
        switch count {
        case 0: return "No pages open"
        case 1: return "1 page open"
        default: return "\(count) pages open"
        }
    }

    func tab(_ id: Int) -> I2PBrowserTab? { pages.first { $0.id == id } }
    func contains(_ id: Int) -> Bool { pages.contains { $0.id == id } }

    /// Opens a fresh page from the address it starts with and puts it on screen.
    @discardableResult
    mutating func open(address: String = "") -> I2PBrowserTab {
        let tab = I2PBrowserTab(id: nextID, address: address)
        nextID += 1
        pages.append(tab)
        activeID = tab.id
        return tab
    }

    /// Makes an open page the one on screen; false when the page is gone.
    @discardableResult
    mutating func activate(_ id: Int) -> Bool {
        guard contains(id) else { return false }
        activeID = id
        return true
    }

    /// Drops a page together with its visit stack and hands back the page that
    /// takes the screen: the one that followed it, else the one before it, and
    /// nil once the last page is gone. A page that was not on screen leaves the
    /// screen where it was.
    @discardableResult
    mutating func close(_ id: Int) -> I2PBrowserTab? {
        guard let index = pages.firstIndex(where: { $0.id == id }) else { return active }
        let wasActive = id == activeID
        pages.remove(at: index)
        guard !pages.isEmpty else {
            activeID = nil
            return nil
        }
        if wasActive {
            activeID = pages[min(index, pages.count - 1)].id
        }
        return active
    }

    /// Writes a page back after the browser worked on it. A page that is no
    /// longer open is ignored.
    mutating func update(_ tab: I2PBrowserTab) {
        guard let index = pages.firstIndex(where: { $0.id == tab.id }) else { return }
        pages[index] = tab
    }

    /// Changes one open page in place.
    mutating func mutate(_ id: Int, _ body: (inout I2PBrowserTab) -> Void) {
        guard let index = pages.firstIndex(where: { $0.id == id }) else { return }
        body(&pages[index])
    }
}

// MARK: - Self-test suite (tabs)

enum I2PEepsiteTabsSelfTest {
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

        run("eepsite browser · tabs keep each page with its own stack and state") {
            // A browser with nothing open has no page on screen and nothing to
            // switch to or close.
            var tabs = I2PBrowserTabs()
            guard tabs.isEmpty, tabs.count == 0, tabs.active == nil,
                  tabs.summary == "No pages open",
                  tabs.close(7) == nil, !tabs.activate(7),
                  tabs.tab(7) == nil, !tabs.contains(7) else {
                throw I2PWireError.invalidFormat
            }

            // Every page gets an identity of its own, and the newest is the one
            // on screen.
            let wiki = tabs.open(address: "wiki.i2p")
            let trac = tabs.open(address: "trac.i2p/ticket/482")
            guard tabs.count == 2, wiki.id != trac.id,
                  tabs.activeID == trac.id, tabs.summary == "2 pages open",
                  tabs.activeIndex == 1 else {
                throw I2PWireError.invalidFormat
            }

            // A page keeps its address, its own visit stack and the page it
            // fetched while another page is on screen.
            let fetched = Date(timeIntervalSince1970: 1_700_000_000)
            tabs.mutate(wiki.id) { tab in
                tab.state = .loaded(page(address: "wiki.i2p", title: "Main Page"))
                tab.fetchedAt = fetched
                tab.visits.push(I2PEepsiteVisit(host: "wiki.i2p", path: "/"))
                tab.visits.push(I2PEepsiteVisit(host: "wiki.i2p", path: "/wiki/Main_Page"))
                tab.addressText = "wiki.i2p/wiki/Main_Page"
            }
            guard let loaded = tabs.tab(wiki.id),
                  loaded.state.isLoaded, loaded.isLoaded,
                  loaded.title == "Main Page",
                  loaded.fetch == .fetched(fetched),
                  loaded.visits.count == 2,
                  loaded.visits.current?.path == "/wiki/Main_Page",
                  loaded.addressText == "wiki.i2p/wiki/Main_Page" else {
                throw I2PWireError.invalidFormat
            }

            // Switching back to it re-reads what it holds: no fetch runs, so
            // the page, its title, its time and its stack are all still there.
            guard tabs.activate(wiki.id), tabs.activeID == wiki.id,
                  let restored = tabs.tab(wiki.id),
                  restored.isLoaded, restored.title == "Main Page",
                  restored.fetch == .fetched(fetched),
                  restored.visits.count == 2 else {
                throw I2PWireError.invalidFormat
            }
            // A page the set does not hold cannot take the screen.
            guard !tabs.activate(9999), tabs.activeID == wiki.id else {
                throw I2PWireError.invalidFormat
            }

            // Closing a page that is not on screen leaves the screen alone.
            guard tabs.close(trac.id)?.id == wiki.id,
                  tabs.count == 1, tabs.activeID == wiki.id,
                  tabs.tab(trac.id) == nil else {
                throw I2PWireError.invalidFormat
            }

            // Closing the page on screen hands it to the page before it when it
            // was the last one open.
            let stats = tabs.open(address: "stats.i2p")
            guard tabs.count == 2, tabs.activeID == stats.id,
                  tabs.close(stats.id)?.id == wiki.id,
                  tabs.activeID == wiki.id else {
                throw I2PWireError.invalidFormat
            }

            // Closing the last page empties the set, so the browser returns to
            // its empty state, and the next load opens a fresh page.
            guard tabs.close(wiki.id) == nil, tabs.isEmpty, tabs.activeID == nil,
                  tabs.active == nil, tabs.summary == "No pages open" else {
                throw I2PWireError.invalidFormat
            }
            let fresh = tabs.open(address: "example.i2p")
            guard fresh.id > stats.id, tabs.count == 1,
                  tabs.activeID == fresh.id else {
                throw I2PWireError.invalidFormat
            }

            // Closing a page in the middle hands the screen to the page that
            // followed it, and leaves the other pages open.
            var three = I2PBrowserTabs()
            let a = three.open(address: "a.i2p")
            let b = three.open(address: "b.i2p")
            let c = three.open(address: "c.i2p")
            guard three.activate(b.id),
                  three.close(b.id)?.id == c.id,
                  three.activeID == c.id, three.count == 2,
                  three.tab(a.id) != nil, three.tab(c.id) != nil else {
                throw I2PWireError.invalidFormat
            }

            return "pages carry their address, stack and fetched page across switches; each page keeps its own identity; closing a background page leaves the screen; closing the visible page hands it to its neighbour; closing the last page empties the set and the next load opens a fresh page"
        }

        run("eepsite browser · a tab's row names its host, title and last fetch") {
            var tabs = I2PBrowserTabs()
            let wiki = tabs.open(address: "wiki.i2p")
            // A page that has not been loaded yet says so, and has no title.
            guard let opening = tabs.tab(wiki.id),
                  opening.displayHost == "wiki.i2p",
                  opening.title == nil,
                  opening.fetch == .notLoaded,
                  opening.fetch.line() == "not loaded yet",
                  !opening.isB33Host else {
                throw I2PWireError.invalidFormat
            }

            // A fetch in flight reads as "reading".
            tabs.mutate(wiki.id) { $0.state = .loading }
            guard let reading = tabs.tab(wiki.id),
                  reading.fetch == .reading,
                  reading.fetch.isReading,
                  reading.fetch.line() == "reading" else {
                throw I2PWireError.invalidFormat
            }

            // A broken fetch names the stage it broke in rather than a time.
            tabs.mutate(wiki.id) {
                $0.state = .failed(I2PEepsiteFailure(stage: .connect,
                                                     message: "the stream did not open"))
            }
            guard let failed = tabs.tab(wiki.id),
                  failed.fetch == .failed(.connect),
                  failed.fetch.line() == "failed at connect",
                  failed.title == nil else {
                throw I2PWireError.invalidFormat
            }

            // A fetched page carries its title and the time it arrived.
            let fetched = Date(timeIntervalSince1970: 1_700_000_000)
            tabs.mutate(wiki.id) { tab in
                tab.state = .loaded(page(address: "wiki.i2p", title: "Main Page"))
                tab.fetchedAt = fetched
            }
            guard let loaded = tabs.tab(wiki.id),
                  loaded.title == "Main Page",
                  loaded.fetch == .fetched(fetched),
                  loaded.fetch.line().hasPrefix("fetched "),
                  loaded.fetch.line().count > "fetched ".count else {
                throw I2PWireError.invalidFormat
            }

            // A page read from a kept copy says so, and carries the kept title.
            tabs.mutate(wiki.id) { tab in
                tab.state = .offline(keptPage(host: "wiki.i2p", at: fetched))
            }
            guard let offline = tabs.tab(wiki.id),
                  offline.title == "Kept wiki.i2p",
                  case .kept(let keptAt) = offline.fetch,
                  keptAt == fetched,
                  offline.fetch.line().hasPrefix("kept copy · ") else {
                throw I2PWireError.invalidFormat
            }

            // A b33 host is marked as one, so the row shows a key instead of a
            // globe.
            let blinded = tabs.open(address: "host.b33.i2p")
            guard let blindedTab = tabs.tab(blinded.id),
                  blindedTab.displayHost == "host.b33.i2p",
                  blindedTab.isB33Host else {
                throw I2PWireError.invalidFormat
            }

            return "a row names the host and the page's title; its status line reads not loaded yet, reading, fetched at a time, failed at a stage or kept copy at a time; a b33 host is marked as a blinded address"
        }

        return results
    }

    // MARK: Fixtures

    private static func page(address: String, title: String?) -> I2PEepsitePage {
        let text = title ?? address
        return I2PEepsitePage(address: address,
                              title: title,
                              blocks: [I2PReadBlock(kind: .title,
                                                    text: AttributedString(text),
                                                    plainText: text)],
                              statusCode: 200,
                              contentType: "text/html",
                              byteCount: 2_048,
                              route: .leaseSet2,
                              leaseCount: 2,
                              elapsed: 1.4,
                              note: nil)
    }

    private static func keptPage(host: String, at keptAt: Date) -> I2PKeptPage {
        I2PKeptPage(page: page(address: host, title: "Kept " + host),
                    host: host,
                    address: host,
                    keptAt: keptAt)
    }
}
