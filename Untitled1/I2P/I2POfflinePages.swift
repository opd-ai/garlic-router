//
//  I2POfflinePages.swift
//  The last readable page of each saved host, kept on the device so the eepsite
//  browser can still show it when a live fetch fails. Only bookmarked hosts
//  keep a copy — at most one per host, replaced by every successful fetch — and
//  a kept copy carries the rendered reader blocks plus the time it was kept.
//

import Foundation
import Combine

// MARK: - Kept run and block

/// One run of a kept block's text: what it says and, for a link run, the
/// absolute address it points at.
struct I2PKeptRun: Codable, Equatable {
    let text: String
    let link: String?

    init(text: String, link: String? = nil) {
        self.text = text
        self.link = link
    }
}

/// One reader block of a kept page, in the reader's own typographic terms, so
/// the kept copy renders exactly like the page it was taken from.
struct I2PKeptBlock: Codable, Equatable {
    /// The block's kind as `I2PReadBlock.Kind` spells it: "title", "heading2" …
    /// "heading6", "paragraph", "bullet", "quote", "code" or "rule".
    let kind: String
    /// The block's text in runs, so a link inside it survives the round trip.
    let runs: [I2PKeptRun]

    var plainText: String { runs.map(\.text).joined() }

    /// Takes one rendered block apart, run by run, keeping every link with the
    /// text it was attached to.
    init(block: I2PReadBlock) {
        self.kind = Self.kindName(block.kind)
        var collected: [I2PKeptRun] = []
        for run in block.text.runs {
            let text = block.text[run.range].characters
                .reduce(into: String()) { $0.append($1) }
            guard !text.isEmpty else { continue }
            collected.append(I2PKeptRun(text: text, link: run.link?.absoluteString))
        }
        self.runs = collected
    }

    /// The block as the reader renders it: the runs joined back into one
    /// attributed string, each link run tappable again.
    var readBlock: I2PReadBlock {
        var attributed = AttributedString()
        for run in runs {
            var piece = AttributedString(run.text)
            if let link = run.link, let url = URL(string: link) {
                piece.link = url
            }
            attributed.append(piece)
        }
        return I2PReadBlock(kind: readKind, text: attributed, plainText: plainText)
    }

    private var readKind: I2PReadBlock.Kind {
        switch kind {
        case "title": return .title
        case "bullet": return .bullet
        case "quote": return .quote
        case "code": return .code
        case "rule": return .rule
        default:
            if kind.hasPrefix("heading"),
               let level = Int(kind.dropFirst("heading".count)) {
                return .heading(level)
            }
            return .paragraph
        }
    }

    private static func kindName(_ kind: I2PReadBlock.Kind) -> String {
        switch kind {
        case .title: return "title"
        case .heading(let level): return "heading\(min(max(level, 1), 6))"
        case .paragraph: return "paragraph"
        case .bullet: return "bullet"
        case .quote: return "quote"
        case .code: return "code"
        case .rule: return "rule"
        }
    }
}

// MARK: - Kept page

/// One kept page: the host it belongs to, the address that was fetched, the
/// reader blocks it rendered and when it was kept. `isBookmarkCopy` identifies
/// copies kept automatically for saved hosts; explicitly kept pages are not
/// removed when a bookmark changes.
struct I2PKeptPage: Codable, Equatable {
    /// Blocks kept per copy: beyond this a page is no longer a reading copy and
    /// the stored copy stays bounded.
    static let blockLimit = 400

    /// The host in the browser's own canonical form — the key a copy is stored
    /// under, one per host.
    let host: String
    /// The address as it was fetched: the host and, when it had one, the path.
    let address: String
    let title: String?
    let statusCode: Int
    let contentType: String
    let byteCount: Int
    /// How the lease set was found, as `I2PEepsiteRoute` spells it.
    let route: String
    let leaseCount: Int
    let elapsed: TimeInterval
    /// When this copy was kept.
    let keptAt: Date
    let blocks: [I2PKeptBlock]
    /// Nil is treated as true for copies persisted before this distinction was
    /// introduced, preserving the saved-host pruning behavior of those copies.
    let isBookmarkCopy: Bool?

    var followsBookmark: Bool { isBookmarkCopy ?? true }

    init(page: I2PEepsitePage,
         host: String,
         address: String,
         keptAt: Date,
         blockLimit: Int = I2PKeptPage.blockLimit,
         isBookmarkCopy: Bool = true) {
        self.host = host
        self.address = address.isEmpty ? page.address : address
        self.title = page.title
        self.statusCode = page.statusCode
        self.contentType = page.contentType
        self.byteCount = page.byteCount
        self.route = page.route.rawValue
        self.leaseCount = page.leaseCount
        self.elapsed = page.elapsed
        self.keptAt = keptAt
        self.blocks = page.blocks.prefix(max(0, blockLimit)).map { I2PKeptBlock(block: $0) }
        self.isBookmarkCopy = isBookmarkCopy
    }

    init(copy: I2PKeptPage,
         host: String,
         address: String,
         keptAt: Date,
         isBookmarkCopy: Bool = false) {
        self.host = host
        self.address = address
        self.title = copy.title
        self.statusCode = copy.statusCode
        self.contentType = copy.contentType
        self.byteCount = copy.byteCount
        self.route = copy.route
        self.leaseCount = copy.leaseCount
        self.elapsed = copy.elapsed
        self.keptAt = keptAt
        self.blocks = Array(copy.blocks.prefix(Self.blockLimit))
        self.isBookmarkCopy = isBookmarkCopy
    }

    /// The blocks back in the reader's terms, ready to be rendered.
    var readBlocks: [I2PReadBlock] { blocks.map(\.readBlock) }

    /// The banner line naming when the copy was kept: "Kept today at 14:02",
    /// "Kept yesterday at 09:14", "Kept Mar 4 at 11:03". The time follows the
    /// device's own clock settings.
    func keptText(now: Date = Date(), calendar: Calendar = .current) -> String {
        let time = keptAt.formatted(date: .omitted, time: .shortened)
        if calendar.isDate(keptAt, inSameDayAs: now) { return "Kept today at \(time)" }
        if let yesterday = calendar.date(byAdding: .day, value: -1, to: now),
           calendar.isDate(keptAt, inSameDayAs: yesterday) {
            return "Kept yesterday at \(time)"
        }
        let day = keptAt.formatted(.dateTime.month(.abbreviated).day())
        return "Kept \(day) at \(time)"
    }

    /// The same keep time as a library row badges it — "kept today at 14:02" —
    /// with a lower-case opening, since it sits in a capsule rather than
    /// starting a sentence.
    func keptBadgeText(now: Date = Date(), calendar: Calendar = .current) -> String {
        let text = keptText(now: now, calendar: calendar)
        return String(text.prefix(1)).lowercased() + String(text.dropFirst())
    }

    /// The copy's size the way the library and its summary read it: "84 KB",
    /// "1.2 MB", "512 B". Whole kilobytes keep the copy's own byte count
    /// legible without a decimal.
    var sizeText: String { I2PKeptPage.sizeText(byteCount) }

    static func sizeText(_ bytes: Int) -> String {
        guard bytes > 0 else { return "0 B" }
        if bytes >= 1_048_576 { return String(format: "%.1f MB", Double(bytes) / 1_048_576) }
        if bytes >= 1_024 { return "\(Int((Double(bytes) / 1_024).rounded())) KB" }
        return "\(bytes) B"
    }
}

/// One offline-library search hit, with its matching block count and a short
/// excerpt centred on the first match in reading order.
struct I2POfflineLibrarySearchResult {
    let page: I2PKeptPage
    let matchingBlockCount: Int
    let snippet: String
}

enum I2POfflineLibrarySearch {
    /// Searches only the text already stored in each copy's reader blocks.
    /// Results retain the library's existing order.
    static func results(in pages: [I2PKeptPage], query: String) -> [I2POfflineLibrarySearchResult] {
        let query = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else { return [] }

        return pages.compactMap { page in
            let matches = page.blocks.compactMap { block -> (text: String, range: Range<String.Index>)? in
                let text = block.plainText.replacingOccurrences(of: "\\s+",
                                                                 with: " ",
                                                                 options: .regularExpression)
                guard let range = text.range(of: query, options: [.caseInsensitive]) else { return nil }
                return (text, range)
            }
            guard let first = matches.first else { return nil }
            return I2POfflineLibrarySearchResult(page: page,
                                                 matchingBlockCount: matches.count,
                                                 snippet: excerpt(first.text, matching: first.range))
        }
    }

    private static func excerpt(_ text: String, matching range: Range<String.Index>) -> String {
        let matchStart = text.distance(from: text.startIndex, to: range.lowerBound)
        let matchLength = text.distance(from: range.lowerBound, to: range.upperBound)
        let windowLength = max(120, matchLength)
        let contextLength = windowLength - matchLength
        var windowStart = max(0, matchStart - contextLength / 2)
        var windowEnd = min(text.count, windowStart + windowLength)
        if windowEnd == text.count {
            windowStart = max(0, windowEnd - windowLength)
        }
        windowEnd = min(text.count, windowStart + windowLength)

        let start = text.index(text.startIndex, offsetBy: windowStart)
        let end = text.index(text.startIndex, offsetBy: windowEnd)
        let prefix = windowStart > 0 ? "…" : ""
        let suffix = windowEnd < text.count ? "…" : ""
        return prefix + String(text[start..<end]) + suffix
    }
}

// MARK: - Offline store

/// The kept pages, one per canonical I2P host.
///
/// Successful fetches of saved hosts are kept automatically and are pruned if
/// their bookmark is removed. Any valid I2P page can also be explicitly kept;
/// that copy lives independently of the bookmark. Every keep replaces the
/// host's previous copy rather than building an archive.
///
/// Every mutation is driven from the main thread (SwiftUI actions and the
/// browser's `MainActor.run` completions), so the published state stays
/// consistent with the views that observe it.
final class I2POfflinePageStore: ObservableObject {
    static let shared = I2POfflinePageStore()
    static let defaultsKey = "i2p.offlinePages"

    /// Every kept copy, keyed by the host it belongs to.
    @Published private(set) var copies: [String: I2PKeptPage] = [:]

    private let savedHosts: I2PSavedHostsStore
    private let defaults: UserDefaults
    private let storageKey: String
    /// Keeps the copies in step with the bookmarks: a host that is no longer
    /// saved cannot keep one.
    private var bookmarkObserver: AnyCancellable?

    init(savedHosts: I2PSavedHostsStore = .shared,
         defaults: UserDefaults = .standard,
         storageKey: String = I2POfflinePageStore.defaultsKey) {
        self.savedHosts = savedHosts
        self.defaults = defaults
        self.storageKey = storageKey
        self.copies = Self.load(defaults: defaults, key: storageKey)
        dropCopies(keeping: Set(savedHosts.entries.map(\.host)))
        bookmarkObserver = savedHosts.$entries.sink { [weak self] entries in
            self?.dropCopies(keeping: Set(entries.map(\.host)))
        }
    }

    // MARK: Keeping and reading

    /// Keeps a successful fetch automatically only when its host is bookmarked.
    /// The browser uses this for its existing last-good-fetch behavior.
    @discardableResult
    func keep(_ page: I2PEepsitePage,
              address: String,
              at date: Date = Date()) -> Bool {
        guard let host = I2PSavedHostsStore.host(in: address)?.host,
              savedHosts.contains(host) else { return false }
        copies[host] = I2PKeptPage(page: page,
                                   host: host,
                                   address: address,
                                   keptAt: date,
                                   isBookmarkCopy: true)
        persist()
        return true
    }

    /// Explicitly keeps any valid I2P page, whether or not it is a saved host.
    /// A host already in the library is replaced in place.
    @discardableResult
    func keepAny(_ page: I2PEepsitePage,
                 address: String,
                 at date: Date = Date()) -> Bool {
        guard let host = I2PSavedHostsStore.host(in: address)?.host else { return false }
        copies[host] = I2PKeptPage(page: page,
                                   host: host,
                                   address: address,
                                   keptAt: date,
                                   isBookmarkCopy: false)
        persist()
        return true
    }

    /// Refreshes a copy already being read, preserving its reader data and fetch
    /// details while updating the address and keep time.
    @discardableResult
    func keepAny(_ copy: I2PKeptPage,
                 address: String? = nil,
                 at date: Date = Date()) -> Bool {
        let keptAddress = address ?? copy.address
        guard let host = I2PSavedHostsStore.host(in: keptAddress)?.host else { return false }
        copies[host] = I2PKeptPage(copy: copy,
                                   host: host,
                                   address: keptAddress,
                                   keptAt: date,
                                   isBookmarkCopy: false)
        persist()
        return true
    }

    /// The copy kept for the host an address points at, whether or not that host
    /// is also bookmarked.
    func copy(for address: String) -> I2PKeptPage? {
        guard let host = I2PSavedHostsStore.host(in: address)?.host else { return nil }
        return copies[host]
    }

    // MARK: The library

    /// Every kept copy, newest first — the order the offline library reads in.
    /// Copies kept in the same instant fall back to the host, so the order
    /// never wobbles between redraws.
    var library: [I2PKeptPage] {
        copies.values.sorted { lhs, rhs in
            if lhs.keptAt != rhs.keptAt { return lhs.keptAt > rhs.keptAt }
            return lhs.host < rhs.host
        }
    }

    /// What every kept copy adds up to on the device, for the library's
    /// summary line.
    var libraryBytes: Int {
        copies.values.reduce(0) { $0 + $1.byteCount }
    }

    /// Deletes one host's kept copy. The bookmark is left alone: the host keeps
    /// its place in the Saved hosts screen and simply has nothing to read
    /// offline until its next good fetch.
    func remove(_ host: String) {
        guard copies[host] != nil else { return }
        copies[host] = nil
        persist()
    }

    /// Empties the library. Bookmarks are untouched — every saved host stays in
    /// the Saved hosts screen and starts keeping a copy again with its next good
    /// fetch.
    func clear() {
        guard !copies.isEmpty else { return }
        copies.removeAll()
        persist()
    }

    // MARK: Pruning

    /// Drops only the automatically-kept copies whose bookmark went away.
    /// Explicitly kept pages remain in the offline library independently.
    private func dropCopies(keeping hosts: Set<String>) {
        let stale = copies.keys.filter { host in
            guard let copy = copies[host] else { return false }
            return copy.followsBookmark && !hosts.contains(host)
        }
        guard !stale.isEmpty else { return }
        for host in stale {
            copies[host] = nil
        }
        persist()
    }

    // MARK: Persistence

    private func persist() {
        guard let data = try? JSONEncoder().encode(copies) else { return }
        defaults.set(data, forKey: storageKey)
    }

    private static func load(defaults: UserDefaults, key: String) -> [String: I2PKeptPage] {
        guard let data = defaults.data(forKey: key),
              let decoded = try? JSONDecoder().decode([String: I2PKeptPage].self, from: data) else {
            return [:]
        }
        return decoded
    }
}

// MARK: - Self-test suite (offline pages)

enum I2POfflinePagesSelfTest {
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

        run("offline pages · only a saved host keeps a copy, and a success replaces it") {
            let (savedDefaults, savedKey) = makeDefaults("keep-saved")
            let (pageDefaults, pageKey) = makeDefaults("keep-pages")
            defer {
                savedDefaults.removePersistentDomain(forName: suiteName("keep-saved"))
                pageDefaults.removePersistentDomain(forName: suiteName("keep-pages"))
            }
            let saved = I2PSavedHostsStore(defaults: savedDefaults, storageKey: savedKey)
            let store = I2POfflinePageStore(savedHosts: saved,
                                            defaults: pageDefaults,
                                            storageKey: pageKey)
            let base = Date(timeIntervalSince1970: 1_700_000_000)

            // An unbookmarked host keeps nothing, however well its fetch ended.
            guard store.keep(makePage(address: "i2pwiki.i2p",
                                      blocks: [block(.paragraph, "One")]),
                             address: "i2pwiki.i2p",
                             at: base) == false,
                  store.copies.isEmpty,
                  store.copy(for: "i2pwiki.i2p") == nil else {
                throw I2PWireError.invalidFormat
            }

            // Once the host is saved, the next success is kept with its address,
            // its reading details and its blocks.
            guard saved.save("i2pwiki.i2p", at: base) else { throw I2PWireError.invalidFormat }
            guard store.keep(makePage(address: "i2pwiki.i2p",
                                      blocks: [block(.paragraph, "One")]),
                             address: "i2pwiki.i2p/wiki/Main_Page",
                             at: base) else {
                throw I2PWireError.invalidFormat
            }
            guard let kept = store.copy(for: "i2pwiki.i2p"),
                  kept.host == "i2pwiki.i2p",
                  kept.address == "i2pwiki.i2p/wiki/Main_Page",
                  kept.keptAt == base,
                  kept.title == "Home",
                  kept.statusCode == 200,
                  kept.route == I2PEepsiteRoute.leaseSet2.rawValue,
                  kept.leaseCount == 3,
                  kept.byteCount == 1_234,
                  kept.blocks.count == 1,
                  kept.blocks.first?.plainText == "One",
                  store.copies.count == 1 else {
                throw I2PWireError.invalidFormat
            }
            // A typed URL or a deeper path reads the same host's copy.
            guard store.copy(for: "HTTPS://I2PWiki.i2p:8080/wiki/Other") == kept,
                  store.copy(for: "i2pwiki.i2p/another/page?q=1") == kept,
                  store.copy(for: "example.com") == nil,
                  store.copy(for: "   ") == nil else {
                throw I2PWireError.invalidFormat
            }

            // A later success replaces the copy instead of adding a second one.
            let later = base.addingTimeInterval(300)
            guard store.keep(makePage(address: "i2pwiki.i2p",
                                      blocks: [block(.paragraph, "Two")]),
                             address: "i2pwiki.i2p",
                             at: later) else {
                throw I2PWireError.invalidFormat
            }
            guard store.copies.count == 1,
                  store.copy(for: "i2pwiki.i2p")?.keptAt == later,
                  store.copy(for: "i2pwiki.i2p")?.address == "i2pwiki.i2p",
                  store.copy(for: "i2pwiki.i2p")?.blocks.first?.plainText == "Two" else {
                throw I2PWireError.invalidFormat
            }

            // A page with no readable text is still worth keeping.
            guard saved.save("empty.i2p", at: base),
                  store.keep(makePage(address: "empty.i2p", blocks: []),
                             address: "empty.i2p",
                             at: base),
                  store.copy(for: "empty.i2p")?.blocks.isEmpty == true,
                  store.copy(for: "empty.i2p")?.readBlocks.isEmpty == true else {
                throw I2PWireError.invalidFormat
            }

            // The copies survive a relaunch.
            let reopened = I2POfflinePageStore(savedHosts: saved,
                                               defaults: pageDefaults,
                                               storageKey: pageKey)
            guard reopened.copies == store.copies,
                  reopened.copy(for: "i2pwiki.i2p")?.blocks.first?.plainText == "Two" else {
                throw I2PWireError.invalidFormat
            }

            // A bookmark that goes away takes its copy with it — the store only
            // ever holds copies of saved hosts.
            saved.remove("i2pwiki.i2p")
            guard store.copies.count == 1,
                  store.copy(for: "i2pwiki.i2p") == nil,
                  store.copy(for: "empty.i2p") != nil else {
                throw I2PWireError.invalidFormat
            }
            let afterRemoval = I2POfflinePageStore(savedHosts: saved,
                                                   defaults: pageDefaults,
                                                   storageKey: pageKey)
            guard afterRemoval.copies.keys.sorted() == ["empty.i2p"] else {
                throw I2PWireError.invalidFormat
            }
            return "unbookmarked host refused; kept copy carries address, route, size and blocks; typed URL and deeper path find it; a later success replaced it; empty page kept; persisted; removing the bookmark dropped its copy"
        }

        run("offline pages · kept blocks keep their kind, text and links") {
            let (savedDefaults, savedKey) = makeDefaults("blocks-saved")
            let (pageDefaults, pageKey) = makeDefaults("blocks-pages")
            defer {
                savedDefaults.removePersistentDomain(forName: suiteName("blocks-saved"))
                pageDefaults.removePersistentDomain(forName: suiteName("blocks-pages"))
            }
            let saved = I2PSavedHostsStore(defaults: savedDefaults, storageKey: savedKey)
            let store = I2POfflinePageStore(savedHosts: saved,
                                            defaults: pageDefaults,
                                            storageKey: pageKey)
            let base = Date(timeIntervalSince1970: 1_700_000_000)
            guard saved.save("wiki.i2p", at: base) else { throw I2PWireError.invalidFormat }

            let blocks: [I2PReadBlock] = [
                block(.title, "I2P Wiki"),
                block(.heading(3), "About"),
                linkedBlock(),
                block(.bullet, "First point"),
                block(.code, "let x = 1"),
                I2PReadBlock(kind: .rule, text: AttributedString(), plainText: "")
            ]
            guard store.keep(makePage(address: "wiki.i2p", blocks: blocks, title: "Wiki"),
                             address: "wiki.i2p/About",
                             at: base) else {
                throw I2PWireError.invalidFormat
            }

            let reopened = I2POfflinePageStore(savedHosts: saved,
                                               defaults: pageDefaults,
                                               storageKey: pageKey)
            guard let copy = reopened.copy(for: "wiki.i2p"),
                  copy.blocks.count == blocks.count,
                  copy.readBlocks.count == blocks.count else {
                throw I2PWireError.invalidFormat
            }
            for (index, original) in blocks.enumerated() {
                let restored = copy.readBlocks[index]
                guard restored.kind == original.kind,
                      restored.plainText == original.plainText else {
                    throw I2PWireError.invalidFormat
                }
            }
            // The heading's level and the rule's emptiness survive too.
            guard copy.readBlocks[1].kind == .heading(3),
                  copy.readBlocks[5].kind == .rule,
                  copy.readBlocks[5].plainText.isEmpty else {
                throw I2PWireError.invalidFormat
            }

            // The link run came back with its text and its absolute address.
            // One block is bound here so its runs and its text are the same
            // attributed string (indices never cross two instances).
            let restoredLinked = copy.readBlocks[2]
            var linkedText: String?
            var linkedURL: String?
            for run in restoredLinked.text.runs where run.link != nil {
                linkedText = restoredLinked.text[run.range].characters
                    .reduce(into: String()) { $0.append($1) }
                linkedURL = run.link?.absoluteString
            }
            guard restoredLinked.plainText == "Read i2pwiki for more.",
                  linkedText == "i2pwiki",
                  linkedURL == "http://wiki.i2p/" else {
                throw I2PWireError.invalidFormat
            }
            return "title, heading level, linked paragraph, bullet, code and rule all round-tripped through storage with their text and the link's absolute address intact"
        }

        run("offline pages · the banner names when the copy was kept") {
            let (savedDefaults, savedKey) = makeDefaults("banner-saved")
            let (pageDefaults, pageKey) = makeDefaults("banner-pages")
            defer {
                savedDefaults.removePersistentDomain(forName: suiteName("banner-saved"))
                pageDefaults.removePersistentDomain(forName: suiteName("banner-pages"))
            }
            let saved = I2PSavedHostsStore(defaults: savedDefaults, storageKey: savedKey)
            let store = I2POfflinePageStore(savedHosts: saved,
                                            defaults: pageDefaults,
                                            storageKey: pageKey)
            let calendar = Calendar(identifier: .gregorian)
            let now = Date(timeIntervalSince1970: 1_700_000_000)
            guard saved.save("wiki.i2p") else { throw I2PWireError.invalidFormat }

            func keptText(at moment: Date) throws -> String {
                guard store.keep(makePage(address: "wiki.i2p", blocks: [block(.paragraph, "x")]),
                                 address: "wiki.i2p",
                                 at: moment),
                      let copy = store.copy(for: "wiki.i2p") else {
                    throw I2PWireError.invalidFormat
                }
                return copy.keptText(now: now, calendar: calendar)
            }

            let time = now.formatted(date: .omitted, time: .shortened)
            guard try keptText(at: now) == "Kept today at \(time)" else {
                throw I2PWireError.invalidFormat
            }
            guard let yesterdayMoment = calendar.date(byAdding: .day, value: -1, to: now) else {
                throw I2PWireError.invalidFormat
            }
            let yesterdayText = try keptText(at: yesterdayMoment)
            guard yesterdayText.hasPrefix("Kept yesterday at "),
                  yesterdayText.hasSuffix(
                    yesterdayMoment.formatted(date: .omitted, time: .shortened)) else {
                throw I2PWireError.invalidFormat
            }
            guard let olderMoment = calendar.date(byAdding: .day, value: -6, to: now) else {
                throw I2PWireError.invalidFormat
            }
            let olderText = try keptText(at: olderMoment)
            guard olderText.hasPrefix("Kept "),
                  !olderText.hasPrefix("Kept today"),
                  !olderText.hasPrefix("Kept yesterday"),
                  olderText.hasSuffix(olderMoment.formatted(date: .omitted, time: .shortened)) else {
                throw I2PWireError.invalidFormat
            }
            return "banner reads 'Kept today at …', 'Kept yesterday at …' or 'Kept Mar 4 at …', each carrying the copy's own keep time"
        }

        run("offline pages · the library lists newest first, deletes one copy and clears") {
            let (savedDefaults, savedKey) = makeDefaults("library-saved")
            let (pageDefaults, pageKey) = makeDefaults("library-pages")
            defer {
                savedDefaults.removePersistentDomain(forName: suiteName("library-saved"))
                pageDefaults.removePersistentDomain(forName: suiteName("library-pages"))
            }
            let saved = I2PSavedHostsStore(defaults: savedDefaults, storageKey: savedKey)
            let store = I2POfflinePageStore(savedHosts: saved,
                                            defaults: pageDefaults,
                                            storageKey: pageKey)
            let base = Date(timeIntervalSince1970: 1_700_000_000)

            // Nothing kept means an empty library, and clearing changes nothing.
            guard store.library.isEmpty, store.libraryBytes == 0 else {
                throw I2PWireError.invalidFormat
            }
            store.clear()
            guard store.copies.isEmpty, store.library.isEmpty else {
                throw I2PWireError.invalidFormat
            }

            // Three saved hosts, each with a kept copy at its own moment.
            for (offset, host) in ["a.i2p", "b.i2p", "c.i2p"].enumerated() {
                guard saved.save(host, at: base),
                      store.keep(makePage(address: host, blocks: [block(.paragraph, host)]),
                                 address: host + "/page",
                                 at: base.addingTimeInterval(Double(offset) * 60)) else {
                    throw I2PWireError.invalidFormat
                }
            }
            guard store.copies.count == 3,
                  store.library.map(\.host) == ["c.i2p", "b.i2p", "a.i2p"],
                  store.library.first?.address == "c.i2p/page",
                  store.library.first?.blocks.count == 1,
                  store.libraryBytes == 3 * 1_234 else {
                throw I2PWireError.invalidFormat
            }

            // The order is the keep time, not the storage order: a fresh copy of
            // the oldest host moves it to the top.
            guard store.keep(makePage(address: "a.i2p", blocks: [block(.paragraph, "a")]),
                             address: "a.i2p/page",
                             at: base.addingTimeInterval(600)) else {
                throw I2PWireError.invalidFormat
            }
            guard store.library.map(\.host) == ["a.i2p", "c.i2p", "b.i2p"],
                  store.copies.count == 3 else {
                throw I2PWireError.invalidFormat
            }

            // Deleting one copy leaves the other copies and every bookmark.
            store.remove("c.i2p")
            guard store.copies.count == 2,
                  store.library.map(\.host) == ["a.i2p", "b.i2p"],
                  store.copy(for: "c.i2p") == nil,
                  saved.contains("c.i2p"),
                  saved.entries.count == 3,
                  store.libraryBytes == 2 * 1_234 else {
                throw I2PWireError.invalidFormat
            }
            // Deleting a host with no copy is a no-op.
            store.remove("c.i2p")
            store.remove("never-saved.i2p")
            guard store.copies.count == 2 else { throw I2PWireError.invalidFormat }

            // The library survives a relaunch, and clearing it empties the copies
            // while every bookmark stays in the saved hosts list.
            let reopened = I2POfflinePageStore(savedHosts: saved,
                                               defaults: pageDefaults,
                                               storageKey: pageKey)
            guard reopened.library.map(\.host) == ["a.i2p", "b.i2p"] else {
                throw I2PWireError.invalidFormat
            }
            reopened.clear()
            guard reopened.copies.isEmpty,
                  reopened.library.isEmpty,
                  reopened.libraryBytes == 0,
                  saved.contains("a.i2p"),
                  saved.contains("b.i2p"),
                  saved.contains("c.i2p"),
                  saved.entries.count == 3 else {
                throw I2PWireError.invalidFormat
            }
            let afterClear = I2POfflinePageStore(savedHosts: saved,
                                                 defaults: pageDefaults,
                                                 storageKey: pageKey)
            guard afterClear.copies.isEmpty, afterClear.library.isEmpty else {
                throw I2PWireError.invalidFormat
            }
            // A cleared host starts keeping a copy again on its next good fetch.
            guard afterClear.keep(makePage(address: "b.i2p", blocks: [block(.paragraph, "b")]),
                                  address: "b.i2p",
                                  at: base.addingTimeInterval(900)),
                  afterClear.library.map(\.host) == ["b.i2p"] else {
                throw I2PWireError.invalidFormat
            }
            return "library is newest copy first and re-orders on a fresh keep; one copy deleted by swipe leaves the bookmarks; clearing empties the library and keeps every bookmark; persisted across a relaunch"
        }

        run("offline pages · a row's size and keep badge read the way the library shows them") {
            // Sizes: whole kilobytes, one decimal for megabytes, plain bytes.
            guard I2PKeptPage.sizeText(0) == "0 B",
                  I2PKeptPage.sizeText(512) == "512 B",
                  I2PKeptPage.sizeText(1_024) == "1 KB",
                  I2PKeptPage.sizeText(84 * 1_024) == "84 KB",
                  I2PKeptPage.sizeText(412 * 1_024) == "412 KB",
                  I2PKeptPage.sizeText(1_048_576) == "1.0 MB",
                  I2PKeptPage.sizeText(3_355_443) == "3.2 MB" else {
                throw I2PWireError.invalidFormat
            }

            let (savedDefaults, savedKey) = makeDefaults("row-saved")
            let (pageDefaults, pageKey) = makeDefaults("row-pages")
            defer {
                savedDefaults.removePersistentDomain(forName: suiteName("row-saved"))
                pageDefaults.removePersistentDomain(forName: suiteName("row-pages"))
            }
            let saved = I2PSavedHostsStore(defaults: savedDefaults, storageKey: savedKey)
            let store = I2POfflinePageStore(savedHosts: saved,
                                            defaults: pageDefaults,
                                            storageKey: pageKey)
            let calendar = Calendar(identifier: .gregorian)
            let now = Date(timeIntervalSince1970: 1_700_000_000)
            guard saved.save("wiki.i2p", at: now),
                  store.keep(makePage(address: "wiki.i2p",
                                      blocks: [block(.paragraph, "One"), block(.paragraph, "Two")]),
                             address: "wiki.i2p/wiki/Main_Page",
                             at: now),
                  let kept = store.copy(for: "wiki.i2p") else {
                throw I2PWireError.invalidFormat
            }
            // The row's readings: the address it was kept from, its route, its
            // lease count, its reader blocks and its size.
            let time = now.formatted(date: .omitted, time: .shortened)
            guard kept.address == "wiki.i2p/wiki/Main_Page",
                  kept.route == I2PEepsiteRoute.leaseSet2.rawValue,
                  kept.leaseCount == 3,
                  kept.blocks.count == 2,
                  kept.sizeText == "1 KB",
                  kept.keptBadgeText(now: now, calendar: calendar) == "kept today at \(time)" else {
                throw I2PWireError.invalidFormat
            }
            // An older copy keeps its own day in the badge, with the same
            // lower-case opening.
            guard let older = calendar.date(byAdding: .day, value: -3, to: now),
                  store.keep(makePage(address: "wiki.i2p", blocks: [block(.paragraph, "x")]),
                             address: "wiki.i2p",
                             at: older),
                  let olderCopy = store.copy(for: "wiki.i2p") else {
                throw I2PWireError.invalidFormat
            }
            let olderBadge = olderCopy.keptBadgeText(now: now, calendar: calendar)
            guard olderBadge.hasPrefix("kept "),
                  !olderBadge.hasPrefix("kept today"),
                  olderBadge.hasSuffix(older.formatted(date: .omitted, time: .shortened)),
                  olderBadge == olderCopy.keptText(now: now, calendar: calendar).prefix(1).lowercased()
                    + String(olderCopy.keptText(now: now, calendar: calendar).dropFirst()) else {
                throw I2PWireError.invalidFormat
            }
            return "sizes read 84 KB / 1.0 MB / 512 B; a row's keep badge is the copy's own keep time with a lower-case opening"
        }

        run("offline pages · any I2P page can be kept, updated and deleted without changing bookmarks") {
            let (savedDefaults, savedKey) = makeDefaults("any-saved")
            let (pageDefaults, pageKey) = makeDefaults("any-pages")
            defer {
                savedDefaults.removePersistentDomain(forName: suiteName("any-saved"))
                pageDefaults.removePersistentDomain(forName: suiteName("any-pages"))
            }
            let saved = I2PSavedHostsStore(defaults: savedDefaults, storageKey: savedKey)
            let store = I2POfflinePageStore(savedHosts: saved,
                                            defaults: pageDefaults,
                                            storageKey: pageKey)
            let base = Date(timeIntervalSince1970: 1_700_000_000)
            let live = makePage(address: "reader.i2p",
                                blocks: [block(.title, "Reader"), block(.paragraph, "Offline text")])

            // An explicitly kept page does not need a bookmark and appears in
            // the same library with the address, time, byte size and block count.
            guard store.keepAny(live, address: "https://reader.i2p/guide", at: base),
                  let first = store.copy(for: "reader.i2p"),
                  first.address == "https://reader.i2p/guide",
                  first.keptAt == base,
                  first.byteCount == live.byteCount,
                  first.blocks.count == 2,
                  first.blocks[1].plainText == "Offline text",
                  store.library.map(\.host) == ["reader.i2p"] else {
                throw I2PWireError.invalidFormat
            }

            // Updating a page already read from a copy refreshes its address and
            // time but still leaves exactly one copy for that host.
            let later = base.addingTimeInterval(600)
            guard store.keepAny(first, address: "reader.i2p/updated", at: later),
                  store.copies.count == 1,
                  store.copy(for: "reader.i2p")?.address == "reader.i2p/updated",
                  store.copy(for: "reader.i2p")?.keptAt == later,
                  store.copy(for: "reader.i2p")?.blocks == first.blocks else {
                throw I2PWireError.invalidFormat
            }

            // Deleting an explicitly-kept copy never deletes its saved-host
            // bookmark. Explicit copies also survive bookmark removal.
            guard saved.save("reader.i2p", at: base) else { throw I2PWireError.invalidFormat }
            store.remove("reader.i2p")
            guard saved.contains("reader.i2p"), store.copy(for: "reader.i2p") == nil,
                  store.keepAny(live, address: "reader.i2p/guide", at: later) else {
                throw I2PWireError.invalidFormat
            }
            saved.remove("reader.i2p")
            guard !saved.contains("reader.i2p"), store.copy(for: "reader.i2p") != nil else {
                throw I2PWireError.invalidFormat
            }

            // Automatic saved-host copies keep their previous bookmark-bound
            // cleanup behavior, and explicit pages persist independently.
            guard saved.save("automatic.i2p", at: base),
                  store.keep(makePage(address: "automatic.i2p", blocks: [block(.paragraph, "Auto")]),
                             address: "automatic.i2p", at: base) else {
                throw I2PWireError.invalidFormat
            }
            saved.remove("automatic.i2p")
            let reopened = I2POfflinePageStore(savedHosts: saved,
                                               defaults: pageDefaults,
                                               storageKey: pageKey)
            guard reopened.library.map(\.host) == ["reader.i2p"],
                  reopened.copy(for: "reader.i2p")?.blocks.map(\.plainText) == ["Reader", "Offline text"] else {
                throw I2PWireError.invalidFormat
            }
            return "an unbookmarked page is persisted in the library; refreshing a copy updates its address and time in place; deleting a copy leaves its bookmark alone; explicitly kept pages survive bookmark removal while automatic saved-host copies still prune"
        }

        run("offline pages · library search reads kept blocks and highlights a useful snippet") {
            let base = Date(timeIntervalSince1970: 1_700_000_000)
            let pages = [
                I2PKeptPage(page: makePage(address: "newest.i2p", blocks: [
                    block(.paragraph, "Floodfill routers\nshare a database."),
                    block(.code, "A floodfill peer answers queries.")
                ]), host: "newest.i2p", address: "newest.i2p/wiki", keptAt: base),
                I2PKeptPage(page: makePage(address: "floodfill.i2p", blocks: [
                    block(.paragraph, "No matching words in this page.")
                ]), host: "floodfill.i2p", address: "floodfill.i2p", keptAt: base),
                I2PKeptPage(page: makePage(address: "older.i2p", blocks: [
                    block(.paragraph, "A FLOODFILL map.")
                ]), host: "older.i2p", address: "older.i2p", keptAt: base.addingTimeInterval(-60))
            ]

            let matches = I2POfflineLibrarySearch.results(in: pages, query: "  floodfill  ")
            guard matches.map({ $0.page.host }) == ["newest.i2p", "older.i2p"],
                  matches[0].matchingBlockCount == 2,
                  matches[1].matchingBlockCount == 1,
                  matches[0].snippet.contains("Floodfill"),
                  !matches[0].snippet.contains("\n"),
                  matches[1].snippet.contains("FLOODFILL"),
                  I2POfflineLibrarySearch.results(in: pages, query: "missing").isEmpty,
                  I2POfflineLibrarySearch.results(in: pages, query: "   ").isEmpty else {
                throw I2PWireError.invalidFormat
            }
            return "case-insensitive search matched only reader-block text, counted matching blocks, kept library order, normalized the snippet to one line, and returned no results for a miss or blank query"
        }

        return results
    }

    // MARK: Helpers

    private static func suiteName(_ label: String) -> String {
        "i2p.offlinePages.selfTest.\(label)"
    }

    private static func makeDefaults(_ label: String) -> (UserDefaults, String) {
        let suite = suiteName(label)
        let defaults = UserDefaults(suiteName: suite) ?? .standard
        defaults.removePersistentDomain(forName: suite)
        return (defaults, "offline-\(label)")
    }

    private static func makePage(address: String,
                                 blocks: [I2PReadBlock],
                                 title: String? = "Home") -> I2PEepsitePage {
        I2PEepsitePage(address: address,
                       title: title,
                       blocks: blocks,
                       statusCode: 200,
                       contentType: "text/html",
                       byteCount: 1_234,
                       route: .leaseSet2,
                       leaseCount: 3,
                       elapsed: 1.5,
                       note: nil)
    }

    private static func block(_ kind: I2PReadBlock.Kind, _ text: String) -> I2PReadBlock {
        I2PReadBlock(kind: kind, text: AttributedString(text), plainText: text)
    }

    /// A paragraph whose middle run is a link, so the round trip has to split
    /// the text and keep the address attached to the right run.
    private static func linkedBlock() -> I2PReadBlock {
        var paragraph = AttributedString("Read ")
        var linked = AttributedString("i2pwiki")
        if let url = URL(string: "http://wiki.i2p/") {
            linked.link = url
        }
        paragraph.append(linked)
        paragraph.append(AttributedString(" for more."))
        return I2PReadBlock(kind: .paragraph,
                            text: paragraph,
                            plainText: "Read i2pwiki for more.")
    }
}
