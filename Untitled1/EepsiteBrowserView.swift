//
//  EepsiteBrowserView.swift
//  The in-app eepsite browser: an address bar for .i2p / b32 / b33 hosts, a
//  staged loading surface, inline diagnostics that name the failing stage, and
//  a native reader view for the fetched page.
//

import SwiftUI

// MARK: - Model

/// The browser screen's state: the address in the bar, the pages this browser
/// has open, the current load, the stage trail and the rendered page. All
/// published state is mutated on the main thread; the client work runs off it.
final class I2PEepsiteBrowserModel: ObservableObject {
    /// What the page on screen is showing. The tabs model holds the same type
    /// for every page it keeps, so switching tabs copies it either way.
    typealias Phase = I2PEepsiteLoadState

    @Published var addressText = ""
    @Published private(set) var phase: Phase = .idle
    @Published private(set) var currentStage: I2PEepsiteStage?
    @Published private(set) var trail: [I2PEepsiteStage] = []
    @Published private(set) var suggestions: [String] = []
    /// The pages this browser has open in this session, with the one on screen
    /// marked. Memory only, exactly like the visit stack: the browser screen
    /// owns them, so closing the browser closes every tab with it.
    @Published private(set) var tabs = I2PBrowserTabs()
    /// Whether the sheet listing the open pages is over the browser.
    @Published private(set) var tabsVisible = false
    /// The pages this browser has visited, and where in them it is.
    @Published private(set) var visits = I2PEepsiteVisitStack()
    /// The copy a failing host kept from its last good fetch, shown under the
    /// failure when the live fetch cannot be served.
    @Published private(set) var keptCopy: I2PKeptPage?
    /// Whether the find bar is on screen over the page.
    @Published private(set) var findVisible = false
    /// The find query as the bar's field shows it.
    @Published private(set) var findQuery = ""
    /// What the bar found in the page on screen, and where it is in it.
    @Published private(set) var find = I2PEepsiteFind()
    /// The block the reader should bring on screen; nil before any step.
    @Published private(set) var findScroll: I2PEepsiteFindScroll?
    private var findScrollToken = 0
    /// Whether the contents sheet is over the page.
    @Published private(set) var contentsVisible = false
    /// The heading the reader should bring on screen; nil before any jump.
    @Published private(set) var contentsJump: I2PEepsiteContentsJump?
    private var contentsJumpToken = 0

    private let client: I2PEepsiteClient
    private let savedHosts: I2PSavedHostsStore
    private let history: I2PBrowserHistoryStore
    private let offline: I2POfflinePageStore
    private let lastReadPage: I2PLastReadPageStore
    private let suggestionProvider: () -> [String]
    /// The fetch each open page is running, so a page keeps loading while
    /// another is on screen and a closed page takes its run with it.
    private var tasks: [Int: Task<Void, Never>] = [:]
    /// Bumped by every load in a page, by a cancel and by closing the page. A
    /// fetch may already be past its last cancellation check when a newer load
    /// starts, so each run carries the generation its page held when it began
    /// and only touches that page while the number still matches.
    private var generations: [Int: Int] = [:]

    init(client: I2PEepsiteClient,
         savedHosts: I2PSavedHostsStore = .shared,
         history: I2PBrowserHistoryStore = .shared,
         offline: I2POfflinePageStore = .shared,
         lastReadPage: I2PLastReadPageStore = .shared,
         suggestions: @escaping () -> [String]) {
        self.client = client
        self.savedHosts = savedHosts
        self.history = history
        self.offline = offline
        self.lastReadPage = lastReadPage
        self.suggestionProvider = suggestions
    }

    var isLoading: Bool { phase.isLoading }

    func refreshSuggestions() {
        let fresh = suggestionProvider()
        if fresh != suggestions { suggestions = fresh }
    }

    /// Loads the address in the bar (or the one passed in, for links), pushing
    /// the visit onto the open page's stack first. The bar shows the pushed
    /// entry, so a typed URL with a scheme, a port or a path settles into the
    /// browser's own canonical form before the fetch starts.
    func load(_ raw: String? = nil) {
        let input = (raw ?? addressText).trimmingCharacters(in: .whitespacesAndNewlines)
        guard !input.isEmpty else { return }
        // The browser's first load opens a page of its own, and a load after
        // every page was closed opens a fresh one.
        let id = ensureActiveTab()
        if let visit = I2PEepsiteVisit(rawValue: input) {
            visits.push(visit)
            addressText = visit.display
        } else {
            addressText = input
        }
        storeActiveTabState(in: id)
        start(input, tab: id)
    }

    /// Re-runs the address in the bar without touching the visit stack — the
    /// failure card's retry, and anything else that is not a navigation.
    func reload() {
        let input = addressText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !input.isEmpty else { return }
        start(input, tab: ensureActiveTab())
    }

    /// Steps back one entry and re-loads it, without growing the stack.
    func goBack() {
        guard let visit = visits.goBack() else { return }
        open(visit)
    }

    /// Steps forward one entry and re-loads it, without pushing a duplicate.
    func goForward() {
        guard let visit = visits.goForward() else { return }
        open(visit)
    }

    /// Re-loads an entry the stack moved to, bar and page together.
    private func open(_ visit: I2PEepsiteVisit) {
        addressText = visit.display
        let id = ensureActiveTab()
        storeActiveTabState(in: id)
        start(visit.display, tab: id)
    }

    /// Runs one fetch for the address in the page that owns it. The visit stack
    /// is not touched here: callers decide whether the address is a new
    /// navigation (load) or a step through the stack (back, forward, retry).
    private func start(_ input: String, tab id: Int) {
        tasks[id]?.cancel()
        let token = generation(for: id) + 1
        generations[id] = token
        updateTab(id) { tab in
            tab.state = .loading
            tab.stage = .address
            tab.trail = []
            tab.keptCopy = nil
            tab.fetchedAt = nil
        }
        phase = .loading
        keptCopy = nil
        currentStage = .address
        trail = []
        // A new load is a new page: its search starts over with it, and a
        // contents sheet left open would outline the page that just left.
        clearFind()
        closeContents()
        let client = self.client
        // The address in the browser's own host-and-path form, which is what a
        // kept copy is labelled with: the rendered page itself only carries the
        // host it was fetched from. Record it as the latest browser address now;
        // a failed load remains a useful explicit continuation, but nothing is
        // fetched again until the user chooses one of its buttons.
        let loadedAddress = I2PEepsiteVisit(rawValue: input)?.display
        if let loadedAddress { lastReadPage.recordRead(loadedAddress) }
        tasks[id] = Task { [weak self] in
            do {
                let page = try await client.load(input) { stage in
                    Task { @MainActor [weak self] in
                        self?.apply(stage, tab: id, generation: token)
                    }
                }
                await MainActor.run { [weak self] in
                    guard let self, self.generation(for: id) == token else { return }
                    self.finish(tab: id, state: .loaded(page),
                                address: loadedAddress ?? page.address)
                    self.savedHosts.recordFetch(page.address, result: .ok)
                    self.history.record(page.address, result: .ok)
                    // Only a saved host keeps a copy, and this success replaces
                    // whatever the host kept before.
                    self.offline.keep(page, address: loadedAddress ?? page.address)
                    if id == self.tabs.activeID { self.refreshFindForArrivedPage() }
                }
            } catch is CancellationError {
                // A newer load (or a closed page) owns the state now.
            } catch let failure as I2PEepsiteFailure {
                await MainActor.run { [weak self] in
                    guard let self, self.generation(for: id) == token else { return }
                    self.savedHosts.recordFetch(input, result: failure.savedHostResult)
                    self.history.record(input, result: failure.savedHostResult)
                    self.finish(tab: id, state: .failed(failure), address: nil)
                    if id == self.tabs.activeID { self.refreshFindForArrivedPage() }
                }
            } catch {
                await MainActor.run { [weak self] in
                    guard let self, self.generation(for: id) == token else { return }
                    let failure = I2PEepsiteFailure(
                        stage: .response,
                        message: "The load failed unexpectedly: \(error)")
                    self.savedHosts.recordFetch(input, result: failure.savedHostResult)
                    self.history.record(input, result: failure.savedHostResult)
                    self.finish(tab: id, state: .failed(failure), address: nil)
                    if id == self.tabs.activeID { self.refreshFindForArrivedPage() }
                }
            }
        }
    }

    func cancel() {
        guard let id = tabs.activeID else { return }
        generations[id] = generation(for: id) + 1
        tasks[id]?.cancel()
        tasks[id] = nil
        phase = .idle
        keptCopy = nil
        currentStage = nil
        trail = []
        clearFind()
        closeContents()
        storeActiveTabState(in: id, content: .idle)
    }

    // MARK: Tabs

    /// The page on screen, opened on demand: the browser's first load lands in
    /// a page of its own, and so does a load after every page was closed.
    private func ensureActiveTab() -> Int {
        if let id = tabs.activeID { return id }
        return tabs.open(address: addressText).id
    }

    /// Changes one open page in place.
    private func updateTab(_ id: Int, _ body: (inout I2PBrowserTab) -> Void) {
        var store = tabs
        store.mutate(id, body)
        tabs = store
    }

    /// The generation a page's running fetch was started with; 0 before its
    /// first load.
    private func generation(for id: Int) -> Int { generations[id] ?? 0 }

    /// Writes what is on screen into the page that holds it, so switching away
    /// leaves that page exactly as it was left.
    private func storeActiveTabState(in id: Int, content: Phase? = nil) {
        let typed = addressText
        let stack = visits
        let state = content ?? phase
        let kept = keptCopy
        let stage = currentStage
        let stages = trail
        updateTab(id) { tab in
            tab.addressText = typed
            tab.visits = stack
            tab.state = state
            tab.keptCopy = kept
            tab.stage = stage
            tab.trail = stages
        }
    }

    /// Opens the sheet listing the pages this browser has open.
    func openTabs() {
        saveActiveTab()
        tabsVisible = true
    }

    /// Closes the sheet without changing the page on screen.
    func closeTabs() {
        guard tabsVisible else { return }
        tabsVisible = false
    }

    /// Saves what is on screen into the page that holds it.
    func saveActiveTab() {
        guard let id = tabs.activeID else { return }
        storeActiveTabState(in: id)
    }

    /// Switches to another page without fetching it again: that page puts back
    /// what it held when it left the screen.
    func activateTab(_ id: Int) {
        guard id != tabs.activeID, tabs.contains(id) else { return }
        saveActiveTab()
        var store = tabs
        store.activate(id)
        tabs = store
        restoreActiveTab()
    }

    /// Opens a fresh page with the address bar emptied, ready for a new load.
    /// The page it was on stays open with its own stack.
    func openNewTab() {
        saveActiveTab()
        var store = tabs
        store.open(address: "")
        tabs = store
        addressText = ""
        visits = I2PEepsiteVisitStack()
        phase = .idle
        keptCopy = nil
        currentStage = nil
        trail = []
        clearFind()
        closeContents()
        tabsVisible = false
    }

    /// Drops a page together with its visit stack. Closing the page on screen
    /// hands the screen to its neighbour, and closing the last page returns the
    /// browser to its empty state.
    func closeTab(_ id: Int) {
        guard tabs.contains(id) else { return }
        tasks[id]?.cancel()
        tasks[id] = nil
        generations[id] = generation(for: id) + 1
        let wasActive = id == tabs.activeID
        var store = tabs
        store.close(id)
        tabs = store
        guard wasActive else { return }
        guard !tabs.isEmpty else {
            resetToEmptyState()
            closeTabs()
            return
        }
        restoreActiveTab()
    }

    /// Puts the page that now holds the screen back on it.
    private func restoreActiveTab() {
        guard let tab = tabs.active else {
            resetToEmptyState()
            return
        }
        addressText = tab.addressText
        visits = tab.visits
        keptCopy = tab.keptCopy
        currentStage = tab.stage
        trail = tab.trail
        phase = tab.state
        if !tab.addressText.isEmpty,
           tab.state.isLoaded || tab.state.isOffline || (tab.state.isFailed && tab.keptCopy != nil) {
            lastReadPage.recordRead(tab.addressText)
        }
        // The page on screen changed, so a search or a contents sheet that
        // belonged to the page before it goes with it.
        clearFind()
        closeContents()
    }

    /// The browser with nothing on screen, as it was before its first load.
    private func resetToEmptyState() {
        addressText = ""
        visits = I2PEepsiteVisitStack()
        phase = .idle
        keptCopy = nil
        currentStage = nil
        trail = []
        clearFind()
        closeContents()
    }

    /// Lands a finished fetch in its own page, and follows it on screen while
    /// that page is the one on screen.
    private func finish(tab id: Int, state: Phase, address: String?) {
        tasks[id] = nil
        guard let page = tabs.tab(id) else { return }
        let addressForCopy = address ?? page.addressText
        let arrivedAt = state.isLoaded || state.isOffline ? Date() : nil
        let kept = state.isFailed ? offline.copy(for: addressForCopy) : nil
        updateTab(id) { tab in
            tab.state = state
            tab.stage = nil
            tab.trail = []
            if let address { tab.addressText = address }
            tab.keptCopy = kept
            if let arrivedAt { tab.fetchedAt = arrivedAt }
        }
        guard id == tabs.activeID else { return }
        phase = state
        keptCopy = kept
        if state.isLoaded || state.isOffline || (state.isFailed && kept != nil) {
            lastReadPage.recordRead(address ?? page.addressText)
        }
        currentStage = nil
        trail = []
    }

    /// Keeps a host as a bookmark. The page on screen already belongs to it
    /// when the loaded page matches, so that fetch counts as its first visit —
    /// and, now that the host is saved, becomes its first kept copy.
    @discardableResult
    func saveBookmark(_ host: String) -> Bool {
        guard savedHosts.save(host) else { return false }
        if case .loaded(let page) = phase, page.address == host {
            savedHosts.recordFetch(host, result: .ok)
            offline.keep(page, address: displayedAddress(for: host))
        }
        return true
    }

    // MARK: Offline library

    /// Reads a copy from the offline library in the browser: the copy comes
    /// straight off the device, so no fetch runs and no loading stage is
    /// entered. The bar shows the address the copy was kept from and the kept
    /// copy's banner sits over the page with its Retry live button, which is
    /// the only thing here that reaches for the network.
    func readOffline(_ kept: I2PKeptPage) {
        let id = ensureActiveTab()
        tasks[id]?.cancel()
        tasks[id] = nil
        generations[id] = generation(for: id) + 1
        if let visit = I2PEepsiteVisit(rawValue: kept.address) {
            visits.push(visit)
            addressText = visit.display
        } else {
            addressText = kept.address
        }
        phase = .offline(kept)
        lastReadPage.recordRead(kept.address)
        keptCopy = nil
        currentStage = nil
        trail = []
        clearFind()
        closeContents()
        storeActiveTabState(in: id)
    }

    /// The address the browser is showing for a host: the entry being viewed
    /// when it belongs to that host, and the fallback address otherwise.
    private func displayedAddress(for host: String, fallback: String? = nil) -> String {
        guard let current = visits.current, current.host == host else { return fallback ?? host }
        return current.display
    }

    /// Whether the current reader page can be kept, and whether this host already
    /// has a copy that the button will update.
    var canKeepCurrentPageOffline: Bool { currentOfflineAddress != nil }

    var isCurrentPageKeptOffline: Bool {
        guard let address = currentOfflineAddress else { return false }
        return offline.copy(for: address) != nil
    }

    /// Keeps or refreshes the reader page on the device. A live fetch stores its
    /// current blocks; a page already read from a copy refreshes that same copy.
    func keepCurrentPageOffline() {
        guard let address = currentOfflineAddress else { return }
        let stored: Bool
        switch phase {
        case .loaded(let page):
            stored = offline.keepAny(page, address: address)
        case .failed:
            guard let keptCopy else { return }
            stored = offline.keepAny(keptCopy, address: address)
        case .offline(let kept):
            stored = offline.keepAny(kept, address: address)
        case .idle, .loading:
            return
        }
        guard stored, let refreshed = offline.copy(for: address) else { return }
        if phase.isOffline {
            phase = .offline(refreshed)
        } else if phase.isFailed {
            keptCopy = refreshed
        }
        saveActiveTab()
    }

    private var currentOfflineAddress: String? {
        switch phase {
        case .loaded(let page):
            let host = I2PSavedHostsStore.host(in: page.address)?.host ?? page.address
            return displayedAddress(for: host, fallback: page.address)
        case .failed:
            guard let keptCopy else { return nil }
            return displayedAddress(for: keptCopy.host, fallback: keptCopy.address)
        case .offline(let kept):
            return displayedAddress(for: kept.host, fallback: kept.address)
        case .idle, .loading:
            return nil
        }
    }

    /// Advances the stage trail for the load that reported it, in the page that
    /// owns the run and, while that page is on screen, in the loading card too.
    /// Main thread only.
    private func apply(_ stage: I2PEepsiteStage, tab id: Int, generation token: Int) {
        guard generation(for: id) == token else { return }
        updateTab(id) { tab in
            guard case .loading = tab.state else { return }
            if let current = tab.stage, current != stage, !tab.trail.contains(current) {
                tab.trail.append(current)
            }
            tab.stage = stage
        }
        guard id == tabs.activeID, case .loading = phase else { return }
        if let current = currentStage, current != stage, !trail.contains(current) {
            trail.append(current)
        }
        currentStage = stage
    }

    // MARK: Contents

    /// The blocks of the page on screen: a live page, the kept copy a failed
    /// load fell back to, or a copy read from the offline library. The find bar
    /// searches them and the contents sheet outlines them.
    var readerBlocks: [I2PReadBlock] {
        switch phase {
        case .loaded(let page):
            return page.blocks
        case .failed:
            return keptCopy?.readBlocks ?? []
        case .offline(let kept):
            return kept.readBlocks
        case .idle, .loading:
            return []
        }
    }

    /// The blocks the find bar searches.
    var findableBlocks: [I2PReadBlock] { readerBlocks }

    /// The headings of the page on screen, in document order with sub-headings
    /// nested under their parents. Empty while nothing is on screen.
    var contents: I2PEepsiteContents { I2PEepsiteContents.outline(readerBlocks) }

    /// The host the contents control names, or nil while nothing is on screen.
    var contentsHost: String? {
        switch phase {
        case .loaded(let page):
            return page.address
        case .failed:
            return keptCopy?.host
        case .offline(let kept):
            return kept.host
        case .idle, .loading:
            return nil
        }
    }

    /// The address the contents sheet is headed with: the entry being viewed
    /// for a live page, the address the copy was taken from for a kept one.
    var contentsAddress: String? {
        switch phase {
        case .loaded(let page):
            return displayedAddress(for: page.address)
        case .failed:
            return keptCopy?.address
        case .offline(let kept):
            return kept.address
        case .idle, .loading:
            return nil
        }
    }

    /// Opens the contents sheet, when the page has headings to jump between.
    func openContents() {
        guard contents.isAvailable else { return }
        contentsVisible = true
    }

    /// Closes the contents sheet without moving the page.
    func closeContents() {
        guard contentsVisible else { return }
        contentsVisible = false
    }

    /// Scrolls the tapped heading's block into view and closes the sheet — a
    /// live page and a kept copy alike.
    func jump(to entry: I2PEepsiteContentsEntry) {
        contentsVisible = false
        contentsJumpToken &+= 1
        contentsJump = I2PEepsiteContentsJump(token: contentsJumpToken, block: entry.block)
    }

    // MARK: Share

    /// The page on screen in the terms the share sheet needs: a live page and a
    /// kept copy alike. Nil while the screen is empty, while a load is running,
    /// and when a failure left nothing on screen — the share control stays
    /// disabled then.
    var sharePayload: I2PEepsiteShare? {
        switch phase {
        case .loaded(let page):
            return I2PEepsiteShare.make(address: displayedAddress(for: page.address),
                                         blocks: page.blocks)
        case .failed:
            guard let kept = keptCopy else { return nil }
            return I2PEepsiteShare.make(address: kept.address, blocks: kept.readBlocks)
        case .offline(let kept):
            return I2PEepsiteShare.make(address: kept.address, blocks: kept.readBlocks)
        case .idle, .loading:
            return nil
        }
    }

    // MARK: Find

    /// Opens the find bar over the page, when there is a page to search.
    func openFind() {
        guard !findableBlocks.isEmpty else { return }
        findVisible = true
    }

    /// Closes the find bar and takes its highlights with it.
    func closeFind() {
        findVisible = false
        clearFind()
    }

    /// Searches the page on screen for a new query and brings the first match
    /// on screen. A bar holding nothing but spaces clears the highlights.
    func updateFind(_ text: String) {
        findQuery = text
        find.search(text, in: findableBlocks)
        scrollToCurrentMatch()
    }

    /// Steps to the next match, wrapping around at the end of the page.
    func findNextMatch() {
        find.next()
        scrollToCurrentMatch()
    }

    /// Steps to the previous match, wrapping around at the start of the page.
    func findPreviousMatch() {
        find.previous()
        scrollToCurrentMatch()
    }

    private func clearFind() {
        findQuery = ""
        find.clear()
        findScroll = nil
    }

    private func scrollToCurrentMatch() {
        guard let match = find.currentMatch else { return }
        findScrollToken &+= 1
        findScroll = I2PEepsiteFindScroll(token: findScrollToken, block: match.block)
    }

    /// Runs the bar's query against the page that just arrived, so a search
    /// typed while a load was in flight reports against what is now on screen.
    private func refreshFindForArrivedPage() {
        guard !findQuery.isEmpty else { return }
        updateFind(findQuery)
    }

    /// The matches inside one block, for the reader to tint.
    func findMatches(inBlock index: Int) -> [I2PEepsiteFindMatch] {
        guard find.isSearching, !find.isEmpty else { return [] }
        return find.matches.filter { $0.block == index }
    }

    /// A block's text with its matches tinted — every one of them, and the one
    /// being stepped to brightest.
    func findText(_ block: I2PReadBlock, blockIndex index: Int) -> AttributedString {
        let matches = findMatches(inBlock: index)
        guard !matches.isEmpty else { return block.text }
        return I2PEepsiteFindHighlight.highlight(block,
                                                 matches: matches,
                                                 current: find.currentMatch)
    }
}

// MARK: - Screen

struct EepsiteBrowserView: View {
    /// The screen owns its browser model, so closing the browser discards it
    /// along with the visit stack: opening it again starts history fresh.
    @StateObject private var model = I2PEepsiteBrowserModel.live()
    @ObservedObject private var savedHosts = I2PSavedHostsStore.shared
    @ObservedObject private var browserHistory = I2PBrowserHistoryStore.shared
    @ObservedObject private var offlinePages = I2POfflinePageStore.shared
    @ObservedObject private var lastReadPage = I2PLastReadPageStore.shared
    /// The reader's text size, shared with every other reader surface and kept
    /// across launches.
    @ObservedObject private var readerText = I2PReaderTextSizeStore.shared
    @FocusState private var addressFocused: Bool
    @FocusState private var findFocused: Bool

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)
    private let okGreen = Color(red: 0.29, green: 0.87, blue: 0.50)

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                VStack(spacing: 14) {
                    addressBar
                    addressSuggestionsList
                    historyBar
                    savedHostsLink
                    historyLink
                    offlineLink
                    findBar
                    readerBar
                    loadContent
                    footnote
                }
                .padding(.horizontal, 16)
                .padding(.top, 4)
                .padding(.bottom, 24)
            }
            .scrollDismissesKeyboard(.immediately)
            .onChange(of: model.findScroll) { _, request in
                guard let request else { return }
                withAnimation(.easeInOut(duration: 0.25)) {
                    proxy.scrollTo(request.block, anchor: .center)
                }
            }
            .onChange(of: model.contentsJump) { _, request in
                guard let request else { return }
                withAnimation(.easeInOut(duration: 0.25)) {
                    proxy.scrollTo(request.block, anchor: .top)
                }
            }
        }
        .background(background.ignoresSafeArea())
        .navigationTitle("Eepsite Browser")
        .navigationBarTitleDisplayMode(.large)
        .preferredColorScheme(.dark)
        .onAppear { model.refreshSuggestions() }
        .onChange(of: model.addressText) { _, text in
            completeAddress(for: text)
        }
        .onChange(of: model.findVisible) { _, visible in
            findFocused = visible
        }
        .sheet(isPresented: contentsPresented) {
            I2PEepsiteContentsSheet(address: model.contentsAddress ?? model.addressText,
                                    contents: model.contents,
                                    onSelect: { entry in model.jump(to: entry) },
                                    onClose: { model.closeContents() })
                .presentationDetents([.large])
        }
        .sheet(isPresented: tabsPresented) {
            OpenTabsView(model: model)
                .presentationDetents([.large])
        }
    }

    // MARK: Address bar

    private var addressBar: some View {
        HStack(spacing: 10) {
            Image(systemName: "globe")
                .font(.subheadline)
                .foregroundStyle(accent)
            TextField("site.i2p · b32 host · b33 address", text: $model.addressText)
                .font(.system(.footnote, design: .monospaced))
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .keyboardType(.URL)
                .submitLabel(.go)
                .focused($addressFocused)
                .onSubmit { model.load() }
            if model.isLoading {
                Button {
                    model.cancel()
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Stop loading")
            } else if !model.addressText.isEmpty {
                Button {
                    model.addressText = ""
                } label: {
                    Image(systemName: "xmark.circle")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Clear address")
            }
            bookmarkButton
            Button {
                addressFocused = false
                model.load()
            } label: {
                Image(systemName: "arrow.right.circle.fill")
                    .font(.title3)
                    .foregroundStyle(model.addressText.isEmpty ? Color.secondary : accent)
            }
            .buttonStyle(.plain)
            .disabled(model.addressText.isEmpty || model.isLoading)
            .accessibilityLabel("Load page")
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
        .background(accent.opacity(0.10), in: RoundedRectangle(cornerRadius: 16))
        .overlay(
            RoundedRectangle(cornerRadius: 16)
                .strokeBorder(accent.opacity(0.28), lineWidth: 1)
        )
    }

    // MARK: Suggestions

    /// The saved hosts matching what is in the bar. The list only exists while
    /// the bar has focus and holds text: an empty bar never suggests anything,
    /// and a tapped suggestion hides it with the keyboard.
    private var addressSuggestionRows: [I2PSavedHostEntry] {
        guard addressFocused, !model.isLoading else { return [] }
        return savedHosts.suggestions(for: model.addressText)
    }

    @ViewBuilder
    private var addressSuggestionsList: some View {
        let rows = addressSuggestionRows
        if !rows.isEmpty {
            VStack(spacing: 0) {
                ForEach(rows) { entry in
                    suggestionRow(entry)
                    if entry.id != rows.last?.id {
                        Rectangle()
                            .fill(Color.white.opacity(0.07))
                            .frame(height: 1)
                            .padding(.leading, 40)
                    }
                }
            }
            .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 14))
            .overlay(
                RoundedRectangle(cornerRadius: 14)
                    .strokeBorder(accent.opacity(0.24), lineWidth: 1)
            )
        }
    }

    private func suggestionRow(_ entry: I2PSavedHostEntry) -> some View {
        Button {
            openSuggestion(entry)
        } label: {
            HStack(spacing: 10) {
                Image(systemName: entry.kind == .b33 ? "key.fill" : "globe")
                    .font(.caption)
                    .foregroundStyle(accent)
                    .frame(width: 22)
                Text(entry.host)
                    .font(.system(.caption, design: .monospaced).weight(.medium))
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer(minLength: 6)
                Text(resultWord(entry))
                    .font(.caption2)
                    .foregroundStyle(resultTint(entry))
                    .lineLimit(1)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 10)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel("\(entry.host), \(resultWord(entry))")
    }

    /// The word after the host: how its last fetch ended, or that it has not
    /// been opened since it was kept.
    private func resultWord(_ entry: I2PSavedHostEntry) -> String {
        entry.lastResult?.label ?? "not visited yet"
    }

    private func resultTint(_ entry: I2PSavedHostEntry) -> Color {
        guard let result = entry.lastResult else { return .secondary }
        return result.isFailure ? Color.orange : okGreen
    }

    /// Loads a suggestion's host and puts the keyboard away, which hides the
    /// list along with the focus.
    private func openSuggestion(_ entry: I2PSavedHostEntry) {
        addressFocused = false
        model.load(entry.host)
    }

    /// Fills the bar in with the one saved host the typed text points at, once
    /// its label is complete, so a bookmark needs no further typing. The store
    /// keeps the rule, and stops the fill from firing on the host it just wrote.
    private func completeAddress(for text: String) {
        guard addressFocused, !model.isLoading else { return }
        guard let host = savedHosts.completion(for: text) else { return }
        model.addressText = host
    }

    // MARK: History

    /// The visit stack under the address bar: a back and a forward chip,
    /// dimmed when there is nowhere to step.
    private var historyBar: some View {
        HStack(spacing: 10) {
            historyChip("Back",
                        systemImage: "chevron.backward",
                        enabled: model.visits.canGoBack) {
                addressFocused = false
                model.goBack()
            }
            historyChip("Forward",
                        systemImage: "chevron.forward",
                        enabled: model.visits.canGoForward) {
                addressFocused = false
                model.goForward()
            }
            Spacer(minLength: 0)
            tabsChip
            findChip
        }
    }

    private func historyChip(_ title: String,
                             systemImage: String,
                             enabled: Bool,
                             action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 6) {
                Image(systemName: systemImage)
                    .font(.caption2.weight(.bold))
                Text(title)
                    .font(.caption.weight(.semibold))
            }
            .foregroundStyle(enabled ? accent : Color.secondary)
            .padding(.horizontal, 12)
            .padding(.vertical, 7)
            .background((enabled ? accent.opacity(0.16) : Color.white.opacity(0.05)),
                        in: Capsule())
            .overlay(
                Capsule()
                    .strokeBorder(enabled ? accent.opacity(0.30) : Color.white.opacity(0.08),
                                  lineWidth: 1)
            )
            .opacity(enabled ? 1 : 0.45)
        }
        .buttonStyle(.plain)
        .disabled(!enabled)
        .accessibilityLabel(title)
    }

    // MARK: Tabs

    /// The chip beside the address bar that opens the sheet listing every page
    /// this browser has open, with how many there are.
    private var tabsChip: some View {
        let count = model.tabs.count
        return Button {
            addressFocused = false
            model.openTabs()
        } label: {
            HStack(spacing: 6) {
                Image(systemName: "square.on.square")
                    .font(.caption2.weight(.bold))
                Text("Tabs")
                    .font(.caption.weight(.semibold))
                if count > 0 {
                    Text("\(count)")
                        .font(.caption2.weight(.bold))
                        .padding(.horizontal, 5)
                        .padding(.vertical, 1)
                        .background(accent.opacity(0.22), in: Capsule())
                }
            }
            .foregroundStyle(accent)
            .padding(.horizontal, 12)
            .padding(.vertical, 7)
            .background(accent.opacity(0.16), in: Capsule())
            .overlay(
                Capsule()
                    .strokeBorder(accent.opacity(0.30), lineWidth: 1)
            )
        }
        .buttonStyle(.plain)
        .accessibilityLabel(tabsChipLabel(count))
        .accessibilityHint("Lists every page this browser has open")
    }

    private func tabsChipLabel(_ count: Int) -> String {
        switch count {
        case 0: return "Tabs, no pages open"
        case 1: return "Tabs, 1 page open"
        default: return "Tabs, \(count) pages open"
        }
    }

    /// The sheet's presentation, routed through the model so the header's Close
    /// and the last page closing both dismiss it.
    private var tabsPresented: Binding<Bool> {
        Binding(get: { model.tabsVisible },
                set: { shown in
                    if !shown { model.closeTabs() }
                })
    }

    // MARK: Find

    /// The chip beside back and forward that puts the find bar over the page,
    /// and closes it again while it is open. It only enables once something is
    /// on screen to search.
    private var findChip: some View {
        let isOpen = model.findVisible
        let enabled = isOpen || !model.findableBlocks.isEmpty
        return Button {
            addressFocused = false
            if isOpen {
                model.closeFind()
            } else {
                model.openFind()
            }
        } label: {
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass")
                    .font(.caption2.weight(.bold))
                Text("Find")
                    .font(.caption.weight(.semibold))
            }
            .foregroundStyle(isOpen ? Color.white : (enabled ? accent : Color.secondary))
            .padding(.horizontal, 12)
            .padding(.vertical, 7)
            .background((isOpen ? accent.opacity(0.85)
                          : (enabled ? accent.opacity(0.16) : Color.white.opacity(0.05))),
                        in: Capsule())
            .overlay(
                Capsule()
                    .strokeBorder(isOpen ? accent.opacity(0.90)
                                    : (enabled ? accent.opacity(0.30)
                                               : Color.white.opacity(0.08)),
                                  lineWidth: 1)
            )
            .opacity(enabled ? 1 : 0.45)
        }
        .buttonStyle(.plain)
        .disabled(!enabled)
        .accessibilityLabel(isOpen ? "Close find" : "Find in page")
    }

    /// The find bar above the page: the search field, what the search found,
    /// the chevrons that step through the matches, and the close button. It
    /// searches the page on screen whether it is live or a kept copy.
    @ViewBuilder
    private var findBar: some View {
        if model.findVisible {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 10) {
                    Image(systemName: "magnifyingglass")
                        .font(.subheadline)
                        .foregroundStyle(accent)
                    TextField("Find in page", text: findTextBinding)
                        .font(.footnote)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .submitLabel(.search)
                        .focused($findFocused)
                        .onSubmit { model.findNextMatch() }
                    matchStepper
                    Button {
                        model.closeFind()
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("Close find")
                }
                if model.find.isSearching {
                    Text(model.find.summary)
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(model.find.isEmpty ? Color.orange : accent)
                }
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            .background(accent.opacity(0.10), in: RoundedRectangle(cornerRadius: 14))
            .overlay(
                RoundedRectangle(cornerRadius: 14)
                    .strokeBorder(accent.opacity(0.28), lineWidth: 1)
            )
        }
    }

    /// The field's text, routed through the model so every keystroke runs the
    /// search and the highlights follow it.
    private var findTextBinding: Binding<String> {
        Binding(get: { model.findQuery },
                set: { model.updateFind($0) })
    }

    /// The pair of chevrons that step through the matches, dimmed when the
    /// search found nothing.
    private var matchStepper: some View {
        let hasMatches = !model.find.isEmpty
        return HStack(spacing: 4) {
            matchChevron("chevron.up", label: "Previous match", enabled: hasMatches) {
                model.findPreviousMatch()
            }
            matchChevron("chevron.down", label: "Next match", enabled: hasMatches) {
                model.findNextMatch()
            }
        }
    }

    private func matchChevron(_ systemImage: String,
                              label: String,
                              enabled: Bool,
                              action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: systemImage)
                .font(.caption.weight(.bold))
                .foregroundStyle(enabled ? accent : Color.secondary)
                .frame(width: 26, height: 26)
                .background((enabled ? accent.opacity(0.16) : Color.white.opacity(0.05)),
                            in: Circle())
        }
        .buttonStyle(.plain)
        .disabled(!enabled)
        .accessibilityLabel(label)
    }

    // MARK: Reader text size

    /// The row above the page: the control that cycles the reader's text size
    /// and names the size in effect, so the page's type, line spacing and block
    /// padding all step together — a live page and a kept copy alike — the
    /// contents control beside it, and, at the other end, the share control.
    private var readerBar: some View {
        HStack(spacing: 8) {
            readerSizeChip
            contentsChip
            Spacer(minLength: 0)
            shareChip
        }
    }

    // MARK: Contents

    /// The contents control above the page: it opens the sheet that lists the
    /// page's headings and names the host it will outline. It stays disabled
    /// while nothing is on screen and while the page has fewer than two
    /// headings, since there is nothing to jump between.
    private var contentsChip: some View {
        let contents = model.contents
        let host = model.contentsHost
        let enabled = contents.isAvailable
        return Button {
            addressFocused = false
            model.openContents()
        } label: {
            HStack(spacing: 6) {
                Image(systemName: "list.number")
                    .font(.caption.weight(.bold))
                VStack(alignment: .leading, spacing: 1) {
                    Text("Contents")
                        .font(.caption.weight(.semibold))
                    if let host {
                        Text(host)
                            .font(.system(size: 10, design: .monospaced))
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .frame(maxWidth: 108, alignment: .leading)
                    }
                }
            }
            .foregroundStyle(enabled ? accent : Color.secondary)
            .padding(.horizontal, 12)
            .padding(.vertical, 7)
            .background((enabled ? accent.opacity(0.16) : Color.white.opacity(0.05)),
                        in: Capsule())
            .overlay(
                Capsule()
                    .strokeBorder(enabled ? accent.opacity(0.30) : Color.white.opacity(0.08),
                                  lineWidth: 1)
            )
            .opacity(enabled ? 1 : 0.45)
        }
        .buttonStyle(.plain)
        .disabled(!enabled)
        .accessibilityLabel(contentsLabel(contents: contents, host: host, enabled: enabled))
        .accessibilityHint("Lists the page's headings and jumps to one")
    }

    /// The control's own name: the host it will outline and how many headings
    /// the sheet will list, or what is missing while it is disabled.
    private func contentsLabel(contents: I2PEepsiteContents,
                               host: String?,
                               enabled: Bool) -> String {
        guard enabled, let host else { return "Contents, no headings to jump to" }
        return "Contents, \(contents.countText.lowercased()) on \(host)"
    }

    /// The sheet's presentation, routed through the model so a new load closes
    /// it along with the page it was outlining.
    private var contentsPresented: Binding<Bool> {
        Binding(get: { model.contentsVisible },
                set: { shown in
                    if !shown { model.closeContents() }
                })
    }

    // MARK: Share

    /// The share control above the page: the system share sheet, with the
    /// page's address as its subject and the address followed by the reader's
    /// plain text as its body, for a live page and a kept copy alike. It names
    /// the host it will share, and stays disabled while nothing is on screen.
    @ViewBuilder
    private var shareChip: some View {
        let payload = model.sharePayload
        if let payload {
            ShareLink(item: payload.body,
                      subject: Text(payload.subject)) {
                shareChipLabel(host: payload.host, enabled: true)
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Share \(payload.host)")
            .accessibilityHint("Shares this page's address and its text")
        } else {
            shareChipLabel(host: nil, enabled: false)
                .accessibilityLabel("Share")
                .accessibilityHint("Load a page to share it")
        }
    }

    private func shareChipLabel(host: String?, enabled: Bool) -> some View {
        HStack(spacing: 6) {
            Image(systemName: "square.and.arrow.up")
                .font(.caption.weight(.bold))
            Text("Share")
                .font(.caption.weight(.semibold))
            if let host {
                Text(host)
                    .font(.system(.caption2, design: .monospaced))
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(accent.opacity(enabled ? 0.18 : 0.10), in: Capsule())
            }
        }
        .foregroundStyle(enabled ? accent : Color.secondary)
        .padding(.horizontal, 12)
        .padding(.vertical, 7)
        .background((enabled ? accent.opacity(0.16) : Color.white.opacity(0.05)),
                    in: Capsule())
        .overlay(
            Capsule()
                .strokeBorder(enabled ? accent.opacity(0.30) : Color.white.opacity(0.08),
                              lineWidth: 1)
        )
        .opacity(enabled ? 1 : 0.45)
    }

    private var readerSizeChip: some View {
        Button {
            readerText.cycle()
        } label: {
            HStack(spacing: 6) {
                Text("Aa")
                    .font(.subheadline.weight(.bold))
                Text(readerText.size.label)
                    .font(.caption.weight(.semibold))
            }
            .foregroundStyle(accent)
            .padding(.horizontal, 12)
            .padding(.vertical, 7)
            .background(accent.opacity(0.16), in: Capsule())
            .overlay(
                Capsule()
                    .strokeBorder(accent.opacity(0.30), lineWidth: 1)
            )
        }
        .buttonStyle(.plain)
        .accessibilityLabel("Reader text size, \(readerText.size.label)")
        .accessibilityHint("Tap to cycle the reader's text size")
    }

    // MARK: Bookmarks

    /// The host in the address bar, in the form a bookmark stores it.
    private var bookmarkCandidate: String? {
        I2PSavedHostsStore.host(in: model.addressText)?.host
    }

    private var bookmarkButton: some View {
        let candidate = bookmarkCandidate
        let saved = candidate.map { savedHosts.contains($0) } ?? false
        return Button {
            saveCurrentHost()
        } label: {
            Image(systemName: saved ? "bookmark.fill" : "bookmark")
                .font(.subheadline)
                .foregroundStyle(candidate == nil && !saved ? Color.secondary : accent)
        }
        .buttonStyle(.plain)
        .disabled(candidate == nil || saved)
        .accessibilityLabel(saved ? "Host already saved" : "Save this host")
    }

    private func saveCurrentHost() {
        guard let candidate = bookmarkCandidate else { return }
        model.saveBookmark(candidate)
    }

    private var savedHostsLink: some View {
        NavigationLink {
            SavedHostsView(currentAddress: model.addressText,
                           onSave: { host in
                               model.saveBookmark(host)
                           },
                           onOpen: { host in
                               addressFocused = false
                               model.load(host)
                           })
        } label: {
            HStack(spacing: 12) {
                Image(systemName: "bookmark")
                    .font(.footnote)
                    .foregroundStyle(accent)
                    .frame(width: 28, height: 28)
                    .background(accent.opacity(0.14), in: RoundedRectangle(cornerRadius: 8))
                VStack(alignment: .leading, spacing: 2) {
                    Text("Saved hosts")
                        .font(.footnote.weight(.semibold))
                        .foregroundStyle(.primary)
                    Text(savedHostsSummary)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 4)
                Image(systemName: "chevron.right")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(.tertiary)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 12)
            .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 16))
            .contentShape(RoundedRectangle(cornerRadius: 16))
        }
        .buttonStyle(.plain)
    }

    private var savedHostsSummary: String {
        switch savedHosts.entries.count {
        case 0: return "Keep a host as a bookmark"
        case 1: return "1 host kept · last visit and result"
        default: return "\(savedHosts.entries.count) hosts kept · last visit and result"
        }
    }

    /// The history screen, beside the bookmarks: every host the browser opened
    /// with the time of the visit and how the fetch ended.
    private var historyLink: some View {
        NavigationLink {
            BrowserHistoryView(onOpen: { host in
                addressFocused = false
                model.load(host)
            })
        } label: {
            HStack(spacing: 12) {
                Image(systemName: "clock")
                    .font(.footnote)
                    .foregroundStyle(accent)
                    .frame(width: 28, height: 28)
                    .background(accent.opacity(0.14), in: RoundedRectangle(cornerRadius: 8))
                VStack(alignment: .leading, spacing: 2) {
                    Text("History")
                        .font(.footnote.weight(.semibold))
                        .foregroundStyle(.primary)
                    Text(historySummary)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 4)
                Image(systemName: "chevron.right")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(.tertiary)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 12)
            .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 16))
            .contentShape(RoundedRectangle(cornerRadius: 16))
        }
        .buttonStyle(.plain)
    }

    private var historySummary: String {
        switch browserHistory.entries.count {
        case 0: return "Every host the browser opened"
        case 1: return "1 visit · newest first"
        default: return "\(browserHistory.entries.count) visits · newest first"
        }
    }

    /// The offline library, beside the bookmarks and the history: every saved
    /// host whose last good fetch is still kept on the device, readable without
    /// the router.
    private var offlineLink: some View {
        NavigationLink {
            OfflineLibraryView(onOpen: { kept in
                addressFocused = false
                model.readOffline(kept)
            })
        } label: {
            HStack(spacing: 12) {
                Image(systemName: "books.vertical")
                    .font(.footnote)
                    .foregroundStyle(accent)
                    .frame(width: 28, height: 28)
                    .background(accent.opacity(0.14), in: RoundedRectangle(cornerRadius: 8))
                VStack(alignment: .leading, spacing: 2) {
                    Text("Offline library")
                        .font(.footnote.weight(.semibold))
                        .foregroundStyle(.primary)
                    Text(offlineSummary)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 4)
                Image(systemName: "chevron.right")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(.tertiary)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 12)
            .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 16))
            .contentShape(RoundedRectangle(cornerRadius: 16))
        }
        .buttonStyle(.plain)
    }

    private var offlineSummary: String {
        let count = offlinePages.copies.count
        guard count > 0 else { return "Keep any page for offline reading" }
        let size = I2PKeptPage.sizeText(offlinePages.libraryBytes)
        return count == 1 ? "1 page kept · \(size)" : "\(count) pages kept · \(size)"
    }

    // MARK: Loaded content

    /// What the screen shows under the address bar: the empty state, the live
    /// load, the failure — or, when the host kept a copy, the failure's banner
    /// followed by the copy itself.
    @ViewBuilder
    private var loadContent: some View {
        switch model.phase {
        case .idle:
            if lastReadPage.shouldOffer, let page = lastReadPage.page {
                continueReadingCard(page)
            }
            emptyStateCard
        case .loading:
            loadingCard
        case .failed(let failure):
            if let kept = model.keptCopy {
                offlineCopyCard(failure, kept: kept)
                keptPageCard(kept)
            } else {
                failureCard(failure)
            }
        case .offline(let kept):
            offlineCopyCard(nil, kept: kept)
            keptPageCard(kept)
        case .loaded(let page):
            pageCard(page)
        }
    }

    // MARK: Loading

    private var loadingCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                ProgressView()
                    .tint(accent)
                VStack(alignment: .leading, spacing: 2) {
                    Text(model.currentStage?.summary ?? "Working…")
                        .font(.footnote.weight(.medium))
                        .fixedSize(horizontal: false, vertical: true)
                    Text(model.addressText)
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                Spacer(minLength: 4)
            }
            stageTrail
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    private var stageTrail: some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(model.trail, id: \.self) { stage in
                HStack(spacing: 8) {
                    Image(systemName: "checkmark.circle.fill")
                        .font(.caption2)
                        .foregroundStyle(accent)
                    Text(stage.completedSummary)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
            if let current = model.currentStage {
                HStack(spacing: 8) {
                    ProgressView()
                        .controlSize(.mini)
                        .tint(accent)
                    Text(current.summary)
                        .font(.caption.weight(.medium))
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    // MARK: Failure

    private func failureCard(_ failure: I2PEepsiteFailure) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Couldn't load the page", systemImage: "exclamationmark.triangle.fill")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(.orange)

            HStack(spacing: 8) {
                Text(failure.stage.rawValue)
                    .font(.caption2.weight(.bold))
                    .foregroundStyle(.orange)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .background(Color.orange.opacity(0.15), in: Capsule())
                Text("failing stage")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }

            Text(failure.message)
                .font(.footnote)
                .foregroundStyle(.primary)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)

            if !model.trail.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(model.trail, id: \.self) { stage in
                        HStack(spacing: 8) {
                            Image(systemName: "checkmark.circle")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                            Text(stage.completedSummary)
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }

            Button {
                model.reload()
            } label: {
                Label("Try again", systemImage: "arrow.clockwise")
                    .font(.subheadline.weight(.semibold))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .background(accent.opacity(0.15), in: RoundedRectangle(cornerRadius: 12))
            }
            .buttonStyle(.plain)
            .tint(accent)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    // MARK: Offline copy

    /// The banner a kept copy shows: when it was kept, the line naming the stage
    /// the live fetch broke in when there was one, and a live retry. The kept
    /// page itself follows in the card below. A copy read from the offline
    /// library has no failure to name — nothing was fetched to fail.
    private func offlineCopyCard(_ failure: I2PEepsiteFailure?,
                                 kept: I2PKeptPage) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: "tray.full")
                    .font(.footnote)
                    .foregroundStyle(accent)
                    .frame(width: 28, height: 28)
                    .background(accent.opacity(0.14), in: RoundedRectangle(cornerRadius: 8))
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 3) {
                    Text("Offline copy")
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(.primary)
                    Text(failure == nil
                         ? "Read from the offline library — no live fetch ran for this page."
                         : "This host didn't load, so the page it kept from its last good fetch is shown below.")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 4)
            }

            HStack(spacing: 6) {
                Image(systemName: "tray.and.arrow.down.fill")
                    .font(.caption2)
                Text(kept.keptText())
                    .font(.caption.weight(.semibold))
            }
            .foregroundStyle(accent)
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(accent.opacity(0.14), in: Capsule())

            if let failure {
                // The line naming the stage the live fetch broke in.
                HStack(spacing: 8) {
                    Text(failure.stage.rawValue)
                        .font(.caption2.weight(.bold))
                        .foregroundStyle(.orange)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .background(Color.orange.opacity(0.15), in: Capsule())
                    Text("failing stage")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }

                Text(failure.message)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Button {
                model.reload()
            } label: {
                HStack(spacing: 6) {
                    Image(systemName: "arrow.clockwise")
                        .font(.caption)
                    Text("Retry live")
                        .font(.footnote.weight(.semibold))
                }
                .foregroundStyle(accent)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 9)
                .background(accent.opacity(0.14), in: Capsule())
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Retry the page live")
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(accent.opacity(0.08), in: RoundedRectangle(cornerRadius: 18))
        .overlay(
            RoundedRectangle(cornerRadius: 18)
                .strokeBorder(accent.opacity(0.28), lineWidth: 1)
        )
    }

    /// The kept page itself: the same reader view a live page gets, headed by
    /// the address it was taken from and the details of the fetch that took it.
    private func keptPageCard(_ kept: I2PKeptPage) -> some View {
        let blocks = kept.readBlocks
        return VStack(alignment: .leading, spacing: 0) {
            keptPageHeader(kept)
            VStack(alignment: .leading, spacing: readerText.size.blockSpacing) {
                if blocks.isEmpty {
                    Text("The kept copy carried no readable text.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(Array(blocks.enumerated()), id: \.offset) { pair in
                        blockView(pair.element, index: pair.offset)
                            .id(pair.offset)
                    }
                }
            }
            .padding(readerText.size.blockPadding)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
        .environment(\.openURL, OpenURLAction { url in
            model.load(url.absoluteString)
            return .handled
        })
    }

    private func keptPageHeader(_ kept: I2PKeptPage) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Image(systemName: "doc.text")
                    .font(.caption)
                    .foregroundStyle(accent)
                Text(kept.address)
                    .font(.system(.caption, design: .monospaced).weight(.medium))
                    .foregroundStyle(Color.primary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer(minLength: 6)
                Text("kept copy")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(accent)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 2)
                    .background(accent.opacity(0.14), in: Capsule())
            }
            Text(keptMetaLine(kept))
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            keepOfflineButton
                .padding(.top, 6)
        }
        .padding(.horizontal, readerText.size.blockPadding)
        .padding(.top, 16)
        .padding(.bottom, 10)
    }

    private func keptMetaLine(_ kept: I2PKeptPage) -> String {
        let leases = kept.leaseCount == 1 ? "1 lease" : "\(kept.leaseCount) leases"
        let size = byteText(kept.byteCount)
        let elapsed = String(format: "%.1fs", kept.elapsed)
        return "\(leases) · \(kept.route) · \(size) · \(elapsed)"
    }

    private var keepOfflineButton: some View {
        let isKept = model.isCurrentPageKeptOffline
        return Button {
            model.keepCurrentPageOffline()
        } label: {
            HStack(spacing: 6) {
                Image(systemName: isKept ? "arrow.clockwise" : "tray.and.arrow.down")
                    .font(.caption2.weight(.bold))
                Text(isKept ? "Kept · update" : "Keep offline")
                    .font(.caption.weight(.semibold))
            }
            .foregroundStyle(model.canKeepCurrentPageOffline ? accent : Color.secondary)
            .padding(.horizontal, 11)
            .padding(.vertical, 6)
            .background((model.canKeepCurrentPageOffline ? accent.opacity(0.14) : Color.white.opacity(0.05)),
                        in: Capsule())
            .overlay(
                Capsule()
                    .strokeBorder(model.canKeepCurrentPageOffline ? accent.opacity(0.28) : Color.white.opacity(0.08),
                                  lineWidth: 1)
            )
        }
        .buttonStyle(.plain)
        .disabled(!model.canKeepCurrentPageOffline)
        .accessibilityLabel(isKept ? "Kept offline. Update copy" : "Keep this page offline")
        .accessibilityHint("Stores this reader page on this device for offline reading")
    }

    // MARK: Page

    private func pageCard(_ page: I2PEepsitePage) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            pageHeader(page)
            if let note = page.note {
                inlineNote(note)
            }
            VStack(alignment: .leading, spacing: readerText.size.blockSpacing) {
                if page.blocks.isEmpty {
                    Text("The page carried no readable text.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(Array(page.blocks.enumerated()), id: \.offset) { pair in
                        blockView(pair.element, index: pair.offset)
                            .id(pair.offset)
                    }
                }
            }
            .padding(readerText.size.blockPadding)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
        .environment(\.openURL, OpenURLAction { url in
            model.load(url.absoluteString)
            return .handled
        })
    }

    private func pageHeader(_ page: I2PEepsitePage) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Image(systemName: "globe")
                    .font(.caption)
                    .foregroundStyle(accent)
                Text(page.address)
                    .font(.system(.caption, design: .monospaced).weight(.medium))
                    .foregroundStyle(Color.primary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer(minLength: 6)
                Text("HTTP \(page.statusCode)")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            Text(metaLine(page))
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            keepOfflineButton
                .padding(.top, 6)
        }
        .padding(.horizontal, readerText.size.blockPadding)
        .padding(.top, 16)
        .padding(.bottom, page.note == nil ? 0 : 10)
    }

    private func metaLine(_ page: I2PEepsitePage) -> String {
        let leases = page.leaseCount == 1 ? "1 lease" : "\(page.leaseCount) leases"
        let size = byteText(page.byteCount)
        let elapsed = String(format: "%.1fs", page.elapsed)
        return "\(leases) · \(page.route.rawValue) · \(size) · \(elapsed)"
    }

    private func inlineNote(_ note: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "exclamationmark.circle")
                .font(.caption)
                .foregroundStyle(.orange)
            Text(note)
                .font(.caption2)
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.horizontal, readerText.size.blockPadding)
        .padding(.top, 10)
    }

    /// One block of the page, laid out with the reader's current text size: the
    /// title, both heading levels, body, bullets, quotes and code all step
    /// together, with their line spacing and padding in proportion.
    @ViewBuilder
    private func blockView(_ block: I2PReadBlock, index: Int) -> some View {
        let text = model.findText(block, blockIndex: index)
        let size = readerText.size
        switch block.kind {
        case .title:
            Text(text)
                .font(size.titleFont)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
        case .heading(let level):
            Text(text)
                .font(size.headingFont(level: level))
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 2 * size.scale)
                .textSelection(.enabled)
        case .paragraph:
            Text(text)
                .font(size.bodyFont)
                .lineSpacing(size.bodyLineSpacing)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
        case .bullet:
            HStack(alignment: .firstTextBaseline, spacing: size.inlineSpacing) {
                Text("•")
                    .font(size.bulletDotFont)
                    .foregroundStyle(accent)
                Text(text)
                    .font(size.bodyFont)
                    .lineSpacing(size.bulletLineSpacing)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
            }
            .padding(.leading, 2 * size.scale)
        case .quote:
            HStack(alignment: .top, spacing: size.inlineSpacing) {
                RoundedRectangle(cornerRadius: 2)
                    .fill(accent.opacity(0.6))
                    .frame(width: 3)
                Text(text)
                    .font(size.quoteFont)
                    .foregroundStyle(.secondary)
                    .lineSpacing(size.quoteLineSpacing)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
            }
        case .code:
            Text(text)
                .font(size.codeFont)
                .fixedSize(horizontal: false, vertical: true)
                .padding(size.codePadding)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.black.opacity(0.25), in: RoundedRectangle(cornerRadius: 10))
                .textSelection(.enabled)
        case .rule:
            Rectangle()
                .fill(Color.white.opacity(0.12))
                .frame(height: 1)
                .padding(.vertical, 2)
        }
    }

    private func byteText(_ bytes: Int) -> String {
        if bytes >= 1_048_576 { return String(format: "%.1f MB", Double(bytes) / 1_048_576) }
        if bytes >= 1_024 { return String(format: "%.1f KB", Double(bytes) / 1_024) }
        return "\(bytes) B"
    }

    // MARK: Empty state & footnote

    /// The one remembered address, offered only while the browser has no page
    /// open. Reading the kept copy consults device storage only; the live button
    /// is the sole action here that starts a fetch.
    private func continueReadingCard(_ page: I2PLastReadPage) -> some View {
        let kept = offlinePages.copy(for: page.address)
        return VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                Image(systemName: "book.closed")
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(accent)
                    .frame(width: 30, height: 30)
                    .background(accent.opacity(0.15), in: RoundedRectangle(cornerRadius: 9))
                    .accessibilityHidden(true)
                Text("Continue reading")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.primary)
                Spacer(minLength: 4)
                Button {
                    lastReadPage.dismiss()
                } label: {
                    Image(systemName: "xmark")
                        .font(.caption.weight(.bold))
                        .foregroundStyle(.secondary)
                        .frame(width: 30, height: 30)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Dismiss continue reading for \(page.address)")
            }

            Text(page.address)
                .font(.system(.footnote, design: .monospaced).weight(.medium))
                .foregroundStyle(.primary)
                .lineLimit(2)
                .truncationMode(.middle)
                .textSelection(.enabled)
            Text("Last read \(page.lastReadAt.formatted(date: .abbreviated, time: .shortened))")
                .font(.caption2)
                .foregroundStyle(.secondary)

            HStack(spacing: 8) {
                Button {
                    addressFocused = false
                    model.load(page.address)
                } label: {
                    Label("Load live", systemImage: "globe")
                        .font(.caption.weight(.semibold))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                        .background(accent.opacity(0.17), in: RoundedRectangle(cornerRadius: 11))
                }
                .buttonStyle(.plain)
                .foregroundStyle(accent)
                .accessibilityHint("Fetches this address now")

                if let kept {
                    Button {
                        addressFocused = false
                        model.readOffline(kept)
                    } label: {
                        Label("Read offline", systemImage: "tray.full")
                            .font(.caption.weight(.semibold))
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 10)
                            .background(Color.white.opacity(0.07), in: RoundedRectangle(cornerRadius: 11))
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(.primary)
                    .accessibilityHint("Opens the kept copy without connecting to the network")
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(accent.opacity(0.09), in: RoundedRectangle(cornerRadius: 18))
        .overlay(
            RoundedRectangle(cornerRadius: 18)
                .strokeBorder(accent.opacity(0.28), lineWidth: 1)
        )
    }

    private var emptyStateCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Browse an eepsite", systemImage: "globe")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(accent)
            Text("Type a .i2p hostname (b32), a b33 address or a base64 destination. The destination is resolved through this router's network database — plain LeaseSets, LeaseSet2, or the blinded key for credentialled b33 hosts — and the page is fetched as a garlic'd stream through the browser's outbound tunnel pool.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if !model.suggestions.isEmpty {
                Text("Credentialled b33 hosts")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .textCase(.uppercase)
                    .padding(.top, 2)
                ForEach(model.suggestions, id: \.self) { address in
                    Button {
                        model.load(address)
                    } label: {
                        HStack(spacing: 8) {
                            Image(systemName: "lock.shield")
                                .font(.caption2)
                                .foregroundStyle(accent)
                            Text(address)
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundStyle(.primary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 8)
                        .background(accent.opacity(0.12), in: RoundedRectangle(cornerRadius: 10))
                    }
                    .buttonStyle(.plain)
                }
            }
            Text("The router must be running with live peers before the tunnel pool can fill.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    private var footnote: some View {
        Text("Pages travel as garlic'd streams over the router's own outbound tunnels and the browser publishes its leases so replies can come back — the eepsite only ever learns a destination hash.")
            .font(.caption2)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 2)
    }
}

// MARK: - Live wiring

extension I2PEepsiteBrowserModel {
    /// The browser bound to the running router: the eepsite client destination
    /// the app context owns, and the b33 hosts its SAM sessions hold
    /// credentials for.
    static func live() -> I2PEepsiteBrowserModel {
        let context = I2PRouterAppContext.shared
        return I2PEepsiteBrowserModel(
            client: context.eepsiteBrowser,
            suggestions: {
                context.samServer.b33Hosts().map(\.address)
            })
    }
}



