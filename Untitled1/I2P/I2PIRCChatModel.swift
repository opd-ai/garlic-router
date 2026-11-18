//
//  I2PIRCChatModel.swift
//  The IRC screen's model: the connection's phase and stage, the chat state it
//  feeds, the outbox that keeps sends in order, the keep-alive and registration
//  watchdogs, and the small command set (`/join`, `/me`, `/msg`, …) that makes
//  the client usable without typing raw IRC.
//
//  Everything published here is mutated on the main actor; the stream work runs
//  off it and reports back through the connection's callbacks.
//

import Foundation
import Combine

final class I2PIRCChatModel: ObservableObject {
    enum Phase: Equatable {
        case idle
        case connecting(I2PIRCStage)
        case connected
        /// The connection broke, at a named stage.
        case failed(stage: String, message: String)
        /// The server (or the stream) closed a live connection.
        case closed(String)
        /// The stream ended on its own and the client is waiting out the
        /// backoff before dialling the same server again.
        case reconnecting(attempt: Int, seconds: Int)

        var isLive: Bool {
            if case .connected = self { return true }
            return false
        }

        var isConnecting: Bool {
            if case .connecting = self { return true }
            return false
        }

        var isReconnecting: Bool {
            if case .reconnecting = self { return true }
            return false
        }

        /// The one-line state the header shows.
        var title: String {
            switch self {
            case .idle: return "Not connected"
            case .connecting(let stage): return "Connecting · \(stage.rawValue)"
            case .connected: return "Connected"
            case .failed: return "Connection failed"
            case .closed: return "Disconnected"
            case .reconnecting: return "Reconnecting"
            }
        }
    }

    @Published private(set) var phase: Phase = .idle
    @Published private(set) var state: I2PIRCChatState
    @Published private(set) var selection = I2PIRCChatState.serverBufferName
    /// The stage trail of the attempt in flight, newest last.
    @Published private(set) var trail: [String] = []
    /// What the composer holds, which is the draft of the conversation on
    /// screen: every edit is recorded against `selection`, and a switch to
    /// another conversation puts that conversation's draft back in the field.
    @Published var draftText = "" {
        didSet {
            guard !isSwappingDraft else { return }
            drafts.store(draftText, for: selection)
        }
    }
    @Published private(set) var connectedServerID: UUID?
    /// The stage the attempt most recently reached.
    @Published private(set) var lastStage: I2PIRCStage?
    /// How many retries of the current outage have been started; zero when the
    /// session is healthy, when the client gave up and when the user took over.
    @Published private(set) var reconnectAttempt = 0
    /// The connected server's channel list, as its LIST listing has arrived so
    /// far. Dropped when the session ends, since the rows belong to that server.
    @Published private(set) var channelList = I2PIRCChannelList()
    /// The stream's round-trip measurement: cleared on connect, on disconnect
    /// and on every reconnect attempt, so it always belongs to the live stream.
    @Published private(set) var latency = I2PIRCLatency()
    /// The conversations of the connected server the user has silenced, by
    /// `I2PIRCName.key`. The chat header's bell sets them, and the chip shows a
    /// slashed bell for each of them instead of a badge.
    @Published private(set) var mutedConversationIDs: Set<String> = []
    /// The conversations of the connected server the user has snoozed, by
    /// `I2PIRCName.key`. The bell sets them for 15 minutes, an hour, until
    /// tomorrow or until it is turned back on, and the chip shows a slashed bell
    /// with the time left instead of a badge. A timed snooze lifts by itself.
    @Published private(set) var snoozedConversationIDs: Set<String> = []
    /// The nicks the connected server ignores, by `I2PIRCName.key`. Their lines
    /// still arrive and still count as unread, but the transcript folds each run
    /// of them into one quiet row the user can open on tap.
    @Published private(set) var ignoredNicks: Set<String> = []
    /// The folded rows the user has opened, by `I2PIRCIgnoredGroup.id`. They stay
    /// open until the conversation on screen changes.
    @Published private(set) var expandedIgnoredGroupIDs: Set<String> = []

    private let client: I2PIRCClient
    private let servers: I2PIRCServerBook
    private let history: I2PIRCHistoryStore
    /// The words the user wants to be told about, shared across servers.
    private let keywords: I2PIRCKeywordBook
    /// The conversations the user has silenced, kept per server.
    private let mutes: I2PIRCMuteBook
    /// The conversations the user has snoozed, kept per server with the moment
    /// each one lifts.
    private let snoozes: I2PIRCSnoozeBook
    /// The nicks the user ignores, kept per server.
    private let ignores: I2PIRCIgnoreBook
    /// Writes the transcript to device storage as the chat state changes.
    private var historyCancellable: AnyCancellable?
    /// Re-marks the transcript when a word is added, paused or deleted.
    private var keywordsCancellable: AnyCancellable?
    /// Re-reads a server's mutes when one is set or cleared.
    private var mutesCancellable: AnyCancellable?
    /// Re-reads a server's snoozes when one is set, cleared or lifts by itself,
    /// and follows the time left while a timed one runs.
    private var snoozesCancellable: AnyCancellable?
    /// Re-reads a server's ignored nicks when one is set or cleared.
    private var ignoresCancellable: AnyCancellable?

    private var connection: I2PIRCStreamConnection?
    private var connectTask: Task<Void, Never>?
    private var registrationTask: Task<Void, Never>?
    private var keepAliveTask: Task<Void, Never>?
    /// The countdown that waits out a backoff before the next attempt.
    private var reconnectTask: Task<Void, Never>?
    /// Why the last session ended, kept for the header a cancelled retry shows.
    private var outageReason: String?
    private var lastInbound = Date()
    /// When the last latency probe went out, which sets the minute's cadence.
    private var lastProbeAt = Date.distantPast
    private var userClosed = false
    private var outbox: [String] = []
    private var pumping = false
    /// The composer's drafts, one per conversation, kept for the session only —
    /// they are never written to disk.
    private var drafts = I2PIRCDrafts()
    /// Set while a conversation switch is putting another conversation's draft
    /// in the field, so the swap is not recorded as an edit of either one.
    private var isSwappingDraft = false
    /// Bumped by every connect and disconnect so a stale send pump cannot write
    /// the next connection's lines onto the previous stream.
    private var generation = 0

    /// How long a registration may take before the client calls it failed.
    private static let registrationTimeout: TimeInterval = 90
    /// Silence after which the client pings the server.
    private static let pingAfter: TimeInterval = 120
    /// Silence after which the stream is declared dead.
    private static let deadAfter: TimeInterval = 300

    init(client: I2PIRCClient,
         servers: I2PIRCServerBook = .shared,
         history: I2PIRCHistoryStore = .shared,
         keywords: I2PIRCKeywordBook = .shared,
         mutes: I2PIRCMuteBook = .shared,
         snoozes: I2PIRCSnoozeBook = .shared,
         ignores: I2PIRCIgnoreBook = .shared) {
        self.client = client
        self.servers = servers
        self.history = history
        self.keywords = keywords
        self.mutes = mutes
        self.snoozes = snoozes
        self.ignores = ignores
        self.state = I2PIRCChatState(serverName: "", nick: "")

        // Save the transcript as it grows: every change to the chat state is
        // written for the connected server, so a kill of the app costs at most
        // the line being written.
        historyCancellable = $state
            .dropFirst()
            .sink { [weak self] state in
                guard let self, let serverID = self.connectedServerID else { return }
                self.history.record(state, for: serverID)
            }

        // A word added, paused or deleted in the Highlights sheet — and the
        // master switch being turned off, or coming back on by itself when its
        // time runs out — re-marks the transcript at once, so the edges and the
        // chip's count follow it.
        keywordsCancellable = Publishers.CombineLatest(keywords.$entries,
                                                       keywords.$pauseEndsAt)
            .dropFirst()
            .sink { [weak self] _, _ in
                self?.applyKeywords()
            }

        // A mute set or cleared re-reads the connected server's record, so the
        // chip's slashed bell and the silence of its badges follow at once.
        mutesCancellable = mutes.$revision
            .dropFirst()
            .sink { [weak self] _ in
                self?.resyncMutes()
            }

        // A snooze set, cleared or lifted re-reads the connected server's
        // record, so the chip's slashed bell and the silence of its badges follow
        // at once — and the time left follows the clock while one is running.
        snoozesCancellable = Publishers.CombineLatest(snoozes.$revision,
                                                      snoozes.$minuteTick)
            .dropFirst()
            .sink { [weak self] _, _ in
                self?.resyncSnoozes()
            }

        // An ignore set or cleared re-reads the connected server's record, so
        // the member list's ignored section and the transcript's quiet rows
        // follow at once.
        ignoresCancellable = ignores.$revision
            .dropFirst()
            .sink { [weak self] _ in
                self?.resyncIgnores()
            }
    }

    // MARK: Derived state

    var selectedConversation: I2PIRCConversation? {
        state.conversation(selection) ?? state.orderedConversations.first
    }

    /// The channel whose member list is open, resolved live from the state so
    /// the list follows joins, parts and mode changes as they arrive.
    func conversation(_ conversationID: String) -> I2PIRCConversation? {
        state.conversation(conversationID)
    }

    var totalUnread: Int { state.totalUnread }

    // MARK: Search

    /// Whether the search field above the transcript is open.
    @Published private(set) var isSearching = false
    /// What the user has typed into the search field.
    @Published var searchText = ""

    /// The lines of the open conversation the field matches, oldest first; the
    /// whole transcript while the field is closed or holds only spaces.
    var visibleMessages: [I2PIRCMessage] {
        guard isFilteringTranscript else { return selectedConversation?.messages ?? [] }
        return searchResults
    }

    /// Whether the field is doing the filtering right now — open, and holding
    /// something to look for.
    var isFilteringTranscript: Bool {
        isSearching && !I2PIRCSearch.normalized(searchText).isEmpty
    }

    /// The count the field shows: "7 matches", "1 match", "No matches".
    var searchSummary: String { I2PIRCSearch.summary(count: searchResults.count) }

    private var searchResults: [I2PIRCMessage] {
        I2PIRCSearch.results(in: selectedConversation?.messages ?? [], query: searchText)
    }

    /// Opens the search field above the transcript.
    func beginSearch() {
        isSearching = true
    }

    /// Closes the field and puts the whole transcript back.
    func clearSearch() {
        isSearching = false
        searchText = ""
    }

    // MARK: Share

    /// What the chat header's share control hands the system share sheet: the
    /// open conversation's name as the subject and its lines, oldest first. Nil
    /// while the conversation holds no lines, which is what leaves the control
    /// disabled — and the transcript is the only thing that goes in it.
    var sharePayload: I2PIRCSharePayload? {
        guard let conversation = selectedConversation else { return nil }
        return I2PIRCShare.payload(for: conversation,
                                   ourNick: state.nick,
                                   serverName: state.serverName)
    }

    // MARK: Nick completion

    /// The nicks the composer is completing right now: the open channel's
    /// roster, narrowed to what the draft starts with — our own first, then the
    /// most recently active — and empty for every conversation without a roster
    /// (the server buffer and the queries) and for a draft that is no nick.
    var nickSuggestions: [I2PIRCNickSuggestion] {
        guard phase.isLive,
              let conversation = selectedConversation,
              conversation.kind == .channel else { return [] }
        return I2PIRCNickCompletion.suggestions(draft: draftText,
                                                members: conversation.members,
                                                roles: conversation.memberRoles,
                                                ourNick: state.nick,
                                                messages: conversation.messages)
    }

    /// Replaces the word being typed with a suggested nick and the ": " that
    /// follows it, keeping the rest of the draft.
    func completeNick(_ nick: String) {
        let completed = I2PIRCNickCompletion.applying(nick, to: draftText)
        guard completed != draftText else { return }
        draftText = completed
    }

    /// What Tab does: completes with the first suggestion. Returns false with
    /// nothing suggested, so the key press is left to the field.
    @discardableResult
    func completeFirstNickSuggestion() -> Bool {
        guard let first = nickSuggestions.first else { return false }
        completeNick(first.nick)
        return true
    }

    // MARK: Mentions

    /// The marked lines of the conversation on screen, oldest first: the ones
    /// that named us and have not been read past yet.
    var selectedMentionIDs: [UUID] {
        (selectedConversation?.messages ?? []).filter { $0.mentionsUs }.map(\.id)
    }

    var selectedMentionCount: Int { selectedMentionIDs.count }

    /// The line the Next mention control last jumped to, so the chat can scroll
    /// it into view.
    @Published private(set) var mentionTarget: UUID?
    /// Bumped by every jump, so stepping onto the same line twice scrolls it
    /// into view again.
    @Published private(set) var mentionJumpCount = 0
    /// Which step of the conversation's marked lines the control is on, counted
    /// from one; zero before it has been used.
    private var mentionPosition = 0

    /// How many lines of the open conversation name us, in a sentence.
    var mentionSummary: String {
        let total = selectedMentionCount
        switch total {
        case 0: return "No lines name you here"
        case 1: return "1 line names you here"
        default: return "\(total) lines name you here"
        }
    }

    /// The control's read-out: "2 of 5", and an empty count with nothing marked.
    var mentionCounter: String {
        I2PIRCMention.counter(position: mentionPosition, count: selectedMentionCount)
    }

    var canStepMentions: Bool { selectedMentionCount > 0 }

    /// Steps to the next marked line of the open conversation, wrapping to the
    /// first after the last. With nothing marked it does nothing, which is what
    /// leaves the control dimmed.
    func nextMention() {
        let ids = selectedMentionIDs
        guard !ids.isEmpty else {
            resetMentionCursor()
            return
        }
        let position = I2PIRCMention.nextPosition(after: mentionPosition, count: ids.count)
        mentionPosition = position
        mentionTarget = ids[position - 1]
        mentionJumpCount += 1
    }

    /// Puts the control back at its start — done when another conversation comes
    /// on screen, so it never steps through the previous one's marks.
    private func resetMentionCursor() {
        mentionPosition = 0
        mentionTarget = nil
    }

    // MARK: Highlights

    /// The open conversation's lines that hold one of the user's switched-on
    /// words, oldest first — what the Highlight control steps through. A line
    /// that both names us and holds a word is in this list, and in the mention
    /// control's too.
    var selectedKeywordIDs: [UUID] {
        I2PIRCKeywordRule.markedIDs(in: selectedConversation?.messages ?? [])
    }

    var selectedKeywordCount: Int { selectedKeywordIDs.count }

    /// The line the Highlight control last jumped to, so the chat can scroll it
    /// into view.
    @Published private(set) var keywordTarget: UUID?
    /// Bumped by every jump, so stepping onto the same line twice scrolls it
    /// into view again.
    @Published private(set) var keywordJumpCount = 0
    /// Which step of the conversation's keyword lines the control is on, counted
    /// from one; zero before it has been used.
    private var keywordPosition = 0

    /// How many lines of the open conversation hold one of the user's words, in
    /// a sentence.
    var keywordSummary: String {
        let total = selectedKeywordCount
        switch total {
        case 0: return "No lines hold one of your words here"
        case 1: return "1 line holds one of your words here"
        default: return "\(total) lines hold one of your words here"
        }
    }

    /// The control's read-out: "2 of 7", and an empty count with nothing marked.
    var keywordCounter: String {
        I2PIRCMention.counter(position: keywordPosition, count: selectedKeywordCount)
    }

    var canStepHighlights: Bool { selectedKeywordCount > 0 }

    /// Steps to the next keyword line of the open conversation, wrapping to the
    /// first after the last. With no keyword line it does nothing, which is what
    /// leaves the control dimmed.
    func nextHighlight() {
        let ids = selectedKeywordIDs
        guard !ids.isEmpty else {
            resetHighlightCursor()
            return
        }
        let position = I2PIRCMention.nextPosition(after: keywordPosition, count: ids.count)
        keywordPosition = position
        keywordTarget = ids[position - 1]
        keywordJumpCount += 1
    }

    /// Puts the control back at its start — done when another conversation comes
    /// on screen, so it never steps through the previous one's marks.
    private func resetHighlightCursor() {
        keywordPosition = 0
        keywordTarget = nil
    }

    // MARK: Silence — mutes and snoozes

    /// Whether a conversation is muted: the server buffer, a channel or a query
    /// the user silenced without a time, as the bell set mutes before snoozes
    /// existed.
    func isMuted(_ conversationID: String) -> Bool {
        mutedConversationIDs.contains(I2PIRCName.key(conversationID))
    }

    /// Whether a conversation is snoozed for a stretch of time by the chat
    /// header's bell.
    func isSnoozed(_ conversationID: String) -> Bool {
        snoozedConversationIDs.contains(I2PIRCName.key(conversationID))
    }

    /// Whether a conversation adds no badge: put to sleep by a snooze, silenced
    /// by a mute, or both. Its chip shows a slashed bell in place of the unread,
    /// mention and keyword counts.
    func isSilenced(_ conversationID: String) -> Bool {
        isMuted(conversationID) || isSnoozed(conversationID)
    }

    /// What is left of a timed snooze as the chip and the bell write it: "42m",
    /// "1h 5m". Nil when the conversation is not snoozed, or when the snooze
    /// waits to be turned back on.
    func snoozeRemaining(_ conversationID: String) -> String? {
        guard let serverID = connectedServerID,
              let entry = snoozes.entry(conversationID, on: serverID),
              let endsAt = entry.endsAt else { return nil }
        return I2PIRCSnoozeRule.shortRemaining(until: endsAt)
    }

    /// What the bell reads on its control: the snooze in effect with the time
    /// left, a mute's plain silence, or that the conversation is heard.
    func bellSummary(_ conversationID: String) -> String {
        let key = I2PIRCName.key(conversationID)
        if snoozedConversationIDs.contains(key) {
            guard let remaining = snoozeRemaining(key) else { return "Snoozed" }
            return "Snoozed · \(remaining)"
        }
        return mutedConversationIDs.contains(key) ? "Muted" : "Unmuted"
    }

    /// Puts one conversation to sleep for the chosen time, and keeps it for this
    /// server across launches and reconnects. While it runs the conversation adds
    /// no unread badge, no mention count and no keyword count, and its chip shows
    /// a slashed bell with the time left; the marks on its lines stay where they
    /// are. A mute the conversation carried from before snoozes existed gives way
    /// to the snooze, so the silence ends when the snooze does.
    func snooze(_ conversationID: String, for duration: I2PIRCSnoozeDuration) {
        guard let serverID = connectedServerID,
              state.conversation(conversationID) != nil else { return }
        let key = I2PIRCName.key(conversationID)
        mutes.setMuted(false, for: key, on: serverID)
        snoozes.snooze(key, for: duration, on: serverID)
    }

    /// Turns the bell back on: ends the conversation's snooze early — the third
    /// way out of it, beside its time running out and its being cleared — and the
    /// plain mute it may carry with it.
    func turnNotificationsBackOn(_ conversationID: String) {
        guard let serverID = connectedServerID else { return }
        let key = I2PIRCName.key(conversationID)
        snoozes.clearSnooze(key, on: serverID)
        mutes.setMuted(false, for: key, on: serverID)
    }

    /// Re-reads the connected server's mutes and puts them with its snoozes on
    /// the live state, which silences what has just been silenced and lets a
    /// conversation whose snooze ran out count again.
    private func resyncMutes() {
        guard let serverID = connectedServerID else {
            mutedConversationIDs = []
            applySilence()
            return
        }
        mutedConversationIDs = mutes.conversations(for: serverID)
        applySilence()
    }

    /// Re-reads the connected server's snoozes the same way, so a timed one lifts
    /// the moment its time is up.
    private func resyncSnoozes() {
        guard let serverID = connectedServerID else {
            snoozedConversationIDs = []
            applySilence()
            return
        }
        snoozedConversationIDs = snoozes.snoozedKeys(for: serverID)
        applySilence()
    }

    /// Hands the chat state every conversation that adds no badge — the muted
    /// ones and the snoozed ones together, since both wear the same silence.
    private func applySilence() {
        state.setMutedConversations(Array(mutedConversationIDs.union(snoozedConversationIDs)))
    }

    // MARK: Ignored nicks

    /// The ignored nicks in force right now: the server's record, minus our own
    /// nick. Our own nick can never be ignored — even if a nick change lands on
    /// a name the record already held.
    var ignoredNicksInForce: Set<String> {
        ignoredNicks.subtracting([I2PIRCIgnoreBook.normalized(state.nick)])
    }

    /// The nicks the connected server ignores, in the order the member list's
    /// ignored section shows them.
    var ignoredNickList: [String] {
        ignoredNicksInForce.sorted()
    }

    /// Whether our own nick may not be ignored — which is what leaves the member
    /// list's swipe off our own row.
    func canIgnore(_ nick: String) -> Bool {
        I2PIRCIgnoreRule.canIgnore(nick, ourNick: state.nick)
    }

    /// Ignores one nick on the connected server and keeps it for that server
    /// across launches. Their lines keep arriving and still count as unread;
    /// only the transcript folds them. Our own nick is refused. Returns whether
    /// the record changed.
    @discardableResult
    func ignore(_ nick: String) -> Bool {
        guard let serverID = connectedServerID else { return false }
        let name = I2PIRCName.stripNickPrefixes(
            nick.trimmingCharacters(in: .whitespacesAndNewlines))
        guard I2PIRCIgnoreRule.canIgnore(name, ourNick: state.nick) else { return false }
        let changed = ignores.setIgnored(true, name, on: serverID)
        ignoredNicks = ignores.nicks(for: serverID)
        return changed
    }

    /// Lets a nick speak again: its lines stop folding and stand on their own
    /// once more. The saved transcript was never touched.
    func stopIgnoring(_ nick: String) {
        guard let serverID = connectedServerID else { return }
        ignores.setIgnored(false, nick, on: serverID)
        ignoredNicks = ignores.nicks(for: serverID)
    }

    /// Re-reads the connected server's ignored nicks, so a change made in the
    /// member list reaches the transcript at once.
    private func resyncIgnores() {
        guard let serverID = connectedServerID else {
            ignoredNicks = []
            return
        }
        ignoredNicks = ignores.nicks(for: serverID)
    }

    // MARK: Folded ignored rows

    /// Whether one quiet row is open right now.
    func isIgnoredGroupExpanded(_ groupID: String) -> Bool {
        expandedIgnoredGroupIDs.contains(groupID)
    }

    /// Opens a quiet row, or folds it away again.
    func toggleIgnoredGroup(_ groupID: String) {
        guard !groupID.isEmpty else { return }
        if expandedIgnoredGroupIDs.contains(groupID) {
            expandedIgnoredGroupIDs.remove(groupID)
        } else {
            expandedIgnoredGroupIDs.insert(groupID)
        }
    }

    /// Folds every quiet row away — done when another conversation comes on
    /// screen, since the rows the user opened belonged to the one being left.
    private func resetIgnoredRows() {
        expandedIgnoredGroupIDs = []
    }

    // MARK: Highlighted lines

    /// The line a tap on the Highlighted lines sheet asked the chat to show.
    @Published private(set) var matchTarget: UUID?
    /// Bumped by every reveal, so tapping the same line twice brings it into
    /// view again.
    @Published private(set) var matchJumpCount = 0

    /// Opens the conversation a highlighted line came from and marks that line
    /// to be scrolled to: what a tap on a row of the Highlighted lines sheet
    /// does. A search filtering the transcript is cleared, since the line has
    /// to be on screen to be brought into view.
    func revealLine(_ messageID: UUID, in conversationID: String) {
        let key = I2PIRCName.key(conversationID)
        if key != selection, state.conversation(key) != nil {
            select(key)
        } else if isFilteringTranscript {
            clearSearch()
        }
        matchTarget = messageID
        matchJumpCount += 1
    }

    // MARK: Keywords

    /// Puts the words switched on now — none of them while the master switch's
    /// pause is running — on the transcript, which re-marks every line already
    /// there.
    private func applyKeywords() {
        state.setKeywords(keywords.enabledWords)
    }

    /// How many lines of the conversations on screen arrived today and hold
    /// `word` the way a keyword does — the read-out under each row of the
    /// Highlights sheet. It counts what the app holds, restored history too.
    func keywordMatchCount(for word: String, on day: Date = Date()) -> Int {
        I2PIRCKeywordRule.matchCount(of: word,
                                     in: state.orderedConversations,
                                     on: day)
    }

    /// The line under the header: what is happening, or why it stopped.
    var statusLine: String {
        switch phase {
        case .idle:
            return servers.entries.isEmpty
                ? "Add an I2P IRC server to start chatting."
                : "Pick a server to connect."
        case .connecting(let stage):
            return stage.summary
        case .connected:
            return "Signed on as \(state.nick) · \(state.serverName)"
        case .failed(_, let message):
            return message
        case .closed(let reason):
            return reason
        case .reconnecting(let attempt, let seconds):
            return I2PIRCReconnectPolicy.line(attempt: attempt, seconds: seconds)
        }
    }

    var canSend: Bool { phase.isLive && selectedConversation != nil }

    // MARK: Round-trip time

    /// The reading the live header carries next to the signed-on nick: "RTT
    /// 240 ms", or "RTT —" until the first probe's PONG lands. Nil outside a
    /// live session, where there is no stream to time.
    var latencyReading: String? {
        guard phase.isLive else { return nil }
        return latency.reading
    }

    /// Whether the reading is slow enough to be shown as a warning.
    var latencyIsSlow: Bool {
        phase.isLive && latency.isSlow
    }

    /// Whether the chat stays on screen: a live session, or an outage whose
    /// retry keeps the messages of the session that dropped where they were.
    var showsTranscript: Bool {
        phase.isLive || phase.isReconnecting || reconnectAttempt > 0
    }

    /// The line under the reconnect header: the countdown, or the stage the
    /// attempt in flight has reached.
    var reconnectLine: String {
        switch phase {
        case .reconnecting(let attempt, let seconds):
            return I2PIRCReconnectPolicy.line(attempt: attempt, seconds: seconds)
        case .connecting(let stage):
            return "Attempt \(reconnectAttempt) of \(I2PIRCReconnectPolicy.attemptLimit) · \(stage.summary)"
        default:
            return "Reconnecting…"
        }
    }

    // MARK: Channel list

    /// Asks the server for its channel list. The channel sheet's Refresh
    /// control calls this too, so a listing that came back stale is one tap
    /// from a fresh one.
    func requestChannelList() {
        guard phase.isLive else { return }
        channelList.beginLoading()
        send(["LIST"])
    }

    /// Requests the listing the first time the channel sheet opens, and after
    /// an attempt the server refused. A listing already on screen or in flight
    /// is left alone.
    func loadChannelListIfNeeded() {
        guard phase.isLive, channelList.needsRequest else { return }
        requestChannelList()
    }

    /// A refusal of the LIST command lands while the listing is waiting for
    /// its rows; it names the reason in the sheet's empty state.
    private func noteChannelListFailure(_ line: I2PIRCLine) {
        guard channelList.isLoading,
              let numeric = line.numeric,
              (400...599).contains(numeric) else { return }
        let reason = line.params.dropFirst().joined(separator: " ")
        channelList.fail(reason.isEmpty ? "The server refused the LIST command (error \(numeric))." : reason)
    }

    // MARK: Connect

    /// Connects to a server the user picked. A countdown left over from an
    /// earlier outage is dropped — this is a fresh start.
    func connect(_ entry: I2PIRCServerEntry) {
        cancelRetry()
        userClosed = false
        if let problem = entry.validationProblem {
            phase = .failed(stage: I2PIRCStage.address.rawValue, message: problem)
            state.noteSystem(problem, kind: .error)
            return
        }
        connectedServerID = entry.id
        // The chat picks up where this server left off: its saved transcript
        // goes into the fresh state before it is published, so the connect note
        // and everything after it follow the old lines.
        let previousSelection = selection
        var restored = I2PIRCChatState(serverName: entry.displayName, nick: entry.nick)
        // The words the user keeps go in before the saved lines, so a transcript
        // from an earlier session wears its keyword edges the moment it is back.
        restored.setKeywords(keywords.enabledWords)
        history.restore(into: &restored, for: entry.id)
        // The conversations the user silenced on this server — muted without a
        // time, or snoozed for one — come back with its transcript, so a quiet
        // channel stays quiet across launches.
        let muted = mutes.conversations(for: entry.id)
        let snoozed = snoozes.snoozedKeys(for: entry.id)
        restored.setMutedConversations(Array(muted.union(snoozed)))
        mutedConversationIDs = muted
        snoozedConversationIDs = snoozed
        // The nicks this server ignores come back with it, so their lines fold
        // into one quiet row from the first restored line on.
        ignoredNicks = ignores.nicks(for: entry.id)
        state = restored
        selection = I2PIRCChatState.serverBufferName
        // The composer follows the conversation on screen: the one left behind
        // keeps its draft, and the server buffer shows its own.
        swapDrafts(from: previousSelection, to: selection)
        resetMentionCursor()
        resetHighlightCursor()
        resetIgnoredRows()
        clearSearch()
        startSession(entry)
    }

    /// Reconnects to the server this client was last connected to.
    func reconnect() {
        if let entry = servers.entry(connectedServerID) {
            connect(entry)
        }
    }

    /// Runs one attempt at the server: the stream, the registration and the
    /// watchdogs. `keepingTranscript` is set by a retry, which must leave the
    /// messages of the session that dropped on screen.
    private func startSession(_ entry: I2PIRCServerEntry, keepingTranscript: Bool = false) {
        connectTask?.cancel()
        connectTask = nil
        registrationTask?.cancel()
        registrationTask = nil
        stopKeepAlive()
        connection?.abort()
        outbox.removeAll()
        pumping = false
        generation += 1
        userClosed = false
        // A fresh attempt starts with no round-trip reading: the number belonged
        // to the stream this one replaces.
        resetLatency()
        // The previous session's channel list says nothing about this one.
        channelList.reset()

        connectedServerID = entry.id
        if keepingTranscript {
            state.beginReconnection()
        }
        trail = [I2PIRCStage.address.completedSummary]
        phase = .connecting(.address)
        if keepingTranscript {
            state.noteSystem("Reconnecting to \(entry.displayName) — attempt \(reconnectAttempt) of \(I2PIRCReconnectPolicy.attemptLimit).")
        } else {
            state.noteSystem("Connecting to \(entry.displayName) at \(entry.address)…")
        }

        let connection = client.connection()
        self.connection = connection
        connection.onLine = { [weak self] line in
            Task { @MainActor in self?.receive(line) }
        }
        connection.onClosed = { [weak self] reason in
            Task { @MainActor in self?.handleClosed(reason) }
        }

        connectTask = Task { @MainActor [weak self] in
            guard let self else { return }
            do {
                try await connection.connect(host: entry.host, port: entry.port) { stage in
                    Task { @MainActor [weak self] in
                        guard let self, self.connectedServerID == entry.id else { return }
                        self.lastStage = stage
                        if case .connecting = self.phase {
                            self.phase = .connecting(stage)
                        }
                        self.trail.append(stage.summary)
                    }
                }
                guard self.connectedServerID == entry.id else {
                    connection.abort()
                    return
                }
                self.phase = .connecting(.register)
                self.trail.append(I2PIRCStage.connect.completedSummary)
                self.state.noteSystem("Stream open — registering as \(entry.nick).")
                self.sendRegistration(entry)
                self.startKeepAlive()
                self.startRegistrationTimeout(entry)
            } catch is CancellationError {
                connection.abort()
            } catch {
                self.fail(error)
            }
        }
    }

    /// Drops a server's saved transcript. When that server is the one connected,
    /// the live transcript goes with it, so the chat is empty at once and the
    /// next connect starts empty instead of saving the old lines again.
    func clearHistory(for serverID: UUID) {
        history.clear(serverID)
        guard connectedServerID == serverID else { return }
        state.clearHistory()
    }

    func disconnect() {
        let wasRegistered: Bool
        if case .connected = phase { wasRegistered = true } else { wasRegistered = false }
        userClosed = true
        cancelRetry()
        connectTask?.cancel()
        connectTask = nil
        registrationTask?.cancel()
        registrationTask = nil
        stopKeepAlive()
        outbox.removeAll()
        pumping = false
        generation += 1
        let connection = self.connection
        if wasRegistered {
            let expected = generation
            Task { @MainActor [weak self] in
                try? await connection?.send("QUIT :Leaving")
                try? await Task.sleep(for: .milliseconds(150))
                // A reconnect may have started while the QUIT slept: the FIN
                // belongs to the stream this call ended, never the new one.
                guard let self, self.generation == expected else { return }
                connection?.close()
            }
        } else {
            connection?.close()
        }
        phase = .idle
        connectedServerID = nil
        // The mutes and snoozes belong to the server that just went away; the
        // next connect reads that server's records back.
        mutedConversationIDs = []
        snoozedConversationIDs = []
        // The ignored nicks belong to it too, and so do the quiet rows opened
        // in its transcript.
        ignoredNicks = []
        resetIgnoredRows()
        channelList.reset()
        resetLatency()
        state.noteSystem("Disconnected.")
    }

    /// Ends a retry sequence the user no longer wants and leaves the failure
    /// card with the reason the session ended, so Reconnect stays one tap away.
    func cancelReconnect() {
        guard !phase.isLive else { return }
        let reason = outageReason ?? "The connection ended."
        cancelRetry()
        connectTask?.cancel()
        connectTask = nil
        registrationTask?.cancel()
        registrationTask = nil
        stopKeepAlive()
        outbox.removeAll()
        pumping = false
        generation += 1
        userClosed = true
        connection?.abort()
        phase = .closed(reason)
        channelList.reset()
        resetLatency()
        state.noteSystem("Reconnecting cancelled.", kind: .system)
    }

    /// The Cancel control of an attempt on screen: during a retry it ends the
    /// whole sequence, on a first connect it ends the session.
    func cancelAttempt() {
        if reconnectAttempt > 0 {
            cancelReconnect()
        } else {
            disconnect()
        }
    }

    /// Drops a countdown that is waiting or running.
    private func cancelRetry() {
        reconnectTask?.cancel()
        reconnectTask = nil
        reconnectAttempt = 0
        outageReason = nil
    }

    // MARK: Registration

    private func sendRegistration(_ entry: I2PIRCServerEntry) {
        var lines: [String] = []
        if !entry.password.isEmpty {
            lines.append("PASS \(entry.password)")
        }
        lines.append("NICK \(entry.nick)")
        lines.append("USER \(entry.nick) 0 * :\(entry.nick)")
        send(lines)
    }

    private func startRegistrationTimeout(_ entry: I2PIRCServerEntry) {
        registrationTask?.cancel()
        registrationTask = Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(Self.registrationTimeout))
            guard let self, !Task.isCancelled else { return }
            guard case .connecting = self.phase else { return }
            let message = "The stream is open but the server did not accept the nick \(entry.nick) within \(Int(Self.registrationTimeout))s — the nick may be taken, or the server may be holding the registration."
            self.attemptFailed(stage: .register, message: message)
        }
    }

    private func joinConfiguredChannels() {
        guard let entry = servers.entry(connectedServerID) else { return }
        for channel in entry.channels {
            join(channel)
        }
    }

    // MARK: Inbound

    private func receive(_ raw: String) {
        guard let line = I2PIRCLine.parse(raw) else { return }
        lastInbound = Date()
        if line.command == "PING" {
            send(["PONG :\(line.params.last ?? "")"])
            return
        }
        if line.command == "PONG" {
            // A PONG that carries one of our probe tokens is a latency sample,
            // never a line of chat: the answer to the plain keep-alive measures
            // nothing and is left alone.
            latency.fulfill(params: line.params, at: Date())
            return
        }

        // The channel list's numerics build the listing, never a chat line.
        if I2PIRCChannelList.handles(line) {
            channelList.apply(line)
            return
        }

        let wasRegistered = state.registered
        state.apply(line)
        noteChannelListFailure(line)
        if !wasRegistered, state.registered {
            registrationTask?.cancel()
            registrationTask = nil
            lastStage = .ready
            phase = .connected
            // A fresh session is healthy again: the next outage starts its
            // backoff at the first retry.
            cancelRetry()
            trail.append(I2PIRCStage.register.completedSummary)
            joinConfiguredChannels()
        }
    }

    /// The stream ended without the user asking.
    private func handleClosed(_ reason: String) {
        endedUnexpectedly(reason)
    }

    /// One attempt failed, at a named stage. During a retry sequence the next
    /// attempt is armed instead of handing the failure to the user.
    private func attemptFailed(stage: I2PIRCStage, message: String) {
        stopKeepAlive()
        registrationTask?.cancel()
        registrationTask = nil
        connection?.abort()
        state.noteSystem("\(stage.rawValue): \(message)", kind: .error)
        // A countdown already armed owns the next attempt: the failure that
        // ended the current one must not consume another attempt of the budget.
        if reconnectAttempt > 0, !phase.isReconnecting, servers.entry(connectedServerID) != nil {
            scheduleRetry(reason: message)
            return
        }
        phase = .failed(stage: stage.rawValue, message: message)
    }

    private func fail(_ error: Error) {
        if let failure = error as? I2PIRCFailure {
            attemptFailed(stage: failure.stage, message: failure.message)
        } else {
            attemptFailed(stage: .connect, message: String(describing: error))
        }
    }

    // MARK: Outbound

    /// Queues lines in order. One pump drains the queue, so registration lines
    /// (PASS, NICK, USER) reach the server in the order they were queued.
    private func send(_ lines: [String]) {
        guard !lines.isEmpty, let connection else { return }
        outbox.append(contentsOf: lines)
        guard !pumping else { return }
        pumping = true
        let generation = self.generation
        Task { @MainActor [weak self] in
            guard let self else { return }
            while self.generation == generation, !self.outbox.isEmpty {
                let line = self.outbox.removeFirst()
                do {
                    try await connection.send(line)
                } catch {
                    if self.generation == generation {
                        self.pumping = false
                        self.handleSendFailure(error)
                    }
                    return
                }
            }
            if self.generation == generation {
                self.pumping = false
            }
        }
    }

    private func handleSendFailure(_ error: Error) {
        guard !userClosed else { return }
        endedUnexpectedly("The stream to the server broke: \(String(describing: error))")
    }

    // MARK: Sending chat

    func select(_ conversationID: String) {
        let previous = selection
        selection = I2PIRCName.key(conversationID)
        state.markRead(selection)
        if previous != selection {
            // Leaving a conversation is what marks its mentions and its keyword
            // lines read: their violet edges and the chip's counts go. They are
            // kept while it is on screen, so the marked lines can be stepped
            // through before they are read.
            state.markMentionsRead(previous)
            state.markKeywordsRead(previous)
            // A search belongs to the conversation it was typed in, so the next
            // conversation starts with its whole transcript on screen.
            clearSearch()
        }
        // Every conversation has its own draft: the field keeps what was typed
        // in the one being left and shows the one arriving.
        swapDrafts(from: previous, to: selection)
        resetMentionCursor()
        resetHighlightCursor()
        // A quiet row the user opened belonged to the conversation just left.
        if previous != selection {
            resetIgnoredRows()
        }
    }

    // MARK: Drafts

    /// Puts the draft of the conversation coming on screen in the field. The
    /// conversation being left keeps exactly what was typed — the field's every
    /// edit is recorded against it — so only what is shown changes.
    private func swapDrafts(from previous: String, to current: String) {
        let incoming = drafts.switchDraft(from: previous, holding: draftText, to: current)
        guard incoming != draftText else { return }
        // A programmatic change of the field must not land on the conversation
        // arriving as an edit of it.
        isSwappingDraft = true
        draftText = incoming
        isSwappingDraft = false
    }

    func sendDraft() {
        let text = draftText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }
        // Sending clears the draft of the conversation it is sent from, and no
        // other one.
        draftText = ""
        if text.hasPrefix("/") {
            runCommand(text)
        } else {
            sendMessage(text, to: selection)
        }
    }

    func sendMessage(_ text: String, to targetID: String) {
        guard phase.isLive else {
            state.noteSystem("Not connected — connect to a server first.", kind: .error)
            return
        }
        let conversationID = state.openConversation(targetID)
        guard let conversation = state.conversation(conversationID) else { return }
        let target = conversation.name
        let pieces = I2PIRCText.split(text)
        guard !pieces.isEmpty else { return }
        for piece in pieces {
            state.noteOutgoing(piece, to: target)
            send(["PRIVMSG \(target) :\(piece)"])
        }
        state.markRead(conversationID)
    }

    func join(_ raw: String) {
        guard let channel = I2PIRCName.channel(raw) else {
            state.noteSystem("Name a channel first — for example #i2p.", kind: .error)
            return
        }
        guard phase.isLive else {
            state.noteSystem("Connect to a server before joining a channel.", kind: .error)
            return
        }
        state.requestJoin(channel)
        send(["JOIN \(channel)"])
        select(channel)
    }

    /// Opens the private query with a nick picked from a channel's member list
    /// and makes it the conversation on screen. Returns false when the tap was
    /// on our own nick, where there is nothing to open.
    @discardableResult
    func openQuery(with nick: String) -> Bool {
        let name = I2PIRCName.stripNickPrefixes(nick)
        guard !name.isEmpty,
              I2PIRCName.key(name) != I2PIRCName.key(state.nick) else { return false }
        let conversationID = state.openConversation(name)
        select(conversationID)
        return true
    }

    func part(_ channel: String? = nil, reason: String? = nil) {
        guard phase.isLive else { return }
        let name: String?
        if let channel, !channel.isEmpty {
            name = I2PIRCText.sanitize(channel)
        } else if let selected = selectedConversation, selected.kind == .channel {
            name = selected.name
        } else {
            name = nil
        }
        guard let name else {
            state.noteSystem("Open a channel to part from.", kind: .error)
            return
        }
        let suffix = reason.map { " :\(I2PIRCText.sanitize($0))" } ?? ""
        send(["PART \(name)\(suffix)"])
    }

    // MARK: Commands

    private func runCommand(_ text: String) {
        let body = String(text.dropFirst())
        let parts = body.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
        guard let raw = parts.first else {
            noteHelp()
            return
        }
        let command = raw.lowercased()
        let rest = parts.count > 1 ? String(parts[1]) : ""
        switch command {
        case "join", "j":
            join(rest)
        case "part", "leave":
            part(rest.isEmpty ? nil : rest)
        case "me":
            performAction(rest)
        case "msg", "query":
            messageCommand(rest)
        case "nick":
            let newNick = I2PIRCText.sanitize(rest)
            guard !newNick.isEmpty, !newNick.contains(" ") else {
                state.noteSystem("Use /nick <name>.", kind: .error)
                return
            }
            send(["NICK \(newNick)"])
        case "topic":
            guard let selected = selectedConversation, selected.kind == .channel else {
                state.noteSystem("Open a channel to set its topic.", kind: .error)
                return
            }
            send(["TOPIC \(selected.name) :\(I2PIRCText.sanitize(rest))"])
        case "quit", "exit":
            disconnect()
        case "raw":
            guard !rest.isEmpty else {
                state.noteSystem("Use /raw <line> to send a command verbatim.", kind: .error)
                return
            }
            send([rest])
        case "help":
            noteHelp()
        default:
            state.noteSystem("Unknown command /\(command) — try /help.", kind: .error)
        }
    }

    private func performAction(_ body: String) {
        guard phase.isLive, let selected = selectedConversation else {
            state.noteSystem("Not connected — connect to a server first.", kind: .error)
            return
        }
        let text = I2PIRCText.sanitize(body)
        guard !text.isEmpty else { return }
        let target = selected.name
        for piece in I2PIRCText.split(text) {
            let encoded = I2PIRCText.action(piece)
            state.noteOutgoing(encoded, to: target)
            send(["PRIVMSG \(target) :\(encoded)"])
        }
    }

    private func messageCommand(_ rest: String) {
        let pieces = rest.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
        guard pieces.count == 2 else {
            state.noteSystem("Use /msg <nick> <message>.", kind: .error)
            return
        }
        let target = String(pieces[0])
        let body = String(pieces[1])
        let conversationID = state.openConversation(target)
        sendMessage(body, to: conversationID)
        select(conversationID)
    }

    private func noteHelp() {
        state.noteSystem("Commands: /join <channel> · /part [channel] · /me <action> · /msg <nick> <text> · /nick <name> · /topic <text> · /raw <line> · /quit · /help")
    }

    // MARK: Keep-alive

    private func startKeepAlive() {
        stopKeepAlive()
        lastInbound = Date()
        // The first probe goes out a minute into the session, so the header
        // reads "RTT —" until its PONG lands.
        lastProbeAt = Date()
        keepAliveTask = Task { @MainActor [weak self] in
            while let self, !Task.isCancelled {
                try? await Task.sleep(for: .seconds(30))
                guard !Task.isCancelled else { break }
                self.keepAliveTick()
            }
        }
    }

    private func stopKeepAlive() {
        keepAliveTask?.cancel()
        keepAliveTask = nil
    }

    private func keepAliveTick() {
        guard phase.isLive else { return }
        let idle = Date().timeIntervalSince(lastInbound)
        if idle > Self.deadAfter {
            endedUnexpectedly("The server has been silent for \(Int(idle))s — the stream is dead.")
            return
        }
        if idle > Self.pingAfter {
            send(["PING :\(state.serverName)"])
        }
        probeLatencyIfDue()
    }

    // MARK: Round-trip probes

    /// Sends one PING a minute carrying a fresh token, and times the PONG that
    /// echoes it. The probe is queued on the same outbox the chat uses, so it
    /// sits behind whatever the user is sending and never delays or reorders a
    /// message.
    private func probeLatencyIfDue() {
        let now = Date()
        guard now.timeIntervalSince(lastProbeAt) >= I2PIRCLatency.probeInterval else { return }
        lastProbeAt = now
        let token = I2PIRCLatency.token(at: now, nonce: String(UUID().uuidString.prefix(8)))
        latency.beginProbe(token: token, at: now)
        send(["PING \(token)"])
    }

    /// Drops the reading and the probe in flight, which is what a connect, a
    /// disconnect and every reconnect attempt do.
    private func resetLatency() {
        latency.clear()
        lastProbeAt = Date.distantPast
    }

    // MARK: Reconnect

    /// The stream ended on its own — the server closed it, a send failed or the
    /// keep-alive declared it dead. Show what happened, keep the transcript up
    /// and arm the first retry rather than leaving the user to tap Reconnect.
    private func endedUnexpectedly(_ reason: String) {
        guard !userClosed else { return }
        // A countdown already owns the retry: a late callback from the stream
        // it is replacing must never restart the sequence.
        if phase.isReconnecting { return }
        // The listing belonged to the session that just ended, and so did the
        // round-trip reading.
        channelList.reset()
        resetLatency()
        outageReason = reason
        state.noteSystem(reason, kind: .error)
        stopKeepAlive()
        registrationTask?.cancel()
        registrationTask = nil
        connectTask?.cancel()
        connectTask = nil
        connection?.abort()
        guard servers.entry(connectedServerID) != nil else {
            // Nothing saved to dial again: the card the client showed before
            // this retry behaviour is what the user is left with.
            cancelRetry()
            phase = .closed(reason)
            return
        }
        scheduleRetry(reason: reason)
    }

    /// Arms the next retry. `reconnectAttempt` counts from one within a single
    /// outage, and a failed attempt arms the next one until the budget is spent.
    private func scheduleRetry(reason: String) {
        reconnectTask?.cancel()
        reconnectTask = nil
        let attempt = reconnectAttempt + 1
        guard let delay = I2PIRCReconnectPolicy.delay(forAttempt: attempt),
              let entry = servers.entry(connectedServerID) else {
            giveUp(reason: reason)
            return
        }
        reconnectAttempt = attempt
        // Set the waiting phase before anything can report another failure, so
        // a second callback for the same outage cannot arm a second countdown.
        phase = .reconnecting(attempt: attempt, seconds: Int(delay))
        state.noteSystem("Retrying in \(Int(delay))s (attempt \(attempt) of \(I2PIRCReconnectPolicy.attemptLimit)).")

        reconnectTask = Task { @MainActor [weak self] in
            for remaining in stride(from: Int(delay), through: 1, by: -1) {
                guard let self, !Task.isCancelled else { return }
                self.phase = .reconnecting(attempt: attempt, seconds: remaining)
                try? await Task.sleep(for: .seconds(1))
            }
            guard let self, !Task.isCancelled, !self.userClosed,
                  self.connectedServerID == entry.id else { return }
            self.reconnectTask = nil
            self.startSession(entry, keepingTranscript: true)
        }
    }

    /// Four attempts failed: stop, and leave the reason the last one gave in the
    /// failure card.
    private func giveUp(reason: String) {
        reconnectTask?.cancel()
        reconnectTask = nil
        let attempts = reconnectAttempt
        reconnectAttempt = 0
        if attempts > 0 {
            state.noteSystem("Reconnecting stopped after \(attempts) failed attempt\(attempts == 1 ? "" : "s").",
                             kind: .error)
        }
        channelList.reset()
        phase = .closed(reason)
    }
}
