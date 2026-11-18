//
//  IRCView.swift
//  The IRC client screen: the connection's state and stage trail, the servers
//  the user keeps, the conversations of the live connection (server buffer,
//  channels and queries) and the composer that sends to whichever is open.
//

import SwiftUI

// MARK: - Screen

struct IRCView: View {
    @StateObject private var model: I2PIRCChatModel
    @ObservedObject private var servers: I2PIRCServerBook
    /// The words the user wants to be told about, which the Highlights sheet
    /// below edits and the transcript marks.
    @ObservedObject private var keywords: I2PIRCKeywordBook
    @State private var showServers = false
    @State private var showJoin = false
    @State private var showChannels = false
    @State private var showMembers = false
    @State private var showHighlights = false
    @State private var showSearchAll = false
    @State private var membersChannelID = ""
    @FocusState private var inputFocused: Bool
    @FocusState private var searchFocused: Bool
    /// What was copied to the clipboard, shown above the composer for a moment
    /// so the user sees which copy landed and what it holds.
    @State private var copiedNotice: I2PIRCLineCopyNotice?
    @State private var copyResetTask: Task<Void, Never>?
    /// IRC rides this router's tunnels, so a connection has no path at all
    /// while the router is off. Read on a slow beat so starting it on the
    /// Router tab clears the hint without a relaunch.
    @State private var routerRunning = I2PRouterAppContext.shared.lifecycleState == .running

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)
    private let okGreen = Color(red: 0.29, green: 0.87, blue: 0.50)
    private let warnOrange = Color(red: 0.98, green: 0.62, blue: 0.24)
    /// The tint a line that names us wears, distinct from the chip's unread
    /// badge so a mention never reads as one more unread line.
    static let mentionViolet = Color(red: 0.68, green: 0.45, blue: 1.00)
    /// The tint a line holding one of the user's keywords wears: in the violet
    /// family the screen is drawn in, and a shade cooler than a mention's so the
    /// two marks never read as the same thing. The emphasis inside the line
    /// wears the same blue.
    static let keywordBlue = I2PIRCKeywordEmphasis.tint

    /// A distinct violet-family tint per nick, so a conversation reads as
    /// people rather than one voice.
    private static let nickTints: [Color] = [
        Color(red: 0.64, green: 0.50, blue: 1.00),
        Color(red: 0.40, green: 0.66, blue: 0.99),
        Color(red: 0.78, green: 0.48, blue: 0.97),
        Color(red: 0.52, green: 0.44, blue: 0.92),
        Color(red: 0.90, green: 0.58, blue: 0.98),
        Color(red: 0.58, green: 0.80, blue: 0.96)
    ]

    init(model: I2PIRCChatModel = I2PIRCChatModel(client: I2PRouterAppContext.shared.ircClient),
         servers: I2PIRCServerBook = .shared,
         keywords: I2PIRCKeywordBook = .shared) {
        _model = StateObject(wrappedValue: model)
        _servers = ObservedObject(wrappedValue: servers)
        _keywords = ObservedObject(wrappedValue: keywords)
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                connectionHeader
                if model.showsTranscript {
                    conversationStrip
                    chatBody
                    if let notice = copiedNotice {
                        copyConfirmation(notice)
                    }
                    if model.phase.isLive {
                        composer
                    }
                } else {
                    idleBody
                }
            }
            .background(background.ignoresSafeArea())
            .navigationTitle("IRC")
            .navigationBarTitleDisplayMode(.large)
            .toolbar { toolbarContent }
            .sheet(isPresented: $showServers) {
                NavigationStack {
                    IRCServersView(book: servers,
                                   onConnect: { entry in model.connect(entry) },
                                   onClearHistory: { serverID in model.clearHistory(for: serverID) })
                }
            }
            .sheet(isPresented: $showJoin) {
                IRCJoinView { channel in
                    model.join(channel)
                }
            }
            .sheet(isPresented: $showMembers) {
                IRCMembersView(model: model, channelID: membersChannelID)
            }
            .sheet(isPresented: $showChannels) {
                IRCChannelsView(model: model)
            }
            .sheet(isPresented: $showHighlights) {
                HighlightsView(model: model, book: keywords) { match in
                    model.revealLine(match.messageID, in: match.conversationID)
                }
            }
            .sheet(isPresented: $showSearchAll) {
                SearchAllView(model: model) { match in
                    model.revealLine(match.messageID, in: match.conversationID)
                }
            }
        }
        .preferredColorScheme(.dark)
    }

    // MARK: - Toolbar

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        ToolbarItem(placement: .topBarTrailing) {
            Button {
                inputFocused = false
                showHighlights = true
            } label: {
                Image(systemName: "key")
            }
            .accessibilityLabel("Highlights")
            .accessibilityHint("The words that mark a line you want to be told about")
        }
        ToolbarItem(placement: .topBarTrailing) {
            Button {
                showServers = true
            } label: {
                Image(systemName: "server.rack")
            }
            .accessibilityLabel("IRC servers")
        }
        if model.showsTranscript {
            ToolbarItem(placement: .topBarTrailing) {
                shareControl
            }
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    toggleSearch()
                } label: {
                    Image(systemName: model.isSearching
                          ? "magnifyingglass.circle.fill"
                          : "magnifyingglass")
                }
                .accessibilityLabel(model.isSearching
                                    ? "Close the search"
                                    : "Search this conversation")
            }
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    inputFocused = false
                    showSearchAll = true
                } label: {
                    Image(systemName: "doc.text.magnifyingglass")
                }
                .accessibilityLabel("Search every conversation")
                .accessibilityHint("Looks through every conversation of the connected server at once")
            }
        }
        if model.phase.isLive {
            ToolbarItemGroup(placement: .topBarLeading) {
                Button {
                    showJoin = true
                } label: {
                    Image(systemName: "plus.bubble")
                }
                .accessibilityLabel("Join a channel")
                Button {
                    showChannels = true
                } label: {
                    Image(systemName: "list.bullet.rectangle")
                }
                .accessibilityLabel("Browse the server's channels")
            }
        }
    }

    // MARK: - Share

    /// The chat header's share control: the system share sheet with the open
    /// conversation's name as its subject and its lines as the body. It names
    /// the conversation it will share, and stays dimmed while it holds no line.
    @ViewBuilder
    private var shareControl: some View {
        if let payload = model.sharePayload {
            ShareLink(item: payload.body,
                      subject: Text(payload.subject)) {
                Image(systemName: "square.and.arrow.up")
            }
            .accessibilityLabel("Share \(payload.name)")
            .accessibilityHint("Shares this conversation's transcript")
        } else {
            Button {
            } label: {
                Image(systemName: "square.and.arrow.up")
                    .foregroundStyle(Color.secondary)
                    .opacity(0.45)
            }
            .disabled(true)
            .accessibilityLabel("Share")
            .accessibilityHint("This conversation has no lines to share yet")
        }
    }

    // MARK: - Connection header

    @ViewBuilder
    private var connectionHeader: some View {
        switch model.phase {
        case .connected:
            liveHeader
        case .reconnecting:
            reconnectingHeader
        case .connecting(let stage):
            connectingCard(stage)
        case .failed(let stage, let message):
            problemCard(title: "Connection failed · \(stage)", message: message)
        case .closed(let reason):
            problemCard(title: "Disconnected", message: reason)
        case .idle:
            EmptyView()
        }
    }

    /// The header a dropped stream shows while the client waits out a backoff:
    /// the countdown, which attempt it is and a way to stop waiting.
    private var reconnectingHeader: some View {
        HStack(spacing: 10) {
            Image(systemName: "arrow.triangle.2.circlepath")
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(warnOrange)
                .frame(width: 34, height: 34)
                .background(warnOrange.opacity(0.16), in: RoundedRectangle(cornerRadius: 10))
            VStack(alignment: .leading, spacing: 2) {
                Text("Reconnecting to \(model.state.serverName)")
                    .font(.footnote.weight(.semibold))
                    .lineLimit(1)
                Text(model.reconnectLine)
                    .font(.caption2)
                    .foregroundStyle(warnOrange.opacity(0.92))
                    .lineLimit(1)
            }
            Spacer(minLength: 4)
            Button {
                inputFocused = false
                model.cancelReconnect()
            } label: {
                Text("Cancel")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.primary)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 7)
                    .background(Color.white.opacity(0.10), in: Capsule())
            }
            .buttonStyle(.plain)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .background(warnOrange.opacity(0.08))
    }

    private var liveHeader: some View {
        HStack(spacing: 10) {
            Circle()
                .fill(okGreen)
                .frame(width: 8, height: 8)
            VStack(alignment: .leading, spacing: 2) {
                Text(model.state.serverName)
                    .font(.subheadline.weight(.semibold))
                    .lineLimit(1)
                liveStatusLine
            }
            Spacer(minLength: 6)
            Button {
                inputFocused = false
                model.disconnect()
            } label: {
                Text("Disconnect")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.primary)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 7)
                    .background(Color.white.opacity(0.10), in: Capsule())
            }
            .buttonStyle(.plain)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .background(Color.white.opacity(0.04))
    }

    /// The status line, with the stream's round-trip reading next to the
    /// signed-on nick. The reading alone turns amber when the stream is slow,
    /// and reads "RTT —" until the first measurement lands.
    private var liveStatusLine: some View {
        HStack(spacing: 0) {
            Text(model.statusLine)
                .lineLimit(1)
            if let reading = model.latencyReading {
                Text(" · \(reading)")
                    .foregroundStyle(model.latencyIsSlow ? warnOrange : Color.secondary)
                    .fixedSize()
            }
        }
        .font(.caption2)
        .foregroundStyle(.secondary)
    }

    private func connectingCard(_ stage: I2PIRCStage) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Image(systemName: "antenna.radiowaves.left.and.right")
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(accent)
                    .frame(width: 34, height: 34)
                    .background(accent.opacity(0.16), in: RoundedRectangle(cornerRadius: 10))
                VStack(alignment: .leading, spacing: 2) {
                    Text(model.reconnectAttempt > 0
                         ? "Reconnecting to \(model.state.serverName)"
                         : "Connecting to \(model.state.serverName)")
                        .font(.footnote.weight(.semibold))
                        .lineLimit(1)
                    Text(model.reconnectAttempt > 0 ? model.reconnectLine : stage.summary)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 4)
                Button {
                    model.cancelAttempt()
                } label: {
                    Text("Cancel")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 6)
                        .background(Color.white.opacity(0.08), in: Capsule())
                }
                .buttonStyle(.plain)
            }
            ProgressView()
                .progressViewStyle(.linear)
                .tint(accent)
            if !model.trail.isEmpty {
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(Array(model.trail.suffix(4).enumerated()), id: \.offset) { _, line in
                        Text(line)
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                            .lineLimit(1)
                    }
                }
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
        .padding(.horizontal, 16)
        .padding(.top, 8)
    }

    private func problemCard(title: String, message: String) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(warnOrange)
                Text(title)
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(warnOrange)
                Spacer()
            }
            Text(message)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 8) {
                if servers.entry(model.connectedServerID) != nil {
                    Button {
                        model.reconnect()
                    } label: {
                        Text("Reconnect")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(Color.white)
                            .padding(.horizontal, 14)
                            .padding(.vertical, 8)
                            .background(accent.opacity(0.80), in: Capsule())
                    }
                    .buttonStyle(.plain)
                }
                Button {
                    showServers = true
                } label: {
                    Text("Choose a server")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.primary)
                        .padding(.horizontal, 14)
                        .padding(.vertical, 8)
                        .background(Color.white.opacity(0.10), in: Capsule())
                }
                .buttonStyle(.plain)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
        .background(warnOrange.opacity(0.10), in: RoundedRectangle(cornerRadius: 18))
        .padding(.horizontal, 16)
        .padding(.top, 8)
    }

    // MARK: - Idle body

    private var idleBody: some View {
        ScrollView {
            VStack(spacing: 14) {
                if !routerRunning {
                    routerOffHint
                }
                introCard
                serversCard
                footnote
            }
            .padding(.horizontal, 16)
            .padding(.top, 8)
            .padding(.bottom, 24)
        }
        .task { await watchRouterState() }
    }

    private func watchRouterState() async {
        while !Task.isCancelled {
            routerRunning = I2PRouterAppContext.shared.lifecycleState == .running
            try? await Task.sleep(for: .seconds(2))
        }
    }

    /// A first-run dependency that is easy to miss: IRC connects through this
    /// router's tunnels, so with the router off nothing can reach the network.
    private var routerOffHint: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "power")
                .font(.footnote.weight(.semibold))
                .foregroundStyle(warnOrange)
                .frame(width: 30, height: 30)
                .background(warnOrange.opacity(0.14), in: RoundedRectangle(cornerRadius: 9))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text("The router is off")
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(warnOrange)
                Text("IRC connects through this router's tunnels. Start it on the Router tab so a connection has a path onto the network.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(14)
        .background(warnOrange.opacity(0.10), in: RoundedRectangle(cornerRadius: 16))
        .accessibilityElement(children: .combine)
    }

    private var introCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Image(systemName: "bubble.left.and.bubble.right.fill")
                    .font(.system(size: 18, weight: .medium))
                    .foregroundStyle(accent)
                    .frame(width: 44, height: 44)
                    .background(accent.opacity(0.16), in: RoundedRectangle(cornerRadius: 12))
                VStack(alignment: .leading, spacing: 3) {
                    Text("IRC over I2P")
                        .font(.subheadline.weight(.semibold))
                    Text("Chat with the networks that live inside I2P")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Text("An IRC server in I2P is addressed like an eepsite — a .i2p name, a b32 host, a b33 address or a base64 destination — on a port, usually 6667. The connection runs through this router's own tunnels, so nothing about it leaves the network.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    private var serversCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Servers")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .textCase(.uppercase)
                Spacer()
                if !servers.entries.isEmpty {
                    Text("\(servers.entries.count)")
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(accent)
                }
            }

            if servers.entries.isEmpty {
                Text("No servers saved yet. Add one with the server list in the toolbar — a .i2p host and the nick you want on it.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                ForEach(servers.entries) { entry in
                    Button {
                        model.connect(entry)
                    } label: {
                        serverRow(entry)
                    }
                    .buttonStyle(.plain)
                }
            }

            Button {
                showServers = true
            } label: {
                Label("Add or manage servers", systemImage: "plus.circle")
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(accent)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 10)
                    .background(accent.opacity(0.14), in: RoundedRectangle(cornerRadius: 12))
            }
            .buttonStyle(.plain)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    private func serverRow(_ entry: I2PIRCServerEntry) -> some View {
        HStack(spacing: 12) {
            Image(systemName: "server.rack")
                .font(.system(size: 15, weight: .medium))
                .foregroundStyle(accent)
                .frame(width: 38, height: 38)
                .background(accent.opacity(0.14), in: RoundedRectangle(cornerRadius: 10))
            VStack(alignment: .leading, spacing: 3) {
                Text(entry.displayName)
                    .font(.subheadline.weight(.medium))
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                Text("\(entry.address) · \(entry.nick)")
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Spacer(minLength: 4)
            Image(systemName: "chevron.right")
                .font(.caption2.weight(.semibold))
                .foregroundStyle(.tertiary)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.white.opacity(0.05), in: RoundedRectangle(cornerRadius: 14))
        .contentShape(RoundedRectangle(cornerRadius: 14))
    }

    private var footnote: some View {
        Text("Your nick, the channels you join and everything said in them stay in this app. The router's identity is the same one the Router tab shows.")
            .font(.caption2)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
    }

    // MARK: - Conversations

    private var conversationStrip: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                ForEach(model.state.orderedConversations) { conversation in
                    conversationChip(conversation)
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 9)
        }
        .background(Color.white.opacity(0.03))
    }

    private func conversationChip(_ conversation: I2PIRCConversation) -> some View {
        let selected = model.selection == conversation.id
        return Button {
            model.select(conversation.id)
        } label: {
            HStack(spacing: 5) {
                Image(systemName: icon(for: conversation))
                    .font(.system(size: 9, weight: .bold))
                Text(chipTitle(conversation))
                    .font(.caption.weight(.semibold))
                    .lineLimit(1)
                if model.isSilenced(conversation.id) {
                    // A silenced conversation wears a small slashed bell in
                    // place of its unread, mention and keyword badges.
                    Image(systemName: "bell.slash.fill")
                        .font(.system(size: 8, weight: .bold))
                        .foregroundStyle(selected ? Color.white.opacity(0.85) : Color.secondary)
                } else {
                    if conversation.unread > 0 {
                        Text("\(min(conversation.unread, 99))")
                            .font(.system(size: 9, weight: .bold, design: .rounded))
                            .foregroundStyle(Color.white)
                            .padding(.horizontal, 5)
                            .padding(.vertical, 1)
                            .background(accent, in: Capsule())
                    }
                    if conversation.mentionCount > 0 {
                        HStack(spacing: 2) {
                            Image(systemName: "bell.fill")
                                .font(.system(size: 7, weight: .bold))
                            Text("\(min(conversation.mentionCount, 99))")
                                .font(.system(size: 9, weight: .bold, design: .rounded))
                        }
                        .foregroundStyle(Color.white)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 1)
                        .background(Self.mentionViolet, in: Capsule())
                    }
                    if conversation.keywordCount > 0 {
                        HStack(spacing: 2) {
                            Image(systemName: "key.fill")
                                .font(.system(size: 7, weight: .bold))
                            Text("\(min(conversation.keywordCount, 99))")
                                .font(.system(size: 9, weight: .bold, design: .rounded))
                        }
                        .foregroundStyle(Color.white)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 1)
                        .background(Self.keywordBlue, in: Capsule())
                    }
                }
            }
            .foregroundStyle(selected ? Color.white : Color.secondary)
            .padding(.horizontal, 12)
            .padding(.vertical, 7)
            .background(selected ? accent.opacity(0.30) : Color.white.opacity(0.06), in: Capsule())
            .overlay(
                Capsule().strokeBorder(selected ? accent.opacity(0.65) : Color.clear, lineWidth: 1)
            )
        }
        .buttonStyle(.plain)
        .accessibilityLabel(conversationLabel(conversation))
    }

    /// What a chip says to VoiceOver: the conversation, how much of a snooze is
    /// left in it, and how many lines in it name us and hold one of the user's
    /// words.
    private func conversationLabel(_ conversation: I2PIRCConversation) -> String {
        var parts = [chipTitle(conversation)]
        if model.isSilenced(conversation.id) {
            parts.append(model.bellSummary(conversation.id))
        }
        if conversation.mentionCount > 0 {
            parts.append("\(conversation.mentionCount) mention\(conversation.mentionCount == 1 ? "" : "s")")
        }
        if conversation.keywordCount > 0 {
            parts.append("\(conversation.keywordCount) keyword line\(conversation.keywordCount == 1 ? "" : "s")")
        }
        return parts.joined(separator: ", ")
    }

    private func icon(for conversation: I2PIRCConversation) -> String {
        switch conversation.kind {
        case .server: return "list.bullet"
        case .channel: return "number"
        case .query: return "person.fill"
        }
    }

    /// The conversation's own name, without the snooze's time left.
    private func baseTitle(_ conversation: I2PIRCConversation) -> String {
        conversation.kind == .server ? "Server" : conversation.name
    }

    /// What the chip reads: the conversation, and — while it is snoozed for a
    /// stretch of time — the time left in it ("#i2p · 42m").
    private func chipTitle(_ conversation: I2PIRCConversation) -> String {
        guard let remaining = model.snoozeRemaining(conversation.id) else {
            return baseTitle(conversation)
        }
        return "\(baseTitle(conversation)) · \(remaining)"
    }

    private var chatBody: some View {
        VStack(spacing: 0) {
            if model.isSearching {
                searchBar
            } else {
                markedLinesBar
            }
            conversationBar
            messagesScroll
        }
    }

    /// The row under the marked-lines bar: the channel's topic bar — which opens
    /// its member list — with the bell beside it. The server buffer and the
    /// queries have no topic bar, so the bell sits alone at the row's trailing
    /// edge.
    private var conversationBar: some View {
        HStack(spacing: 8) {
            if let conversation = model.selectedConversation, conversation.kind == .channel {
                topicBar(conversation, topic: conversation.topic)
                    .padding(.leading, 16)
            } else {
                Spacer(minLength: 0)
            }
            bellControl
                .padding(.trailing, 16)
        }
        .padding(.vertical, 4)
        .background(Color.white.opacity(0.03))
    }

    /// The chat header's bell: tapping it offers the same durations the highlights
    /// pause does — 15 minutes, 1 hour, until tomorrow — and a snooze that lasts
    /// until it is turned back on. While one is running the bell names the time
    /// left and turns it back on early. A snoozed conversation adds no unread
    /// badge, no mention count and no keyword count — its chip shows a slashed
    /// bell with the time left — while the marks on its lines stay where they are.
    @ViewBuilder
    private var bellControl: some View {
        if let conversation = model.selectedConversation {
            let silenced = model.isSilenced(conversation.id)
            let reading = model.bellSummary(conversation.id)
            let name = baseTitle(conversation)
            Menu {
                if silenced {
                    Button {
                        inputFocused = false
                        model.turnNotificationsBackOn(conversation.id)
                    } label: {
                        Label("Turn notifications back on", systemImage: "bell")
                    }
                    Divider()
                }
                ForEach(I2PIRCSnoozeDuration.allCases) { duration in
                    Button {
                        inputFocused = false
                        model.snooze(conversation.id, for: duration)
                    } label: {
                        Label(duration.label, systemImage: duration.icon)
                    }
                }
            } label: {
                HStack(spacing: 4) {
                    Image(systemName: silenced ? "bell.slash" : "bell")
                        .font(.system(size: 11, weight: .semibold))
                    Text(reading)
                        .font(.system(size: 11, weight: .semibold))
                        .lineLimit(1)
                    Image(systemName: "chevron.up.chevron.down")
                        .font(.system(size: 8, weight: .bold))
                        .foregroundStyle(silenced ? Color.primary.opacity(0.55)
                                                  : Color.secondary.opacity(0.75))
                }
                .foregroundStyle(silenced ? Color.primary : Color.secondary)
                .padding(.horizontal, 10)
                .padding(.vertical, 5)
                .background(silenced ? Color.white.opacity(0.12) : Color.white.opacity(0.06),
                            in: Capsule())
                .overlay(
                    Capsule().strokeBorder(silenced ? Self.mentionViolet.opacity(0.55) : Color.clear,
                                           lineWidth: 1)
                )
            }
            .accessibilityLabel(silenced ? "Notifications for \(name): \(reading)"
                                         : "Snooze notifications for \(name)")
            .accessibilityValue(reading)
            .accessibilityHint(silenced
                               ? "Turns them back on now"
                               : "Offers 15 minutes, 1 hour, until tomorrow, or until you turn it back on")
        }
    }

    /// Opens the search field above the transcript, or closes it and puts the
    /// whole transcript back.
    private func toggleSearch() {
        if model.isSearching {
            searchFocused = false
            model.clearSearch()
        } else {
            model.beginSearch()
        }
    }

    /// The search field: what is typed filters the open conversation's loaded
    /// lines as it goes, and the count under it says how many are left.
    private var searchBar: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                HStack(spacing: 6) {
                    Image(systemName: "magnifyingglass")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(accent.opacity(0.85))
                    TextField("Search this conversation", text: $model.searchText)
                        .font(.callout)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled(true)
                        .submitLabel(.search)
                        .focused($searchFocused)
                    if !model.searchText.isEmpty {
                        Button {
                            model.searchText = ""
                        } label: {
                            Image(systemName: "xmark.circle.fill")
                                .font(.system(size: 14))
                                .foregroundStyle(.secondary)
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel("Clear the search")
                    }
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 8)
                .background(Color.white.opacity(0.08), in: RoundedRectangle(cornerRadius: 12))
                Button {
                    searchFocused = false
                    model.clearSearch()
                } label: {
                    Text("Close")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(Color.white)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 8)
                        .background(accent.opacity(0.55), in: Capsule())
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Close the search")
            }
            Text(model.isFilteringTranscript
                 ? model.searchSummary
                 : "Type to search the nicks and lines of this conversation")
                .font(.caption2)
                .foregroundStyle(model.isFilteringTranscript ? accent : Color.secondary)
                .padding(.leading, 2)
                .accessibilityLabel(model.isFilteringTranscript
                                    ? model.searchSummary
                                    : "No search yet")
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .background(Color.white.opacity(0.04))
        .task {
            // A short beat, so the field is in the hierarchy before it takes
            // focus and the keyboard rises with it.
            try? await Task.sleep(for: .milliseconds(60))
            searchFocused = true
        }
    }

    /// The chat header's marked-lines bar: how many lines of the open
    /// conversation name us, the Next mention control that steps through them,
    /// and — beside it — the Highlight control that steps through the lines
    /// holding one of the user's words. A line that does both is stepped by both
    /// controls.
    private var markedLinesBar: some View {
        HStack(spacing: 8) {
            Image(systemName: "bell.badge")
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(Self.mentionViolet.opacity(model.canStepMentions ? 1 : 0.55))
            Text(model.mentionSummary)
                .font(.caption2)
                .foregroundStyle(.secondary)
                .lineLimit(1)
            Spacer(minLength: 4)
            mentionStepControl
                .layoutPriority(1)
            highlightStepControl
                .layoutPriority(1)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 6)
        .background(Self.mentionViolet.opacity(0.05))
    }

    /// The Next mention control: steps through the lines that name us.
    private var mentionStepControl: some View {
        Button {
            inputFocused = false
            model.nextMention()
        } label: {
            HStack(spacing: 4) {
                Text("Next")
                    .font(.system(size: 11, weight: .semibold))
                Text(model.mentionCounter)
                    .font(.system(size: 11, weight: .semibold, design: .rounded))
                    .monospacedDigit()
                Image(systemName: "chevron.down")
                    .font(.system(size: 9, weight: .bold))
            }
            .foregroundStyle(model.canStepMentions ? Color.white : Color.secondary)
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(model.canStepMentions
                        ? Self.mentionViolet.opacity(0.28)
                        : Color.white.opacity(0.06),
                        in: Capsule())
            .overlay(
                Capsule().strokeBorder(model.canStepMentions
                                       ? Self.mentionViolet.opacity(0.55)
                                       : Color.clear,
                                       lineWidth: 1)
            )
        }
        .buttonStyle(.plain)
        .disabled(!model.canStepMentions)
        .opacity(model.canStepMentions ? 1 : 0.45)
        .accessibilityLabel("Next mention")
        .accessibilityValue(model.mentionCounter)
    }

    /// The Highlight control: steps through the lines of the open conversation
    /// that hold one of the user's switched-on words and reports which step it is
    /// on ("2 of 7"). It stays dimmed while the conversation holds no such line.
    private var highlightStepControl: some View {
        Button {
            inputFocused = false
            model.nextHighlight()
        } label: {
            HStack(spacing: 4) {
                Image(systemName: "highlighter")
                    .font(.system(size: 10, weight: .semibold))
                Text(model.keywordCounter)
                    .font(.system(size: 11, weight: .semibold, design: .rounded))
                    .monospacedDigit()
            }
            .foregroundStyle(model.canStepHighlights ? Color.white : Color.secondary)
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(model.canStepHighlights
                        ? Self.keywordBlue.opacity(0.28)
                        : Color.white.opacity(0.06),
                        in: Capsule())
            .overlay(
                Capsule().strokeBorder(model.canStepHighlights
                                       ? Self.keywordBlue.opacity(0.55)
                                       : Color.clear,
                                       lineWidth: 1)
            )
        }
        .buttonStyle(.plain)
        .disabled(!model.canStepHighlights)
        .opacity(model.canStepHighlights ? 1 : 0.45)
        .accessibilityLabel("Next highlighted line")
        .accessibilityValue(model.keywordCounter)
        .accessibilityHint(model.keywordSummary)
    }

    /// The channel's topic line, which opens the member list for that channel.
    private func topicBar(_ conversation: I2PIRCConversation, topic: String?) -> some View {
        Button {
            inputFocused = false
            membersChannelID = conversation.id
            showMembers = true
        } label: {
            HStack(spacing: 10) {
                VStack(alignment: .leading, spacing: 2) {
                    if let topic, !topic.isEmpty {
                        Text(topic)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(2)
                            .fixedSize(horizontal: false, vertical: true)
                            .multilineTextAlignment(.leading)
                    }
                    Text(membersLine(conversation))
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                        .lineLimit(1)
                }
                Spacer(minLength: 6)
                Image(systemName: "person.2")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(accent.opacity(0.80))
                Image(systemName: "chevron.right")
                    .font(.system(size: 10, weight: .bold))
                    .foregroundStyle(.tertiary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.vertical, 7)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel("Members of \(conversation.name)")
    }

    private func membersLine(_ conversation: I2PIRCConversation) -> String {
        let members = conversation.sortedMembers(ourNick: model.state.nick)
        guard !members.isEmpty else {
            return conversation.joined ? "Just you here" : "Not in this channel"
        }
        let shown = members.prefix(6).joined(separator: ", ")
        let extra = members.count > 6 ? " +\(members.count - 6)" : ""
        return "\(members.count) here · \(shown)\(extra)"
    }

    /// The lines on screen: the whole transcript, or the lines the search field
    /// matches while it is filtering.
    private var messages: [I2PIRCMessage] {
        model.visibleMessages
    }

    /// The lines on screen broken into days: a separator opens each day that
    /// has a line in them, and a day the search left nothing in gets none. The
    /// lines of a nick the server ignores fold into one quiet row, and the
    /// separators are drawn from the lines' own dates, so saved history and a
    /// restored transcript are grouped exactly as a live session is.
    private var transcriptRows: [I2PIRCTranscriptRow] {
        I2PIRCIgnoreFold.rows(messages: messages,
                              ignored: model.ignoredNicksInForce,
                              now: Date())
    }

    private var messagesScroll: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 10) {
                    if messages.isEmpty {
                        if model.isFilteringTranscript {
                            noMatchesCard
                        } else {
                            emptyConversationCard
                        }
                    }
                    ForEach(transcriptRows) { row in
                        switch row {
                        case .day(let separator):
                            daySeparator(separator)
                        case .message(let message):
                            messageRow(message)
                                .id(message.id)
                        case .ignored(let group):
                            ignoredRow(group)
                                .id(row.id)
                        }
                    }
                    Color.clear
                        .frame(height: 1)
                        .id("irc-bottom")
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
            }
            .scrollDismissesKeyboard(.interactively)
            .onChange(of: messages.count) { _, _ in
                // Lines filtered out of the transcript never push the view to
                // the bottom the way an arriving line does.
                guard !model.isFilteringTranscript else { return }
                scrollToBottom(proxy)
            }
            .onChange(of: model.selection) { _, _ in
                scrollToBottom(proxy, animated: false)
            }
            .onChange(of: model.mentionJumpCount) { _, _ in
                scrollToMention(proxy)
            }
            .onChange(of: model.keywordJumpCount) { _, _ in
                scrollToHighlight(proxy)
            }
            .onChange(of: model.matchJumpCount) { _, _ in
                scrollToMatch(proxy)
            }
            .onAppear {
                guard !model.isFilteringTranscript else { return }
                scrollToBottom(proxy, animated: false)
            }
        }
    }

    /// What the transcript shows when the search field matches nothing.
    private var noMatchesCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("No matches")
                .font(.footnote.weight(.semibold))
                .foregroundStyle(accent)
            Text("Nothing here matches “\(model.searchText)”. The search looks through the lines loaded in this conversation.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(14)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 16))
        .padding(.top, 8)
    }

    /// Brings the line the Next mention control stepped onto into view.
    private func scrollToMention(_ proxy: ScrollViewProxy) {
        guard let target = model.mentionTarget else { return }
        withAnimation(.easeOut(duration: 0.25)) {
            proxy.scrollTo(target, anchor: .center)
        }
    }

    /// Brings the line the Highlight control stepped onto into view.
    private func scrollToHighlight(_ proxy: ScrollViewProxy) {
        guard let target = model.keywordTarget else { return }
        withAnimation(.easeOut(duration: 0.25)) {
            proxy.scrollTo(target, anchor: .center)
        }
    }

    /// Brings the line a tap on the Highlighted lines sheet chose into view. The
    /// line may belong to a conversation that has only just come on screen, so
    /// the scroll waits a beat for the transcript to lay out.
    private func scrollToMatch(_ proxy: ScrollViewProxy) {
        guard let target = model.matchTarget else { return }
        Task { @MainActor in
            try? await Task.sleep(for: .milliseconds(220))
            withAnimation(.easeOut(duration: 0.25)) {
                proxy.scrollTo(target, anchor: .center)
            }
        }
    }

    private func scrollToBottom(_ proxy: ScrollViewProxy, animated: Bool = true) {
        guard !messages.isEmpty else { return }
        if animated {
            withAnimation(.easeOut(duration: 0.2)) {
                proxy.scrollTo("irc-bottom", anchor: .bottom)
            }
        } else {
            proxy.scrollTo("irc-bottom", anchor: .bottom)
        }
    }

    private var emptyConversationCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(model.selectedConversation?.kind == .channel
                 ? "Nothing said here yet"
                 : "The server buffer")
                .font(.footnote.weight(.semibold))
                .foregroundStyle(accent)
            Text(model.selectedConversation?.kind == .channel
                 ? "Say something to open the conversation. Type /help in the composer for the commands."
                 : "Registration, the message of the day and server errors appear here.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(14)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 16))
        .padding(.top, 8)
    }

    // MARK: - Transcript days

    /// A day's separator: a quiet capsule over a hairline on either side, so the
    /// transcript reads as days without the date shouting over the chat.
    private func daySeparator(_ separator: I2PIRCDaySeparator) -> some View {
        HStack(spacing: 10) {
            dayHairline
            Text(separator.label)
                .font(.system(size: 10, weight: .semibold))
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .padding(.horizontal, 10)
                .padding(.vertical, 3)
                .background(Color.white.opacity(0.05), in: Capsule())
                .overlay(
                    Capsule().strokeBorder(Color.white.opacity(0.06), lineWidth: 1)
                )
            dayHairline
        }
        .padding(.top, 6)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(separator.label)
        .accessibilityAddTraits(.isHeader)
    }

    private var dayHairline: some View {
        Rectangle()
            .fill(Color.white.opacity(0.10))
            .frame(height: 1)
            .frame(maxWidth: .infinity)
    }

    // MARK: - Message rows

    private func messageRow(_ message: I2PIRCMessage) -> some View {
        Group {
            switch message.kind {
            case .system, .error:
                systemRow(message)
            case .action:
                actionRow(message)
            case .notice:
                noticeRow(message)
            case .message:
                bubbleRow(message)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .contentShape(Rectangle())
        .contextMenu {
            copyMenu(for: message)
        }
    }

    /// One quiet row: the lines a nick the server ignores said in the open
    /// conversation, folded into a single sentence. The lines still arrived and
    /// still counted as unread; a tap opens them in place, and they close again
    /// when another conversation comes on screen.
    private func ignoredRow(_ group: I2PIRCIgnoredGroup) -> some View {
        let expanded = model.isIgnoredGroupExpanded(group.id)
        return VStack(alignment: .leading, spacing: 8) {
            Button {
                inputFocused = false
                withAnimation(.easeOut(duration: 0.18)) {
                    model.toggleIgnoredGroup(group.id)
                }
            } label: {
                HStack(spacing: 9) {
                    Image(systemName: "eye.slash")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(accent.opacity(0.90))
                    VStack(alignment: .leading, spacing: 1) {
                        Text(group.summary)
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                        Text(expanded ? "Tap to fold them away" : "Tap to read them")
                            .font(.system(size: 10))
                            .foregroundStyle(.tertiary)
                    }
                    Spacer(minLength: 6)
                    Image(systemName: expanded ? "chevron.down" : "chevron.right")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundStyle(.tertiary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 12)
                .padding(.vertical, 9)
                .background(Color.white.opacity(0.045),
                            in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                .overlay(
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .strokeBorder(Color.white.opacity(0.07), lineWidth: 1)
                )
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel(group.summary)
            .accessibilityHint(expanded ? "Folds the lines away" : "Shows the lines")
            .accessibilityAddTraits(expanded ? [.isSelected] : [])

            if expanded {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(group.messages) { message in
                        messageRow(message)
                    }
                }
                .padding(.leading, 10)
                .overlay(alignment: .leading) {
                    RoundedRectangle(cornerRadius: 1.5, style: .continuous)
                        .fill(Color.white.opacity(0.12))
                        .frame(width: 2)
                }
                .transition(.opacity)
            }
        }
    }

    // MARK: - Copy

    /// What a long press on a line offers: the line in the share sheet's shape,
    /// and — for a line someone said — the same line with its nick named.
    @ViewBuilder
    private func copyMenu(for message: I2PIRCMessage) -> some View {
        let options = I2PIRCLineCopy.options(for: message, ourNick: model.state.nick)
        ForEach(options) { option in
            Button {
                copy(option)
            } label: {
                Label(option.title,
                      systemImage: option.kind == .nickAndText
                      ? "person.text.rectangle"
                      : "doc.on.doc")
            }
        }
    }

    /// Puts the copied line on the clipboard and says so above the composer for
    /// a moment. Only the line is written — never the server, the destination or
    /// the peer.
    private func copy(_ option: I2PIRCLineCopyOption) {
        UIPasteboard.general.string = option.text
        withAnimation(.easeOut(duration: 0.18)) {
            copiedNotice = option.notice
        }
        copyResetTask?.cancel()
        copyResetTask = Task { @MainActor in
            try? await Task.sleep(for: .milliseconds(1800))
            guard !Task.isCancelled else { return }
            guard copiedNotice == option.notice else { return }
            withAnimation(.easeOut(duration: 0.20)) {
                copiedNotice = nil
            }
        }
    }

    /// The short confirmation above the composer: which copy landed, and the
    /// line it took so it can be read before it is pasted somewhere.
    private func copyConfirmation(_ notice: I2PIRCLineCopyNotice) -> some View {
        HStack(spacing: 7) {
            Image(systemName: "doc.on.doc.fill")
                .font(.system(size: 10, weight: .semibold))
                .foregroundStyle(accent)
            Text(notice.title)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.primary)
                .lineLimit(1)
            Text(notice.line)
                .font(.system(.caption2, design: .monospaced))
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 7)
        .background(accent.opacity(0.14), in: Capsule())
        .overlay(Capsule().strokeBorder(accent.opacity(0.32), lineWidth: 1))
        .padding(.horizontal, 16)
        .padding(.bottom, 6)
        .transition(.opacity.combined(with: .move(edge: .bottom)))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(notice.title): \(notice.line)")
    }

    private func systemRow(_ message: I2PIRCMessage) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Image(systemName: message.kind == .error
                  ? "exclamationmark.circle"
                  : "smallcircle.filled.circle")
                .font(.system(size: 8))
                .foregroundStyle(message.kind == .error ? warnOrange : Color.secondary.opacity(0.6))
                .padding(.top, 4)
            VStack(alignment: .leading, spacing: 1) {
                Text(message.text)
                    .font(.caption)
                    .foregroundStyle(message.kind == .error ? warnOrange : Color.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Text(timeText(message.date))
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundStyle(.tertiary)
            }
            Spacer(minLength: 0)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func actionRow(_ message: I2PIRCMessage) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Text("·")
                .font(.callout.weight(.bold))
                .foregroundStyle(accent)
            Text(actionText(message))
                .font(.callout)
                .italic()
                .foregroundStyle(accent.opacity(0.92))
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .lineEdge(edgeTint(for: message))
    }

    private func noticeRow(_ message: I2PIRCMessage) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Text("—")
                .font(.caption.weight(.bold))
                .foregroundStyle(warnOrange)
            VStack(alignment: .leading, spacing: 1) {
                Text(markedText(message, boldFont: .caption.weight(.bold)))
                    .font(.caption)
                    .foregroundStyle(warnOrange.opacity(0.92))
                    .fixedSize(horizontal: false, vertical: true)
                Text(timeText(message.date))
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundStyle(.tertiary)
            }
            Spacer(minLength: 0)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .lineEdge(edgeTint(for: message))
    }

    /// An action's line: the nick that did it, then the sentence with the
    /// words it was marked for tinted and emboldened. The nick is left alone.
    private func actionText(_ message: I2PIRCMessage) -> AttributedString {
        var text = AttributedString("\(message.nick ?? model.state.nick) ")
        text.append(markedText(message, boldFont: .callout.weight(.bold).italic()))
        return text
    }

    /// A marked line's own text with the words it was marked for tinted and
    /// emboldened in the edge's cool blue. A line no switched-on word marks
    /// comes back exactly as it is.
    private func markedText(_ message: I2PIRCMessage, boldFont: Font) -> AttributedString {
        I2PIRCKeywordEmphasis.attributed(message.text,
                                         words: message.keywordHits,
                                         tint: Self.keywordBlue,
                                         boldFont: boldFont)
    }

    /// The tint a line's edge wears: the mention violet when the line names us,
    /// the cooler keyword tint when it holds one of the user's words, and none
    /// otherwise. A line that does both reads as a mention first.
    private func edgeTint(for message: I2PIRCMessage) -> Color? {
        if message.mentionsUs { return Self.mentionViolet }
        if !message.keywordHits.isEmpty { return Self.keywordBlue }
        return nil
    }

    private func bubbleRow(_ message: I2PIRCMessage) -> some View {
        VStack(alignment: message.isLocal ? .trailing : .leading, spacing: 3) {
            HStack(spacing: 6) {
                if !message.isLocal, let nick = message.nick {
                    Text(nick)
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(nickColor(nick))
                } else if message.isLocal {
                    Text("You")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(accent)
                }
                Text(timeText(message.date))
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundStyle(.tertiary)
            }
            Text(markedText(message, boldFont: .callout.weight(.bold)))
                .font(.callout)
                .multilineTextAlignment(.leading)
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(
                    message.isLocal ? accent.opacity(0.22) : Color.white.opacity(0.06),
                    in: RoundedRectangle(cornerRadius: 14)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 14)
                        .strokeBorder(edgeTint(for: message)?.opacity(0.85) ?? Color.clear,
                                      lineWidth: 1.4)
                )
                .shadow(color: edgeTint(for: message)?.opacity(0.30) ?? Color.clear,
                        radius: 6)
        }
        .frame(maxWidth: .infinity, alignment: message.isLocal ? .trailing : .leading)
    }

    private func nickColor(_ nick: String) -> Color {
        var hash: UInt32 = 5381
        for scalar in nick.lowercased().unicodeScalars {
            hash = hash &* 33 &+ scalar.value
        }
        return Self.nickTints[Int(hash % UInt32(Self.nickTints.count))]
    }

    private func timeText(_ date: Date) -> String {
        date.formatted(date: .omitted, time: .shortened)
    }

    // MARK: - Composer

    private var canSendDraft: Bool {
        model.phase.isLive && !model.draftText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    private var composerPlaceholder: String {
        guard let conversation = model.selectedConversation else { return "Message" }
        switch conversation.kind {
        case .server: return "Type a command (try /help)"
        case .channel, .query: return "Message \(conversation.name)"
        }
    }

    /// The composer with the nick strip over it: the roster nicks the draft
    /// starts with, and the field itself below.
    private var composer: some View {
        VStack(spacing: 0) {
            if !model.nickSuggestions.isEmpty {
                nickStrip
            }
            inputBar
        }
    }

    /// The strip of matching nicks above the composer: ours first, then the most
    /// recently active, at most five rows. A tap fills the composer with that
    /// nick and its colon, and so does Tab on the first row.
    private var nickStrip: some View {
        let suggestions = model.nickSuggestions
        return VStack(spacing: 0) {
            ForEach(suggestions) { suggestion in
                VStack(spacing: 0) {
                    if suggestion.id != suggestions.first?.id {
                        Rectangle()
                            .fill(Color.white.opacity(0.06))
                            .frame(height: 1)
                            .padding(.leading, 40)
                    }
                    nickSuggestionRow(suggestion,
                                      showsTabHint: suggestion.id == suggestions.first?.id)
                }
            }
        }
        .background(Color.white.opacity(0.07), in: RoundedRectangle(cornerRadius: 14))
        .overlay(
            RoundedRectangle(cornerRadius: 14)
                .strokeBorder(accent.opacity(0.30), lineWidth: 1)
        )
        .padding(.horizontal, 16)
        .padding(.top, 8)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Matching nicks")
    }

    private func nickSuggestionRow(_ suggestion: I2PIRCNickSuggestion,
                                   showsTabHint: Bool) -> some View {
        Button {
            model.completeNick(suggestion.nick)
        } label: {
            HStack(spacing: 9) {
                nickRoleBadge(suggestion.role)
                Text(suggestion.nick)
                    .font(.system(.callout, weight: .medium))
                    .foregroundStyle(nickColor(suggestion.nick))
                    .lineLimit(1)
                if suggestion.isUs {
                    Text("you")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundStyle(accent)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(accent.opacity(0.18), in: Capsule())
                }
                Spacer(minLength: 6)
                if suggestion.role != .participant {
                    Text(suggestion.role.title.lowercased())
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
                if showsTabHint {
                    Text("Tab")
                        .font(.system(size: 9, weight: .semibold, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Color.white.opacity(0.08), in: RoundedRectangle(cornerRadius: 5))
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(suggestionLabel(suggestion))
    }

    private func nickRoleBadge(_ role: I2PIRCMemberRole) -> some View {
        ZStack {
            RoundedRectangle(cornerRadius: 6)
                .fill(role == .participant
                      ? Color.white.opacity(0.06)
                      : badgeTint(role).opacity(0.24))
            if role == .participant {
                Image(systemName: "person.fill")
                    .font(.system(size: 8, weight: .bold))
                    .foregroundStyle(.secondary)
            } else {
                Text(role == .op ? "@" : "+")
                    .font(.system(size: 10, weight: .bold, design: .monospaced))
                    .foregroundStyle(badgeTint(role))
            }
        }
        .frame(width: 18, height: 18)
    }

    /// The tint an operator's "@" and a voiced "+" wear: violet for the first,
    /// the nick palette's blue for the second.
    private func badgeTint(_ role: I2PIRCMemberRole) -> Color {
        switch role {
        case .op: return accent
        case .voiced: return Self.nickTints[1]
        case .participant: return Color.secondary
        }
    }

    private func suggestionLabel(_ suggestion: I2PIRCNickSuggestion) -> String {
        var parts = [suggestion.nick]
        if suggestion.isUs { parts.append("you") }
        if suggestion.role != .participant { parts.append(suggestion.role.title.lowercased()) }
        parts.append("completes the nick")
        return parts.joined(separator: ", ")
    }

    private var inputBar: some View {
        HStack(alignment: .bottom, spacing: 8) {
            TextField(composerPlaceholder, text: $model.draftText, axis: .vertical)
                .font(.callout)
                .lineLimit(1...4)
                .textInputAutocapitalization(.sentences)
                .autocorrectionDisabled(true)
                .focused($inputFocused)
                .onSubmit { model.sendDraft() }
                .onKeyPress(.tab) {
                    if model.completeFirstNickSuggestion() {
                        return .handled
                    }
                    return .ignored
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 10)
                .background(Color.white.opacity(0.08), in: RoundedRectangle(cornerRadius: 18))
            Button {
                model.sendDraft()
            } label: {
                Image(systemName: "arrow.up.circle.fill")
                    .font(.system(size: 30))
                    .foregroundStyle(canSendDraft ? accent : Color.white.opacity(0.18))
            }
            .buttonStyle(.plain)
            .disabled(!canSendDraft)
            .accessibilityLabel("Send")
        }
        .padding(.horizontal, 16)
        .padding(.top, 8)
        .padding(.bottom, 8)
        .background(background.opacity(0.96))
    }
}

// MARK: - Line edge

/// Rings a line that needs a second look — a line that names us or holds one of
/// the user's keywords: a bar down its leading edge, so an action or a notice
/// reads as a marked line the same way a bubble does.
private struct I2PIRCLineEdgeModifier: ViewModifier {
    let tint: Color?

    func body(content: Content) -> some View {
        content
            .padding(.leading, tint == nil ? 0 : 10)
            .overlay(alignment: .leading) {
                if let tint {
                    RoundedRectangle(cornerRadius: 1.5, style: .continuous)
                        .fill(tint)
                        .frame(width: 3)
                        .padding(.vertical, 1)
                }
            }
    }
}

private extension View {
    func lineEdge(_ tint: Color?) -> some View {
        modifier(I2PIRCLineEdgeModifier(tint: tint))
    }
}

// MARK: - Servers sheet

struct IRCServersView: View {
    @ObservedObject var book: I2PIRCServerBook
    let onConnect: (I2PIRCServerEntry) -> Void
    let onClearHistory: (UUID) -> Void

    @Environment(\.dismiss) private var dismiss
    @ObservedObject private var history = I2PIRCHistoryStore.shared
    @State private var showForm = false

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)

    var body: some View {
        Group {
            if book.entries.isEmpty {
                emptyState
            } else {
                list
            }
        }
        .background(background.ignoresSafeArea())
        .navigationTitle("IRC servers")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarLeading) {
                Button("Done") { dismiss() }
            }
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    showForm = true
                } label: {
                    Image(systemName: "plus")
                }
                .accessibilityLabel("Add a server")
            }
        }
        .sheet(isPresented: $showForm) {
            NavigationStack {
                IRCServerFormView(book: book) { entry in
                    onConnect(entry)
                    dismiss()
                }
            }
        }
        .preferredColorScheme(.dark)
    }

    private var list: some View {
        List {
            ForEach(book.entries) { entry in
                Button {
                    onConnect(entry)
                    dismiss()
                } label: {
                    HStack(spacing: 12) {
                        Image(systemName: "server.rack")
                            .font(.system(size: 15, weight: .medium))
                            .foregroundStyle(accent)
                            .frame(width: 38, height: 38)
                            .background(accent.opacity(0.14), in: RoundedRectangle(cornerRadius: 10))
                        VStack(alignment: .leading, spacing: 3) {
                            Text(entry.displayName)
                                .font(.subheadline.weight(.medium))
                                .foregroundStyle(.primary)
                                .lineLimit(1)
                            Text("\(entry.address) · \(entry.nick)")
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                            if !entry.channels.isEmpty {
                                Text(entry.channels.joined(separator: ", "))
                                    .font(.caption2)
                                    .foregroundStyle(.tertiary)
                                    .lineLimit(1)
                            }
                        }
                        Spacer(minLength: 4)
                        Image(systemName: "chevron.right")
                            .font(.caption2.weight(.semibold))
                            .foregroundStyle(.tertiary)
                    }
                    .padding(.vertical, 4)
                }
                .buttonStyle(.plain)
                .listRowBackground(Color.clear)
                .listRowSeparator(.hidden)
                .listRowInsets(EdgeInsets(top: 5, leading: 16, bottom: 5, trailing: 16))
                .swipeActions(edge: .leading, allowsFullSwipe: false) {
                    if history.hasHistory(for: entry.id) {
                        Button {
                            onClearHistory(entry.id)
                        } label: {
                            Label("Clear history", systemImage: "clock.arrow.circlepath")
                        }
                        .tint(accent)
                    }
                }
                .swipeActions(edge: .trailing, allowsFullSwipe: true) {
                    Button(role: .destructive) {
                        book.remove(entry.id)
                    } label: {
                        Label("Delete", systemImage: "trash")
                    }
                }
            }
        }
        .listStyle(.plain)
        .scrollContentBackground(.hidden)
    }

    private var emptyState: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("No IRC servers yet", systemImage: "server.rack")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(accent)
            Text("Save an I2P IRC server and it appears in the IRC tab, one tap from a connection. The address is a .i2p name, a b32 host, a b33 address or a base64 destination; the port is usually 6667.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Button {
                showForm = true
            } label: {
                Label("Add a server", systemImage: "plus.circle")
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(accent)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 10)
                    .background(accent.opacity(0.14), in: Capsule())
            }
            .buttonStyle(.plain)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .padding(20)
    }
}

// MARK: - Server form

struct IRCServerFormView: View {
    @ObservedObject var book: I2PIRCServerBook
    let onSaved: (I2PIRCServerEntry) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var host = ""
    @State private var portText = String(I2PIRCServerEntry.defaultPort)
    @State private var nick = ""
    @State private var password = ""
    @State private var channelsText = "#i2p"

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)

    private var draft: I2PIRCServerEntry {
        I2PIRCServerEntry(name: name,
                          host: host,
                          port: UInt16(portText) ?? 0,
                          nick: nick,
                          password: password,
                          channels: I2PIRCServerBook.channels(from: channelsText))
    }

    private var problem: String? {
        guard !host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return nil }
        return draft.validationProblem
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                field("Name", placeholder: "Optional — the name the list shows", text: $name)
                field("Address", placeholder: "irc.example.i2p", text: $host, monospaced: true)
                field("Port", placeholder: "6667", text: $portText, monospaced: true,
                      keyboard: .numberPad)
                field("Nick", placeholder: "yournick", text: $nick, monospaced: true)
                passwordField
                field("Channels to join", placeholder: "#i2p, #help", text: $channelsText)
                if let problem {
                    Text(problem)
                        .font(.caption)
                        .foregroundStyle(Color.orange)
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    Text("On connect the client registers with this nick and joins these channels. A b33 server needs credentials the router holds (see the b33 Hosts screen).")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Button {
                    save()
                } label: {
                    Text("Save server")
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(draft.validationProblem == nil ? Color.white : Color.white.opacity(0.45))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 14)
                        .background(draft.validationProblem == nil ? accent.opacity(0.80) : accent.opacity(0.32),
                                    in: Capsule())
                }
                .buttonStyle(.plain)
                .disabled(draft.validationProblem != nil)
            }
            .padding(16)
        }
        .background(background.ignoresSafeArea())
        .navigationTitle("Add a server")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarLeading) {
                Button("Cancel") { dismiss() }
            }
        }
        .preferredColorScheme(.dark)
    }

    private func field(_ title: String,
                       placeholder: String,
                       text: Binding<String>,
                       monospaced: Bool = false,
                       keyboard: UIKeyboardType = .default) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .textCase(.uppercase)
            TextField(placeholder, text: text)
                .font(monospaced ? .system(.callout, design: .monospaced) : .callout)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled(true)
                .keyboardType(keyboard)
                .padding(.horizontal, 14)
                .padding(.vertical, 12)
                .background(Color.white.opacity(0.07), in: RoundedRectangle(cornerRadius: 14))
        }
    }

    private var passwordField: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text("Server password")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .textCase(.uppercase)
            SecureField("Optional — sent as PASS before the nick", text: $password)
                .font(.callout)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled(true)
                .padding(.horizontal, 14)
                .padding(.vertical, 12)
                .background(Color.white.opacity(0.07), in: RoundedRectangle(cornerRadius: 14))
        }
    }

    private func save() {
        let entry = draft
        guard book.save(entry) else { return }
        onSaved(entry)
        dismiss()
    }
}

// MARK: - Join sheet

struct IRCJoinView: View {
    let onJoin: (String) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var channel = ""

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)

    private var normalized: String? {
        I2PIRCName.channel(channel)
    }

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 14) {
                Text("Type a channel name — the # is added when you leave it out.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                TextField("#channel", text: $channel)
                    .font(.system(.callout, design: .monospaced))
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled(true)
                    .submitLabel(.join)
                    .onSubmit { join() }
                    .padding(.horizontal, 14)
                    .padding(.vertical, 12)
                    .background(Color.white.opacity(0.07), in: RoundedRectangle(cornerRadius: 14))
                Button {
                    join()
                } label: {
                    Text("Join")
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(normalized == nil ? Color.white.opacity(0.45) : Color.white)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 14)
                        .background(normalized == nil ? accent.opacity(0.32) : accent.opacity(0.80),
                                    in: Capsule())
                }
                .buttonStyle(.plain)
                .disabled(normalized == nil)
                Spacer()
            }
            .padding(16)
            .background(background.ignoresSafeArea())
            .navigationTitle("Join a channel")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
        .preferredColorScheme(.dark)
        .presentationDetents([.medium])
    }

    private func join() {
        guard let normalized else { return }
        onJoin(normalized)
        dismiss()
    }
}
