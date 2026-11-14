//
//  StrategyView.swift
//  The product, growth and commercial strategy for Garlic Router, rendered
//  natively: the verdict, the five highest-impact improvements, positioning,
//  the phased roadmap with per-phase metrics and experiments, the missing
//  capabilities and prerequisites, the sourced market and App Store claims,
//  and the commercial reality check.
//
//  Long-form source document: /scratchpad/Garlic-Router-Product-Strategy.md
//

import SwiftUI

struct StrategyView: View {
    @State private var expandedImprovements: Set<Int> = [1]
    @State private var expandedPhases: Set<Int> = []
    @State private var showAssumptions = false

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    summaryCard
                    verdictCard
                    firstMovesCard
                    improvementsCard
                    positioningCard
                    roadmapCard
                    capabilitiesCard
                    sourcesCard
                    commercialCard
                    assumptionsCard
                    footerLine
                }
                .padding(.horizontal, 16)
                .padding(.top, 4)
                .padding(.bottom, 24)
            }
            .background(background.ignoresSafeArea())
            .navigationTitle("Strategy")
            .navigationBarTitleDisplayMode(.large)
        }
        .preferredColorScheme(.dark)
    }

    // MARK: - Summary

    private var summaryCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                Image(systemName: "map.fill")
                    .font(.caption)
                    .foregroundStyle(accent)
                Text("Product, growth & commercial plan")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .textCase(.uppercase)
            }

            Text("I2P in your pocket, not on your desk.")
                .font(.system(.title3, design: .rounded).weight(.bold))
                .foregroundStyle(accent)

            Text("A candid assessment of the iOS router as a product: what it needs to succeed with users and commercially, and the order to do it in.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            HStack(spacing: 8) {
                chip("5", label: "improvements")
                chip("7", label: "phases")
                chip("~4.5", label: "months to launch")
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    private func chip(_ value: String, label: String) -> some View {
        VStack(spacing: 2) {
            Text(value)
                .font(.subheadline.weight(.bold))
                .foregroundStyle(accent)
            Text(label)
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 8)
        .background(Color.white.opacity(0.05), in: RoundedRectangle(cornerRadius: 10))
    }

    // MARK: - Verdict

    private var verdictCard: some View {
        card(title: "Verdict") {
            labeledBlock(
                title: "Strongest opportunity",
                tint: .green,
                body: "iOS is the only major platform with no I2P router, and this is a pure-Swift, modern-crypto-only node with an on-device SAMv3.3 socket. Two defensible positions fall out of that: “I2P in your pocket” for users, and “SAM on device” as the only embeddable I2P client for any iOS app."
            )
            labeledBlock(
                title: "Biggest obstacle",
                tint: .orange,
                body: "Nothing a user can do with it works yet. Outbound tunnel builds through real mainnet hops do not complete and inbound participation is not observed, so every payoff — eepsite browsing, hosting, contributing bandwidth — is blocked. Layered on top: iOS suspends the process, so a phone can never be the always-on node I2P rewards. Fixing the protocol is expensive; there is also no product on top of it, and that part is cheap."
            )
        }
    }

    private var firstMovesCard: some View {
        card(title: "Do these first") {
            Text("The next ten working days, in order.")
                .font(.caption2)
                .foregroundStyle(.secondary)
            ForEach(Array(StrategyContent.firstMoves.enumerated()), id: \.offset) { index, move in
                HStack(alignment: .top, spacing: 10) {
                    Text("\(index + 1)")
                        .font(.system(.caption2, design: .monospaced).weight(.bold))
                        .foregroundStyle(accent)
                        .frame(width: 18, height: 18)
                        .background(accent.opacity(0.16), in: Circle())
                    Text(move)
                        .font(.footnote)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 0)
                }
            }
        }
    }

    // MARK: - Improvements

    private var improvementsCard: some View {
        card(title: "Five highest-impact improvements") {
            Text("Ranked by impact, with effort and dependencies. #2 has the best impact-per-day; #1 is the only one that unblocks the rest.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            ForEach(StrategyContent.improvements) { item in
                improvementRow(item)
            }
        }
    }

    @ViewBuilder
    private func improvementRow(_ item: StrategyImprovement) -> some View {
        let isExpanded = expandedImprovements.contains(item.id)
        VStack(alignment: .leading, spacing: 6) {
            Button {
                withAnimation(.easeInOut(duration: 0.2)) {
                    if isExpanded {
                        expandedImprovements.remove(item.id)
                    } else {
                        expandedImprovements.insert(item.id)
                    }
                }
            } label: {
                HStack(alignment: .top, spacing: 10) {
                    Text("\(item.rank)")
                        .font(.system(.caption, design: .rounded).weight(.bold))
                        .foregroundStyle(accent)
                        .frame(width: 22, height: 22)
                        .background(accent.opacity(0.16), in: Circle())
                    VStack(alignment: .leading, spacing: 4) {
                        Text(item.title)
                            .font(.footnote.weight(.semibold))
                            .foregroundStyle(.primary)
                            .multilineTextAlignment(.leading)
                        HStack(spacing: 6) {
                            pill("impact: \(item.impact)", color: impactColor(item.impact))
                            pill("effort: \(item.effort)", color: .blue)
                        }
                    }
                    Spacer(minLength: 0)
                    Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
                        .font(.caption2.weight(.bold))
                        .foregroundStyle(.secondary)
                        .padding(.top, 4)
                }
            }
            .buttonStyle(.plain)

            if isExpanded {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(Array(item.detail.enumerated()), id: \.offset) { _, line in
                        bullet(line)
                    }
                    HStack(alignment: .top, spacing: 6) {
                        Text("Depends on")
                            .font(.caption2.weight(.semibold))
                            .foregroundStyle(.secondary)
                        Text(item.dependsOn)
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                    HStack(alignment: .top, spacing: 6) {
                        Image(systemName: "flag.checkered")
                            .font(.caption2)
                            .foregroundStyle(.green)
                        Text(item.exitCriterion)
                            .font(.caption2)
                            .foregroundStyle(.green)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .padding(10)
                .background(Color.white.opacity(0.04), in: RoundedRectangle(cornerRadius: 10))
                .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
        .padding(.top, 6)
    }

    private func impactColor(_ impact: String) -> Color {
        switch impact {
        case "blocking": return .red
        case "very high": return .orange
        default: return .green
        }
    }

    // MARK: - Positioning

    private var positioningCard: some View {
        card(title: "Positioning") {
            positioningBlock(label: "Primary · consumer", text: StrategyContent.positioning.consumer)
            positioningBlock(label: "Developer · the commercial story", text: StrategyContent.positioning.developer)
            positioningBlock(label: "Against Tor", text: StrategyContent.positioning.againstTor)
            Text("Never say")
                .font(.caption2.weight(.semibold))
                .foregroundStyle(.orange)
                .textCase(.uppercase)
                .padding(.top, 2)
            ForEach(Array(StrategyContent.positioning.avoid.enumerated()), id: \.offset) { _, line in
                bullet(line, tint: .orange)
            }
        }
    }

    private func positioningBlock(label: String, text: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(label)
                .font(.caption2.weight(.semibold))
                .foregroundStyle(.secondary)
                .textCase(.uppercase)
            Text(text)
                .font(.footnote)
                .foregroundStyle(.primary)
                .fixedSize(horizontal: false, vertical: true)
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(accent.opacity(0.10), in: RoundedRectangle(cornerRadius: 12))
        }
    }

    // MARK: - Roadmap

    private var roadmapCard: some View {
        card(title: "Roadmap · validation to ongoing growth") {
            Text("Phases overlap deliberately: protocol interop is one engineer's long pole, and product and design run beside it. Weeks assume two iOS engineers, a part-time designer and a shared protocol engineer.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            ForEach(StrategyContent.phases) { phase in
                phaseRow(phase)
            }
        }
    }

    @ViewBuilder
    private func phaseRow(_ phase: StrategyPhase) -> some View {
        let isExpanded = expandedPhases.contains(phase.id)
        VStack(alignment: .leading, spacing: 6) {
            Button {
                withAnimation(.easeInOut(duration: 0.2)) {
                    if isExpanded {
                        expandedPhases.remove(phase.id)
                    } else {
                        expandedPhases.insert(phase.id)
                    }
                }
            } label: {
                HStack(alignment: .center, spacing: 10) {
                    Text("P\(phase.id)")
                        .font(.system(.caption, design: .monospaced).weight(.bold))
                        .foregroundStyle(accent)
                        .frame(width: 26, height: 22)
                        .background(accent.opacity(0.16), in: RoundedRectangle(cornerRadius: 6))
                    VStack(alignment: .leading, spacing: 2) {
                        Text(phase.name)
                            .font(.footnote.weight(.semibold))
                            .foregroundStyle(.primary)
                        Text(phase.window)
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                    Spacer(minLength: 0)
                    Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
                        .font(.caption2.weight(.bold))
                        .foregroundStyle(.secondary)
                }
            }
            .buttonStyle(.plain)

            if isExpanded {
                VStack(alignment: .leading, spacing: 8) {
                    Text(phase.goal)
                        .font(.caption.weight(.medium))
                        .foregroundStyle(accent)
                        .fixedSize(horizontal: false, vertical: true)

                    ForEach(Array(phase.work.enumerated()), id: \.offset) { _, line in
                        bullet(line)
                    }

                    HStack(alignment: .top, spacing: 6) {
                        Image(systemName: "flag.checkered")
                            .font(.caption2)
                            .foregroundStyle(.green)
                        Text("Exit: \(phase.exit)")
                            .font(.caption2)
                            .foregroundStyle(.green)
                            .fixedSize(horizontal: false, vertical: true)
                    }

                    VStack(alignment: .leading, spacing: 4) {
                        Text("Metrics")
                            .font(.caption2.weight(.semibold))
                            .foregroundStyle(.secondary)
                            .textCase(.uppercase)
                        ForEach(Array(phase.metrics.enumerated()), id: \.offset) { _, line in
                            bullet(line)
                        }
                    }

                    VStack(alignment: .leading, spacing: 4) {
                        Text("Experiments")
                            .font(.caption2.weight(.semibold))
                            .foregroundStyle(.secondary)
                            .textCase(.uppercase)
                        ForEach(Array(phase.experiments.enumerated()), id: \.offset) { _, line in
                            bullet(line, tint: .blue)
                        }
                    }
                }
                .padding(10)
                .background(Color.white.opacity(0.04), in: RoundedRectangle(cornerRadius: 10))
                .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
        .padding(.top, 6)
    }

    // MARK: - Capabilities

    private var capabilitiesCard: some View {
        card(title: "Missing capabilities & prerequisites") {
            Text("Nobody has built these yet, and each one gates something in the roadmap.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            ForEach(StrategyContent.capabilityGroups) { group in
                VStack(alignment: .leading, spacing: 4) {
                    Text(group.title)
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(accent)
                        .textCase(.uppercase)
                        .padding(.top, 4)
                    ForEach(Array(group.items.enumerated()), id: \.offset) { _, line in
                        bullet(line)
                    }
                }
            }
        }
    }

    // MARK: - Sources

    private var sourcesCard: some View {
        card(title: "Sources & verification") {
            Text("Claims checked against public sources. Anything unverified is labelled as an assumption.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            ForEach(StrategyContent.sources) { source in
                VStack(alignment: .leading, spacing: 4) {
                    Text(source.claim)
                        .font(.footnote.weight(.medium))
                        .fixedSize(horizontal: false, vertical: true)
                    Text(source.note)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    if let url = URL(string: source.url) {
                        Link(destination: url) {
                            Label(source.label, systemImage: "arrow.up.right.square")
                                .font(.caption2.weight(.semibold))
                                .foregroundStyle(accent)
                        }
                    }
                }
                .padding(.vertical, 4)
            }
            Divider().opacity(0.2)
            Text("Check before committing money")
                .font(.caption2.weight(.semibold))
                .foregroundStyle(.orange)
                .textCase(.uppercase)
            ForEach(Array(StrategyContent.unverified.enumerated()), id: \.offset) { _, line in
                bullet(line, tint: .orange)
            }
        }
    }

    // MARK: - Commercial reality

    private var commercialCard: some View {
        card(title: "Commercial reality") {
            ForEach(StrategyContent.commercial) { point in
                VStack(alignment: .leading, spacing: 4) {
                    Text(point.headline)
                        .font(.footnote.weight(.semibold))
                    Text(point.body)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(.vertical, 4)
            }
            Text("No pricing page until a .i2p page loads over our own tunnels.")
                .font(.caption2.weight(.semibold))
                .foregroundStyle(accent)
                .padding(.top, 2)
        }
    }

    // MARK: - Assumptions

    private var assumptionsCard: some View {
        card(title: "Assumptions") {
            Button {
                withAnimation(.easeInOut(duration: 0.2)) {
                    showAssumptions.toggle()
                }
            } label: {
                HStack(spacing: 8) {
                    Text(showAssumptions ? "Hide the six labelled assumptions" : "Show the six labelled assumptions")
                        .font(.footnote.weight(.medium))
                        .foregroundStyle(accent)
                    Spacer()
                    Image(systemName: showAssumptions ? "chevron.up" : "chevron.down")
                        .font(.caption2.weight(.bold))
                        .foregroundStyle(.secondary)
                }
            }
            .buttonStyle(.plain)

            if showAssumptions {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(StrategyContent.assumptions) { item in
                        HStack(alignment: .top, spacing: 8) {
                            Text(item.id)
                                .font(.system(.caption2, design: .monospaced).weight(.bold))
                                .foregroundStyle(accent)
                            Text(item.body)
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }
                .padding(10)
                .background(Color.white.opacity(0.04), in: RoundedRectangle(cornerRadius: 10))
                .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
    }

    private var footerLine: some View {
        Text("Long-form document · /scratchpad/Garlic-Router-Product-Strategy.md")
            .font(.caption2)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
            .frame(maxWidth: .infinity)
    }

    // MARK: - Shared components (match the Core, Router and Alignment tabs)

    private func card(title: String, @ViewBuilder content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .textCase(.uppercase)
            content()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    private func labeledBlock(title: String, tint: Color, body: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.caption2.weight(.semibold))
                .foregroundStyle(tint)
                .textCase(.uppercase)
            Text(body)
                .font(.footnote)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.vertical, 2)
    }

    private func bullet(_ text: String, tint: Color = .secondary) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Circle()
                .fill(tint)
                .frame(width: 4, height: 4)
                .padding(.top, 5)
            Text(text)
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
    }

    private func pill(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.caption2.weight(.semibold))
            .foregroundStyle(color)
            .padding(.horizontal, 7)
            .padding(.vertical, 2)
            .background(color.opacity(0.16), in: Capsule())
    }
}

// MARK: - Content

private struct StrategyImprovement: Identifiable {
    let id: Int
    let rank: Int
    let title: String
    let impact: String
    let effort: String
    let dependsOn: String
    let detail: [String]
    let exitCriterion: String
}

private struct StrategyPhase: Identifiable {
    let id: Int
    let name: String
    let window: String
    let goal: String
    let work: [String]
    let exit: String
    let metrics: [String]
    let experiments: [String]
}

private struct StrategySource: Identifiable {
    let id: Int
    let claim: String
    let note: String
    let label: String
    let url: String
}

private struct StrategyCapabilityGroup: Identifiable {
    let id: Int
    let title: String
    let items: [String]
}

private struct StrategyCommercialPoint: Identifiable {
    let id: Int
    let headline: String
    let body: String
}

private struct StrategyAssumption: Identifiable {
    let id: String
    let body: String
}

private struct StrategyPositioning {
    let consumer: String
    let developer: String
    let againstTor: String
    let avoid: [String]
}

private enum StrategyContent {

    static let firstMoves: [String] = [
        "Instrument a scoreboard instead of audit ticks: build success %, time-to-first-lease, resolve p50, eepsite fetch p50, battery %/hour, crash-free sessions. Turn pass/fail into a trend.",
        "Start 12-15 community interviews this week: I2P forum, r/i2p, i2pd developers, I2P Router for Android reviews, and a few non-technical iPhone users.",
        "Assign one engineer to the tunnel build record layout and treat it as the gate. Nothing user-facing ships around it.",
        "Send the App Store pre-submission inquiry covering the WebKit browser, battery behaviour and background execution.",
        "Stop leading with the audit console: a Network home, onboarding and an Advanced drawer cost a week and change everything about first impressions."
    ]

    static let improvements: [StrategyImprovement] = [
        StrategyImprovement(
            id: 1,
            rank: 1,
            title: "Close the live-tunnel gap",
            impact: "blocking",
            effort: "L · 4-6 wks",
            dependsOn: "nothing. This is the gate.",
            detail: [
                "Record shape is now on spec: 154-byte short request records sealed with the Noise_N_X25519/ChaChaPoly handshake into 218-byte ShortTunnelBuild records (I2NP types 25/26), and reply records follow the KDF, nonce and AD rules. The loopback suite proves the build/reply path; what is left is proving it against live routers.",
                "Wire SSU2 into the running transport set. The UDP transport exists but the app context is NTCP2-only, so a phone behind carrier NAT can never be reachable, selected as a hop or able to accept an inbound tunnel.",
                "Keep hidden mode until SSU2 works: the router already publishes only once a listener and an external IPv4 are known, so peers are never handed an unreachable address."
            ],
            exitCriterion: "Exit: 90%+ of builds through modern mainnet routers succeed, and a real .i2p page is fetched over our own tunnels."
        ),
        StrategyImprovement(
            id: 2,
            rank: 2,
            title: "Make it a product in 60 seconds",
            impact: "very high",
            effort: "S · ~1 wk",
            dependsOn: "nothing. Best impact-per-effort on this list.",
            detail: [
                "Three onboarding screens, one decision each: what this is, what it does with your connection, start or limit. No account, no email.",
                "A Network home with one honest status line: connected, 4 floodfills, 2 tunnels, 12 min. One primary action, plain-language health.",
                "Move the cryptographic suite and the five audits under Advanced. Keep them, stop leading with them.",
                "Add the privacy-tool basics: stop router, wipe netdb, rotate identity, export identity."
            ],
            exitCriterion: "Exit: a first-run that ends on a working status screen instead of a test console."
        ),
        StrategyImprovement(
            id: 3,
            rank: 3,
            title: "Ship the eepsite browser as the front door",
            impact: "high",
            effort: "M · ~3 wks",
            dependsOn: "the live-tunnel gap.",
            detail: [
                "App Store guideline 2.5.6 requires web browsing to use WebKit. A hand-rolled HTML reader is a rejection risk; a localhost HTTP proxy served by the router's stream layer plus WKWebView is the precedented architecture.",
                "Failure copy in user language: could not find this site on the network, found it but the tunnel would not build, building tunnels and this can take 30 seconds. The code knows these stages.",
                "This is the first end-to-end consumer of the garlic delivery path, and the only payoff a non-technical user will feel."
            ],
            exitCriterion: "Exit: a .i2p site loads, renders and can be navigated, with a named stage when it fails."
        ),
        StrategyImprovement(
            id: 4,
            rank: 4,
            title: "Decide the always-on strategy honestly",
            impact: "high",
            effort: "M-L · 2-3 wks",
            dependsOn: "the live-tunnel gap.",
            detail: [
                "Guideline 2.5.4 limits background services to their intended purposes and 2.4.2 forbids apps that drain battery or generate heat. iOS suspension is the structural constraint on this product.",
                "Opportunistic participation is the recommended first answer: run while foregrounded plus a BGProcessingTask refresh, with copy that says the node participates while the app is open.",
                "A Network Extension is the only path to genuine always-on execution. It needs an entitlement, a justification and a review conversation; treat it as a later decision, not a launch blocker.",
                "A companion always-on relay is the only contribution story that solves both battery and uptime, and the only subscription with real substance."
            ],
            exitCriterion: "Exit: a written decision, matching UI copy, and a measured battery budget per hour."
        ),
        StrategyImprovement(
            id: 5,
            rank: 5,
            title: "Package it for launch and distribution",
            impact: "high",
            effort: "S-M · ~2 wks",
            dependsOn: "nothing, but must land before the ship phase.",
            detail: [
                "The repo still says Untitled1: product name, bundle identifier, project name. The display name Garlic Router is good; make everything else match it.",
                "Remove NSAllowsArbitraryLoads or scope it narrowly. Add a privacy manifest, an export-compliance answer, a 17+ rating if the browser ships, and review notes with a demo video.",
                "Distribution is not App Store and hope: the first 500 users are the I2P forum, r/i2p, the i2pd and Java I2P developers, and the self-hosting crowd."
            ],
            exitCriterion: "Exit: passes review, and 500 community testers have run the real build."
        )
    ]

    static let positioning = StrategyPositioning(
        consumer: "Your phone is now a node on the invisible internet. Garlic Router runs a full I2P router inside iOS - no desktop, no daemon, no jailbreak. Carry an anonymous identity, open .i2p sites, and lend bandwidth while you are connected. Your keys stay in the iOS Keychain.",
        developer: "SAM v3.3 on device. Any iOS app can open an anonymous destination over the real I2P network, with no desktop router and no companion process. The first embeddable I2P client for iPhone.",
        againstTor: "Tor hides where you go. I2P gives you somewhere to be.",
        avoid: [
            "Not a VPN, and never described as one.",
            "Not a censorship-circumvention tool; that is Tor's job and the claim brings the wrong users and the wrong reviewers.",
            "No browse the dark web framing.",
            "No network-size numbers you cannot source: the widely repeated 55,000 computers figure is undated and unmatched by any measurement."
        ]
    )

    static let phases: [StrategyPhase] = [
        StrategyPhase(
            id: 0,
            name: "Validation & recon",
            window: "Weeks 0-2",
            goal: "Replace opinions with numbers and quotes, and de-risk review before writing product code.",
            work: [
                "Interviews: I2P forum users, r/i2p, i2pd developers, Android I2P Router users mined from Play Store reviews, and three or four privacy-curious non-technical iPhone users.",
                "Turn the live suite into a scoreboard: build success %, time-to-first-lease, inbound participation minutes, resolve p50/p95, eepsite fetch p50, battery %/hour, crash-free sessions.",
                "Policy: draft review notes, confirm the WebKit browser approach, export compliance, privacy manifest plan, and a Network Extension yes/no/later.",
                "Choose a privacy-consistent analytics scheme: opt-in, aggregate, no IDFA, no third-party SDK by default.",
                "Lock the name, bundle identifier, icon direction and tone of voice."
            ],
            exit: "a baseline scoreboard, at least 10 interviews summarized, a written review-risk register, and name plus bundle identifier locked.",
            metrics: [
                "Interviews completed: 12 or more.",
                "Intent to install: 50%+ of the I2P-aware cohort, 20%+ of the non-technical cohort.",
                "Baseline build success % and baseline battery %/hour, recorded as the reference for every later phase."
            ],
            experiments: [
                "Concept test two positioning scripts (help the network vs browse .i2p sites) with five people each.",
                "Willingness to pay: free, $4.99 one-time, $1.99 monthly."
            ]
        ),
        StrategyPhase(
            id: 1,
            name: "Make the node work",
            window: "Weeks 2-8",
            goal: "The one thing that matters: a tunnel through real hops, and a page fetched over it.",
            work: [
                "Tunnel build record alignment, single owner, highest priority.",
                "SSU2 in the router app context: UDP listener, hole punching, NAT classification, hidden mode as the default posture.",
                "LS2 and b33 resolution used by the real delivery path; encrypted LS2 publication for SAM sessions.",
                "Eepsite fetch MVP with no UI: resolve, open a stream over the outbound pool, HTTP GET, hand back bytes.",
                "Battery and thermal budget: measure, then cap. An idle router must not spin.",
                "QA: 24-hour soak on device, WiFi to cellular handover, low-power mode, background cycling, memory-pressure kills.",
                "Parallel: App Store pre-submission inquiry on 2.5.6, 2.4.2 and background behaviour."
            ],
            exit: "90%+ build success to modern routers, one live .i2p page fetched over our tunnels, a 30-minute session stable, 8% battery per hour or less, zero crashes in a 24-hour soak.",
            metrics: [
                "Tunnel build success %, target 90%+.",
                "Median build time, target under 15 seconds.",
                "Inbound participation minutes per session.",
                "Battery %/hour, target 8 or less.",
                "Crash-free sessions, target 99.5%."
            ],
            experiments: [
                "Record-layout A/B against live hops: does the aligned shape change build acceptance.",
                "Hidden mode versus published address: measure its effect on inbound build requests.",
                "SSU2 versus NTCP2-only reachability delta."
            ]
        ),
        StrategyPhase(
            id: 2,
            name: "Make it a product",
            window: "Weeks 6-12 (overlaps Phase 1)",
            goal: "A first-run that ends with a page on screen, and a reason to come back.",
            work: [
                "Information architecture: Network (status, start, health), Browse (address, history, bookmarks), Me (destination, share), Advanced (audits, peer inspector, alignment).",
                "Onboarding: three screens, one bandwidth decision, one honest sentence about background execution.",
                "Eepsite browser on WKWebView behind a localhost proxy, with loading, failure and retry states.",
                "b33 host book and participation controls built into this shell, not as separate islands.",
                "Empty states, error copy, VoiceOver, Dynamic Type, light and dark.",
                "Analytics funnel: launch, start router, connect, first page, return.",
                "Identity safety: export and import the destination, clear identity, a recovery story for a lost phone."
            ],
            exit: "activation (first page load) at 40% of beta installs or better, time-to-first-page p50 under 60 seconds, and no unlabelled error state in the UI.",
            metrics: [
                "Activation, target 40%+.",
                "Time-to-first-page p50, target under 60 seconds.",
                "Onboarding completion, target 80%+.",
                "D1 and D7 in beta, target 50% and 25%."
            ],
            experiments: [
                "Onboarding length: three screens versus one.",
                "Status phrasing: Connected versus 12 peers · ready.",
                "Failure copy: technical versus plain language, measured by retry rate.",
                "Start on launch versus manual start, measuring battery and retention together."
            ]
        ),
        StrategyPhase(
            id: 3,
            name: "Make it shippable",
            window: "Weeks 10-16",
            goal: "Pass review, and survive the beta.",
            work: [
                "App Store: icon, five screenshots showing the app in use, preview, 17+ rating for unrestricted web access, privacy answers, privacy manifest, export compliance.",
                "Review notes plus a screen recording of the node starting and a page loading. Reviewers will not know what I2P is.",
                "Support URL, docs site, security disclosure policy, terms and acceptable use, abuse contact.",
                "TestFlight external beta with 300-500 testers recruited from the I2P and privacy communities, split into cohorts.",
                "Release engineering: symbolication, crash reporting backend, release checklist, device matrix.",
                "Localization: English first, then German, Russian, Persian and Chinese only after the beta geography justifies it."
            ],
            exit: "approved, 99.5% crash-free sessions, and beta D7 at 40% or better.",
            metrics: [
                "Review outcome and iteration count.",
                "Beta D7 and D30.",
                "Crash-free % and support tickets per 100 installs."
            ],
            experiments: [
                "Cohort segmentation: I2P-expert versus privacy-curious, to learn which one retains.",
                "Browser-first versus node-first default landing tab."
            ]
        ),
        StrategyPhase(
            id: 4,
            name: "Launch & learn",
            window: "Weeks 16-20",
            goal: "Real users and honest numbers.",
            work: [
                "Soft launch to the I2P community (forum, r/i2p, Mastodon, I2P news), then privacy and self-hosting channels, then the developer angle for SAM on Hacker News and iOS communities.",
                "Launch asset built only on measurable, sourced claims: the first I2P router that runs on a phone.",
                "Growth loops: share your .i2p or b33 address from the app, import a friend's host, a what this node contributed card.",
                "Monetization v1: free app plus a supporter in-app purchase with a visible badge. No gating of the mission.",
                "Weekly metrics review and a fix ship every week for the first month."
            ],
            exit: "3-5k installs as a hypothesis to recalibrate, activation at 30% or better, D30 at 10% or better, and first paying supporters.",
            metrics: [
                "Installs, activation %, D1/D7/D30.",
                "Supporter conversion %.",
                "App Store page conversion, impressions to installs.",
                "Referral shares per 100 users."
            ],
            experiments: [
                "App Store screenshot order: browser first versus node first.",
                "Supporter framing and placement.",
                "Community AMA versus press-first launch, one after the other."
            ]
        ),
        StrategyPhase(
            id: 5,
            name: "Grow & monetize",
            window: "Months 5-9",
            goal: "Turn a niche app into a platform position.",
            work: [
                "SDK and developer tier: documented embedded SAM surface, sample app, commercial licence for closed-source apps. This is the realistic revenue line.",
                "Supporter tier with real value: larger tunnel pool, multi-hop configuration, priority reseed, early builds. Not cosmetic only.",
                "Companion relay, later and largest in scope: pair the phone to an always-on node so contribution is real and battery is spared.",
                "Retention: bookmarks, address book, discovery of reachable sites, a notification when a saved site becomes resolvable.",
                "Community: bug bounty and a measurement paper with an academic group. Credibility no paid marketing can buy.",
                "Localization expansion only where the funnel shows demand."
            ],
            exit: "a paid conversion baseline, SDK conversations, and stable MAU with contribution minutes per user tracked.",
            metrics: [
                "Paid conversion, target 1-3% of MAU.",
                "SDK licence conversations and close rate.",
                "WAU/MAU and contribution minutes per MAU.",
                "Churn reasons."
            ],
            experiments: [
                "Supporter value bundles: configuration versus cosmetics.",
                "In-app prompt for developer docs versus none.",
                "Retention prompt timing after first successful page load."
            ]
        ),
        StrategyPhase(
            id: 6,
            name: "Operate",
            window: "Month 9+",
            goal: "Stay correct, stay alive, stay trusted.",
            work: [
                "Track the I2P release cadence, roughly every 6-8 weeks, and keep a standing spec-delta ticket each cycle.",
                "Post-quantum upkeep is mandatory: hybrid ML-KEM with X25519 has been required in implementations since 2.10.0. The ML-KEM adapter gap is a shipping risk, not a nice-to-have.",
                "One external security audit before v2, published.",
                "Quarterly pricing and plan review, retention experiments, and SLO tracking for build success, participation minutes and resolve success."
            ],
            exit: "a release cadence the community can rely on, and no known spec delta older than one cycle.",
            metrics: [
                "Spec-delta time-to-fix.",
                "Security findings opened and closed.",
                "Quarterly retention cohorts.",
                "Support response time."
            ],
            experiments: [
                "Pricing and plan mix review each quarter.",
                "One retention experiment per quarter, never more."
            ]
        )
    ]

    static let capabilityGroups: [StrategyCapabilityGroup] = [
        StrategyCapabilityGroup(id: 0, title: "Product & design", items: [
            "Onboarding, first-run value, information architecture, a home screen with a single truth.",
            "Plain-language diagnostics: current failures are engineer-readable, not user-readable.",
            "Kill switch, identity export, clear everything.",
            "Accessibility, localization, light mode.",
            "App icon, screenshots, preview, brand system. The display name exists; everything else says Untitled1."
        ]),
        StrategyCapabilityGroup(id: 1, title: "Engineering", items: [
            "Tunnel build record alignment. The gate.",
            "SSU2 in the running router, NAT classification, hole punching, hidden mode.",
            "A localhost HTTP proxy for the browser, for guideline 2.5.6.",
            "Battery and thermal instrumentation, BGProcessingTask scheduling, suspension-safe shutdown.",
            "Auto-uploaded crash reports with symbolication. I2PCrashReporter is local-only today.",
            "Remote, privacy-consistent analytics.",
            "Identity backup and restore across devices.",
            "A device test matrix, not only live CI probes."
        ]),
        StrategyCapabilityGroup(id: 2, title: "App Store & legal", items: [
            "Real bundle identifier and product name; remove NSAllowsArbitraryLoads or scope it narrowly.",
            "Privacy manifest, App Privacy answers, export compliance.",
            "17+ rating if a browser ships.",
            "Review notes plus a demo video and a pre-submission inquiry.",
            "Support URL, docs site, terms and acceptable use, abuse contact, security disclosure policy.",
            "Trademark check on Garlic Router: garlic routing is I2P terminology, so use it descriptively."
        ]),
        StrategyCapabilityGroup(id: 3, title: "Commercial", items: [
            "No in-app purchase, no paywall, no pricing, no StoreKit testing.",
            "No developer-facing docs or site beyond SAM_API.md inside the repo.",
            "No measurement or attribution, so no way to know what works."
        ])
    ]

    static let sources: [StrategySource] = [
        StrategySource(
            id: 0,
            claim: "I2P is a live, maintained network with a fast release cadence.",
            note: "2.12.0 (2026-04-20), 2.13.0 (2026-07-24) and 2.14.0 (2026-10-22): roughly every 6-8 weeks. Implication: a standing spec-delta ticket every cycle.",
            label: "en.wikipedia.org/wiki/I2P",
            url: "https://en.wikipedia.org/wiki/I2P"
        ),
        StrategySource(
            id: 1,
            claim: "Post-quantum is now required of implementations.",
            note: "From 2.10.0 a hybrid ML-KEM with X25519 scheme is required to be implemented, with classical defaults still available to users. Implication: the ML-KEM adapter gap is a compliance risk, not research.",
            label: "en.wikipedia.org/wiki/I2P · geti2p.net/spec/ecies-hybrid",
            url: "https://geti2p.net/spec/ecies-hybrid"
        ),
        StrategySource(
            id: 2,
            claim: "Mobile I2P clients exist on Android, not on iOS.",
            note: "A Google Play I2P router under the Privacy Solutions Project is documented; no iOS client is listed. Assumption A5 applies: the App Store itself was not checked, so treat this as strongly likely rather than proven.",
            label: "en.wikipedia.org/wiki/I2P",
            url: "https://en.wikipedia.org/wiki/I2P"
        ),
        StrategySource(
            id: 3,
            claim: "Network size is not reliably known and should not be quoted.",
            note: "Wikipedia asserts a volunteer-run network of roughly 55,000 computers, undated and unsourced to any measurement. The best public measurement remains the 2018 IMC study, which also found a censor could block 95%+ of known peers with 10 routers. No current number is verified here.",
            label: "dl.acm.org/doi/10.1145/3278532.3278565",
            url: "https://dl.acm.org/doi/10.1145/3278532.3278565"
        ),
        StrategySource(
            id: 4,
            claim: "Guideline 2.5.6: web browsing must use WebKit.",
            note: "Account for the browser with WKWebView and a localhost proxy rather than a custom HTML renderer.",
            label: "developer.apple.com/app-store/review/guidelines",
            url: "https://developer.apple.com/app-store/review/guidelines/"
        ),
        StrategySource(
            id: 5,
            claim: "Guidelines 2.4.2 and 2.5.4: power efficiency and background services.",
            note: "Apps may not rapidly drain battery or generate excessive heat, and background services must serve their intended purposes. Battery budget is a review criterion, and always-on relaying needs either a Network Extension or honest scoping.",
            label: "developer.apple.com/app-store/review/guidelines",
            url: "https://developer.apple.com/app-store/review/guidelines/"
        ),
        StrategySource(
            id: 6,
            claim: "Guideline 3.1.1: digital unlocks must use in-app purchase.",
            note: "A supporter tier or feature unlock cannot be sold outside in-app purchase inside the app; a donation model has to be a tip jar via in-app purchase.",
            label: "developer.apple.com/app-store/review/guidelines",
            url: "https://developer.apple.com/app-store/review/guidelines/"
        )
    ]

    static let unverified: [String] = [
        "Current live I2P router count and median participation stats.",
        "Whether any I2P client is listed on the App Store today.",
        "Apple's position on the browser-proxy architecture and on battery-heavy networking. Ask, do not infer.",
        "Trademark status of Garlic Router.",
        "Whether the I2P developer community welcomes a third-party mobile router. Ask them in Phase 0."
    ]

    static let commercial: [StrategyCommercialPoint] = [
        StrategyCommercialPoint(
            id: 0,
            headline: "Consumer revenue will be small.",
            body: "I2P's audience is measured in thousands of committed users at most, and comparable privacy tools are free. On an assumption of 1-3% conversion at $4.99-9.99, 5,000 monthly users is roughly $250-1,500 gross per year before Apple's cut. Plan the consumer app as a credibility and distribution asset, not a profit centre."
        ),
        StrategyCommercialPoint(
            id: 1,
            headline: "The SDK is the business.",
            body: "I2P on device for any iOS app has no alternative today and can be licensed per app per year. It needs the same interop work plus docs, a sample and support, and it is the reason to keep SAM a first-class surface rather than a debug tab."
        ),
        StrategyCommercialPoint(
            id: 2,
            headline: "A companion relay is the only recurring revenue with substance.",
            body: "It solves the iOS suspension problem for the user at the same moment it creates the only meaningful cost line. It is also the biggest scope risk: do it in the grow phase, if the launch funnel justifies it."
        )
    ]

    static let assumptions: [StrategyAssumption] = [
        StrategyAssumption(id: "A1", body: "The primary product is the consumer iOS app; the SAMv3.3 socket is a secondary developer surface that could become an SDK."),
        StrategyAssumption(id: "A2", body: "The team is small: two iOS engineers, one part-time designer, one shared protocol and security engineer."),
        StrategyAssumption(id: "A3", body: "No users, no distribution, no revenue and no analytics today."),
        StrategyAssumption(id: "A4", body: "No current live I2P network size could be verified. Any network-size number in this plan is flagged, never quoted as fact."),
        StrategyAssumption(id: "A5", body: "No I2P router ships for iOS today. Strongly likely, not proven: the App Store was not queried."),
        StrategyAssumption(id: "A6", body: "The team owns no App Store review precedent for this category; the guidelines were read literally, and a pre-submission inquiry is part of the plan.")
    ]
}

#Preview {
    StrategyView()
        .preferredColorScheme(.dark)
}
