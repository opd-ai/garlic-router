//
//  B33HostsView.swift
//  The b33 host book screen: the blinded destinations this router knows about,
//  the credentials it holds for them, and each host's lease resolution.
//

import SwiftUI

struct B33HostsView: View {
    @StateObject private var book = I2PB33HostBook.live()
    @State private var pastedAddress = ""
    @State private var addExpanded = false
    @FocusState private var addFocused: Bool

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                captionText
                if book.entries.isEmpty {
                    emptyStateCard
                } else {
                    summaryCard
                    ForEach(book.entries) { entry in
                        hostCard(entry)
                    }
                }
                addCard
                footnoteText
            }
            .padding(.horizontal, 16)
            .padding(.top, 4)
            .padding(.bottom, 24)
        }
        .background(background.ignoresSafeArea())
        .navigationTitle("b33 Hosts")
        .navigationBarTitleDisplayMode(.large)
        .preferredColorScheme(.dark)
        .onAppear { book.refresh() }
    }

    // MARK: - Header

    private var captionText: some View {
        Text("Encrypted destinations under blinded keys. Credentialled hosts unlock; stranger hosts stay opaque.")
            .font(.footnote)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var footnoteText: some View {
        Text("Resolution rides the blinded netdb key — the unblinded destination hash never leaves the device.")
            .font(.caption2)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 2)
    }

    // MARK: - Summary

    private var summaryCard: some View {
        let summary = book.summary
        return Text("\(summary.resolvable) resolvable · \(summary.opaque) opaque · \(summary.tracked) hosts tracked")
            .font(.footnote.weight(.medium))
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(16)
            .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    // MARK: - Empty state

    private var emptyStateCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("No b33 hosts yet", systemImage: "book.closed")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(accent)
            Text("A b33 address is a destination whose LeaseSet2 is published under a blinded key, so the network never sees who publishes it. This book lists the b33 hosts the router knows about: the ones it holds credentials for unlock their leases, stranger hosts stay opaque.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Text("Add one by pasting its address below — or create an encrypted SAM session and its b33 appears here.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    // MARK: - Host row

    private func hostCard(_ entry: I2PB33HostEntry) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Text(entry.displayPrefix)
                    .font(.system(.footnote, design: .monospaced).weight(.medium))
                    .foregroundStyle(entry.credentialled ? Color.primary : Color.secondary)
                    .lineLimit(1)
                    .textSelection(.enabled)
                Spacer(minLength: 6)
                badge(entry.credentialled)
            }

            Text(resolutionLine(entry))
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if let failure = book.failures[entry.address] {
                Text(failure)
                    .font(.caption2)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if entry.credentialled {
                resolveButton(entry)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
        .opacity(entry.credentialled ? 1 : 0.62)
        .contextMenu {
            Button(role: .destructive) {
                book.forget(entry.address)
            } label: {
                Label("Remove from host book", systemImage: "trash")
            }
        }
    }

    private func badge(_ credentialled: Bool) -> some View {
        Text(credentialled ? "Resolvable" : "Opaque")
            .font(.caption2.weight(.semibold))
            .foregroundStyle(credentialled ? accent : Color.secondary)
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(credentialled ? accent.opacity(0.15) : Color.white.opacity(0.08),
                        in: Capsule())
    }

    private func resolveButton(_ entry: I2PB33HostEntry) -> some View {
        let busy = book.resolving.contains(entry.address)
        return Button {
            Task { await book.resolveNow(entry.address) }
        } label: {
            HStack(spacing: 6) {
                if busy {
                    ProgressView()
                        .controlSize(.mini)
                        .tint(accent)
                } else {
                    Image(systemName: "arrow.triangle.2.circlepath")
                        .font(.caption)
                }
                Text(busy ? "Resolving…" : "Resolve now")
                    .font(.subheadline.weight(.semibold))
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 10)
            .background(accent.opacity(0.15), in: RoundedRectangle(cornerRadius: 12))
        }
        .buttonStyle(.plain)
        .tint(accent)
        .disabled(busy)
    }

    /// "2 leases · resolved 4 min ago", or why nothing has been read yet.
    private func resolutionLine(_ entry: I2PB33HostEntry) -> String {
        let leases = entry.leaseCount == 1 ? "1 lease" : "\(entry.leaseCount) leases"
        if let resolved = entry.lastResolvedAt {
            return "\(leases) · resolved \(resolved.formatted(.relative(presentation: .named)))"
        }
        return entry.credentialled
            ? "Never resolved yet · the blinded lookup runs on demand"
            : "Never resolved · stranger host, the inner body stays sealed"
    }

    // MARK: - Add

    private var addCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Button {
                withAnimation(.easeInOut(duration: 0.2)) {
                    addExpanded.toggle()
                }
                addFocused = addExpanded
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: addExpanded ? "xmark.circle" : "plus.circle")
                        .font(.footnote)
                    Text("Paste a destination to track a new b33 host")
                        .font(.footnote.weight(.medium))
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .foregroundStyle(accent)
            }
            .buttonStyle(.plain)

            if addExpanded {
                HStack(spacing: 8) {
                    TextField("b33 address", text: $pastedAddress)
                        .font(.system(.caption, design: .monospaced))
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .submitLabel(.done)
                        .focused($addFocused)
                        .onSubmit { track() }
                        .padding(.vertical, 8)
                        .padding(.horizontal, 10)
                        .background(accent.opacity(0.12), in: RoundedRectangle(cornerRadius: 10))
                    Button("Add") { track() }
                        .font(.footnote.weight(.semibold))
                        .foregroundStyle(accent)
                        .padding(.horizontal, 14)
                        .padding(.vertical, 8)
                        .background(accent.opacity(0.18), in: Capsule())
                        .buttonStyle(.plain)
                }

                if let failure = book.addFailure {
                    Text(failure)
                        .font(.caption2)
                        .foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(
            RoundedRectangle(cornerRadius: 18)
                .strokeBorder(accent.opacity(0.35), style: StrokeStyle(lineWidth: 1, dash: [5, 4]))
        )
    }

    private func track() {
        guard book.track(pastedAddress) else { return }
        pastedAddress = ""
        addFocused = false
        withAnimation(.easeInOut(duration: 0.2)) {
            addExpanded = false
        }
    }
}

// MARK: - Live wiring

extension I2PB33HostBook {
    /// The host book bound to the running router: the hosts whose credentials
    /// the SAM bridge holds, resolved over the live netdb's b33 blinding path.
    static func live() -> I2PB33HostBook {
        let context = I2PRouterAppContext.shared
        return I2PB33HostBook(
            credentialledHosts: {
                var hosts: [String: I2PB33Credentials] = [:]
                for host in context.samServer.b33Hosts() {
                    hosts[host.address] = host.credentials
                }
                return hosts
            },
            lookup: { credentials in
                guard let resolved = await context.mainnetNetDB
                    .lookupEncryptedLeaseSet2(credentials: credentials) else {
                    return nil
                }
                let now = Date()
                return resolved.leases.filter { $0.expiration > now }.count
            })
    }
}
