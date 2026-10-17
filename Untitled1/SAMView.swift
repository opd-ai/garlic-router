//
//  SAMView.swift
//  The SAMv3.3 tab: listener control, live client sessions, the command
//  reference for SAM clients, and the bridge activity log.
//

import SwiftUI

struct SAMView: View {
    @State private var sessions: [I2PSAMSessionSummary] = []
    @State private var stateText = "Stopped"
    @State private var listening = false
    @State private var failure: String?
    @State private var logLines: [String] = []

    private let accent = Color(red: 0.47, green: 0.44, blue: 0.97)
    private let background = Color(red: 0.055, green: 0.06, blue: 0.09)

    private var server: I2PSAMServer {
        I2PRouterAppContext.shared.samServer
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    serverCard
                    if !sessions.isEmpty { sessionsCard }
                    apiCard
                    if !logLines.isEmpty { logCard }
                }
                .padding(.horizontal, 16)
                .padding(.top, 4)
                .padding(.bottom, 24)
            }
            .background(background.ignoresSafeArea())
            .navigationTitle("SAM")
            .navigationBarTitleDisplayMode(.large)
        }
        .preferredColorScheme(.dark)
        .task {
            I2PRouterAppContext.shared.start()
            while !Task.isCancelled {
                refresh()
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    private func refresh() {
        switch server.state {
        case .stopped:
            stateText = "Stopped"
            listening = false
            failure = nil
        case .listening(let port):
            stateText = "Listening · 127.0.0.1:\(port)"
            listening = true
            failure = nil
        case .failed(let error):
            stateText = "Failed"
            listening = false
            failure = error
        }
        sessions = server.sessionSummaries()
        logLines = server.log
    }

    // MARK: Server card

    private var serverCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                Circle().fill(listening ? Color.green : Color.orange).frame(width: 8, height: 8)
                Text(listening ? "API socket live" : "API socket idle")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(listening ? Color.green : Color.orange)
                Spacer()
                Text("SAMv3.3")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(accent)
            }

            Text("SAM socket")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .textCase(.uppercase)

            Text(stateText)
                .font(.system(.footnote, design: .monospaced).weight(.medium))
                .padding(.vertical, 8)
                .padding(.horizontal, 12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(accent.opacity(0.12), in: RoundedRectangle(cornerRadius: 12))

            if let failure {
                Text(failure)
                    .font(.caption2)
                    .foregroundStyle(.red)
            }

            Text("Sessions \(sessions.count) · tunnels build once peers are known")
                .font(.caption2)
                .foregroundStyle(.secondary)

            Button {
                if listening { server.stop() } else { server.start() }
                refresh()
            } label: {
                Label(listening ? "Stop SAM socket" : "Start SAM socket",
                      systemImage: listening ? "stop.circle" : "play.circle")
                    .font(.subheadline.weight(.semibold))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .background(accent.opacity(0.18), in: RoundedRectangle(cornerRadius: 12))
            }
            .buttonStyle(.plain)
            .tint(accent)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    // MARK: Sessions

    private var sessionsCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Client Sessions")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .textCase(.uppercase)
            ForEach(sessions.indices, id: \.self) { index in
                let session = sessions[index]
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text(session.nickname)
                            .font(.footnote.weight(.semibold))
                        Text(session.style)
                            .font(.caption2.weight(.semibold))
                            .foregroundStyle(accent)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(accent.opacity(0.14), in: RoundedRectangle(cornerRadius: 6))
                        Spacer()
                        Text("tx \(session.bytesTx) · rx \(session.bytesRx)")
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                    Text("dest \(session.destinationHash) · out \(session.tunnelsOut) in \(session.tunnelsIn) · \(session.published ? "lease published" : "no lease yet")")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                .padding(.vertical, 4)
                if index < sessions.count - 1 {
                    Divider().opacity(0.3)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    // MARK: Client protocol reference

    private var apiCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Client Protocol Reference")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .textCase(.uppercase)
            commandRow("HELLO VERSION MIN=3.0 MAX=3.3",
                       caption: "negotiate — replies RESULT=OK VERSION=3.3")
            commandRow("SESSION CREATE STYLE=STREAM ID=s1 DESTINATION=TRANSIENT",
                       caption: "destination + tunnels + LeaseSet; PUB dest returned")
            commandRow("SESSION CREATE STYLE=DATAGRAM ID=d1 DESTINATION=<priv b64> PORT=7658",
                       caption: "imported keys; UDP replies to PORT")
            commandRow("STREAM CONNECT ID=s1 DESTINATION=<dest b64>",
                       caption: "outbound stream; raw bytes follow the OK reply")
            commandRow("STREAM ACCEPT ID=s1",
                       caption: "wait for an inbound stream; OK then raw bytes")
            commandRow("DATAGRAM SEND ID=d1 DESTINATION=<dest b64> SIZE=n",
                       caption: "repliable; the n payload bytes follow the line")
            commandRow("NAMING LOOKUP NAME=me.i2p / .b32.i2p / ME",
                       caption: "DHT LeaseSet + addressbook resolution")
            commandRow("NAMING ADD NAME=site.i2p DESTINATION=<b64>",
                       caption: "destination import into the addressbook")
            commandRow("DEST GENERATE",
                       caption: "PUB + PRIV destination keys (b64)")
            commandRow("SESSION QUIT",
                       caption: "close the session and connection")
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }

    private func commandRow(_ command: String, caption: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(command)
                .font(.system(.caption2, design: .monospaced).weight(.medium))
                .foregroundStyle(.primary)
                .lineLimit(1)
                .minimumScaleFactor(0.6)
            Text(caption)
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .padding(.vertical, 2)
    }

    // MARK: Activity log

    private var logCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Activity Log")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .textCase(.uppercase)
            ForEach(logLines.suffix(10).indices, id: \.self) { index in
                Text(logLines.suffix(10)[index])
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.head)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 18))
    }
}