//
//  I2PRouterHealthExport.swift
//  Exports retained local router-health samples as a shareable CSV file.
//

import Foundation
import CoreTransferable
import UniformTypeIdentifiers

struct I2PRouterHealthExportFile: Equatable, Sendable {
    let data: Data
    let fileName: String
    let subject: String
    let rowCount: Int
}

extension I2PRouterHealthExportFile: Transferable {
    static var transferRepresentation: some TransferRepresentation {
        FileRepresentation(exportedContentType: .commaSeparatedText) { export in
            try export.writeToTemporaryFile()
        }
    }

    private func writeToTemporaryFile() throws -> SentTransferredFile {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("router-health-exports", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent(fileName)
        try data.write(to: url, options: .atomic)
        return SentTransferredFile(url)
    }
}

enum I2PRouterHealthExport {
    static let appName = I2PAlignmentReportShare.appName
    static let header = "timestamp,availability,active_peer_count,ready_tunnel_count,received_bytes_delta,sent_bytes_delta,interruption_marker"

    static func payload(samples: [I2PRouterHealthSample],
                        capturedAt: Date = Date()) -> I2PRouterHealthExportFile? {
        let ordered = samples.sorted { $0.sampledAt < $1.sampledAt }
        guard !ordered.isEmpty else { return nil }
        return I2PRouterHealthExportFile(
            data: Data(csv(from: ordered).utf8),
            fileName: fileName(capturedAt: capturedAt),
            subject: "\(appName) router health history",
            rowCount: ordered.count)
    }

    static func csv(from samples: [I2PRouterHealthSample]) -> String {
        var lines = [header]
        for sample in samples.sorted(by: { $0.sampledAt < $1.sampledAt }) {
            let marker = sample.interruptionBefore.map {
                "\($0.cause.rawValue):\(timeStamp($0.startedAt)):\(number($0.duration))"
            } ?? ""
            let fields = [
                timeStamp(sample.sampledAt),
                sample.available ? "available" : "unavailable",
                String(max(0, sample.activePeers)),
                String(max(0, sample.readyTunnels)),
                String(max(0, sample.receivedBytes)),
                String(max(0, sample.sentBytes)),
                marker,
            ]
            lines.append(fields.map(csvField).joined(separator: ","))
        }
        return lines.joined(separator: "\n")
    }

    static func fileName(capturedAt: Date = Date()) -> String {
        "\(appName)-router-health-\(dateStamp(capturedAt)).csv"
    }

    static func timeStamp(_ date: Date) -> String {
        timeFormatter.string(from: date)
    }

    private static func csvField(_ value: String) -> String {
        guard value.contains(",") || value.contains("\"") || value.contains("\n") || value.contains("\r") else {
            return value
        }
        return "\"\(value.replacingOccurrences(of: "\"", with: "\"\""))\""
    }

    private static func number(_ value: TimeInterval) -> String {
        String(format: "%.1f", locale: Locale(identifier: "en_US_POSIX"), max(0, value))
    }

    private static let timeFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
        return formatter
    }()

    private static let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyy-MM-dd"
        return formatter
    }()

    private static func dateStamp(_ date: Date) -> String {
        dateFormatter.string(from: date)
    }
}
