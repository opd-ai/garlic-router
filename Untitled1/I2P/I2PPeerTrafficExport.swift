//
//  I2PPeerTrafficExport.swift
//  The peer inspector's Session traffic card as the share sheet gets it: the
//  readings the chart is drawing, one CSV row per plotted bucket, named for the
//  peer's shortened hash and the capture date.
//
//  The file carries exactly three columns — the bucket's time and the two
//  per-second rates — and nothing else. No peer address, no key material, no
//  tunnel ID and no message contents ever reach it: the buckets the chart draws
//  are the only source.
//

import Foundation
import CoreTransferable
import UniformTypeIdentifiers

// MARK: - File

/// One exported traffic window: the CSV bytes, the file name the share sheet
/// offers them under, the subject it shows above the sheet, and how many
/// readings the file holds.
struct I2PPeerTrafficExportFile: Equatable, Sendable {
    let data: Data
    /// e.g. `garlic-router-peer-a3f9c1d2e4b5-traffic-2026-11-17.csv`
    let fileName: String
    let subject: String
    /// One row per plotted bucket, header excluded.
    let rowCount: Int
}

extension I2PPeerTrafficExportFile: Transferable {
    static var transferRepresentation: some TransferRepresentation {
        FileRepresentation(exportedContentType: .commaSeparatedText) { export in
            try export.writeToTemporaryFile()
        }
    }

    /// Writes the bytes into the temporary directory so the share sheet gets the
    /// `.csv` file itself, carrying the peer-and-date name, instead of text.
    private func writeToTemporaryFile() throws -> SentTransferredFile {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("peer-traffic-exports", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent(fileName)
        try data.write(to: url, options: .atomic)
        return SentTransferredFile(url)
    }
}

// MARK: - Builder

enum I2PPeerTrafficExport {

    static let appName = I2PAlignmentReportShare.appName

    /// The one header row the file carries.
    static let header = "time,received_bytes_per_second,sent_bytes_per_second"

    /// The export for a set of chart buckets, or nil when nothing is charted —
    /// which is what keeps the share control disabled.
    ///
    /// `points` is what the chart draws (see `I2PPeerTrafficRecorder.points`), so
    /// the file holds one row per drawn bucket, oldest first.
    static func payload(peerID: String,
                        points: [I2PPeerTrafficPoint],
                        capturedAt: Date = Date()) -> I2PPeerTrafficExportFile? {
        let buckets = points.sorted { $0.at < $1.at }
        guard !buckets.isEmpty else { return nil }
        return I2PPeerTrafficExportFile(
            data: Data(csv(from: buckets).utf8),
            fileName: fileName(peerID: peerID, capturedAt: capturedAt),
            subject: subject(peerID: peerID),
            rowCount: buckets.count
        )
    }

    /// The same export from the raw per-second readings: bucket them exactly the
    /// way the inspector's chart does, then export those buckets.
    static func payload(peerID: String,
                        samples: [I2PPeerTrafficSample],
                        capturedAt: Date = Date()) -> I2PPeerTrafficExportFile? {
        payload(peerID: peerID,
                points: I2PPeerTrafficRecorder.points(from: samples),
                capturedAt: capturedAt)
    }

    /// The file's text: the header row, then one row per bucket in time order.
    static func csv(from points: [I2PPeerTrafficPoint]) -> String {
        var lines = [header]
        for point in points.sorted(by: { $0.at < $1.at }) {
            lines.append([
                timeStamp(point.at),
                number(point.receivedBytesPerSecond),
                number(point.sentBytesPerSecond),
            ].joined(separator: ","))
        }
        return lines.joined(separator: "\n")
    }

    /// `garlic-router-peer-a3f9c1d2e4b5-traffic-2026-11-17.csv`: the shortened
    /// peer hash and the day the readings were captured.
    static func fileName(peerID: String, capturedAt: Date = Date()) -> String {
        "\(appName)-peer-\(shortHash(peerID))-traffic-\(dateStamp(capturedAt)).csv"
    }

    /// What the share sheet shows above the sheet: it names the peer the file is
    /// about, so two exports are never confused.
    static func subject(peerID: String) -> String {
        "\(appName) peer traffic — \(shortHash(peerID))"
    }

    /// The first twelve characters of the identity hash, trimmed to what a file
    /// name can carry — no ellipsis, no spaces. An empty identity reads
    /// 'unknown' rather than leaving a gap in the name.
    static func shortHash(_ peerID: String, length: Int = 12) -> String {
        let cleaned = peerID
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .filter { $0.isLetter || $0.isNumber }
        guard !cleaned.isEmpty else { return "unknown" }
        let keep = max(4, length)
        guard cleaned.count > keep else { return cleaned }
        return String(cleaned.prefix(keep))
    }

    // MARK: Formatting

    /// A rate as one decimal with a dot, whatever the device's locale: a comma
    /// decimal mark would split the column in a spreadsheet.
    static func number(_ value: Double) -> String {
        String(format: "%.1f", locale: Locale(identifier: "en_US_POSIX"), max(0, value))
    }

    /// The bucket's time as an absolute instant — `2026-11-17T14:03:12Z` — so
    /// the file reads the same wherever it is opened.
    static let timeFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
        return formatter
    }()

    static func timeStamp(_ date: Date) -> String {
        timeFormatter.string(from: date)
    }

    /// The capture day as the file name carries it, in the device's own time
    /// zone so it reads as the day the user exported.
    private static let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd"
        return formatter
    }()

    private static func dateStamp(_ date: Date) -> String {
        dateFormatter.string(from: date)
    }
}

// MARK: - Self-test

enum I2PPeerTrafficExportSelfTest {
    static func runAll() -> [I2PSelfTestResult] {
        var results: [I2PSelfTestResult] = []
        func run(_ name: String, _ body: () throws -> String) {
            do {
                results.append(I2PSelfTestResult(name: name, passed: true, detail: try body()))
            } catch {
                results.append(I2PSelfTestResult(name: name, passed: false, detail: "\(error)"))
            }
        }

        let start = Date(timeIntervalSince1970: 1_700_000_000)

        run("Peer traffic export · one row per plotted bucket, oldest first") {
            let points = [
                I2PPeerTrafficPoint(id: 0, at: start, receivedBytesPerSecond: 2048,
                                    sentBytesPerSecond: 512),
                I2PPeerTrafficPoint(id: 1, at: start.addingTimeInterval(60),
                                    receivedBytesPerSecond: 4096,
                                    sentBytesPerSecond: 1024),
            ]
            let csv = I2PPeerTrafficExport.csv(from: points)
            let lines = csv.components(separatedBy: "\n")
            guard lines.count == 3,
                  lines[0] == "time,received_bytes_per_second,sent_bytes_per_second",
                  lines[1] == "2023-11-14T22:13:20Z,2048.0,512.0",
                  lines[2] == "2023-11-14T22:14:20Z,4096.0,1024.0" else {
                throw I2PWireError.invalidFormat
            }
            return "a header row and two rows, each the bucket's time and its two rates in UTC"
        }

        run("Peer traffic export · the rows follow time order whatever order they arrive in") {
            let later = I2PPeerTrafficPoint(id: 0, at: start.addingTimeInterval(120),
                                            receivedBytesPerSecond: 100,
                                            sentBytesPerSecond: 50)
            let earlier = I2PPeerTrafficPoint(id: 1, at: start,
                                              receivedBytesPerSecond: 300,
                                              sentBytesPerSecond: 200)
            let lines = I2PPeerTrafficExport.csv(from: [later, earlier])
                .components(separatedBy: "\n")
            guard lines.count == 3,
                  lines[1].hasPrefix("2023-11-14T22:13:20Z"),
                  lines[2].hasPrefix("2023-11-14T22:15:20Z") else {
                throw I2PWireError.invalidFormat
            }
            return "the older bucket was written first even though it arrived second"
        }

        run("Peer traffic export · nothing charted means no file at all") {
            guard I2PPeerTrafficExport.payload(peerID: "a3f9", points: []) == nil,
                  I2PPeerTrafficExport.payload(peerID: "a3f9", samples: []) == nil else {
                throw I2PWireError.invalidFormat
            }
            return "an empty window exports nothing, so the share control stays disabled"
        }

        run("Peer traffic export · the file is named for the peer hash and the capture date") {
            let point = I2PPeerTrafficPoint(id: 0, at: start, receivedBytesPerSecond: 1,
                                            sentBytesPerSecond: 2)
            guard let file = I2PPeerTrafficExport.payload(
                peerID: "a3f9c1d2e4b5a6970f12",
                points: [point],
                capturedAt: start) else {
                throw I2PWireError.invalidFormat
            }
            guard file.fileName.hasPrefix("garlic-router-peer-a3f9c1d2e4b5-traffic-"),
                  file.fileName.hasSuffix("-2023-11-14.csv"),
                  file.fileName.components(separatedBy: ".").count == 2,
                  file.rowCount == 1,
                  file.subject == "garlic-router peer traffic — a3f9c1d2e4b5",
                  String(data: file.data, encoding: .utf8)
                    == I2PPeerTrafficExport.csv(from: [point]) else {
                throw I2PWireError.invalidFormat
            }
            return "the name carries the 12-character hash and the day, with no ellipsis"
        }

        run("Peer traffic export · every row carries a time and two rates, nothing else") {
            let samples = (0..<4).map { index in
                I2PPeerTrafficSample(id: index,
                                     at: start.addingTimeInterval(Double(index)),
                                     bytesInPerSecond: 1024,
                                     bytesOutPerSecond: 512)
            }
            guard let file = I2PPeerTrafficExport.payload(peerID: "peer-a", samples: samples),
                  let text = String(data: file.data, encoding: .utf8) else {
                throw I2PWireError.invalidFormat
            }
            let lines = text.components(separatedBy: "\n")
            guard lines.count == file.rowCount + 1,
                  lines.allSatisfy({ $0.components(separatedBy: ",").count == 3 }),
                  lines[1] == "2023-11-14T22:13:20Z,1024.0,512.0",
                  lines.dropFirst().allSatisfy({ $0.hasSuffix(",1024.0,512.0") }) else {
                throw I2PWireError.invalidFormat
            }
            return "\(file.rowCount) rows of exactly three fields — timestamp, received, sent"
        }

        run("Peer traffic export · short hashes stay short and file-name safe") {
            guard I2PPeerTrafficExport.shortHash("a3f9c1d2e4b5a6970f12") == "a3f9c1d2e4b5",
                  I2PPeerTrafficExport.shortHash(" a3f9 ") == "a3f9",
                  I2PPeerTrafficExport.shortHash("") == "unknown",
                  I2PPeerTrafficExport.shortHash("   ") == "unknown",
                  I2PPeerTrafficExport.number(-9) == "0.0",
                  I2PPeerTrafficExport.number(1536) == "1536.0" else {
                throw I2PWireError.invalidFormat
            }
            return "20 hex characters flattened to 12, whitespace trimmed, a negative rate written as zero"
        }

        return results
    }
}
