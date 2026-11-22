//
//  I2PPeerTrafficExportTests.swift
//  Pins the peer inspector's CSV export: one header row, one row per plotted
//  bucket oldest first, a file named for the peer's shortened hash and the
//  capture date, and nothing in it but the timestamps and the two rates.
//

import Foundation
import Testing
@testable import Untitled1

struct I2PPeerTrafficExportTests {

    private let start = Date(timeIntervalSince1970: 1_700_000_000)

    private func point(_ index: Int,
                       received: Double,
                       sent: Double) -> I2PPeerTrafficPoint {
        I2PPeerTrafficPoint(id: index,
                            at: start.addingTimeInterval(Double(index) * 60),
                            receivedBytesPerSecond: received,
                            sentBytesPerSecond: sent)
    }

    @Test func headerAndOneRowPerBucketOldestFirst() throws {
        let export = try #require(I2PPeerTrafficExport.payload(
            peerID: "a3f9c1d2e4b5a6970f12",
            points: [point(1, received: 4096, sent: 1024),
                     point(0, received: 2048, sent: 512)],
            capturedAt: start))
        let text = try #require(String(data: export.data, encoding: .utf8))
        let lines = text.components(separatedBy: "\n")

        #expect(lines[0] == "time,received_bytes_per_second,sent_bytes_per_second")
        #expect(lines.count == 3)
        #expect(export.rowCount == 2)
        #expect(lines[1] == "2023-11-14T22:13:20Z,2048.0,512.0")
        #expect(lines[2] == "2023-11-14T22:14:20Z,4096.0,1024.0")
    }

    @Test func fileNameCarriesTheShortHashAndCaptureDate() {
        let name = I2PPeerTrafficExport.fileName(peerID: "a3f9c1d2e4b5a6970f12",
                                                capturedAt: start)
        #expect(name == "garlic-router-peer-a3f9c1d2e4b5-traffic-\(dateStamp(start)).csv")
        #expect(!name.contains("…"))
        #expect(name.hasSuffix(".csv"))
    }

    @Test func nothingChartedExportsNothing() {
        #expect(I2PPeerTrafficExport.payload(peerID: "a3f9", points: []) == nil)
        #expect(I2PPeerTrafficExport.payload(peerID: "a3f9", samples: []) == nil)
    }

    @Test func exportCarriesTimestampsAndRatesOnly() throws {
        let samples = (0..<3).map { index in
            I2PPeerTrafficSample(id: index,
                                 at: start.addingTimeInterval(Double(index)),
                                 bytesInPerSecond: 1024,
                                 bytesOutPerSecond: 512)
        }
        let export = try #require(I2PPeerTrafficExport.payload(peerID: "peer-a",
                                                              samples: samples))
        #expect(export.subject == "garlic-router peer traffic — peer-a")

        let text = try #require(String(data: export.data, encoding: .utf8))
        let lines = text.components(separatedBy: "\n")
        #expect(lines.count == samples.count + 1)
        for line in lines {
            #expect(line.components(separatedBy: ",").count == 3, "a row carries an extra field")
        }
        #expect(!text.contains("peer-a"), "the file names the peer")
        for key in ["transport", "address", "key", "tunnel", "message"] {
            #expect(!text.lowercased().contains(key), "the file carries \(key)")
        }
    }

    private func dateStamp(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd"
        return formatter.string(from: date)
    }
}
