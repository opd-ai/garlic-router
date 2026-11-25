//
//  I2PRouterHealthExportTests.swift
//  Verifies router-health history is exported as a CSV file without unrelated data.
//

import Foundation
import Testing
@testable import Untitled1

struct I2PRouterHealthExportTests {
    private let start = Date(timeIntervalSince1970: 1_700_000_000)

    @Test func exportContainsRetainedSampleFieldsInTimestampOrder() throws {
        let later = sample(at: start.addingTimeInterval(60),
                           available: false,
                           peers: 2,
                           tunnels: 3,
                           received: 400,
                           sent: 50)
        let earlier = sample(at: start,
                             available: true,
                             peers: 4,
                             tunnels: 5,
                             received: 100,
                             sent: 25)
        let export = try #require(I2PRouterHealthExport.payload(
            samples: [later, earlier], capturedAt: start))
        let text = try #require(String(data: export.data, encoding: .utf8))
        let lines = text.components(separatedBy: "\n")

        #expect(lines[0] == "timestamp,availability,active_peer_count,ready_tunnel_count,received_bytes_delta,sent_bytes_delta,interruption_marker")
        #expect(lines.count == 3)
        #expect(lines[1] == "2023-11-14T22:13:20Z,available,4,5,100,25,")
        #expect(lines[2] == "2023-11-14T22:14:20Z,unavailable,2,3,400,50,")
        #expect(export.rowCount == 2)
    }

    @Test func interruptionMarkerIsIncludedWithItsCauseAndTiming() throws {
        let interruption = I2PRouterHealthInterruption(
            startedAt: start.addingTimeInterval(10), duration: 180, cause: .appSuspended)
        let marked = sample(at: start.addingTimeInterval(240),
                            available: true,
                            peers: 1,
                            tunnels: 2,
                            received: 30,
                            sent: 10,
                            interruption: interruption)
        let csv = I2PRouterHealthExport.csv(from: [marked])
        let row = try #require(csv.components(separatedBy: "\n").last)

        #expect(row == "2023-11-14T22:17:20Z,available,1,2,30,10,appSuspended:2023-11-14T22:13:30Z:180.0")
    }

    @Test func emptyHistoryHasNoExportAndFilenameUsesUTCDate() {
        #expect(I2PRouterHealthExport.payload(samples: []) == nil)
        #expect(I2PRouterHealthExport.fileName(capturedAt: start)
                == "garlic-router-router-health-2023-11-14.csv")
    }

    private func sample(at date: Date,
                        available: Bool,
                        peers: Int,
                        tunnels: Int,
                        received: Int,
                        sent: Int,
                        interruption: I2PRouterHealthInterruption? = nil) -> I2PRouterHealthSample {
        I2PRouterHealthSample(sampledAt: date,
                              available: available,
                              activePeers: peers,
                              readyTunnels: tunnels,
                              receivedBytes: received,
                              sentBytes: sent,
                              availableSeconds: 60,
                              interruptionBefore: interruption)
    }
}
