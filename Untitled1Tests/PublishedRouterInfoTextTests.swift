//
//  PublishedRouterInfoTextTests.swift
//  Pins the wording and formatting the published-RouterInfo card and sheet
//  share: the publication line, the address endpoint, and the readable names
//  of the RouterInfo capability flags.
//

import Foundation
import Testing
@testable import Untitled1

struct PublishedRouterInfoTextTests {

    @Test func publishedLineNamesTheState() {
        let now = Date()
        #expect(I2PPublishedRouterInfoText.publishedStateLine(nil, now: now)
                .hasPrefix("Not published yet"))

        let line = I2PPublishedRouterInfoText.publishedStateLine(now.addingTimeInterval(-240), now: now)
        #expect(line.hasPrefix("Published "))
        #expect(line.contains("ago"))
    }

    @Test func endpointReadsHostAndPort() {
        let published = I2PRouterAddress(
            cost: 5,
            transportStyle: "NTCP2",
            expiration: nil,
            options: ["host": "203.0.113.7", "port": "21457"])
        #expect(I2PPublishedRouterInfoText.endpoint(published) == "203.0.113.7:21457")

        let hostOnly = I2PRouterAddress(
            cost: 14,
            transportStyle: "SSU2",
            expiration: nil,
            options: ["host": "203.0.113.7"])
        #expect(I2PPublishedRouterInfoText.endpoint(hostOnly) == "203.0.113.7")

        let unpublished = I2PRouterAddress(
            cost: 14,
            transportStyle: "SSU2",
            expiration: nil,
            options: ["s": "key", "v": "2"])
        #expect(I2PPublishedRouterInfoText.endpoint(unpublished) == "no host or port published")
    }

    @Test func capabilityFlagsReadAsTheSpecNames() {
        #expect(I2PPublishedRouterInfoText.capabilityName("f") == "floodfill")
        #expect(I2PPublishedRouterInfoText.capabilityName("R") == "reachable")
        #expect(I2PPublishedRouterInfoText.capabilityName("O") == "128–256 KB/s")
        // An unknown flag reads as itself rather than disappearing.
        #expect(I2PPublishedRouterInfoText.capabilityName("Z") == "Z")
        #expect(I2PPublishedRouterInfoText.capabilityList("fO") == "floodfill, 128–256 KB/s")
    }

    @Test func identityHashRendersAsHex() {
        #expect(I2PPublishedRouterInfoText.hex(Data([0x00, 0x0f, 0xff])) == "000fff")
    }
}
