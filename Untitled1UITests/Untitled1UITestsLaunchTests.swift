//
//  Untitled1UITestsLaunchTests.swift
//  Untitled1UITests
//
//  The first-run journey: the one-time screen appears on a fresh launch, its
//  "Not now" path leaves the shell usable, and it does not come back. Replaces
//  Apple's template, which took a screenshot and asserted nothing.
//

import XCTest

final class Untitled1UITestsLaunchTests: XCTestCase {

    /// One configuration is enough: the screen is not configuration-specific, and
    /// a second run would start with the flag the first one set.
    override class var runsForEachTargetApplicationUIConfiguration: Bool {
        false
    }

    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    @MainActor
    func testFirstRunAppearsOnceAndCanBeSkipped() throws {
        let app = XCUIApplication()
        // The argument domain forces the flag off for this launch, so the screen
        // appears whatever a previous run left behind. Dismissing it writes the
        // flag to the standard domain, which the relaunch below reads — that
        // write is the behaviour under test, not a setup step.
        app.launchArguments += ["-i2p.firstRun.completed", "NO"]
        app.launch()

        let notNow = app.buttons["Not now"]
        XCTAssertTrue(notNow.waitForExistence(timeout: 30),
                      "the first-run screen did not appear on a fresh launch")

        let attachment = XCTAttachment(screenshot: app.screenshot())
        attachment.name = "First run"
        attachment.lifetime = .keepAlways
        add(attachment)

        notNow.tap()
        XCTAssertTrue(app.tabBars.firstMatch.waitForExistence(timeout: 20),
                      "the shell did not appear after dismissing the first run")

        app.terminate()

        // Relaunch with no arguments: the flag now comes from what the app wrote,
        // so a returning user meets the shell straight away.
        app.launchArguments = []
        app.launch()
        XCTAssertTrue(app.tabBars.firstMatch.waitForExistence(timeout: 30),
                      "the shell did not appear on the second launch")
        XCTAssertFalse(app.buttons["Not now"].waitForExistence(timeout: 5),
                       "the first-run screen appeared a second time")
    }
}
