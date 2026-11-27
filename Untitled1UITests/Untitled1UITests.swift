//
//  Untitled1UITests.swift
//  Untitled1UITests
//
//  One launch smoke path for the app shell: the five tabs exist, each opens its
//  own screen, and the process is still in the foreground afterwards. It
//  replaces Apple's template, which launched the app and asserted nothing.
//
//  Deliberately narrow: the app has 40+ screens, so a full UI suite would be out
//  of proportion, but the shell is the journey every other screen hangs off.
//

import XCTest

final class Untitled1UITests: XCTestCase {

    /// The shell's tabs in the order the bar lists them, each paired with the
    /// title its root screen sets. One list, so a tab that is renamed or dropped
    /// fails this test instead of silently leaving the suite.
    private let tabs: [(label: String, title: String)] = [
        ("IRC", "IRC"),
        ("I2P Core", "I2P Core"),
        ("Router", "Router"),
        ("SAM", "SAM"),
        ("Alignment", "Alignment"),
    ]

    override func setUpWithError() throws {
        // A launch that fails makes every later step meaningless.
        continueAfterFailure = false
    }

    @MainActor
    func testEveryTabOpensItsScreen() throws {
        let app = XCUIApplication()
        // The first-run screen is one decision, not part of this journey. The
        // argument domain answers it for this launch only, so the test neither
        // starts the router nor writes anything the user's install would keep.
        app.launchArguments += ["-i2p.firstRun.completed", "YES"]
        app.launch()

        let tabBar = app.tabBars.firstMatch
        XCTAssertTrue(tabBar.waitForExistence(timeout: 30),
                      "the tab bar never appeared after launch")
        XCTAssertEqual(app.state, .runningForeground,
                       "the app is not in the foreground after launch")

        for tab in tabs {
            let button = tabBar.buttons[tab.label]
            XCTAssertTrue(button.exists,
                          "the \(tab.label) tab is missing from the tab bar")
            button.tap()
            XCTAssertTrue(app.navigationBars[tab.title].waitForExistence(timeout: 20),
                          "tapping \(tab.label) did not show the \(tab.title) screen")
            XCTAssertEqual(app.state, .runningForeground,
                           "the app left the foreground after opening \(tab.label)")
        }
    }
}
