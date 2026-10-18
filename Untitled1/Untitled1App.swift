//
//  Untitled1App.swift
//

import SwiftUI

@main
struct Untitled1App: App {
    init() {
        // Install fatal-signal handlers before any audit or transport work so
        // a crash anywhere — including mid-audit — persists its backtrace for
        // the next launch's crash-diagnostics surface.
        I2PCrashReporter.install()
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}