//
//  Untitled1App.swift
//

import SwiftUI

@main
struct Untitled1App: App {
    init() {
        // Install signal-safe fatal-signal handlers before audit or transport
        // work so a minimal marker is available to next-launch diagnostics.
        I2PCrashReporter.install()
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}