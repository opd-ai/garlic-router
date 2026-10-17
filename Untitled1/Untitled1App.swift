//
//  Untitled1App.swift
//  The router's lifecycle rides the app's scene phase: graceful restart on
//  launch or foreground (the reachability advertisement re-runs, picking up
//  network-interface changes), clean shutdown on suspension or termination.
//

import SwiftUI

@main
struct Untitled1App: App {
    @Environment(\.scenePhase) private var scenePhase

    init() {
        // Persist the faulting context of any launch crash so the next run can
        // surface the exact failure point (crash-diagnostics card, core tab).
        I2PCrashReporter.install()
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
        .onChange(of: scenePhase) { _, phase in
            switch phase {
            case .active:
                I2PRouterAppContext.shared.resumeAfterBackground()
            case .background:
                I2PRouterAppContext.shared.shutdownForTermination()
            default:
                break
            }
        }
    }
}