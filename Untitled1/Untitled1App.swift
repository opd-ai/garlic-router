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