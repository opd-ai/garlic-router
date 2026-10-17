//
//  I2PReadinessAudit.swift
//  Bounded, mobile-safe checks for the in-app readiness summary.
//

import Foundation

/// Categories represented by the lightweight readiness checks. Computationally
/// intensive signature suites, Keychain mutation and live transport tests are
/// deliberately kept out of this button: they belong in their dedicated suites,
/// not in a single on-device audit that can terminate the app under load.
enum I2PReadinessArea: String, CaseIterable {
    case networkCompat = "Network compatibility & interoperability"
    case crypto = "Cryptographic correctness & security"
    case identity = "Router identity & certificate management"
    case transports = "Transport layer (NTCP2 & SSU2)"
    case tunnels = "Tunnel architecture & build process"
    case garlic = "Garlic routing & end-to-end encryption"
    case netdb = "Network database & floodfill integration"
    case robustness = "Error handling & robustness"
    case iosRuntime = "iOS runtime & Milq integration"
    case compliance = "Compliance & security hardening"
}

enum I2PReadinessAudit {
    static func runAll() async -> [I2PSelfTestResult] {
        var results: [I2PSelfTestResult] = []

        func record(_ name: String, _ body: () throws -> String) {
            do {
                results.append(I2PSelfTestResult(name: name, passed: true, detail: try body()))
            } catch {
                results.append(I2PSelfTestResult(name: name, passed: false, detail: String(describing: error)))
            }
        }

        // These checks are deterministic and bounded. They do not perform
        // signature operations, create keys, touch Keychain, open sockets, or
        // access the shared router context.
        record("Readiness · modern algorithm policy") {
            try I2PCryptoPolicy.audit()
            return "Algorithm registries contain only the configured modern I2P types."
        }

        record("Readiness · I2NP type-code table") {
            let expected: [(I2NPMessageType, UInt8)] = [
                (.databaseStore, 1), (.databaseLookup, 2), (.databaseSearchReply, 3),
                (.deliveryStatus, 4), (.garlic, 5), (.tunnelData, 6),
                (.tunnelGateway, 7), (.dataMessage, 8), (.tunnelBuild, 21),
                (.tunnelBuildReply, 22)
            ]
            guard expected.allSatisfy({ $0.0.rawValue == $0.1 }) else {
                throw I2PWireError.invalidFormat
            }
            return "All 10 registered I2NP type codes match the expected table."
        }

        record("Readiness · tunnel lifetime bounds") {
            var config = I2PTunnelPool.Config()
            config.lifetime = 100
            guard config.clampedLifetime == 600 else { throw I2PWireError.invalidFormat }
            config.lifetime = 5_000
            guard config.clampedLifetime == 1_800 else { throw I2PWireError.invalidFormat }
            return "Configured tunnel lifetimes remain clamped to the supported 10–30 minute range."
        }

        record("Readiness · specification tracking integrity") {
            let rows = I2PSpecTruthTable.rows
            let ids = rows.map(\.id)
            guard Set(ids).count == ids.count else { throw I2PWireError.invalidFormat }
            guard I2PSpecTruthTable.defects.allSatisfy({
                $0.deviation?.classification == .defect && !($0.deviation?.trackingRef ?? "").isEmpty
            }) else { throw I2PWireError.invalidFormat }
            let defectCount = I2PSpecTruthTable.defects.count
            return "\(rows.count) specification rows have unique identifiers; all \(defectCount) tracked defects include a follow-up reference."
        }

        results.append(I2PSelfTestResult(
            name: "Readiness · extended checks not run",
            passed: true,
            detail: "This mobile-safe audit intentionally skips CPU-intensive pure-Swift signature suites, Keychain mutation, and live network/UDP tests. Those checks are not represented as verified here."))

        let checks = results.filter { $0.name.hasPrefix("Readiness ·") && $0.name != "Readiness · extended checks not run" }
        let passing = checks.filter(\.passed).count
        results.append(I2PSelfTestResult(
            name: "Readiness · bounded audit summary",
            passed: passing == checks.count,
            detail: "\(passing)/\(checks.count) bounded checks passed. Extended cryptographic and live-transport readiness remains unverified by this mobile-safe audit."))
        return results
    }
}
