//
//  I2PLastReadPage.swift
//  The most recent address shown in the eepsite browser, persisted so the empty
//  browser can offer to continue with a live fetch or a kept copy.
//

import Foundation
import Combine

/// The address the browser last showed and when it was last read.
struct I2PLastReadPage: Codable, Equatable {
    let address: String
    let lastReadAt: Date
}

/// Persists one continuation address and the address the user dismissed.
/// Dismissal remains in effect for that address until a different address is
/// read and replaces it.
final class I2PLastReadPageStore: ObservableObject {
    static let shared = I2PLastReadPageStore()
    static let defaultsKey = "i2p.lastReadPage"

    @Published private(set) var page: I2PLastReadPage?

    private let defaults: UserDefaults
    private let storageKey: String
    @Published private(set) var dismissedAddress: String?

    private struct StoredState: Codable {
        var page: I2PLastReadPage?
        var dismissedAddress: String?
    }

    init(defaults: UserDefaults = .standard,
         storageKey: String = I2PLastReadPageStore.defaultsKey) {
        self.defaults = defaults
        self.storageKey = storageKey
        let state = Self.load(defaults: defaults, key: storageKey)
        self.page = state.page
        self.dismissedAddress = state.dismissedAddress
    }

    /// Whether the continuation card should be offered in the browser's empty
    /// state.
    var shouldOffer: Bool {
        guard let page else { return false }
        return dismissedAddress != page.address
    }

    /// Records a valid I2P address. A different address replaces the previous
    /// one and makes the new address eligible to be offered again.
    @discardableResult
    func recordRead(_ rawAddress: String, at date: Date = Date()) -> Bool {
        let trimmed = rawAddress.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let visit = I2PEepsiteVisit(rawValue: trimmed) else { return false }
        let address = visit.display
        if page?.address != address {
            dismissedAddress = nil
        }
        page = I2PLastReadPage(address: address, lastReadAt: date)
        persist()
        return true
    }

    /// Stops offering the current address from the empty state.
    func dismiss() {
        guard let page else { return }
        dismissedAddress = page.address
        persist()
    }

    private func persist() {
        let state = StoredState(page: page, dismissedAddress: dismissedAddress)
        guard let data = try? JSONEncoder().encode(state) else { return }
        defaults.set(data, forKey: storageKey)
    }

    private static func load(defaults: UserDefaults, key: String) -> StoredState {
        guard let data = defaults.data(forKey: key),
              let state = try? JSONDecoder().decode(StoredState.self, from: data) else {
            return StoredState(page: nil, dismissedAddress: nil)
        }
        return state
    }
}

// MARK: - Self-test suite

enum I2PLastReadPageSelfTest {
    static func runAll() -> [I2PSelfTestResult] {
        var results: [I2PSelfTestResult] = []
        func run(_ name: String, _ body: () throws -> String) {
            do {
                let detail = try body()
                results.append(I2PSelfTestResult(name: name, passed: true, detail: detail))
            } catch {
                results.append(I2PSelfTestResult(name: name, passed: false,
                                                 detail: String(describing: error)))
            }
        }

        run("eepsite browser · last-read address persists and dismissal follows that address") {
            let suite = "i2p.lastReadPage.selfTest.\(UUID().uuidString)"
            guard let defaults = UserDefaults(suiteName: suite) else {
                throw I2PWireError.invalidFormat
            }
            defer { defaults.removePersistentDomain(forName: suite) }

            let firstRead = Date(timeIntervalSince1970: 1_700_000_000)
            let laterRead = firstRead.addingTimeInterval(300)
            let store = I2PLastReadPageStore(defaults: defaults, storageKey: "last-read")
            guard !store.shouldOffer,
                  !store.recordRead("example.com", at: firstRead),
                  store.recordRead("HTTPS://Wiki.i2p:8080/wiki/Main_Page", at: firstRead),
                  store.page == I2PLastReadPage(address: "wiki.i2p/wiki/Main_Page",
                                                lastReadAt: firstRead),
                  store.shouldOffer else {
                throw I2PWireError.invalidFormat
            }

            let reopened = I2PLastReadPageStore(defaults: defaults, storageKey: "last-read")
            guard reopened.page == store.page, reopened.shouldOffer else {
                throw I2PWireError.invalidFormat
            }
            reopened.dismiss()
            guard !reopened.shouldOffer else { throw I2PWireError.invalidFormat }

            // Dismissal persists and remains for the same address, even when it
            // is read again; a different address replaces it and is offered.
            let dismissed = I2PLastReadPageStore(defaults: defaults, storageKey: "last-read")
            guard !dismissed.shouldOffer,
                  dismissed.recordRead("wiki.i2p/wiki/Main_Page", at: laterRead),
                  !dismissed.shouldOffer,
                  dismissed.recordRead("other.i2p", at: laterRead),
                  dismissed.shouldOffer,
                  dismissed.page == I2PLastReadPage(address: "other.i2p",
                                                    lastReadAt: laterRead) else {
                throw I2PWireError.invalidFormat
            }
            return "canonical address and read time persist; a dismissed address stays hidden; reading a different address replaces it and clears the dismissal"
        }

        return results
    }
}
