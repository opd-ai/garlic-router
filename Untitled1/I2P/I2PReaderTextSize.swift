//
//  I2PReaderTextSize.swift
//  The eepsite browser's reader text size: the three named sizes its Aa control
//  cycles through, the metrics every reader block is laid out with, and the
//  store that keeps the choice across launches.
//

import Combine
import SwiftUI

// MARK: - Sizes

/// The reader's three text sizes — compact, default and large. A page reads in
/// the size in effect for its type, line spacing and block padding alike, and
/// the choice survives a relaunch.
enum I2PReaderTextSize: String, CaseIterable, Identifiable {
    case compact = "compact"
    case standard = "default"
    case large = "large"

    var id: String { rawValue }

    /// The name the Aa control shows for the size in effect.
    var label: String {
        switch self {
        case .compact: return "Compact"
        case .standard: return "Default"
        case .large: return "Large"
        }
    }

    /// How far the reader's type, line spacing and block padding grow. The
    /// default size is the reader's own scale, so every other size is a
    /// proportional step away from the plain page.
    var scale: CGFloat {
        switch self {
        case .compact: return 0.88
        case .standard: return 1
        case .large: return 1.18
        }
    }

    /// The size the Aa control steps to, wrapping from large around to compact.
    var next: I2PReaderTextSize {
        let all = Self.allCases
        guard let index = all.firstIndex(of: self) else { return .standard }
        return all[(index + 1) % all.count]
    }

    // MARK: Type

    /// A page's own title (`<h1>`): the size the rest of the block set steps
    /// away from.
    var titleSize: CGFloat { 32 * scale }
    /// `<h2>` and `<h3>`.
    var headingSize: CGFloat { 22 * scale }
    /// `<h4>` and below.
    var subheadingSize: CGFloat { 20 * scale }
    var bodySize: CGFloat { 17 * scale }
    var quoteSize: CGFloat { 16 * scale }
    var codeSize: CGFloat { 15 * scale }

    var titleFont: Font { .system(size: titleSize, weight: .bold) }

    func headingFont(level: Int) -> Font {
        .system(size: level <= 2 ? headingSize : subheadingSize, weight: .semibold)
    }

    var bodyFont: Font { .system(size: bodySize) }
    var bulletDotFont: Font { .system(size: bodySize, weight: .bold) }
    var quoteFont: Font { .system(size: quoteSize).italic() }
    var codeFont: Font { .system(size: codeSize, design: .monospaced) }

    // MARK: Spacing

    /// The air between two reader blocks and inside the page card, kept in the
    /// same proportion as the type.
    var blockSpacing: CGFloat { 14 * scale }
    var blockPadding: CGFloat { 18 * scale }
    var codePadding: CGFloat { 12 * scale }
    /// The gap inside a bullet or a quote, between its marker and its text.
    var inlineSpacing: CGFloat { 8 * scale }

    var bodyLineSpacing: CGFloat { 4 * scale }
    var bulletLineSpacing: CGFloat { 3 * scale }
    var quoteLineSpacing: CGFloat { 2 * scale }
}

// MARK: - Store

/// The reader's text size, kept across launches in user defaults. The Aa
/// control writes it; the reader reads it for every block it lays out, so a
/// live page and a kept copy are always drawn in the same size.
final class I2PReaderTextSizeStore: ObservableObject {
    static let shared = I2PReaderTextSizeStore()
    static let defaultsKey = "i2p.readerTextSize"

    @Published private(set) var size: I2PReaderTextSize

    private let defaults: UserDefaults
    private let storageKey: String

    init(defaults: UserDefaults = .standard,
         storageKey: String = I2PReaderTextSizeStore.defaultsKey) {
        self.defaults = defaults
        self.storageKey = storageKey
        self.size = Self.keptSize(defaults: defaults, key: storageKey)
    }

    /// Steps to the next size and keeps it: what the Aa control does.
    @discardableResult
    func cycle() -> I2PReaderTextSize {
        set(size.next)
        return size
    }

    /// Puts a size in effect and keeps it for the next launch.
    func set(_ value: I2PReaderTextSize) {
        if value != size { size = value }
        defaults.set(value.rawValue, forKey: storageKey)
    }

    /// The size kept from an earlier launch. Nothing kept — or a value this
    /// build does not know — reads as the default size.
    static func keptSize(defaults: UserDefaults, key: String) -> I2PReaderTextSize {
        guard let raw = defaults.string(forKey: key),
              let kept = I2PReaderTextSize(rawValue: raw) else { return .standard }
        return kept
    }
}

// MARK: - Self-test suite (reader text size)

enum I2PReaderTextSizeSelfTest {
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

        run("reader text size · three named sizes cycle in order and keep their metrics in proportion") {
            // Three sizes in steps, each naming itself, each with the raw value
            // that is persisted.
            guard I2PReaderTextSize.allCases == [.compact, .standard, .large],
                  I2PReaderTextSize.compact.label == "Compact",
                  I2PReaderTextSize.standard.label == "Default",
                  I2PReaderTextSize.large.label == "Large",
                  I2PReaderTextSize.compact.rawValue == "compact",
                  I2PReaderTextSize.standard.rawValue == "default",
                  I2PReaderTextSize.large.rawValue == "large" else {
                throw I2PWireError.invalidFormat
            }

            // The control steps compact → default → large → compact again, and
            // the default size is the reader's own scale of 1.
            guard I2PReaderTextSize.compact.next == .standard,
                  I2PReaderTextSize.standard.next == .large,
                  I2PReaderTextSize.large.next == .compact,
                  I2PReaderTextSize.standard.scale == 1,
                  I2PReaderTextSize.compact.scale < I2PReaderTextSize.standard.scale,
                  I2PReaderTextSize.standard.scale < I2PReaderTextSize.large.scale else {
                throw I2PWireError.invalidFormat
            }

            // Every size is the default one multiplied by its own scale: the
            // title, both heading levels, body, quote and code type, and the
            // line spacing, inline gap, code padding and block padding with
            // them, so nothing grows out of step with anything else.
            let basis = I2PReaderTextSize.standard
            let basisValues: [CGFloat] = [
                basis.titleSize, basis.headingSize, basis.subheadingSize,
                basis.bodySize, basis.quoteSize, basis.codeSize,
                basis.blockSpacing, basis.blockPadding, basis.codePadding,
                basis.inlineSpacing, basis.bodyLineSpacing,
                basis.bulletLineSpacing, basis.quoteLineSpacing
            ]
            guard basisValues == [32, 22, 20, 17, 16, 15, 14, 18, 12, 8, 4, 3, 2] else {
                throw I2PWireError.invalidFormat
            }

            for size in I2PReaderTextSize.allCases {
                let values: [CGFloat] = [
                    size.titleSize, size.headingSize, size.subheadingSize,
                    size.bodySize, size.quoteSize, size.codeSize,
                    size.blockSpacing, size.blockPadding, size.codePadding,
                    size.inlineSpacing, size.bodyLineSpacing,
                    size.bulletLineSpacing, size.quoteLineSpacing
                ]
                guard values.count == basisValues.count else {
                    throw I2PWireError.invalidFormat
                }
                for (value, base) in zip(values, basisValues) {
                    guard abs(value - base * size.scale) < 0.0001 else {
                        throw I2PWireError.invalidFormat
                    }
                }
                // The reader's proportions hold at every size: the padding
                // against the body sits at the same ratio throughout.
                guard abs(size.blockPadding / size.bodySize
                          - basis.blockPadding / basis.bodySize) < 0.0001,
                      abs(size.bodyLineSpacing / size.bodySize
                          - basis.bodyLineSpacing / basis.bodySize) < 0.0001,
                      size.headingSize > size.bodySize,
                      size.bodySize > size.quoteSize,
                      size.quoteSize > size.codeSize else {
                    throw I2PWireError.invalidFormat
                }
            }
            return "compact/default/large step in order and wrap; every type and spacing metric is the default's × its scale, block padding and line spacing staying proportional to the body"
        }

        run("reader text size · the choice cycles and is kept across launches") {
            let suite = "i2p.readerTextSize.selfTest"
            let defaults = UserDefaults(suiteName: suite) ?? .standard
            defaults.removePersistentDomain(forName: suite)
            let key = "reader"

            // Nothing kept yet reads as the default size.
            let store = I2PReaderTextSizeStore(defaults: defaults, storageKey: key)
            guard store.size == .standard,
                  I2PReaderTextSizeStore.keptSize(defaults: defaults, key: key) == .standard else {
                throw I2PWireError.invalidFormat
            }

            // Cycling steps the size and writes it out.
            guard store.cycle() == .large, store.size == .large,
                  I2PReaderTextSizeStore.keptSize(defaults: defaults, key: key) == .large,
                  defaults.string(forKey: key) == "large" else {
                throw I2PWireError.invalidFormat
            }
            // A store built as if by the next launch reads the same size, and
            // keeps stepping from there.
            let relaunched = I2PReaderTextSizeStore(defaults: defaults, storageKey: key)
            guard relaunched.size == .large,
                  relaunched.cycle() == .compact,
                  relaunched.size == .compact,
                  I2PReaderTextSizeStore.keptSize(defaults: defaults, key: key) == .compact,
                  I2PReaderTextSizeStore(defaults: defaults, storageKey: key).size == .compact else {
                throw I2PWireError.invalidFormat
            }
            // Setting a size writes it without disturbing the cycle, and
            // setting the size already in effect leaves it where it is.
            relaunched.set(.large)
            guard relaunched.size == .large,
                  I2PReaderTextSizeStore.keptSize(defaults: defaults, key: key) == .large else {
                throw I2PWireError.invalidFormat
            }
            relaunched.set(.large)
            guard relaunched.size == .large,
                  relaunched.cycle() == .compact else {
                throw I2PWireError.invalidFormat
            }
            // A value this build does not know falls back to the default size
            // instead of failing to open the page.
            defaults.set("enormous", forKey: key)
            guard I2PReaderTextSizeStore(defaults: defaults, storageKey: key).size == .standard,
                  I2PReaderTextSizeStore.keptSize(defaults: defaults, key: key) == .standard else {
                throw I2PWireError.invalidFormat
            }
            defaults.removePersistentDomain(forName: suite)
            return "a fresh store reads the default size; cycling writes each size out; a relaunched store reads the kept size and steps from it; an unknown kept value reads as the default"
        }

        return results
    }
}
