//
//  I2PAlignmentJSONExport.swift
//  The truth table as the share sheet gets it: the JSON representation the
//  truth-table model already produces, written to a file named for the app
//  version and the export date (garlic-router-alignment-1.0-2026-11-17.json).
//
//  The file is the table's own export — coverage, intentional deviations,
//  defects and every row with its wire layout, encoding rules, cryptographic
//  parameters and edge cases — handed to the share sheet as a real .json file
//  rather than as pasted text. Nothing about peers, sessions or destinations is
//  in it: the truth table is the only source.
//

import Foundation
import CoreTransferable
import UniformTypeIdentifiers

// MARK: - Export

/// One exported truth table: the JSON bytes, the file name the share sheet
/// offers them under, and the subject it shows above the sheet.
struct I2PAlignmentJSONExportFile: Equatable, Sendable {
    let data: Data
    /// e.g. `garlic-router-alignment-1.0-2026-11-17.json`
    let fileName: String
    let subject: String
}

extension I2PAlignmentJSONExportFile: Transferable {
    static var transferRepresentation: some TransferRepresentation {
        FileRepresentation(exportedContentType: .json) { export in
            try export.writeToTemporaryFile()
        }
    }

    /// Writes the bytes into the temporary directory so the share sheet gets
    /// the file itself, carrying the version-and-date name, instead of text.
    private func writeToTemporaryFile() throws -> SentTransferredFile {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("alignment-exports", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent(fileName)
        try data.write(to: url, options: .atomic)
        return SentTransferredFile(url)
    }
}

// MARK: - Builder

enum I2PAlignmentJSONExport {

    static let appName = I2PAlignmentReportShare.appName

    /// The export for the app version in effect and the moment it is made, or
    /// nil when the truth table cannot be encoded (a coding bug; the table is
    /// always present and always encodable).
    static func export(generatedAt: Date = Date(),
                       appVersion: String = I2PAlignmentReportShare.marketingVersion()) -> I2PAlignmentJSONExportFile? {
        guard let data = try? I2PSpecTruthTable.jsonRepresentation() else { return nil }
        return I2PAlignmentJSONExportFile(
            data: data,
            fileName: fileName(appVersion: appVersion, generatedAt: generatedAt),
            subject: "\(appName) alignment truth table")
    }

    /// `garlic-router-alignment-1.0-2026-11-17.json`: the app's marketing
    /// version — the file name carries '1.0', not the report's provenance form
    /// '1.0 (build 1)' — and the export date.
    static func fileName(appVersion: String, generatedAt: Date = Date()) -> String {
        "\(appName)-alignment-\(versionComponent(appVersion))-\(dateStamp(generatedAt)).json"
    }

    // MARK: Formatting

    /// A version string reduced to what a file name can carry: anything outside
    /// letters, digits, dot, dash and underscore becomes a dash, and an empty
    /// version reads 'unknown' rather than leaving a gap in the name.
    static func versionComponent(_ version: String) -> String {
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_")
        let folded = String(version.map { character -> Character in
            character.unicodeScalars.allSatisfy { allowed.contains($0) } ? character : "-"
        })
        let trimmed = folded.trimmingCharacters(in: CharacterSet(charactersIn: "-._"))
        return trimmed.isEmpty ? "unknown" : trimmed
    }

    /// A fixed, locale-independent date so the file name reads the same
    /// wherever it was produced.
    private static let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd"
        return formatter
    }()

    private static func dateStamp(_ date: Date) -> String {
        dateFormatter.string(from: date)
    }
}
