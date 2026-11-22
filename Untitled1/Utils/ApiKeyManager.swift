//
//  ApiKeyManager.swift
//  Untitled1
//
//  Secure storage for API keys using Keychain Services
//

import Foundation
import Security
import CryptoKit

/// Manages secure storage of API keys in Keychain
class ApiKeyManager {
    
    // MARK: - Singleton
    
    static let shared = ApiKeyManager()
    
    private init() {
        // Initialize keys from encrypted file on first launch
        UserDefaults.standard.removeObject(forKey: initializationKey)
        initializeKeysFromEncryptedFile()
    }
    
    // MARK: - Properties
    
    // Use the app's bundle identifier as the service name
    private var service: String {
        return Bundle.main.bundleIdentifier ?? "com.projectname.apiKeys"
    }
    
    // UserDefaults key to track initialization
    private let initializationKey = "ApiKeyManager_Initialized"
    
    // Get project name from bundle (should match what Swifty used for encryption)
    private var projectName: String {
        // Try to get from bundle identifier or use a default
        if let bundleId = Bundle.main.bundleIdentifier {
            // Extract project name from bundle ID (e.g., "com.example.MyApp" -> "MyApp")
            let components = bundleId.components(separatedBy: ".")
            return components.last ?? "Untitled1"
        }
        return "Untitled1"
    }
    
    // MARK: - Public Methods
    
    /// Retrieve an API key from Keychain
    /// - Parameter key: The key name (e.g., "OPENAI_API_KEY")
    /// - Returns: The API key value, or nil if not found
    func get(key: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        if status == errSecSuccess,
           let data = result as? Data,
           let string = String(data: data, encoding: .utf8) {
            return string
        }
        
        return nil
    }
    
    /// Check if an API key exists in Keychain
    /// - Parameter key: The key name
    /// - Returns: True if the key exists, false otherwise
    func has(key: String) -> Bool {
        return get(key: key) != nil
    }
    
    // MARK: - Private Methods
    
    /// Initializes API keys from the encrypted file on first launch.
    private func initializeKeysFromEncryptedFile() {
        guard !UserDefaults.standard.bool(forKey: initializationKey) else { return }

        guard let bundlePath = Bundle.main.path(forResource: "ENCRYPTED_KEYS", ofType: "plist"),
              let plistData = try? Data(contentsOf: URL(fileURLWithPath: bundlePath)),
              let plist = try? PropertyListSerialization.propertyList(
                from: plistData, options: [], format: nil) as? [String: Any] else {
            UserDefaults.standard.set(true, forKey: initializationKey)
            return
        }

        for (key, encryptedValue) in plist {
            guard let encryptedString = encryptedValue as? String,
                  let decryptedValue = decryptValue(encryptedString, projectName: projectName) else {
                continue
            }
            _ = save(key: key, value: decryptedValue)
        }

        UserDefaults.standard.set(true, forKey: initializationKey)
    }
    
    /// Save an API key to Keychain
    /// - Parameters:
    ///   - key: The key name
    ///   - value: The API key value
    /// - Returns: True if successful, false otherwise
    private func save(key: String, value: String) -> Bool {
        guard let data = value.data(using: .utf8) else {
            return false
        }
        
        // Delete existing item first (if any)
        delete(key: key)
        
        // Create query for saving
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked
        ]
        
        let status = SecItemAdd(query as CFDictionary, nil)
        return status == errSecSuccess
    }
    
    /// Delete an API key from Keychain
    /// - Parameter key: The key name
    /// - Returns: True if successful, false otherwise
    private func delete(key: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }
    
    /// Decrypts an encrypted API key value
    /// - Parameters:
    ///   - encryptedValue: Base64-encoded encrypted string
    ///   - projectName: Project name used to derive decryption key
    /// - Returns: Decrypted API key value, or nil if decryption fails
    private func decryptValue(_ encryptedValue: String, projectName: String) -> String? {
        guard let encryptedData = Data(base64Encoded: encryptedValue),
              let sealedBox = try? AES.GCM.SealedBox(combined: encryptedData) else {
            return nil
        }

        let decryptionKey = deriveKey(from: projectName)
        guard let decryptedData = try? AES.GCM.open(sealedBox, using: decryptionKey) else {
            return nil
        }
        return String(data: decryptedData, encoding: .utf8)
    }
    
    /// Derives a symmetric key from project name using SHA256
    /// - Parameter projectName: Project name
    /// - Returns: Symmetric key for encryption/decryption
    private func deriveKey(from projectName: String) -> SymmetricKey {
        // Use SHA256 hash of project name as key material
        let keyData = SHA256.hash(data: projectName.data(using: .utf8) ?? Data())
        return SymmetricKey(data: keyData)
    }
}
