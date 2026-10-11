//  ConcurrentAssertionTest.swift
import Foundation
import Security
import DeviceCheck
import CryptoKit
import Testing

@Test(
  arguments: 0..<256
)
func testAssertions(it: UInt64) async throws {
  let keyId = try await KeyIdStore.keyId
  let clientDataHash = Data(SHA256.hash(data: Data("\(UUID().uuidString)".utf8)))
  await #expect(throws: Never.self) {
    let assertion = try await DCAppAttestService.shared.generateAssertion(keyId, clientDataHash: clientDataHash)
    print("\(it): \(assertion.count)")
  }
}



enum KeyIdStore {
  static var keyId: String {
    @AttestActor get async throws {
      if let task {
        return try await task.value
      }
      task = Task {
        if let keyId = try load() {
          return keyId
        }
        
        let keyID = try await attestService.generateKey()
        let clientDataHash = Data(SHA256.hash(data: Data(service.utf8)))
        let attestation = try await attestService.attestKey(keyID, clientDataHash: clientDataHash)
        print("Attestation length: \(attestation.count)")
        try save(keyId: keyID)
        return keyID
      }
      return try await task!.value
    }
  }
  
  static var task: Task<String, any Error>?

  static let attestService = DCAppAttestService.shared
  static let service = "com.example.test"
  static let account = "key-id"
  
  static func save(keyId: String, expiresAfter seconds: TimeInterval = 60 * 60 * 24) throws {
    let keyIdData = Data(keyId.utf8)
    
    let expirationDate = Date().addingTimeInterval(seconds)
    let expirationString = String(expirationDate.timeIntervalSince1970)
    
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
      kSecAttrGeneric as String: Data(expirationString.utf8),
      kSecValueData as String: keyIdData
    ]
    
    SecItemDelete(query as CFDictionary)
    let status = SecItemAdd(query as CFDictionary, nil)
    guard status == errSecSuccess else {
      throw status.asKeychainError
    }
  }
  
  static func load() throws -> String? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
      kSecReturnData as String: true,
      kSecReturnAttributes as String: true // Return attributes too
    ]
    
    var itemRef: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &itemRef)
    
    guard status == errSecSuccess,
          let dict = itemRef as? [String: Any],
          let data = dict[kSecValueData as String] as? Data,
          let genericData = dict[kSecAttrGeneric as String] as? Data,
          let expiryString = String(data: genericData, encoding: .utf8),
          let expiryTimestamp = Double(expiryString) else {
      return nil
    }
    
    // Check if expired
    if Date().timeIntervalSince1970 > expiryTimestamp {
      let deleteQuery: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account
      ]
      SecItemDelete(deleteQuery as CFDictionary)
      return nil
    }
    
    return String(decoding: data, as: UTF8.self)
  }

}

extension OSStatus {
  /// Converts a Security framework OSStatus code into a detailed NSError.
  var asKeychainError: NSError {
    // Retrieve the system message for this error status code
    let message = SecCopyErrorMessageString(self, nil) as String?
    ?? "Unknown Keychain error code: \(self)"
    
    return NSError(
      domain: NSOSStatusErrorDomain,
      code: Int(self),
      userInfo: [
        NSLocalizedDescriptionKey: message,
        NSLocalizedFailureReasonErrorKey: "Keychain API operation failed."
      ]
    )
  }
}

@globalActor
actor AttestActor {
    static let shared = AttestActor()
}
