//
//  SecurityManager.swift
//  AppAttestationExample
//
//  Created by Sean Erickson on 2/18/25.
//

import DeviceCheck
import CryptoKit

class SecurityManager {
    
    private init() {}
    
    static func generateKey() async throws {
        guard DCAppAttestService.shared.isSupported else { throw DCError(.featureUnsupported) }
        let keyId = try await DCAppAttestService.shared.generateKey()
        UserDefaults.standard.set(keyId, forKey: "AppAttestKeyId")
    }
    
    static func attestKey(challenge: Data) async throws -> String {
        // ensure a valid key has been created
        guard let keyId = UserDefaults.standard.string(forKey: "AppAttestKeyId") else { throw DCError(.invalidKey) }
        
        // create hash from challenge recieved from server
        let clientDataHash = Data(SHA256.hash(data: challenge))
        
        // generate attestation using locally generated key and server generated challenge hash
        let attestation = try await DCAppAttestService.shared.attestKey(keyId, clientDataHash: clientDataHash)
        
        // encode to string and return the attestation
        return attestation.base64EncodedString()
    }
    
    static func generateAssertion(challenge: Data) async throws -> (keyId: String, assertion: String) {
        // ensure a valid key has been created
        guard let keyId = UserDefaults.standard.string(forKey: "AppAttestKeyId") else { throw DCError(.invalidKey) }
        
        // create hash from challenge recieved from server
        let clientDataHash = Data(SHA256.hash(data: challenge))
        
        // generate assertion using existing key and server generated challenge hash
        let assertion = try await DCAppAttestService.shared.generateAssertion(keyId, clientDataHash: clientDataHash)
        
        // encode the assertion and return
        return (keyId: keyId, assertion: assertion.base64EncodedString())
    }
}
