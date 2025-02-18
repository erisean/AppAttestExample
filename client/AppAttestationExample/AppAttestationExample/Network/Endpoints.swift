//
//  Endpoints.swift
//  AppAttestationExample
//
//  Created by Sean Erickson on 2/18/25.
//

enum Endpoints: String {
    static var base: String { "https://appattestexample.onrender.com" }
    
    case challenge = "/challenge"
    case restricted = "/restricted"
    case authRestricted = "/auth/restricted"
    case attestation = "/verifyAttestation"
}
