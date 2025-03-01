//
//  NetworkClient.swift
//  AppAttestationExample
//
//  Created by Sean Erickson on 2/17/25.
//

import Foundation

class NetworkClient {
    
    enum Method: String {
        case get, post, put, patch
    }
    
    enum Body {
        case json([String: Any])
        case encodable(Encodable)
    }
    
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder
    private let session: URLSession
    
    init(session: URLSession = URLSession(configuration: .default)) {
        self.encoder = JSONEncoder()
        self.decoder = JSONDecoder()
        self.session = session
    }
    
    func makeRequest<Response: Decodable>(
        endpoint: URL,
        method: Method = .get,
        headers: [String: String] = [:],
        body: Body?
    ) async throws -> Response {
        let request = try buildRequest(url: endpoint, method: method, headers: headers, body: body)
        
        let (data, response) = try await dataRequest(for: request)
        
        guard let urlResponse = response as? HTTPURLResponse,
                urlResponse.statusCode >= 200 &&
                urlResponse.statusCode < 400
        else {
            throw URLError(.badServerResponse)
        }
        
        return try decoder.decode(Response.self, from: data)
    }
    
    func makeAuthRequest<Response: Decodable>(
        endpoint: URL,
        method: Method = .get,
        headers: [String: String] = [:],
        body: Body?
    ) async throws -> Response {
        let challengeUrl = URL(string: Endpoints.base.appending(Endpoints.challenge.rawValue))
        let challengeRequest = try buildRequest(url: challengeUrl!, method: .get, headers: [:], body: nil)
        
        Logger.logRequest(challengeRequest)
        let (challengeData, challengeResponse) = try await session.data(for: challengeRequest)
        Logger.logResponse(challengeResponse, data: challengeData)
        
        let (assertion, keyId) = try await SecurityManager.generateAssertion(challenge: challengeData)
        
        let securityHeaders = ["assertion": assertion, "keyid": keyId, "challenge": String(data: challengeData, encoding: .utf8) ?? ""]
        
        let requestHeaders = securityHeaders.merging(headers) { (current, _ ) in current }
        
        let request = try buildRequest(url: endpoint, method: method, headers: requestHeaders, body: body)
        
        Logger.logRequest(request)
        let (data, response) = try await session.data(for: request)
        Logger.logResponse(response, data: data)
        
        guard let urlResponse = response as? HTTPURLResponse,
                urlResponse.statusCode >= 200 &&
                urlResponse.statusCode < 400
        else {
            throw URLError(.badServerResponse)
        }
        
        return try decoder.decode(Response.self, from: data)
    }
    
    func attest() async throws {
        if SecurityManager.isAttested { return }
        
        try await SecurityManager.generateKey()
        
        let challengeUrl = URL(string: Endpoints.base.appending(Endpoints.challenge.rawValue))
        let (challengeData, challengeResponse) = try await dataRequest(for: URLRequest(url: challengeUrl!))
        
        let attestation = try await SecurityManager.attestKey(challenge: challengeData)
        
        let attestationUrl = URL(string: Endpoints.base.appending(Endpoints.attestation.rawValue))
        let (attestationData, attestationResponse) = try await dataRequest(for: URLRequest(url: attestationUrl!))
        
        Logger.log("Attest successful.", category: .security)
    }
    
    private func buildRequest(url: URL, method: Method, headers: [String: String], body: Body?) throws -> URLRequest {
        var request = URLRequest(url: url)
        request.httpMethod = method.rawValue
        for header in headers {
            request.setValue(header.value, forHTTPHeaderField: header.key)
        }
        
        switch body {
        case .json(let dictionary):
            if request.allHTTPHeaderFields?["Content-Type"] == nil {
                request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            }
            request.httpBody = try JSONSerialization.data(withJSONObject: dictionary)
        case .encodable(let encodable):
            request.httpBody = try encoder.encode(encodable)
        case nil:
            break
        }
        return request
    }
    private func dataRequest(for request: URLRequest) async throws -> (data: Data, response: URLResponse) {
        Logger.logRequest(request)
        let value = try await session.data(for: request)
        Logger.logResponse(value.1, data: value.0)
        return value
    }
}
