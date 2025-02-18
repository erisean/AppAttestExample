//
//  AppAttestationExampleApp.swift
//  AppAttestationExample
//
//  Created by Sean Erickson on 2/17/25.
//

import SwiftUI

@main
struct AppAttestationExampleApp: App {
    
    @State var error: Error?
    private let network = NetworkClient()
    
    var body: some Scene {
        WindowGroup {
            ContentView()
                .task {
                    if !SecurityManager.isAttested {
                        do {
                            try await network.attest()
                        } catch {
                            self.error = error
                        }
                    }
                }
        }
    }
}
