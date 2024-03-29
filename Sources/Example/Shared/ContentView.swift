//
// Copyright © 2022 Daniel Farrelly
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
// *	Redistributions of source code must retain the above copyright notice, this list
//		of conditions and the following disclaimer.
// *	Redistributions in binary form must reproduce the above copyright notice, this
//		list of conditions and the following disclaimer in the documentation and/or
//		other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
// IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
// OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

import SwiftUI
import DropboxAuth

struct ContentView: View {

	class ViewModel: ObservableObject {

		private let authManager: AuthManager

		@Published var accessToken: AccessToken?

		init() {
			self.authManager = AuthManager(key: "d25u9w2pgql046o")
			self.accessToken = authManager.store.first
		}

		@MainActor
		func connect() async {
			#if targetEnvironment(macCatalyst) || os(macOS)
			// Authenticate in the user's preferred browser on macOS.
			authManager.authenticateInBrowser()
			#else
			// Authenticate locally on iOS and iPadOS.
			do {
				accessToken = try await authManager.authenticateLocally()
			}
			catch {
				print(error)
			}
			#endif
		}

		@MainActor
		func handle(_ redirectURI: URL) async {
			accessToken = try? await authManager.handle(redirectURI)
		}

		func disconnect() {
			do {
				try authManager.store.removeAll()

				accessToken = nil
			}
			catch {}
		}

	}

	@ObservedObject private var viewModel = ViewModel()

	@State private var isShowingAuthView = false

	@State private var connectTask: Task<Void, Never>?

	@State private var openURLTask: Task<Void, Never>?

	var body: some View {
		if let accessToken = viewModel.accessToken {
			VStack(spacing: 10) {
				AccountView(accessToken: accessToken)
					.multilineTextAlignment(.center)

				Button("Disconnect") {
					viewModel.disconnect()
				}
			}
			.scenePadding()
		}
		else {
			Button("Connect to Dropbox") {
				connectTask = Task {
					await viewModel.connect()
				}
			}
			.onOpenURL { redirectURI in
				openURLTask = Task {
					await viewModel.handle(redirectURI)
				}
			}
		}
    }

}

struct ContentView_Previews: PreviewProvider {

	static var previews: some View {
        ContentView()
    }

}
