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

	@Environment(\.authManager) private static var authManager

	@State private var accessToken: AccessToken? = ContentView.authManager.store.first

	@State private var isShowingAuthView = false

	var body: some View {
		if let accessToken = accessToken {
			VStack(spacing: 10) {
				AccountView(accessToken: accessToken)
					.multilineTextAlignment(.center)

				Button("Disconnect", action: disconnect)
			}
			.scenePadding()
		}
		else {
			Button("Connect to Dropbox", action: connect)
				.onOpenURL { url in
					Task {
						accessToken = try? await ContentView.authManager.handle(url)
					}
				}
		}
    }

	private func connect() {
		Task {
			#if targetEnvironment(macCatalyst) || os(macOS)
			// Authenticate in the user's preferred browser on macOS.
			await ContentView.authManager.authenticateInBrowser()
			#else
			// Authenticate locally on iOS and iPadOS.
			do {
				accessToken = try await ContentView.authManager.authenticateLocally()
			}
			catch {
				print(error)
			}
			#endif
		}
	}

	private func disconnect() {
		do {
			try ContentView.authManager.store.removeAll()

			accessToken = nil
		}
		catch {}
	}

}

struct ContentView_Previews: PreviewProvider {

	static var previews: some View {
        ContentView()
    }

}
