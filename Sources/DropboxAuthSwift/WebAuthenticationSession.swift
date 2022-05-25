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

import Foundation
import AuthenticationServices

class WebAuthenticationSession: NSObject {

	private let session: ASWebAuthenticationSession

	private let windowProviderContainer: WindowProviderContainer?

	init(authManager: AuthManager, windowProvider: (@MainActor () -> AuthManager.Window)?, completion: ((Result<AccessToken, Swift.Error>) -> Void)?) {
		assert(Bundle.main.hasConfiguredScheme("db-\(authManager.appKey)"))

		self.session = ASWebAuthenticationSession(
			url: URL.authenticationURL(for: authManager)!,
			callbackURLScheme: "db-\(authManager.appKey)",
			completionHandler: { [weak authManager, completion] url, error in
				do {
					if let error = error {
						throw error
					}
					else if let url = url, let authManager = authManager {
						authManager.handle(url, completion: completion ?? { _ in })
					}
				}
				catch {
					completion?(.failure(error))
				}
			}
		)

		if #available(iOS 13.0, *), let windowProvider = windowProvider {
			let container = WindowProviderContainer(windowProvider: windowProvider)
			session.presentationContextProvider = container
			self.windowProviderContainer = container
		}
		else {
			self.windowProviderContainer = nil
		}
	}

	fileprivate class WindowProviderContainer: NSObject {

		let windowProvider: @MainActor () -> AuthManager.Window

		init(windowProvider: @escaping @MainActor () -> AuthManager.Window) {
			self.windowProvider = windowProvider
		}

	}

	private enum Error: Swift.Error {
		case unableToStart
	}

	func start() throws {
		if !session.start() {
			throw Error.unableToStart
		}
	}

}

@available(iOS 13.0, *)
extension WebAuthenticationSession.WindowProviderContainer: ASWebAuthenticationPresentationContextProviding {

	func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
		return DispatchQueue.main.sync { windowProvider() }
	}

}
