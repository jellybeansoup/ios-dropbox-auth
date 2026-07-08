//
// Copyright © 2025 Daniel Farrelly
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

@MainActor
class WebAuthenticationSession: NSObject {

	/// A typealias for the completion handler used in the authentication flow.
	typealias CompletionHandler = @MainActor @Sendable (Result<AccessToken, Swift.Error>) -> Void

	/// The underlying authentication session.
	let session: ASWebAuthenticationSession

	/// Container for the window provider, which acts as the context provider for the `session`.
	let windowProviderContainer: WindowProviderContainer

	/// Initializes a new web authentication session.
	/// - Important: Before using this class, ensure that the appropriate custom URL scheme has been configured in the app's Info.plist file.
	/// - Parameters:
	///   - authManager: An instance of the ``AuthManager`` this session acts on behalf of.
	///   - windowProvider: A closure providing a window for presenting the authentication session UI.
	///   - completion: A closure to be called upon completion of the authentication flow, providing the result of the authentication attempt.
	init(
		authManager: AuthManager,
		windowProvider: @escaping AuthManager.WindowProvider,
		completion: @escaping CompletionHandler
	) {
		assert(Bundle.main.hasConfiguredScheme("db-\(authManager.appKey)"))

		self.session = ASWebAuthenticationSession(
			url: authManager.authenticationURL!,
			callbackURLScheme: "db-\(authManager.appKey)",
			completionHandler: { [weak authManager, completion] url, error in
				WebAuthenticationSession.handleCompletion(url: url, error: error, authManager: authManager, completion: completion)
			}
		)

		self.windowProviderContainer = WindowProviderContainer(windowProvider: windowProvider)
		session.presentationContextProvider = windowProviderContainer
	}

	/// Starts the web authentication session.
	/// - Throws: An error if the session cannot be started.
	func start() throws {
		try WebAuthenticationSession.throwIfFailedToStart(session.start())
	}

	/// Maps an `ASWebAuthenticationSession` completion callback (`url`, `error`) to this type's
	/// `CompletionHandler`, exactly as `init` above wires it up.
	///
	/// - Important: Extracted as a `Bundle`/assertion-independent pure function (taking
	///   `authManager` as a plain, already-weakened optional rather than capturing it) specifically
	///   so it's unit-testable: constructing a real `WebAuthenticationSession` trips the
	///   scheme-configuration assertion in `init` on any host — like the unit test bundle — whose
	///   `Bundle.main` has no `CFBundleURLTypes` entry, regardless of the URL/error values under
	///   test. This function has no such dependency, so it can be exercised directly.
	static func handleCompletion(
		url: URL?,
		error: Swift.Error?,
		authManager: AuthManager?,
		completion: @escaping CompletionHandler
	) {
		do {
			if let error {
				throw error
			}
			else {
				guard let authManager else {
					throw Error.missingAuthManager
				}

				guard let url else {
					throw Error.missingURL
				}

				authManager.handle(url, completion: completion)
			}
		}
		catch {
			completion(.failure(error))
		}
	}

	/// The `session.start()` → `throws` translation, exactly as `start()` above uses it. Extracted
	/// as a pure function for the same reason as `handleCompletion(...)` above: directly testable
	/// without constructing a real session.
	static func throwIfFailedToStart(_ started: Bool) throws {
		if started == false {
			throw Error.unableToStart
		}
	}

	enum Error: Swift.Error {
		case missingAuthManager
		case missingURL
		case unableToStart
	}
}

class WindowProviderContainer: NSObject, ASWebAuthenticationPresentationContextProviding {

	/// The window provider closure.
	let windowProvider: AuthManager.WindowProvider

	/// Initializes a new window provider container.
	/// - Parameter windowProvider: A closure providing the window to present the authentication session UI.
	init(windowProvider: @escaping AuthManager.WindowProvider) {
		self.windowProvider = windowProvider
	}

	/// Provides the anchor window for presenting the authentication session UI.
	/// - Parameter session: The ``ASWebAuthenticationSession`` instance.
	func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
		if #available(iOS 17.0, *) {
			return MainActor.assumeIsolated(windowProvider)
		}
		else {
			dispatchPrecondition(condition: .onQueue(.main))
			return withoutActuallyEscaping(windowProvider) { fn in
				unsafeBitCast(fn, to: (() -> AuthManager.Window).self)()
			}
		}
	}

}
