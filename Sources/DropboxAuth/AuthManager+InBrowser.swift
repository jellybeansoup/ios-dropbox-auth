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

public extension AuthManager {

	enum BrowserAuthenticationError: Swift.Error {
		case invalidQuery(String?)
	}

	/// Hands off to the default web browser on the device to authenticate.
	/// - Note: To receive the access token from this flow, you must call `handle(_:)` with the
	/// 	response URL, which will be parsed to retrieve and then store the access token.
	/// - Parameter urlHandler: Optional closure used to handle the generated URL.
	/// - Returns: Flag to indicate if the URL was handled successfully (as returned from the
	/// 	provided `urlHandler`).
	@discardableResult
	func authenticateInBrowser(
		urlHandler: @Sendable (_ url: URL) -> Bool
	) -> Bool {
		return urlHandler(authenticationURL!)
	}

	/// Try to handle a redirect back into the application
	/// - Parameter url: The URL to attempt to handle.
	/// - Returns: Returns the `AccessToken` if the redirect URL can be handled successfully.
	@discardableResult
	func handle(
		_ url: URL
	) async throws -> AccessToken {
		try await handle(url, urlSession: .shared)
	}

	/// Try to handle a redirect back into the application
	/// - Parameter url: The URL to attempt to handle.
	/// - Returns: Returns the `AccessToken` if the redirect URL can be handled successfully.
	func handle(
		_ url: URL,
		completion: @escaping @MainActor @Sendable (_ result: Result<AccessToken, Error>) -> ()
	) {
		Task {
			do {
				let token = try await handle(url)
				await completion(.success(token))
			}
			catch {
				await completion(.failure(error))
			}
		}
	}

}

extension AuthManager {

	/// Internal seam used by tests to inject a stubbed `URLSession` in place of `.shared`.
	/// Production callers always reach this through the public `handle(_:)` overload above, which
	/// always passes `.shared` — so production behavior is unchanged.
	@discardableResult
	func handle(
		_ url: URL,
		urlSession: URLSession
	) async throws -> AccessToken {
		let parameters = url.query?.queryParameters

		if let code = parameters?["code"] {
			let token = try await urlSession.token(
				with: ExchangeRequest(
					appKey: appKey,
					code: code,
					verifier: pckeCode.verifier,
					redirectURI: redirectURI.absoluteString
				)
			)

			try store.save(token)

			return token
		}
		else if let rawValue = parameters?["error"], let error = OAuthError(rawValue: rawValue) {
			throw error
		}
		else {
			throw BrowserAuthenticationError.invalidQuery(url.query)
		}
	}

}

#if canImport(UIKit)
import UIKit

public extension AuthManager {

	/// Hands off to the default web browser on the device to authenticate.
	/// - Note: To receive the access token from this flow, you must call `handle(_:)` with the
	/// 	response URL, which will be parsed to retrieve and then store the access token.
	/// - Parameter urlHandler: Optional closure used to handle the generated URL.
	/// - Returns: Flag to indicate if the URL was handled successfully (as returned from the
	/// 	provided `urlHandler`).
	@MainActor
	@discardableResult
	func authenticateInBrowser() -> Bool {
		openInSystemBrowser(opener: Self.defaultURLOpener)
	}

}

extension AuthManager {

	/// The production URL-opener: hands the URL to `UIApplication`, identical to what
	/// `authenticateInBrowser()` did directly before the injection seam was introduced.
	@MainActor
	static let defaultURLOpener: (URL) -> Bool = { url in
		guard
			let application = UIApplication.value(forKey: "sharedApplication") as? UIApplication,
			application.canOpenURL(url)
		else {
			return false
		}

		application.open(url, options: [:], completionHandler: nil)

		return true
	}

	/// Internal seam used by tests to inject a fake URL-opener in place of `UIApplication`, whose
	/// real `.open(_:)` would launch the live system browser to a real Dropbox OAuth URL.
	/// Production callers always reach this through the public `authenticateInBrowser()` overload
	/// above, which always passes `defaultURLOpener` — so production behavior is unchanged.
	@MainActor
	@discardableResult
	func openInSystemBrowser(opener: (URL) -> Bool) -> Bool {
		opener(authenticationURL!)
	}

}
#endif

#if canImport(AppKit) && !targetEnvironment(macCatalyst)
import AppKit

public extension AuthManager {

	/// Hands off to the default web browser on the device to authenticate.
	/// - Note: To receive the access token from this flow, you must call `handle(_:)` with the
	/// 	response URL, which will be parsed to retrieve and then store the access token.
	/// - Parameter urlHandler: Optional closure used to handle the generated URL.
	/// - Returns: Flag to indicate if the URL was handled successfully (as returned from the
	/// 	provided `urlHandler`).
	@MainActor
	@discardableResult
	func authenticateInBrowser() -> Bool {
		openInSystemBrowser(opener: Self.defaultURLOpener)
	}

}

extension AuthManager {

	/// The production URL-opener: hands the URL to `NSWorkspace`, identical to what
	/// `authenticateInBrowser()` did directly before the injection seam was introduced.
	@MainActor
	static let defaultURLOpener: (URL) -> Bool = { url in
		guard
			let application = NSWorkspace.value(forKey: "sharedWorkspace") as? NSWorkspace
		else {
			return false
		}

		application.open(url)

		return true
	}

	/// Internal seam used by tests to inject a fake URL-opener in place of `NSWorkspace`, whose
	/// real `.open(_:)` would launch the live system browser to a real Dropbox OAuth URL.
	/// Production callers always reach this through the public `authenticateInBrowser()` overload
	/// above, which always passes `defaultURLOpener` — so production behavior is unchanged.
	@MainActor
	@discardableResult
	func openInSystemBrowser(opener: (URL) -> Bool) -> Bool {
		opener(authenticationURL!)
	}

}
#endif
