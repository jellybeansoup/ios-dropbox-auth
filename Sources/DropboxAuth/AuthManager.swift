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

import CryptoKit
import Combine
import UIKit

public final class AuthManager: Sendable {

	/// The application's consumer key.
	/// Found in the Dropbox developer console: <https://www.dropbox.com/developers/apps>
	public let appKey: String

	/// The manager used to store and retrieve tokens from the Keychain.
	public let store: AccessTokenStore

	///
	public let redirectURI: URL

	/// A series of client-generated codes used to authenticate token requests.
	internal let pckeCode = PCKECode()

	/// Create an auth manager with the given app key.
	/// - Parameters:
	///   - key The app key to use for authorisation (optional).
	public convenience init(
		key: String,
		redirectURI: URL? = nil
	) {
		self.init(
			key: key,
			redirectURI: redirectURI,
			store: .init(appKey: key)
		)
	}

	internal init(
		key: String,
		redirectURI: URL? = nil,
		store: AccessTokenStore
	) {
		self.appKey = key
		self.redirectURI = redirectURI ?? URL(string: "db-\(key)://2/token")!
		self.store = store
	}

	// MARK: Defaults

	public typealias Window = UIWindow

	public typealias WindowProvider = @MainActor @Sendable () -> Window

	/// Method used as a default for providing the window from which to present the in-app authentication flow.
	/// - Returns: The first window in the first scene found to be in the `.foregroundActive` state.
	@MainActor
	public static func defaultWindowProvider() -> Window {
		guard
			let application = UIApplication.value(forKey: "sharedApplication") as? UIApplication,
			let scene = application.connectedScenes.compactMap({ $0 as? UIWindowScene }).first(where: { $0.activationState == .foregroundActive }),
			let window = scene.windows.first
		else {
			return UIWindow()
		}

		return window
	}

	var authenticationURL: URL? {
		var components = URLComponents()
		components.scheme = "https"
		components.host = "www.dropbox.com"
		components.path = "/oauth2/authorize"
		components.queryItems = [
			URLQueryItem(name: "response_type", value: "code"),
			URLQueryItem(name: "code_challenge", value: pckeCode.challenge),
			URLQueryItem(name: "code_challenge_method", value: "S256"),
			URLQueryItem(name: "client_id", value: appKey),
			URLQueryItem(name: "redirect_uri", value: redirectURI.absoluteString),
			URLQueryItem(name: "token_access_type", value: "offline"),
			URLQueryItem(name: "disable_signup", value: "true"),
		]

		return components.url
	}

	// MARK: Handling authorization in-app

	/// Uses `ASWebAuthenticationSession` to authenticate without leaving the app.
	///
	/// On iOS and iPadOS, this presents a web browser window within the current scene. On macOS
	/// (including with Catalyst), this presents a web browser in a new window.
	/// - Note: Because the entire authentication flow occurs in-app, it is not necessary to call
	/// 	`handle(_:)` at any at any stage when using this authentication option. By the time the
	/// 	method returns the token will have been fully processed and stored in Keychain.
	/// - Parameter windowProvider: Optional closure that returns the underlying window from which to
	///   	present the authentication prompt.
	/// - Returns: The access token returned by Dropbox, if the authentication was successful.
	@MainActor
	public func authenticateLocally(
		from windowProvider: @escaping WindowProvider = { AuthManager.defaultWindowProvider() }
	) async throws -> AccessToken {
		try await withCheckedThrowingContinuation { continuation in
			do {
				var session: WebAuthenticationSession!
				session = WebAuthenticationSession(
					authManager: self,
					windowProvider: windowProvider,
					completion: {
						continuation.resume(with: $0)
						session = nil
					}
				)

				try session.start()
			}
			catch {
				continuation.resume(throwing: error)
			}
		}
	}

	// MARK: Handling authentication in browser

	/// Hands off to the default web browser on the device to authenticate.
	/// - Note: To receive the access token from this flow, you must call `handle(_:)` with the
	/// 	response URL, which will be parsed to retrieve and then store the access token.
	/// - Parameter urlHandler: Optional closure used to handle the generated URL.
	/// - Returns: Flag to indicate if the URL was handled successfully (as returned from the
	/// 	provided `urlHandler`).
	@discardableResult
	public func authenticateInBrowser(
		urlHandler: @Sendable (_ url: URL) -> Bool
	) -> Bool {
		return urlHandler(authenticationURL!)
	}

	/// Hands off to the default web browser on the device to authenticate.
	/// - Note: To receive the access token from this flow, you must call `handle(_:)` with the
	/// 	response URL, which will be parsed to retrieve and then store the access token.
	/// - Parameter urlHandler: Optional closure used to handle the generated URL.
	/// - Returns: Flag to indicate if the URL was handled successfully (as returned from the
	/// 	provided `urlHandler`).
	@MainActor
	@discardableResult
	public func authenticateInBrowser() -> Bool {
		guard
			let application = UIApplication.value(forKey: "sharedApplication") as? UIApplication,
			application.canOpenURL(authenticationURL!)
		else {
			return false
		}

		application.open(authenticationURL!, options: [:], completionHandler: nil)

		return true
	}

	/// Try to handle a redirect back into the application
	/// - Parameter url: The URL to attempt to handle.
	/// - Returns: Returns the `AccessToken` if the redirect URL can be handled successfully.
	@discardableResult
	public func handle(
		_ url: URL
	) async throws -> AccessToken {
		let parameters = url.query?.queryParameters

		if let code = parameters?["code"] {
			let token = try await URLSession.shared.token(
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
		else if let error = parameters?["error"] {
			throw AuthError(string: error)
		}
		else {
			throw AuthError.unknown
		}
	}

	// MARK: Refreshing an access token

	public func refresh(
		_ accessToken: AccessToken,
		force: Bool = false
	) async throws -> AccessToken {
		var accessToken = accessToken
		accessToken.appKey = appKey

		guard force || accessToken.hasExpired else {
			return accessToken
		}

		let token = try await URLSession.shared.token(
			with: RefreshRequest(token: accessToken)
		)

		try store.save(token)

		return token
	}

	public func refresh(
		_ accessToken: AccessToken,
		force: Bool = false
	) -> AnyPublisher<AccessToken, any Error> {
		var accessToken = accessToken
		accessToken.appKey = appKey

		guard force || accessToken.hasExpired else {
			return Just(accessToken)
				.setFailureType(to: Error.self)
				.eraseToAnyPublisher()
		}

		return URLSession.shared.token(
			with: RefreshRequest(token: accessToken)
		)
		.tryMap { [store] accessToken in
			try store.save(accessToken)

			return accessToken
		}
		.eraseToAnyPublisher()
	}

}

extension AuthManager {

	/// Uses `ASWebAuthenticationSession` to authenticate without leaving the app.
	///
	/// On iOS and iPadOS, this presents a web browser window within the current scene. On macOS
	/// (including with Catalyst), this presents a web browser in a new window.
	/// - Note: Because the entire authentication flow occurs in-app, it is not necessary to call
	/// 	`handle(_:)` at any stage when using this authentication option. By the time the completion
	/// 	handler is called, the token will have been fully processed and stored in Keychain.
	/// - Parameters:
	///   - windowProvider: Optional closure that returns the underlying window from which to
	///   		present the authentication prompt.
	///   - completion: Optional closure that is called with the result of the authentication.
	public func authenticateLocally(
		from windowProvider: @escaping WindowProvider = { AuthManager.defaultWindowProvider() },
		completion: (@MainActor @Sendable (Result<AccessToken, Error>) -> Void)? = nil
	) {
		Task {
			do {
				let token = try await authenticateLocally(from: windowProvider)
				await completion?(.success(token))
			}
			catch {
				await completion?(.failure(error))
			}
		}
	}

	/// Try to handle a redirect back into the application
	/// - Parameter url: The URL to attempt to handle.
	/// - Returns: Returns the `AccessToken` if the redirect URL can be handled successfully.
	public func handle(
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

	public func refresh(
		_ accessToken: AccessToken,
		force: Bool = false,
		completion: @escaping @MainActor @Sendable (_ result: Result<AccessToken, Error>) -> Void
	) {
		Task {
			do {
				let token = try await refresh(accessToken, force: force)
				await completion(.success(token))
			}
			catch {
				await completion(.failure(error))
			}
		}
	}

}
