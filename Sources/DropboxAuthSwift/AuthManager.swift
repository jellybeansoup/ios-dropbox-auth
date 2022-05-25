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

import UIKit
import CryptoKit
import Combine

public class AuthManager {

	/// Delegate which gets notified when changes occur.
	public weak var delegate: AuthManagerDelegate?

	/// The application's consumer key.
	/// Found in the Dropbox developer console: <https://www.dropbox.com/developers/apps>
	public let appKey: String

	/// The manager used to store and retrieve tokens from the Keychain.
	private let keychainManager: KeychainManager

	/// Create an auth manager with the given app key.
	/// - Parameters:
	///   - key The app key to use for authorisation (optional).
	public convenience init(
		key: String
	) {
		self.init(
			key: key,
			keychainManager: .init()
		)
	}

	internal init(
		key: String,
		keychainManager: KeychainManager = .init()
	) {
		self.appKey = key
		self.keychainManager = keychainManager
	}

	// MARK: Defaults

	public typealias Window = UIWindow

	/// Method used as a default for providing the window from which to present the in-app authentication flow.
	/// - Returns: The first window in the first scene found to be in the `.foregroundActive` state.
	@MainActor public static func defaultWindowProvider() -> Window {
		guard
			let application = UIApplication.value(forKey: "sharedApplication") as? UIApplication,
			let scene = application.connectedScenes.compactMap({ $0 as? UIWindowScene }).first(where: { $0.activationState == .foregroundActive }),
			let window = scene.windows.first
		else {
			return UIWindow()
		}

		return window
	}

	/// Method used as a default for handling the provided URL.
	/// - Parameter url: The authentication URL to be handled.
	/// - Returns: A flag that indicates whether the URL was handled successfully or not.
	@MainActor public static func defaultURLHandler(_ url: URL) -> Bool {
		guard
			let application = UIApplication.value(forKey: "sharedApplication") as? UIApplication,
			application.canOpenURL(url)
		else {
			return false
		}

		application.open(url, options: [:], completionHandler: nil)

		return true
	}

	// MARK: Authorization

	internal lazy var pckeCode = PCKECode()

	internal lazy var redirectURI = "db-\(appKey)://2/token"

	//	self.appSecret = SHA256.hash(data: Data(secret.utf8))








	// MARK: Handling authorization in-app

	/// The session being used to authenticate in-app.
	private var webAuthenticationSession: WebAuthenticationSession?

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
		from windowProvider: @escaping @MainActor () -> Window = AuthManager.defaultWindowProvider,
		completion: ((Result<AccessToken, Error>) -> Void)? = nil
	) {
		do {
			let session = WebAuthenticationSession(
				authManager: self,
				windowProvider: windowProvider,
				completion: completion
			)

			try session.start()

			webAuthenticationSession = session
		}
		catch {
			completion?(.failure(error))
		}
	}

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
	public func authenticateLocally(
		from windowProvider: @escaping @MainActor () -> Window = AuthManager.defaultWindowProvider
	) async throws -> AccessToken {
		try await withCheckedThrowingContinuation { continuation in
			authenticateLocally(from: windowProvider) { result in
				continuation.resume(with: result)
			}
		}
	}

	// MARK: Handling authentication in browser

	private var tokenSubscriptions: [AnyCancellable] = []

	/// Hands off to the default web browser on the device to authenticate.
	/// - Note: To receive the access token from this flow, you must call `handle(_:)` with the
	/// 	response URL, which will be parsed to retrieve and then store the access token.
	/// - Parameter urlHandler: Optional closure used to handle the generated URL.
	/// - Returns: Flag to indicate if the URL was handled successfully (as returned from the
	/// 	provided `urlHandler`).
	@discardableResult
	@MainActor public func authenticateInBrowser(
		urlHandler: @MainActor (_ url: URL) -> Bool = AuthManager.defaultURLHandler
	) -> Bool {
		return urlHandler(URL.authenticationURL(for: self)!)
	}

	/// Try to handle a redirect back into the application
	/// - Parameter url: The URL to attempt to handle.
	/// - Returns: Returns the `AccessToken` if the redirect URL can be handled successfully.
	public func handle(_ url: URL, completion: @escaping (_ result: Result<AccessToken, Error>) -> ()) {
		do {
			let parameters = url.query?.queryParameters

			if let code = parameters?["code"] {
				AccessTokenRequest(
					appKey: appKey,
					source: .exchange(
						code: code,
						verifier: pckeCode.verifier,
						redirectURI: redirectURI
					)
				)
				.perform { [weak self] result in
					if case .success(let token) = result, let self = self {
						_ = self.add(token)
					}

					completion(result)
				}
			}
			else if let error = parameters?["error"] {
				throw AuthError(string: error)
			}
			else {
				throw AuthError.unknown
			}
		}
		catch {
			completion(.failure(error))
		}
	}

	/// Try to handle a redirect back into the application
	/// - Parameter url: The URL to attempt to handle.
	/// - Returns: Returns the `AccessToken` if the redirect URL can be handled successfully.
	@discardableResult
	public func handle(_ url: URL) async throws -> AccessToken {
		return try await withCheckedThrowingContinuation { continuation in
			handle(url) { result in
				continuation.resume(with: result)
			}
		}
	}

	// MARK: Handling access tokens

	/// Flag that indicates if there are any stored access tokens.
	public var hasAccessTokens: Bool {
		return firstAccessToken != nil
	}

	/// All stored access tokens.
	public var accessTokens: [AccessToken] {
		return keychainManager.all.compactMap { accessToken(for: $0) }
	}

	/// The first access token found, if available.
	public var firstAccessToken: AccessToken? {
		guard let userID = keychainManager.all.first else {
			return nil
		}

		return accessToken(for: userID)
	}

	/// Retrieve the access token for a particular user identifier
	/// - Parameter userID: The identifier representing the user whose token to retrieve.
	/// - Returns: An access token if present, otherwise `nil`.
	public func accessToken(for userID: String) -> AccessToken? {
		fatalError()

//		guard let accessToken = keychainManager.string(forKey: userID) else {
//			return nil
//		}
//
//		return AccessToken(string: accessToken, uid: userID)
	}

	/// Add a specific access token
	/// - Parameter accessToken: The access token to add.
	/// - Returns: Flag indicating whether the operation succeeded.
	internal func add(_ accessToken: AccessToken) -> Bool {
		return true

//		let success = keychainManager.setValue(accessToken.accessToken, forKey: accessToken.uid)
//
//		if success, let delegate = delegate {
//			delegate.authManager(self, didAdd: accessToken)
//		}
//
//		return success
	}

	/// Delete a specific access token
	/// - Parameter accessToken: The access token to delete.
	/// - Returns: Flag indicating whether the operation succeeded.
	public func remove(_ accessToken: AccessToken) -> Bool {
		return true

//		let success = keychainManager.removeValue(forKey: accessToken.uid)
//
//		if success, let delegate = delegate {
//			delegate.authManager(self, didRemove: accessToken)
//		}
//
//		return success
	}

	/// Delete all stored access tokens
	/// - Returns: Flag indicating whether the operation succeeded.
	@discardableResult
	public func removeAllAccessTokens() -> Bool {
		return keychainManager.removeAll()
	}

}
