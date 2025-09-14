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

import CryptoKit
import Combine
import Foundation

public final class AuthManager: Sendable {

	/// The application's consumer key.
	/// Found in the Dropbox developer console: <https://www.dropbox.com/developers/apps>
	public let appKey: String

	/// The manager used to store and retrieve tokens from the Keychain.
	public let store: AccessTokenStore

	///
	public let redirectURI: URL

	/// A series of client-generated codes used to authenticate token requests.
	let pckeCode = PCKECode()

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

	// MARK: Refreshing an access token

	public func refresh(
		_ accessToken: AccessToken,
		force: Bool = false,
		urlSession: URLSession = .shared
	) async throws -> AccessToken {
		var accessToken = accessToken
		accessToken.appKey = appKey

		guard force || accessToken.hasExpired else {
			return accessToken
		}

		let token = try await urlSession.token(
			with: RefreshRequest(token: accessToken)
		)

		try store.save(token)

		return token
	}

	public func refresh(
		_ accessToken: AccessToken,
		force: Bool = false,
		urlSession: URLSession = .shared
	) -> AnyPublisher<AccessToken, any Error> {
		var accessToken = accessToken
		accessToken.appKey = appKey

		guard force || accessToken.hasExpired else {
			return Just(accessToken)
				.setFailureType(to: Error.self)
				.eraseToAnyPublisher()
		}

		return urlSession.token(
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
