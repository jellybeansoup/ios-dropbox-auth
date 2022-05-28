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
import Combine

class AccessTokenRequest {

	/// The application's consumer key.
	/// Found in the Dropbox developer console: <https://www.dropbox.com/developers/apps>
	let appKey: String

	/// Value that indicates the type of token request being made.
	let source: Source

	enum Source {

		/// Request that exchanges a code returned from Dropbox via a callback URL for an access token.
		case exchange(code: String, verifier: String, redirectURI: String)

		/// Request that uses the long-lived `refreshToken` to refresh the short-lived `accessToken`.
		case refresh(token: AccessToken)

	}

	init(appKey: String, source: Source) {
		self.appKey = appKey
		self.source = source
	}

	// MARK: Requesting a token

	private var dataSubscription: AnyCancellable?

	private var retainSelf: AccessTokenRequest?

	func perform(
		urlSession: URLSession = .shared,
		completion: @escaping (Result<AccessToken, Error>) -> Void
	) {
		var request = URLRequest(url: URL(string: "https://api.dropbox.com/oauth2/token")!)
		request.httpMethod = "POST"
		request.httpBody = multipartEncodedData
		request.addValue("multipart/form-data; charset=utf-8; boundary=\(multipartBoundary)", forHTTPHeaderField: "Content-Type")

		retainSelf = self
		dataSubscription = urlSession.dataTaskPublisher(for: request)
			.tryCompactMap { [source] value -> AccessToken in
				let decoder = JSONDecoder()

				do {
					switch source {
					case .exchange:
						return try decoder.decode(
							ExchangeResponse.self,
							from: value.data
						).construct()

					case .refresh(let token):
						return try decoder.decode(
							RefreshResponse.self,
							from: value.data
						).updating(token)
					}
				}
				catch {
					throw (try? decoder.decode(
						AuthError.self,
						from: value.data
					)) ?? error
				}
			}
			.sink(
				receiveCompletion: { [unowned self] result in
					if case .failure(let error) = result {
						completion(.failure(error))
					}

					self.dataSubscription = nil
					self.retainSelf = nil
				},
				receiveValue: { token in
					completion(.success(token))

					self.dataSubscription = nil
					self.retainSelf = nil
				}
			)
	}

	private struct ExchangeResponse: Decodable {
		let accessToken: String
		let expiresIn: TimeInterval
		let scope: String?
		let accountID: String
		let teamID: String?
		let refreshToken: String

		enum CodingKeys: String, CodingKey {
			case accessToken = "access_token"
			case expiresIn = "expires_in"
			case scope
			case accountID = "account_id"
			case teamID = "team_id"
			case refreshToken = "refresh_token"
		}

		func construct() -> AccessToken {
			return AccessToken(
				accessToken: accessToken,
				expiryDate: .init(timeIntervalSinceNow: expiresIn),
				scope: scope,
				accountID: accountID,
				teamID: teamID,
				refreshToken: refreshToken
			)
		}

	}

	private struct RefreshResponse: Decodable {
		let accessToken: String
		let expiresIn: TimeInterval

		enum CodingKeys: String, CodingKey {
			case accessToken = "access_token"
			case expiresIn = "expires_in"
		}

		func updating(_ token: AccessToken) -> AccessToken {
			var token = token
			token.accessToken = accessToken
			token.expiryDate = .init(timeIntervalSinceNow: expiresIn)
			return token
		}

	}

	// MARK: Multipart

	private enum MultipartKey: String {
		case code
		case grantType = "grant_type"
		case refreshToken = "refresh_token"
		case clientID = "client_id"
		case redirectURI = "redirect_uri"
		case codeVerifier = "code_verifier"
	}

	private var multipartEncodedData: Data {
		var multipart = Data()

		switch source {
		case .exchange(let code, let verifier, let redirectURI):
			appendMultipart(to: &multipart, value: code, name: .code)
			appendMultipart(to: &multipart, value: verifier, name: .codeVerifier)
			appendMultipart(to: &multipart, value: redirectURI, name: .redirectURI)
			appendMultipart(to: &multipart, value: appKey, name: .clientID)
			appendMultipart(to: &multipart, value: "authorization_code", name: .grantType)

		case .refresh(let token):
			appendMultipart(to: &multipart, value: token.refreshToken, name: .refreshToken)
			appendMultipart(to: &multipart, value: appKey, name: .clientID)
			appendMultipart(to: &multipart, value: "refresh_token", name: .grantType)
		}

		finalizeMultipart(&multipart)

		return multipart
	}

	private let multipartBoundary = UUID().uuidString.replacingOccurrences(of: "\\W", with: "_", options: .regularExpression)

	private func appendMultipart(to data: inout Data, value: String, name: MultipartKey) {
		data.append(Data("--\(multipartBoundary)\r\n".utf8))
		data.append(Data("Content-Disposition: form-data; name=\"\(name.rawValue)\"\r\n\r\n".utf8))
		data.append(Data("\(value)\r\n".utf8))
	}

	private func finalizeMultipart(_ data: inout Data) {
		data.append(Data("--\(multipartBoundary)--\r\n".utf8))
	}

}
