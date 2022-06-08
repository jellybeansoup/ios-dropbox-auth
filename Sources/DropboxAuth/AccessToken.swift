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

public struct AccessToken: Codable {

	/// The access token string.
	public var accessToken: String

	public var expiryDate: Date

	public let scope: String?

	public let accountID: String

	public let teamID: String?

	public let refreshToken: String

	internal var appKey: String?

	internal var store: AccessTokenStore?

	/// Create an instance of the receiver with the access token and uid.
	init(accessToken: String, expiryDate: Date, scope: String?, accountID: String, teamID: String?, refreshToken: String) {
		self.accessToken = accessToken
		self.expiryDate = expiryDate
		self.scope = scope
		self.accountID = accountID
		self.teamID = teamID
		self.refreshToken = refreshToken
	}

	/// Flag that indicates whether the token should be considered to have expired.
	public var hasExpired: Bool {
		return expiryDate.timeIntervalSinceNow < 30
	}

	// MARK: Signing URL requests

	/// Create a URL request from the given request, signed using the receiver.
	/// - Parameter request: The URL request to be signed.
	/// - Returns: The signed URL request.
	public func signedRequest(from request: URLRequest) -> URLRequest {
		var request = request
		let authorization = "Bearer \(accessToken)"
		request.addValue(authorization, forHTTPHeaderField: "Authorization")
		return request
	}

	/// Create a URL request with the given URL, cache policy and timeout, signed using the receiver.
	///
	/// This method replicates the `URLRequest(url:cachePolicy:timeoutInterval:)`, while also signing for access to the API.
	/// - Parameters:
	///   - url: The URL for the new request.
	///   - cachePolicy: The cache policy for the new request.
	///   - timeoutInterval: The timeout interval for the new request, in seconds.
	/// - Returns: The signed URL request.
	public func signedRequest(with url: URL, cachePolicy: URLRequest.CachePolicy, timeoutInterval: TimeInterval) -> URLRequest {
		return signedRequest(from: URLRequest(
			url: url,
			cachePolicy: cachePolicy,
			timeoutInterval: timeoutInterval
		))
	}

	/// Create a URL request from the given URL, signed using the receiver.
	///
	/// This method replicates the `URLRequest(url:)`, while also signing for access to the API.
	/// - Parameter url: The URL for the new request.
	/// - Returns: The signed URL request.
	public func signedRequest(with url: URL) -> URLRequest {
		return signedRequest(from: URLRequest(
			url: url
		))
	}

	// MARK: Refreshing the token

	public func refresh(force: Bool = false, completion: @escaping (_ result: Result<AccessToken, Error>) -> Void) {
		guard force || hasExpired else {
			return completion(.success(self))
		}

		AccessTokenRequest(
			source: .refresh(token: self),
			store: store
		)
		.perform(completion: completion)
	}

	public func refreshed(force: Bool = false) async throws -> AccessToken {
		return try await withCheckedThrowingContinuation { continuation in
			refresh(force: force) { result in
				continuation.resume(with: result)
			}
		}
	}

	// MARK: Codable

	private enum CodingKeys: CodingKey {
		case accessToken
		case expiryDate
		case scope
		case accountID
		case teamID
		case refreshToken
	}

	public init(from decoder: Decoder) throws {
		let container = try decoder.container(keyedBy: CodingKeys.self)
		accessToken = try container.decode(String.self, forKey: .accessToken)
		expiryDate = try container.decode(Date.self, forKey: .expiryDate)
		scope = try container.decodeIfPresent(String.self, forKey: .scope)
		accountID = try container.decode(String.self, forKey: .accountID)
		teamID = try container.decodeIfPresent(String.self, forKey: .teamID)
		refreshToken = try container.decode(String.self, forKey: .refreshToken)
	}

	public func encode(to encoder: Encoder) throws {
		var container = encoder.container(keyedBy: CodingKeys.self)
		try container.encode(accessToken, forKey: .accessToken)
		try container.encode(expiryDate, forKey: .expiryDate)
		try container.encodeIfPresent(scope, forKey: .scope)
		try container.encode(accountID, forKey: .accountID)
		try container.encodeIfPresent(teamID, forKey: .teamID)
		try container.encode(refreshToken, forKey: .refreshToken)
	}

}
