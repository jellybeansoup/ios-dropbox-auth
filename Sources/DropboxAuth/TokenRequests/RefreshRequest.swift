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

struct RefreshRequest: API.Request, Sendable {

	typealias Response = RefreshResponse
	typealias Error = OAuthError

	static let endpoint: API.Endpoint = .oauth

	static let method = API.Method.post

	let grantType = "refresh_token"
	var token: AccessToken

	func configure(_ urlRequest: inout URLRequest) throws {
		urlRequest.setValue("application/x-www-form-urlencoded; charset=utf-8", forHTTPHeaderField: "Content-Type")
		urlRequest.httpBody = Data("client_id=\(token.appKey ?? "")&refresh_token=\(token.refreshToken)&grant_type=\(grantType)".utf8)
	}

}

struct RefreshResponse: API.Response, TokenResponse, Sendable {

	typealias Request = RefreshRequest

	let accessToken: String
	let expiresIn: TimeInterval

	enum CodingKeys: String, CodingKey {
		case accessToken = "access_token"
		case expiresIn = "expires_in"
	}

	func token(for originalRequest: Request) -> AccessToken {
		.init(
			accessToken: accessToken,
			expiryDate: .init(timeIntervalSinceNow: expiresIn),
			scope: originalRequest.token.scope,
			accountID: originalRequest.token.accountID,
			teamID: originalRequest.token.teamID,
			refreshToken: originalRequest.token.refreshToken
		)
	}

}
