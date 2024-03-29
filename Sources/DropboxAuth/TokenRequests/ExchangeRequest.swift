//
// Copyright © 2024 Daniel Farrelly
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

struct ExchangeRequest: TokenRequest, Sendable {

	typealias Response = ExchangeResponse

	static let url = URL(string: "https://api.dropbox.com/oauth2/token")!

	static let method = Method.post

	var appKey: String
	var code: String
	var verifier: String
	var redirectURI: String
	let grantType = "authorization_code"

	enum CodingKeys: String, CodingKey {
		case appKey = "client_id"
		case code
		case verifier = "code_verifier"
		case redirectURI = "redirect_uri"
		case grantType = "grant_type"
	}

	func encode(to encoder: MultipartEncoder) {
		let container = encoder.container(keyedBy: CodingKeys.self)
		container.encode(code, forKey: .code)
		container.encode(verifier, forKey: .verifier)
		container.encode(redirectURI, forKey: .redirectURI)
		container.encode(appKey, forKey: .appKey)
		container.encode(grantType, forKey: .grantType)
	}

}

struct ExchangeResponse: TokenResponse, Sendable {

	typealias Request = ExchangeRequest

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

	func token(for originalRequest: Request) -> AccessToken {
		.init(
			accessToken: accessToken,
			expiryDate: .init(timeIntervalSinceNow: expiresIn),
			scope: scope,
			accountID: accountID,
			teamID: teamID,
			refreshToken: refreshToken
		)
	}

}
