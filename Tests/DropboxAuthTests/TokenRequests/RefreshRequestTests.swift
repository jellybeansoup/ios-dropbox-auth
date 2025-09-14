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

@testable import DropboxAuth
import Foundation
import Testing

struct RefreshRequestTests {

	@Test func encoding() throws {
		let request = RefreshRequest(
			token: .mock(
				accessToken: "token_1234",
				expiryDate: .init(timeIntervalSince1970: 1577869200), // 2020-01-01 09:00
				scope: nil,
				accountID: "account_1234",
				teamID: nil,
				refreshToken: "refresh_1234",
				appKey: "app_key"
			)
		)

		#expect(request.grantType == "refresh_token")

		let urlRequest = try request.urlRequest

		#expect(urlRequest.url?.absoluteString == "https://api.dropbox.com/oauth2/token")
		#expect(urlRequest.httpMethod == "POST")

		let data = try #require(urlRequest.httpBody)
		let string = String(data: data, encoding: .utf8)
		#expect(string == "client_id=app_key&refresh_token=refresh_1234&grant_type=refresh_token")

		#expect(urlRequest.allHTTPHeaderFields == ["Content-Type": "application/x-www-form-urlencoded; charset=utf-8"])
	}

	@Test func decoding() throws {
		let data = Data("""
		{
			"access_token": "token_5678",
			"expires_in": 3600,
		}
		""".utf8)

		let request = RefreshRequest(
			token: .mock(
				accessToken: "token_1234",
				expiryDate: .init(timeIntervalSince1970: 1577869200), // 2020-01-01 09:00
				scope: nil,
				accountID: "account_1234",
				teamID: nil,
				refreshToken: "refresh_1234",
				appKey: "app_key"
			)
		)
		let response = try request.response(from: data)

		#expect(response.accessToken == "token_5678")
		#expect(response.expiresIn == 3600)

		let token = response.token(for: request)

		#expect(token.accessToken == "token_5678")
		#expect(ceil(token.expiryDate.timeIntervalSinceNow) == 3600) // We should be inside of a second
		#expect(token.scope == nil)
		#expect(token.accountID == "account_1234")
		#expect(token.teamID == nil)
		#expect(token.refreshToken == "refresh_1234")
	}

	@Test func decodingAccessDenied() throws {
		let data = Data("""
		{
			"error_summary": "access_denied/.",
			"error": {
				".tag": "access_denied",
			}
		}
		""".utf8)

		let request = RefreshRequest(
			token: .mock()
		)
		#expect(throws: OAuthError.accessDenied) {
			try request.response(from: data)
		}
	}

}
