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
import DropboxAuthMocks
import Foundation
import Testing

@Suite struct AccessTokenTests {

	@Test func hasExpired() async throws {
		#expect(AccessToken.mock(
			expiryDate: Date(timeIntervalSinceNow: -100)
		).hasExpired)

		#expect(AccessToken.mock(
			expiryDate: Date(timeIntervalSinceNow: 10)
		).hasExpired)

		#expect(AccessToken.mock(
			expiryDate: Date(timeIntervalSinceNow: 100)
		).hasExpired == false)
	}

	@Test func signedRequestFromRequest() async throws {
		let url = try #require(URL(string: "https://example.com"))
		var request = URLRequest(
			url: url
		)
		request.httpMethod = "POST"
		request.httpBody = Data([0,0,0,0,0,0])
		request.addValue("application/json", forHTTPHeaderField: "Content-Type")

		let accessToken = AccessToken.mock(accessToken: "access_token")
		let signedRequest = accessToken.signedRequest(from: request)

		request.addValue("Bearer access_token", forHTTPHeaderField: "Authorization")

		#expect(signedRequest == request)
	}

	@Test func signedRequestWithURLCachePolicyAndTimeoutInterval() async throws {
		let url = try #require(URL(string: "https://example.com"))
		let accessToken = AccessToken.mock(
			accessToken: "access_token"
		)

		var request = URLRequest(
			url: url,
			cachePolicy: .reloadIgnoringLocalAndRemoteCacheData,
			timeoutInterval: 123.456
		)
		request.addValue("Bearer access_token", forHTTPHeaderField: "Authorization")

		let signedRequest = accessToken.signedRequest(
			with: url,
			cachePolicy: .reloadIgnoringLocalAndRemoteCacheData,
			timeoutInterval: 123.456
		)

		#expect(signedRequest == request)
	}

	@Test func signedRequestWithURL() async throws {
		let url = try #require(URL(string: "https://example.com"))
		let accessToken = AccessToken.mock(
			accessToken: "access_token"
		)

		var request = URLRequest(url: url)
		request.addValue("Bearer access_token", forHTTPHeaderField: "Authorization")

		let signedRequest = accessToken.signedRequest(with: url)

		#expect(signedRequest == request)
	}

}
