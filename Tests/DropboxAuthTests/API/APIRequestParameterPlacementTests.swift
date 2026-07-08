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
@testable import DropboxAuth
import Testing

/// Covers the request infrastructure that lets a request declare a content-style host
/// (`content.dropboxapi.com`) and place its encoded parameters in the `Dropbox-API-Arg`
/// header instead of the JSON body. Actual content requests (upload/download/thumbnail)
/// are implemented separately; these mock requests exist only to exercise the infrastructure.
@Suite struct APIRequestParameterPlacementTests {

	struct MockAPIRequest: API.Request {

		typealias Response = MockAPIResponse
		typealias Error = MockAPIError

		static let endpoint: Endpoint = .api("/files/example")
		static let method = Method.post

		var path: String

	}

	struct MockAPIResponse: API.Response {
		typealias Request = MockAPIRequest
	}

	enum MockAPIError: API.Error {
		typealias Request = MockAPIRequest

		case unknown

		init(summary: Summary) throws {
			self = .unknown
		}
	}

	struct MockContentRequest: API.Request {

		typealias Response = MockContentResponse
		typealias Error = MockContentError

		static let endpoint: Endpoint = .content("/files/example")
		static let method = Method.post
		static let parameterPlacement = ParameterPlacement.header

		var path: String

	}

	struct MockContentResponse: API.Response {
		typealias Request = MockContentRequest
	}

	enum MockContentError: API.Error {
		typealias Request = MockContentRequest

		case unknown

		init(summary: Summary) throws {
			self = .unknown
		}
	}

	@Test func apiHostRequestKeepsPreviousBodyShape() throws {
		let request = MockAPIRequest(path: "/hello/world")

		let urlRequest = try request.urlRequest(signedWith: .mock())

		#expect(urlRequest.url?.absoluteString == "https://api.dropboxapi.com/2/files/example")

		let data = try #require(urlRequest.httpBody)
		let string = String(data: data, encoding: .utf8)
		#expect(string == "{\"path\":\"/hello/world\"}")

		#expect(urlRequest.value(forHTTPHeaderField: "Content-Type") == "application/json")
		#expect(urlRequest.value(forHTTPHeaderField: "Dropbox-API-Arg") == nil)
	}

	@Test func contentHostRequestUsesHeaderPlacement() throws {
		let request = MockContentRequest(path: "/hello/world")

		let urlRequest = try request.urlRequest(signedWith: .mock())

		#expect(urlRequest.url?.absoluteString == "https://content.dropboxapi.com/2/files/example")
		#expect(urlRequest.httpBody == nil)
		#expect(urlRequest.value(forHTTPHeaderField: "Content-Type") == nil)
		#expect(urlRequest.value(forHTTPHeaderField: "Dropbox-API-Arg") == "{\"path\":\"/hello/world\"}")
	}

	@Test func contentHostRequestEscapesNonASCIIInHeader() throws {
		let request = MockContentRequest(path: "/\u{1F389} party.gif")

		let urlRequest = try request.urlRequest(signedWith: .mock())

		#expect(urlRequest.value(forHTTPHeaderField: "Dropbox-API-Arg") == "{\"path\":\"/\\ud83c\\udf89 party.gif\"}")
	}

}
