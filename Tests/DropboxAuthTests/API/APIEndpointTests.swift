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

@Suite struct APIEndpointTests {

	@Test func api() throws {
		let endpoint = API.Endpoint.api("/example")
		#expect(endpoint.root == "api.dropboxapi.com/2")
		#expect(endpoint.path == "/example")
		#expect(try endpoint.url == #require(URL(string: "https://api.dropboxapi.com/2/example")))
	}

	@Test func content() throws {
		let endpoint = API.Endpoint.content("/example")
		#expect(endpoint.root == "content.dropboxapi.com/2")
		#expect(endpoint.path == "/example")
		#expect(try endpoint.url == #require(URL(string: "https://content.dropboxapi.com/2/example")))
	}

	@Test func notify() throws {
		let endpoint = API.Endpoint.notify("/example")
		#expect(endpoint.root == "notify.dropboxapi.com/2")
		#expect(endpoint.path == "/example")
		#expect(try endpoint.url == #require(URL(string: "https://notify.dropboxapi.com/2/example")))
	}

	@Test func oauth() throws {
		let endpoint = API.Endpoint.oauth
		#expect(endpoint.root == "api.dropbox.com/oauth2")
		#expect(endpoint.path == "/token")
		#expect(try endpoint.url == #require(URL(string: "https://api.dropbox.com/oauth2/token")))
	}

	@Test func urlWithMalformedRoot() {
		let endpoint = API.Endpoint(root: "\0", path: "/example")
		#expect(endpoint.root == "\0")
		#expect(endpoint.path == "/example")
		#expect(throws: API.Endpoint.URLError.invalidRoot("\0")) {
			_ = try endpoint.url
		}
	}

	@Test func initWithStringLiteral() throws {
		let endpoint: API.Endpoint = "/example"
		#expect(endpoint.root == "api.dropboxapi.com/2")
		#expect(endpoint.path == "/example")
		#expect(try endpoint.url == #require(URL(string: "https://api.dropboxapi.com/2/example")))
	}

}
