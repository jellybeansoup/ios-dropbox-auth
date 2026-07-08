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

/// `API.Request.response(from:)` falls back through `OAuthError` and `AuthenticationError` when a
/// request's own `Error` type can't interpret the `error_summary` tag chain (i.e. its `init(summary:)`
/// rethrows the summary unchanged) — used so any request can still surface a recognisable
/// authentication failure even if its dedicated error enum doesn't have a matching case.
@Suite struct APIRequestErrorMappingTests {

	/// An `API.Error` that never recognises any summary, always rethrowing it — exercising the
	/// fallback chain in `response(from:)`.
	enum StrictError: API.Error {
		typealias Request = MockRequest

		case neverMatches

		init(summary: Summary) throws {
			throw summary
		}
	}

	struct MockRequest: API.Request {
		typealias Response = MockResponse
		typealias Error = StrictError

		static let endpoint: Endpoint = .api("/echo")
		static let method = Method.post
	}

	struct MockResponse: API.Response, Hashable {
		typealias Request = MockRequest
		let foo: String
	}

	@Test func fallsBackToOAuthErrorWhenRequestErrorDoesNotMatch() throws {
		let data = Data("""
		{
			"error_summary": "access_denied/.",
			"error": {
				".tag": "access_denied"
			}
		}
		""".utf8)

		let request = MockRequest()
		#expect(throws: OAuthError.accessDenied) {
			_ = try request.response(from: data)
		}
	}

	@Test func fallsBackToAuthenticationErrorWhenRequestErrorDoesNotMatch() throws {
		let data = Data("""
		{
			"error_summary": "invalid_access_token/.",
			"error": {
				".tag": "invalid_access_token"
			}
		}
		""".utf8)

		let request = MockRequest()
		#expect(throws: AuthenticationError.invalidAccessToken) {
			_ = try request.response(from: data)
		}
	}

	@Test func propagatesOriginalSummaryWhenNoFallbackMatches() throws {
		let data = Data("""
		{
			"error_summary": "something_else_entirely/.",
			"error": {
				".tag": "something_else_entirely"
			}
		}
		""".utf8)

		let request = MockRequest()
		do {
			_ = try request.response(from: data)
			Issue.record("Expected the original summary to be thrown")
		}
		catch let summary as API.ErrorSummary {
			#expect(summary.component == "something_else_entirely")
		}
		catch {
			Issue.record("Expected API.ErrorSummary, got \(type(of: error))")
		}
	}

}
