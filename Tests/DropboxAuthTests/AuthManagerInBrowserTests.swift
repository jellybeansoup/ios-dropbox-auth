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

/// Covers the URL-scheme redirect side of browser-based authentication: constructing the
/// hand-off URL and parsing the app's return redirect (`handle(_:)`).
///
/// Not covered here: the platform `authenticateInBrowser()` overloads (UIKit/AppKit), which call
/// straight through to `UIApplication.open`/`NSWorkspace.open` with no injection seam — calling
/// them in a test would actually launch the system browser, an untestable-at-this-layer side
/// effect. `handle(_:)`'s network path has no `URLSession` injection point either, so it's
/// exercised via `GlobalURLProtocolStub`, which intercepts `.shared` for the duration of a test.
@Suite(.serialized) struct AuthManagerInBrowserTests {

	private static func store() -> AccessTokenStore {
		.mock(
			copyMatching: { _, _ in noErr },
			update: { _, _ in noErr },
			add: { _, _ in noErr },
			delete: { _ in noErr }
		)
	}

	// MARK: authenticateInBrowser(urlHandler:)

	@Test func authenticateInBrowserPassesTheAuthenticationURLToTheHandler() {
		let authManager = AuthManager(key: "mock", redirectURI: nil, store: Self.store())
		let expectedURL = authManager.authenticationURL

		let handled = authManager.authenticateInBrowser { url in
			url == expectedURL
		}

		#expect(handled)
	}

	@Test func authenticateInBrowserReturnsTheHandlersResult() {
		let authManager = AuthManager(key: "mock", redirectURI: nil, store: Self.store())

		let handled = authManager.authenticateInBrowser { _ in false }

		#expect(handled == false)
	}

	// MARK: handle(_:) async

	@Test func handleExchangesACodeForAToken() async throws {
		let authManager = AuthManager(key: "mock", redirectURI: nil, store: Self.store())
		let url = try #require(URL(string: "db-mock://2/token?code=auth_code_1234"))

		let token = try await GlobalURLProtocolStub.withStub({ _ in
			"""
			{
				"access_token": "exchanged_token",
				"expires_in": 3600,
				"account_id": "account_1234",
				"refresh_token": "refresh_1234"
			}
			"""
		}) {
			try await authManager.handle(url)
		}

		#expect(token.accessToken == "exchanged_token")
		#expect(token.accountID == "account_1234")
		#expect(token.refreshToken == "refresh_1234")
	}

	@Test func handlePropagatesOAuthErrorFromQuery() async throws {
		let authManager = AuthManager(key: "mock", redirectURI: nil, store: Self.store())
		let url = try #require(URL(string: "db-mock://2/token?error=access_denied"))

		await #expect(throws: OAuthError.accessDenied) {
			_ = try await authManager.handle(url)
		}
	}

	@Test func handleThrowsInvalidQueryWhenNeitherCodeNorErrorIsPresent() async throws {
		let authManager = AuthManager(key: "mock", redirectURI: nil, store: Self.store())
		let url = try #require(URL(string: "db-mock://2/token?foo=bar"))

		do {
			_ = try await authManager.handle(url)
			Issue.record("Expected invalidQuery to be thrown")
		}
		catch let AuthManager.BrowserAuthenticationError.invalidQuery(query) {
			#expect(query == "foo=bar")
		}
		catch {
			Issue.record("Expected BrowserAuthenticationError.invalidQuery, got \(type(of: error))")
		}
	}

	@Test func handleThrowsInvalidQueryWhenThereIsNoQuery() async throws {
		let authManager = AuthManager(key: "mock", redirectURI: nil, store: Self.store())
		let url = try #require(URL(string: "db-mock://2/token"))

		do {
			_ = try await authManager.handle(url)
			Issue.record("Expected invalidQuery to be thrown")
		}
		catch let AuthManager.BrowserAuthenticationError.invalidQuery(query) {
			#expect(query == nil)
		}
		catch {
			Issue.record("Expected BrowserAuthenticationError.invalidQuery, got \(type(of: error))")
		}
	}

	// MARK: handle(_:completion:)

	@Test func handleWithCompletionHandlerSucceeds() async throws {
		let authManager = AuthManager(key: "mock", redirectURI: nil, store: Self.store())
		let url = try #require(URL(string: "db-mock://2/token?code=auth_code_5678"))

		let result: Result<AccessToken, Error> = try await GlobalURLProtocolStub.withStub({ _ in
			"""
			{
				"access_token": "completion_exchanged_token",
				"expires_in": 3600,
				"account_id": "account_5678",
				"refresh_token": "refresh_5678"
			}
			"""
		}) {
			await withCheckedContinuation { continuation in
				authManager.handle(url, completion: { result in
					continuation.resume(returning: result)
				})
			}
		}

		let token = try result.get()
		#expect(token.accessToken == "completion_exchanged_token")
	}

	@Test func handleWithCompletionHandlerPropagatesFailure() async throws {
		let authManager = AuthManager(key: "mock", redirectURI: nil, store: Self.store())
		let url = try #require(URL(string: "db-mock://2/token?error=invalid_scope"))

		let result: Result<AccessToken, Error> = await withCheckedContinuation { continuation in
			authManager.handle(url, completion: { result in
				continuation.resume(returning: result)
			})
		}

		#expect(throws: OAuthError.invalidScope) {
			_ = try result.get()
		}
	}

}
