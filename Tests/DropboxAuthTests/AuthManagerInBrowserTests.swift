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
/// hand-off URL and parsing the app's return redirect (`handle(_:)`), plus the platform
/// `authenticateInBrowser()` overloads via their `openInSystemBrowser(opener:)` injection seam.
///
/// The public `authenticateInBrowser()` overloads (UIKit/AppKit) call straight through to
/// `UIApplication.open`/`NSWorkspace.open`, which would actually launch the system browser if
/// exercised directly — so they're tested via `openInSystemBrowser(opener:)`, the internal seam
/// they delegate to, which lets a fake opener stand in for the real one. `handle(_:)`'s network
/// path has no such internal seam, so it's exercised via `GlobalURLProtocolStub`, which intercepts
/// `.shared` for the duration of a test.
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
		struct ExchangeResponse: Stub {
			static func stub(for request: URLRequest) throws -> String {
				"""
				{
					"access_token": "exchanged_token",
					"expires_in": 3600,
					"account_id": "account_1234",
					"refresh_token": "refresh_1234"
				}
				"""
			}
		}

		let authManager = AuthManager(key: "mock", redirectURI: nil, store: Self.store())
		let url = try #require(URL(string: "db-mock://2/token?code=auth_code_1234"))

		let token = try await authManager.handle(url, urlSession: .stubbed(with: ExchangeResponse.self))

		#expect(token.accessToken == "exchanged_token")
		#expect(token.accountID == "account_1234")
		#expect(token.refreshToken == "refresh_1234")
	}

	@Test func handlePropagatesOAuthErrorFromQuery() async throws {
		struct UnexpectedNetworkCall: Stub {
			static func stub(for request: URLRequest) throws -> String {
				Issue.record("Unexpectedly attempted to exchange a code — the query has no code, only an error.")
				return "{}"
			}
		}

		let authManager = AuthManager(key: "mock", redirectURI: nil, store: Self.store())
		let url = try #require(URL(string: "db-mock://2/token?error=access_denied"))

		await #expect(throws: OAuthError.accessDenied) {
			_ = try await authManager.handle(url, urlSession: .stubbed(with: UnexpectedNetworkCall.self))
		}
	}

	@Test func handleUsesTheSharedURLSessionByDefault() async throws {
		// Confirms the public `handle(_:)` overload really does default to `.shared` (rather than,
		// say, some other session), by intercepting `.shared` globally — the one case where
		// `GlobalURLProtocolStub` is still needed, since there's no seam on the public overload
		// itself to inject a session directly.
		let authManager = AuthManager(key: "mock", redirectURI: nil, store: Self.store())
		let url = try #require(URL(string: "db-mock://2/token?code=auth_code_default_session"))

		let token = try await GlobalURLProtocolStub.withStub({ _ in
			"""
			{
				"access_token": "default_session_token",
				"expires_in": 3600,
				"account_id": "account_default_session",
				"refresh_token": "refresh_default_session"
			}
			"""
		}) {
			try await authManager.handle(url)
		}

		#expect(token.accessToken == "default_session_token")
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

	// MARK: openInSystemBrowser(opener:)

#if canImport(UIKit)
	@MainActor
	@Test func openInSystemBrowserPassesTheAuthenticationURLToTheOpener() {
		let authManager = AuthManager(key: "mock", redirectURI: nil, store: Self.store())
		let expectedURL = authManager.authenticationURL

		let handled = authManager.openInSystemBrowser { url in url == expectedURL }

		#expect(handled)
	}

	@MainActor
	@Test func openInSystemBrowserReturnsFalseWhenTheOpenerFails() {
		let authManager = AuthManager(key: "mock", redirectURI: nil, store: Self.store())

		let handled = authManager.openInSystemBrowser { _ in false }

		#expect(handled == false)
	}
#endif

#if canImport(AppKit) && !targetEnvironment(macCatalyst)
	@MainActor
	@Test func openInSystemBrowserPassesTheAuthenticationURLToTheOpenerOnAppKit() {
		let authManager = AuthManager(key: "mock", redirectURI: nil, store: Self.store())
		let expectedURL = authManager.authenticationURL

		let handled = authManager.openInSystemBrowser { url in url == expectedURL }

		#expect(handled)
	}

	@MainActor
	@Test func openInSystemBrowserReturnsFalseWhenTheOpenerFailsOnAppKit() {
		let authManager = AuthManager(key: "mock", redirectURI: nil, store: Self.store())

		let handled = authManager.openInSystemBrowser { _ in false }

		#expect(handled == false)
	}
#endif

}
