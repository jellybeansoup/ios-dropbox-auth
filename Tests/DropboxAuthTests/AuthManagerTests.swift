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
import Combine
import DropboxAuthMocks
import Foundation
import Testing

@Suite(.serialized) struct AuthManagerTests {

	// A store whose Keychain handlers never assert on the query contents, so these tests remain
	// unaffected by the bundle-identifier-dependent query string (the pre-existing keychain-mock
	// issue tracked separately in `AccessTokenStoreTests`).
	private static func store() -> AccessTokenStore {
		.mock(
			copyMatching: { _, _ in noErr },
			update: { _, _ in noErr },
			add: { _, _ in noErr },
			delete: { _ in noErr }
		)
	}

	// MARK: authenticationURL

	@Test func authenticationURL() throws {
		let authManager = AuthManager(
			key: "appkey",
			redirectURI: URL(string: "db-appkey://2/token"),
			store: Self.store()
		)

		let url = try #require(authManager.authenticationURL)
		var components = try #require(URLComponents(url: url, resolvingAgainstBaseURL: false))
		let queryItems = try #require(components.queryItems)

		#expect(components.scheme == "https")
		#expect(components.host == "www.dropbox.com")
		#expect(components.path == "/oauth2/authorize")

		components.queryItems = nil
		#expect(queryItems.first(where: { $0.name == "response_type" })?.value == "code")
		#expect(queryItems.first(where: { $0.name == "client_id" })?.value == "appkey")
		#expect(queryItems.first(where: { $0.name == "redirect_uri" })?.value == "db-appkey://2/token")
		#expect(queryItems.first(where: { $0.name == "token_access_type" })?.value == "offline")
		#expect(queryItems.first(where: { $0.name == "disable_signup" })?.value == "true")
		#expect(queryItems.first(where: { $0.name == "code_challenge_method" })?.value == "S256")
		#expect(queryItems.first(where: { $0.name == "code_challenge" })?.value?.isEmpty == false)
	}

	// MARK: refresh(_:force:urlSession:) async

	@Test func refreshAsyncReturnsUnchangedTokenWhenNotExpiredAndNotForced() async throws {
		struct UnexpectedNetworkCall: Stub {
			static func stub(for request: URLRequest) throws -> String {
				Issue.record("Unexpectedly attempted to refresh the token.")
				return "{}"
			}
		}

		let authManager = AuthManager(key: "mock", redirectURI: nil, store: Self.store())
		let token = AccessToken.mock(accessToken: "current_token", expiryDate: .init(timeIntervalSinceNow: 3600))

		let result = try await authManager.refresh(token, urlSession: .stubbed(with: UnexpectedNetworkCall.self))

		#expect(result.accessToken == "current_token")
		#expect(result.appKey == "mock")
	}

	@Test func refreshAsyncRefreshesWhenExpired() async throws {
		struct RefreshResponse: Stub {
			static func stub(for request: URLRequest) throws -> String {
				"""
				{
					"access_token": "refreshed_token",
					"expires_in": 3600
				}
				"""
			}
		}

		let authManager = AuthManager(key: "mock", redirectURI: nil, store: Self.store())
		let token = AccessToken.mock(
			accessToken: "expired_token",
			scope: "account_info.read",
			accountID: "account_1234",
			teamID: "team_1234",
			refreshToken: "refresh_1234"
		)

		let result = try await authManager.refresh(token, urlSession: .stubbed(with: RefreshResponse.self))

		#expect(result.accessToken == "refreshed_token")
		#expect(ceil(result.expiryDate.timeIntervalSinceNow) == 3600)
		#expect(result.scope == "account_info.read")
		#expect(result.accountID == "account_1234")
		#expect(result.teamID == "team_1234")
		#expect(result.refreshToken == "refresh_1234")
	}

	@Test func refreshAsyncRefreshesWhenForcedDespiteNotExpired() async throws {
		struct RefreshResponse: Stub {
			static func stub(for request: URLRequest) throws -> String {
				"""
				{
					"access_token": "forced_refresh_token",
					"expires_in": 3600
				}
				"""
			}
		}

		let authManager = AuthManager(key: "mock", redirectURI: nil, store: Self.store())
		let token = AccessToken.mock(accessToken: "current_token", expiryDate: .init(timeIntervalSinceNow: 3600))

		let result = try await authManager.refresh(token, force: true, urlSession: .stubbed(with: RefreshResponse.self))

		#expect(result.accessToken == "forced_refresh_token")
	}

	// MARK: refresh(_:force:urlSession:) -> AnyPublisher

	@Test func refreshPublisherReturnsUnchangedTokenWhenNotExpiredAndNotForced() async throws {
		struct UnexpectedNetworkCall: Stub {
			static func stub(for request: URLRequest) throws -> String {
				Issue.record("Unexpectedly attempted to refresh the token.")
				return "{}"
			}
		}

		let authManager = AuthManager(key: "mock", redirectURI: nil, store: Self.store())
		let token = AccessToken.mock(accessToken: "current_token", expiryDate: .init(timeIntervalSinceNow: 3600))

		var cancellable: AnyCancellable?
		let result: AccessToken = try await withCheckedThrowingContinuation { continuation in
			cancellable = authManager.refresh(token, urlSession: .stubbed(with: UnexpectedNetworkCall.self))
				.sink(
					receiveCompletion: { completion in
						if case let .failure(error) = completion {
							continuation.resume(throwing: error)
						}
					},
					receiveValue: { value in
						continuation.resume(returning: value)
					}
				)
		}
		_ = cancellable

		#expect(result.accessToken == "current_token")
	}

	@Test func refreshPublisherRefreshesWhenExpired() async throws {
		struct RefreshResponse: Stub {
			static func stub(for request: URLRequest) throws -> String {
				"""
				{
					"access_token": "refreshed_token",
					"expires_in": 3600
				}
				"""
			}
		}

		let authManager = AuthManager(key: "mock", redirectURI: nil, store: Self.store())
		let token = AccessToken.mock(accessToken: "expired_token")

		var cancellable: AnyCancellable?
		let result: AccessToken = try await withCheckedThrowingContinuation { continuation in
			cancellable = authManager.refresh(token, urlSession: .stubbed(with: RefreshResponse.self))
				.sink(
					receiveCompletion: { completion in
						if case let .failure(error) = completion {
							continuation.resume(throwing: error)
						}
					},
					receiveValue: { value in
						continuation.resume(returning: value)
					}
				)
		}
		_ = cancellable

		#expect(result.accessToken == "refreshed_token")
	}

	// MARK: refresh(_:force:completion:)

	@Test func refreshWithCompletionHandlerSucceeds() async throws {
		let authManager = AuthManager(key: "mock", redirectURI: nil, store: Self.store())
		let token = AccessToken.mock(accessToken: "expired_token")

		let result: Result<AccessToken, Error> = try await GlobalURLProtocolStub.withStub({ _ in
			"""
			{
				"access_token": "completion_refreshed_token",
				"expires_in": 3600
			}
			"""
		}) {
			await withCheckedContinuation { continuation in
				authManager.refresh(token, completion: { result in
					continuation.resume(returning: result)
				})
			}
		}

		let refreshedToken = try result.get()
		#expect(refreshedToken.accessToken == "completion_refreshed_token")
	}

	@Test func refreshWithCompletionHandlerPropagatesFailure() async throws {
		let authManager = AuthManager(key: "mock", redirectURI: nil, store: Self.store())
		let token = AccessToken.mock(accessToken: "expired_token")

		let result: Result<AccessToken, Error> = try await GlobalURLProtocolStub.withStub({ _ in
			"""
			{
				"error_summary": "access_denied/.",
				"error": {
					".tag": "access_denied"
				}
			}
			"""
		}) {
			await withCheckedContinuation { continuation in
				authManager.refresh(token, completion: { result in
					continuation.resume(returning: result)
				})
			}
		}

		#expect(throws: OAuthError.accessDenied) {
			_ = try result.get()
		}
	}

}
