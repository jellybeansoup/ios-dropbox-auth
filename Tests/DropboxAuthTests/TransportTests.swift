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

@Suite struct TransportTests {

	@Test func responseForUnauthenticatedRequest() async throws {
		struct Response: Stub {

			static func stub(for request: URLRequest) throws -> String {
				#expect(request.value(forHTTPHeaderField: "Authorization") == nil)

				return #"{"foo": "bar"}"#
			}

		}

		struct Dummy: API.Request, Encodable, Sendable {

			struct Response: API.Response, Hashable {
				typealias Request = Dummy
				let foo: String
			}

			enum Error: String, API.Error {
				case example
			}

			static let endpoint: API.Endpoint = .api("/echo")
			static let method: API.Method = .post

		}

		let token = AccessToken.mock(accessToken: "provided_token")
		let transport = Transport(
			authManager: .init(key: "mock", store: .mock(token: token)),
			accountID: token.accountID,
			urlSession: .stubbed(with: Response.self)
		)

		let request = Dummy()
		let response = try await transport.response(for: request, needsAuthentication: false)

		#expect(response == Dummy.Response(foo: "bar"))
	}

	@Test func responseForAuthenticatedRequest() async throws {
		struct Response: Stub {

			static func stub(for request: URLRequest) throws -> String {
				#expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer provided_token")

				return #"{"foo": "bar"}"#
			}

		}

		struct Dummy: API.Request, Encodable, Sendable {

			struct Response: API.Response, Hashable {
				typealias Request = Dummy
				let foo: String
			}

			enum Error: String, API.Error {
				case example
			}

			static let endpoint: API.Endpoint = .api("/echo")
			static let method: API.Method = .post

		}

		let token = AccessToken.mock(accessToken: "provided_token")
		let transport = Transport(
			authManager: .init(key: "mock", store: .mock(token: token)),
			accountID: token.accountID,
			urlSession: .stubbed(with: Response.self)
		)

		let request = Dummy()
		let response = try await transport.response(for: request, needsAuthentication: true)

		#expect(response == Dummy.Response(foo: "bar"))
	}

	@Test func withRetryRefreshesOnExpired() async throws {
		struct Response: Stub {

			static func stub(for request: URLRequest) throws -> String {
				"""
				{
					"access_token": "new_token",
					"expires_in": 3600
				}
				"""
			}

		}

		let token = AccessToken.mock(accessToken: "old_token")
		let transport = Transport(
			authManager: .init(
				key: "mock",
				redirectURI: nil,
				store: .mock(token: token)
			),
			accountID: token.accountID,
			urlSession: .stubbed(with: Response.self)
		)

		var attempt = 0
		let result: String = try await transport.withRetry {
			attempt += 1

			if attempt == 1 {
				throw AuthenticationError.expiredAccessToken
			} else {
				return "ok"
			}
		}

		#expect(attempt == 2)
		#expect(result == "ok")
	}

	@Test func withRetryRefreshesOnlyOnce() async throws {
		struct Response: Stub {

			static func stub(for request: URLRequest) throws -> String {
				"""
				{
					"access_token": "new_token",
					"expires_in": 3600
				}
				"""
			}

		}

		let token = AccessToken.mock(accessToken: "old_token")
		let transport = Transport(
			authManager: .init(
				key: "mock",
				redirectURI: nil,
				store: .mock(token: token)
			),
			accountID: token.accountID,
			urlSession: .stubbed(with: Response.self)
		)

		var attempt = 0
		await #expect(throws: AuthenticationError.expiredAccessToken) {
			_ = try await transport.withRetry {
				attempt += 1
				throw AuthenticationError.expiredAccessToken
			}
		}
		#expect(attempt == 2)
	}

	@Test func withRetryPropagatesNonExpirationErrors() async throws {
		let transport = Transport(
			authManager: .init(key: "mock"),
			token: .mock()
		)

		var attempt = 0
		await #expect(throws: AuthenticationError.invalidAccessToken) {
			_ = try await transport.withRetry {
				attempt += 1
				throw AuthenticationError.invalidAccessToken
			}
		}
		#expect(attempt == 1)
	}

	@Test func withRetryRespectsCancellation() async throws {
		struct Response: Stub {

			static func stub(for request: URLRequest) throws -> String {
				"""
				{
					"access_token": "new_token",
					"expires_in": 3600
				}
				"""
			}

		}

		let transport = Transport(
			authManager: .init(key: "mock"),
			token: .mock(),
			urlSession: .stubbed(with: Response.self)
		)

		let task = Task {
			try await transport.withRetry {
				try await Task.sleep(for: .milliseconds(100))
				throw AuthenticationError.expiredAccessToken
			}
		}

		task.cancel()

		await #expect(throws: CancellationError.self) {
			_ = try await task.value
		}
	}

}
