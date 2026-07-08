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

/// Covers `URLSession.token(with:) -> AnyPublisher<AccessToken, Error>`, the Combine counterpart
/// to the `async` `token(with:)` used by `AuthManager`'s publisher-based `refresh` API.
@Suite struct TokenResponseTests {

	@Test func publisherDecodesTokenOnSuccess() async throws {
		struct Response: Stub {
			static func stub(for request: URLRequest) throws -> String {
				"""
				{
					"access_token": "token_5678",
					"expires_in": 3600
				}
				"""
			}
		}

		let request = RefreshRequest(token: .mock(refreshToken: "refresh_1234"))
		let urlSession = URLSession.stubbed(with: Response.self)

		var cancellable: AnyCancellable?
		let token: AccessToken = try await withCheckedThrowingContinuation { continuation in
			cancellable = urlSession.token(with: request)
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

		#expect(token.accessToken == "token_5678")
		#expect(token.refreshToken == "refresh_1234")
	}

	@Test func publisherPropagatesErrorResponse() async throws {
		struct Response: Stub {
			static func stub(for request: URLRequest) throws -> String {
				"""
				{
					"error_summary": "access_denied/.",
					"error": {
						".tag": "access_denied"
					}
				}
				"""
			}
		}

		let request = RefreshRequest(token: .mock())
		let urlSession = URLSession.stubbed(with: Response.self)

		var cancellable: AnyCancellable?
		await #expect(throws: OAuthError.accessDenied) {
			try await withCheckedThrowingContinuation { continuation in
				cancellable = urlSession.token(with: request)
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
		}
		_ = cancellable
	}

}
