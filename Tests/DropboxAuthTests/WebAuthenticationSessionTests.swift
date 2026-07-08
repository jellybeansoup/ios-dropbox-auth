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

/// Covers `WebAuthenticationSession.handleCompletion(...)` and `.throwIfFailedToStart(...)` — the
/// two pieces of `WebAuthenticationSession`'s logic that were extracted into pure, `Bundle`
/// independent static functions specifically so they're unit-testable.
///
/// Not covered here (the intentional untested boundary): `WebAuthenticationSession.init` and
/// `.start()` themselves. Constructing a real `ASWebAuthenticationSession` there presents live
/// interactive UI and waits on user action — already known to be untestable — but there's a second,
/// independent reason discovered while building this seam: `init` asserts that `Bundle.main` has
/// the app's custom URL scheme configured (`Bundle.main.hasConfiguredScheme(...)`), and the
/// `swift test` executable's bundle has no `CFBundleURLTypes` entry at all, so that assertion trips
/// immediately regardless of which `AuthManager`/appKey is used — no injection seam on the session
/// type itself changes that. Extracting the two functions below was the way to make the actual
/// *logic* reachable without needing to get past that assertion.
@Suite struct WebAuthenticationSessionTests {

	private static func authManager() -> AuthManager {
		AuthManager(
			key: "mock",
			redirectURI: nil,
			store: .mock(
				copyMatching: { _, _ in noErr },
				update: { _, _ in noErr },
				add: { _, _ in noErr },
				delete: { _ in noErr }
			)
		)
	}

	// MARK: throwIfFailedToStart(_:)

	@MainActor
	@Test func throwIfFailedToStartThrowsUnableToStartWhenFalse() {
		#expect(throws: WebAuthenticationSession.Error.unableToStart) {
			try WebAuthenticationSession.throwIfFailedToStart(false)
		}
	}

	@MainActor
	@Test func throwIfFailedToStartDoesNotThrowWhenTrue() throws {
		try WebAuthenticationSession.throwIfFailedToStart(true)
	}

	// MARK: handleCompletion(url:error:authManager:completion:)

	@MainActor
	@Test func handleCompletionPropagatesTheUnderlyingErrorDirectly() {
		var result: Result<AccessToken, Swift.Error>?

		// `ASWebAuthenticationSessionError(.canceledLogin)` is what the real session reports when
		// the user cancels; the code has no special case for it, so any error — cancel included —
		// should surface unchanged.
		struct SomeError: Swift.Error, Equatable {}

		WebAuthenticationSession.handleCompletion(
			url: nil,
			error: SomeError(),
			authManager: Self.authManager(),
			completion: { result = $0 }
		)

		switch result {
		case .failure(let error as SomeError):
			#expect(error == SomeError())
		default:
			Issue.record("Expected a failure wrapping the underlying error, got \(String(describing: result))")
		}
	}

	@MainActor
	@Test func handleCompletionFailsWithMissingURLWhenBothURLAndErrorAreNil() {
		var result: Result<AccessToken, Swift.Error>?

		WebAuthenticationSession.handleCompletion(
			url: nil,
			error: nil,
			authManager: Self.authManager(),
			completion: { result = $0 }
		)

		switch result {
		case .failure(WebAuthenticationSession.Error.missingURL):
			break
		default:
			Issue.record("Expected .missingURL, got \(String(describing: result))")
		}
	}

	@MainActor
	@Test func handleCompletionFailsWithMissingAuthManagerWhenAuthManagerIsNil() {
		var result: Result<AccessToken, Swift.Error>?
		let url = URL(string: "db-mock://2/token?code=abc")!

		WebAuthenticationSession.handleCompletion(
			url: url,
			error: nil,
			authManager: nil,
			completion: { result = $0 }
		)

		switch result {
		case .failure(WebAuthenticationSession.Error.missingAuthManager):
			break
		default:
			Issue.record("Expected .missingAuthManager, got \(String(describing: result))")
		}
	}

	@Test func handleCompletionExchangesTheCodeForATokenOnSuccess() async throws {
		let authManager = Self.authManager()
		let url = URL(string: "db-mock://2/token?code=session_code")!

		let result: Result<AccessToken, Swift.Error> = try await GlobalURLProtocolStub.withStub({ _ in
			"""
			{
				"access_token": "session_exchanged_token",
				"expires_in": 3600,
				"account_id": "account_9999",
				"refresh_token": "refresh_9999"
			}
			"""
		}) {
			await withCheckedContinuation { continuation in
				Task { @MainActor in
					WebAuthenticationSession.handleCompletion(
						url: url,
						error: nil,
						authManager: authManager,
						completion: { continuation.resume(returning: $0) }
					)
				}
			}
		}

		let token = try result.get()
		#expect(token.accessToken == "session_exchanged_token")
		#expect(token.accountID == "account_9999")
	}

}

#if canImport(AppKit) && !targetEnvironment(macCatalyst)
import AppKit
import AuthenticationServices

/// Covers `WindowProviderContainer`, which has no dependency on `Bundle.main`'s URL-scheme
/// configuration (unlike `WebAuthenticationSession.init` above) and so is directly testable: it
/// never presents any UI, it just returns whatever window its `windowProvider` closure supplies.
@Suite struct WindowProviderContainerTests {

	@MainActor
	@Test func presentationAnchorReturnsTheProvidedWindow() {
		let expectedWindow = NSWindow()
		let container = WindowProviderContainer(windowProvider: { expectedWindow })

		// The real `ASWebAuthenticationSession` instance here is just an opaque argument that
		// `presentationAnchor(for:)` never inspects — constructing one doesn't touch `Bundle.main`
		// or trip any assertion, unlike `WebAuthenticationSession.init`.
		let session = ASWebAuthenticationSession(
			url: URL(string: "https://example.com")!,
			callbackURLScheme: "example",
			completionHandler: { _, _ in }
		)

		let anchor = container.presentationAnchor(for: session)

		#expect(anchor === expectedWindow)
	}

}
#endif
