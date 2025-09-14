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

public extension AuthManager {

	typealias WindowProvider = @MainActor @Sendable () -> Window

	/// Uses `ASWebAuthenticationSession` to authenticate without leaving the app.
	///
	/// On iOS and iPadOS, this presents a web browser window within the current scene. On macOS
	/// (including with Catalyst), this presents a web browser in a new window.
	/// - Note: Because the entire authentication flow occurs in-app, it is not necessary to call
	/// 	`handle(_:)` at any at any stage when using this authentication option. By the time the
	/// 	method returns the token will have been fully processed and stored in Keychain.
	/// - Parameter windowProvider: Optional closure that returns the underlying window from which to
	///   	present the authentication prompt.
	/// - Returns: The access token returned by Dropbox, if the authentication was successful.
	@MainActor
	func authenticateLocally(
		from windowProvider: @escaping WindowProvider = { AuthManager.defaultWindowProvider() }
	) async throws -> AccessToken {
		try await withCheckedThrowingContinuation { continuation in
			do {
				var session: WebAuthenticationSession!
				session = WebAuthenticationSession(
					authManager: self,
					windowProvider: windowProvider,
					completion: {
						continuation.resume(with: $0)
						session = nil
					}
				)

				try session.start()
			}
			catch {
				continuation.resume(throwing: error)
			}
		}
	}

	/// Uses `ASWebAuthenticationSession` to authenticate without leaving the app.
	///
	/// On iOS and iPadOS, this presents a web browser window within the current scene. On macOS
	/// (including with Catalyst), this presents a web browser in a new window.
	/// - Note: Because the entire authentication flow occurs in-app, it is not necessary to call
	/// 	`handle(_:)` at any stage when using this authentication option. By the time the completion
	/// 	handler is called, the token will have been fully processed and stored in Keychain.
	/// - Parameters:
	///   - windowProvider: Optional closure that returns the underlying window from which to
	///   		present the authentication prompt.
	///   - completion: Optional closure that is called with the result of the authentication.
	func authenticateLocally(
		from windowProvider: @escaping WindowProvider = { AuthManager.defaultWindowProvider() },
		completion: (@MainActor @Sendable (Result<AccessToken, Error>) -> Void)? = nil
	) {
		Task {
			do {
				let token = try await authenticateLocally(from: windowProvider)
				await completion?(.success(token))
			}
			catch {
				await completion?(.failure(error))
			}
		}
	}

}

#if canImport(UIKit)
import UIKit

public extension AuthManager {

	typealias Window = UIWindow

	/// Method used as a default for providing the window from which to present the in-app authentication flow.
	/// - Returns: The first window in the first scene found to be in the `.foregroundActive` state.
	@MainActor
	static func defaultWindowProvider() -> Window {
		guard
			let application = UIApplication.value(forKey: "sharedApplication") as? UIApplication,
			let scene = application.connectedScenes.compactMap({ $0 as? UIWindowScene }).first(where: { $0.activationState == .foregroundActive }),
			let window = scene.windows.first
		else {
			return UIWindow()
		}

		return window
	}

}
#endif

#if canImport(AppKit) && !targetEnvironment(macCatalyst)
import AppKit

public extension AuthManager {

	typealias Window = NSWindow

	/// Method used as a default for providing the window from which to present the in-app authentication flow.
	/// - Returns: The first window in the first scene found to be in the `.foregroundActive` state.
	@MainActor
	static func defaultWindowProvider() -> Window {
		guard
			let application = NSApplication.value(forKey: "sharedApplication") as? NSApplication,
			let window = application.mainWindow
		else {
			return NSWindow()
		}

		return window
	}

}
#endif
