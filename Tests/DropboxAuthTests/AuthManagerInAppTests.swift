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
import Testing

#if canImport(AppKit) && !targetEnvironment(macCatalyst)
import AppKit

/// Covers `AuthManager.defaultWindowProvider()` on macOS. This is safe to exercise directly: it
/// never presents any UI, it only inspects `NSApplication.shared.mainWindow` (nil in a test host)
/// and falls back to constructing a fresh, unshown `NSWindow`.
///
/// The rest of `AuthManager+InApp.swift` (`authenticateLocally`) constructs and starts a real
/// `ASWebAuthenticationSession`, which presents interactive UI and waits on user action — that's
/// untestable-at-this-layer without a source-level injection point for the session itself.
@Suite struct AuthManagerInAppTests {

	@MainActor
	@Test func defaultWindowProviderReturnsAWindow() {
		// With no `NSApplication.mainWindow` in the test host, this falls back to constructing a
		// fresh `NSWindow` each call, rather than returning some shared/cached instance.
		let first = AuthManager.defaultWindowProvider()
		let second = AuthManager.defaultWindowProvider()

		#expect(first !== second)
		#expect(first.isVisible == false)
	}

}
#endif
