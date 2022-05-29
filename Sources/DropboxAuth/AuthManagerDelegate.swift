//
// Copyright © 2022 Daniel Farrelly
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

public protocol AuthManagerDelegate: AnyObject {

	/// Called when the auth manager adds a new access token.
	/// - Parameters:
	///   - authManager: The auth manager.
	///   - accessToken: The access token that was added.
	func authManager(_ authManager: AuthManager, didAdd accessToken: AccessToken)

	/// Called when the auth manager removes an access token.
	/// - Parameters:
	///   - authManager: The auth manager.
	///   - accessToken: The access token that was removed.
	func authManager(_ authManager: AuthManager, didRemove accessToken: AccessToken)

}

public extension AuthManagerDelegate {

	func authManager(_ authManager: AuthManager, didAdd accessToken: AccessToken) {}

	func authManager(_ authManager: AuthManager, didRemove accessToken: AccessToken) {}

}
