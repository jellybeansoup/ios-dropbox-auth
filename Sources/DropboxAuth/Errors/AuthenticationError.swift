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

public enum AuthenticationError: String, API.Error, LocalizedError {

	/// The token has become invalid, which usually happens due to being revoked.
	///
	/// If you get this error, you will need to manually prompt the user to reauthenticate before using the account to
	/// perform any additional API calls.
	case invalidAccessToken = "invalid_access_token"

	/// The access token has expired and should be refreshed.
	///
	/// Refresh is done automatically when using `Transport` APIs, and can be done manually using the APIs available on
	/// the `AuthManager`. Once refreshed, the new token can be used to make additional calls.
	case expiredAccessToken = "expired_access_token"

	public init(summary: Summary) throws {
		guard let component = summary.component else {
			throw summary
		}

		if let error = Self(rawValue: component) {
			self = error
		}
		else if component == "invalid_grant" {
			self = .invalidAccessToken
		}
		else {
			throw summary
		}
	}

	// MARK: Localized Error

	public var errorDescription: String? {
		NSLocalizedString("AuthenticationError.\(self).description", bundle: .module, comment: "")
	}

	public var failureReason: String? {
		NSLocalizedString("AuthenticationError.\(self).failureReason", bundle: .module, comment: "")
	}

	public var recoverySuggestion: String? {
		NSLocalizedString("AuthenticationError.recoverySuggestion", bundle: .module, comment: "")
	}

}
