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

/// Flag for indicating the reason authorisation failed.
public enum OAuthError: String, API.Error, LocalizedError {

	/// The client is not authorized to request an access token using this method.
	case unauthorizedClient = "unauthorized_client"

	/// The resource owner or authorization server denied the request.
	case accessDenied = "access_denied"

	/// The authorization server does not support obtaining an access token using this method.
	case unsupportedResponseType = "unsupported_response_type"

	/// The request is invalid.
	case invalidRequest = "invalid_request"

	/// The requested scope is invalid, unknown, or malformed.
	case invalidScope = "invalid_scope"

	/// The authorization server encountered an unexpected condition that prevented it from fulfilling the request.
	case serverError = "server_error"

	/// The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.
	case temporarilyUnavailable = "temporarily_unavailable"

	// MARK: Localized Error

	public var errorDescription: String? {
		NSLocalizedString("OAuthError.\(self).description", bundle: .module, comment: "")
	}

}
