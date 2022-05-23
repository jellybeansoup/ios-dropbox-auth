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

/// Flag for indicating the reason authorisation failed.
public enum AuthError: Int, Error, CustomNSError {

	/// Some other error (outside of the OAuth2 specification)
	case unknown = 0

	/// The client is not authorized to request an access token using this method.
	case unauthorizedClient = 1

	/// The resource owner or authorization server denied the request.
	case accessDenied = 2

	/// The authorization server does not support obtaining an access token using this method.
	case unsupportedResponseType = 3

	/// The requested scope is invalid, unknown, or malformed.
	case invalidScope = 4

	/// The authorization server encountered an unexpected condition that prevented it from fulfilling the request.
	case serverError = 5

	/// The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.
	case temporarilyUnavailable = 6

	init(string: String) {
		switch string {
		case "unauthorized_client":
			self = .unauthorizedClient

		case "access_denied":
			self = .accessDenied

		case "unsupported_response_type":
			self = .unsupportedResponseType

		case "invalid_scope":
			self = .invalidScope

		case "server_error":
			self = .serverError

		case "temporarily_unavailable":
			self = .temporarilyUnavailable

		default:
			self = .unknown
		}
	}

	// MARK: Error

	var localizedDescription: String {
		switch self {
		case .unknown:
			return NSLocalizedString("An unknown error occurred.", comment: "AuthError.unknown")
		case .unauthorizedClient:
			return NSLocalizedString("The client is not authorized to request an access token using this method.", comment: "AuthError.unauthorizedClient")
		case .accessDenied:
			return NSLocalizedString("The resource owner or authorization server denied the request.", comment: "AuthError.accessDenied")
		case .unsupportedResponseType:
			return NSLocalizedString("The authorization server does not support obtaining an access token using this method.", comment: "AuthError.unsupportedResponseType")
		case .invalidScope:
			return NSLocalizedString("The requested scope is invalid, unknown, or malformed.", comment: "AuthError.invalidScope")
		case .serverError:
			return NSLocalizedString("The authorization server encountered an unexpected condition that prevented it from fulfilling the request.", comment: "AuthError.serverError")
		case .temporarilyUnavailable:
			return NSLocalizedString("The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.", comment: "AuthError.temporarilyUnavailable")
		}
	}

	// MARK: Custom NSError

	public var errorDomain: String {
		return "DropboxAuth.AuthError"
	}

	public var errorCode: Int {
		return rawValue
	}

}
