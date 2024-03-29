//
// Copyright © 2024 Daniel Farrelly
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
import XCTest

class AuthErrorTests: XCTestCase {

	func testInitWithString() {
		XCTAssertEqual(AuthError(string: "unauthorized_client"), .unauthorizedClient)
		XCTAssertEqual(AuthError(string: "access_denied"), .accessDenied)
		XCTAssertEqual(AuthError(string: "unsupported_response_type"), .unsupportedResponseType)
		XCTAssertEqual(AuthError(string: "invalid_request"), .invalidRequest)
		XCTAssertEqual(AuthError(string: "invalid_scope"), .invalidScope)
		XCTAssertEqual(AuthError(string: "server_error"), .serverError)
		XCTAssertEqual(AuthError(string: "temporarily_unavailable"), .temporarilyUnavailable)
		XCTAssertEqual(AuthError(string: "some_unknown_error"), .unknown)
	}

	func testLocalizedDescription() {
		XCTAssertEqual(AuthError.unknown.localizedDescription, NSLocalizedString("An unknown error occurred.", comment: "AuthError.unknown"))
		XCTAssertEqual(AuthError.unauthorizedClient.localizedDescription, NSLocalizedString("The client is not authorized to request an access token using this method.", comment: "AuthError.unauthorizedClient"))
		XCTAssertEqual(AuthError.accessDenied.localizedDescription, NSLocalizedString("The resource owner or authorization server denied the request.", comment: "AuthError.accessDenied"))
		XCTAssertEqual(AuthError.unsupportedResponseType.localizedDescription, NSLocalizedString("The authorization server does not support obtaining an access token using this method.", comment: "AuthError.unsupportedResponseType"))
		XCTAssertEqual(AuthError.invalidRequest.localizedDescription, NSLocalizedString("The request is invalid.", comment: "AuthError.invalidRequest"))
		XCTAssertEqual(AuthError.invalidScope.localizedDescription, NSLocalizedString("The requested scope is invalid, unknown, or malformed.", comment: "AuthError.invalidScope"))
		XCTAssertEqual(AuthError.serverError.localizedDescription, NSLocalizedString("The authorization server encountered an unexpected condition that prevented it from fulfilling the request.", comment: "AuthError.serverError"))
		XCTAssertEqual(AuthError.temporarilyUnavailable.localizedDescription, NSLocalizedString("The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.", comment: "AuthError.temporarilyUnavailable"))
	}

	func testErrorDomain() {
		XCTAssertEqual(AuthError.unknown.errorDomain, "DropboxAuth.AuthError")
	}

	func testErrorCode() {
		XCTAssertEqual(AuthError.unknown.errorCode, 0)
		XCTAssertEqual(AuthError.unauthorizedClient.errorCode, 1)
		XCTAssertEqual(AuthError.accessDenied.errorCode, 2)
		XCTAssertEqual(AuthError.unsupportedResponseType.errorCode, 3)
		XCTAssertEqual(AuthError.invalidRequest.errorCode, 4)
		XCTAssertEqual(AuthError.invalidScope.errorCode, 5)
		XCTAssertEqual(AuthError.serverError.errorCode, 6)
		XCTAssertEqual(AuthError.temporarilyUnavailable.errorCode, 7)
	}

	func testCodableInitialization() {
		let jsonData = #"{"error": "invalid_scope"}"#.data(using: .utf8)!
		let error = try! JSONDecoder().decode(AuthError.self, from: jsonData)
		XCTAssertEqual(error, .invalidScope)
	}
}
