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

@Suite struct OAuthErrorTests {

	@Test func errorDescription() {
		#expect(OAuthError.unauthorizedClient.errorDescription == "The client is not authorized to request an access token using this method.")
		#expect(OAuthError.accessDenied.errorDescription == "The resource owner or authorization server denied the request.")
		#expect(OAuthError.unsupportedResponseType.errorDescription == "The authorization server does not support obtaining an access token using this method.")
		#expect(OAuthError.invalidRequest.errorDescription == "The request is invalid.")
		#expect(OAuthError.invalidScope.errorDescription == "The requested scope is invalid, unknown, or malformed.")
		#expect(OAuthError.serverError.errorDescription == "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.")
		#expect(OAuthError.temporarilyUnavailable.errorDescription == "The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.")
	}

}
