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

extension URL {

	static func authenticationURL(for authManager: AuthManager) -> URL? {
		var components = URLComponents()
		components.scheme = "https"
		components.host = "www.dropbox.com"
		components.path = "/oauth2/authorize"
		components.queryItems = [
			URLQueryItem(name: "response_type", value: "code"),
			URLQueryItem(name: "code_challenge", value: authManager.pckeCode.challenge),
			URLQueryItem(name: "code_challenge_method", value: "S256"),
			URLQueryItem(name: "client_id", value: authManager.appKey),
			URLQueryItem(name: "redirect_uri", value: authManager.redirectURI),
			URLQueryItem(name: "token_access_type", value: "offline"),
			URLQueryItem(name: "disable_signup", value: "true"),
		]

		return components.url
	}

}
