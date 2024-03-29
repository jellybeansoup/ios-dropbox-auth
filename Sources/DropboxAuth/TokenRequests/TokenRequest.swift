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

import Foundation

enum Method: String {
	case get = "GET"
	case post = "POST"
}

protocol TokenRequest: MultipartEncodable {

	associatedtype Response: TokenResponse where Response.Request == Self

	static var url: URL { get }

	static var method: Method { get }

}

protocol TokenResponse: Decodable {

	associatedtype Request: TokenRequest where Request.Response == Self

	func token(for originalRequest: Request) -> AccessToken

}

extension URLSession {

	func token<Request: TokenRequest>(
		with request: Request
	) async throws -> AccessToken {
		var urlRequest = URLRequest(url: Request.url)
		urlRequest.httpMethod = Request.method.rawValue

		let encoder = MultipartEncoder()
		urlRequest.httpBody = encoder.encode(request)
		urlRequest.addValue("multipart/form-data; charset=utf-8; boundary=\(encoder.boundary)", forHTTPHeaderField: "Content-Type")

		let (data, _) = try await data(for: urlRequest)

		let response: Request.Response
		do {
			response = try JSONDecoder().decode(Request.Response.self, from: data)
		}
		catch {
			throw (try? JSONDecoder().decode(AuthError.self, from: data)) ?? error
		}

		return response.token(for: request)
	}

}
