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

public extension API {

	protocol Request: Encodable, Sendable {

		associatedtype Response: API.Response where Response.Request == Self
		associatedtype Error: API.Error

		typealias Endpoint = API.Endpoint
		typealias Method = API.Method
		typealias ParameterPlacement = API.ParameterPlacement

		static var endpoint: Endpoint { get }

		static var method: Method { get }

		/// Where this request's encoded parameters are placed on the outgoing `URLRequest`.
		///
		/// Defaults to `.body`, matching the JSON-body behaviour used by most Dropbox API requests.
		/// Content endpoints (`content.dropboxapi.com`) should declare `.header` instead, which places
		/// the encoded parameters in the `Dropbox-API-Arg` header and leaves the HTTP body untouched.
		static var parameterPlacement: ParameterPlacement { get }

		func configure(_ urlRequest: inout URLRequest) throws

	}

}

public extension API.Request {

	func configure(_ urlRequest: inout URLRequest) {}

	static var parameterPlacement: ParameterPlacement { .body }

	var urlRequest: URLRequest {
		get throws {
			var urlRequest = URLRequest(url: try Self.endpoint.url)
			urlRequest.httpMethod = Self.method.rawValue

			let encoder = JSONEncoder()
			encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
			let json = try encoder.encode(self)

			switch Self.parameterPlacement {
			case .body:
				urlRequest.httpBody = json
				urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")

			case .header:
				let jsonString = String(decoding: json, as: UTF8.self)
				urlRequest.setValue(API.headerArgEncodedJSONString(jsonString), forHTTPHeaderField: "Dropbox-API-Arg")
			}

			try configure(&urlRequest)

			return urlRequest
		}
	}

	func urlRequest(
		signedWith token: AccessToken
	) throws -> URLRequest {
		token.signedRequest(from: try urlRequest)
	}

	func response(from data: Data) throws -> Response {
		let decoder = JSONDecoder()

		do {
			return try decoder.decode(Response.self, from: data)
		}
		catch {
			let decodingError = error

			let responseError: Error
			do {
				responseError = try decoder.decode(API.ErrorResponse<Error>.self, from: data).error
			}
			catch let summary as Error.Summary {
				if let oauthError = try? OAuthError(summary: summary) {
					throw oauthError
				}
				else if let authenticationError = try? AuthenticationError(summary: summary) {
					throw authenticationError
				}
				else {
					throw summary
				}
			}
			catch {
				throw decodingError
			}

			throw responseError
		}
	}

}
