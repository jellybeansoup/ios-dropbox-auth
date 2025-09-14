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

	/// Represents an HTTP request method.
	///
	/// This enum provides the standard HTTP methods as defined by RFC 7231 and related specifications.
	/// Use these cases to specify the desired method when constructing a `Request`.
	@frozen enum Method: String, Sendable {

		/// The GET method requests a representation of the specified resource.
		case get = "GET"

		/// The POST method submits data to be processed to a specified resource.
		case post = "POST"

		/// The PUT method replaces all current representations of the target resource with the request payload.
		case put = "PUT"

		/// The PATCH method applies partial modifications to a resource.
		case patch = "PATCH"

		/// The DELETE method deletes the specified resource.
		case delete = "DELETE"

		/// The HEAD method asks for a response identical to a GET request, but without the response body.
		case head = "HEAD"

		/// The OPTIONS method describes the communication options for the target resource.
		case options = "OPTIONS"

		/// The TRACE method performs a message loop-back test along the path to the target resource.
		case trace = "TRACE"

		/// The CONNECT method establishes a tunnel to the server identified by the target resource.
		case connect = "CONNECT"

	}

}
