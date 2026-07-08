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

	/// Escapes a JSON string for safe transmission as a `Dropbox-API-Arg` HTTP header value.
	///
	/// HTTP headers must not contain raw non-ASCII bytes, so every non-ASCII UTF-16 code unit in the
	/// supplied JSON string is replaced with its `\uXXXX` escape sequence, as defined by RFC 8259.
	/// Characters outside the Basic Multilingual Plane (such as emoji) are escaped as a UTF-16 surrogate
	/// pair. ASCII code units (including characters JSON already escapes, such as `\"` and `\\`) are left untouched.
	/// - Parameter jsonString: A JSON-encoded string, typically produced by encoding a request's parameters.
	/// - Returns: The JSON string with all non-ASCII code units replaced by `\uXXXX` escapes.
	static func headerArgEncodedJSONString(_ jsonString: String) -> String {
		jsonString.utf16.reduce(into: "") { result, unit in
			if unit < 0x80, let scalar = Unicode.Scalar(unit) {
				result.unicodeScalars.append(scalar)
			}
			else {
				result += String(format: "\\u%04x", unit)
			}
		}
	}

}
