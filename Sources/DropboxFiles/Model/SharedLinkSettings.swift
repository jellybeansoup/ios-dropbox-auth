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

/// Settings for a shared link, used when creating one.
///
/// Only `requestedVisibility: .public` is modelled — the only visibility GIFwrapped requests.
struct SharedLinkSettings: Hashable, Sendable {

	enum RequestedVisibility: String, Hashable, Sendable {

		case `public`

	}

	var requestedVisibility: RequestedVisibility?

	init(requestedVisibility: RequestedVisibility? = nil) {
		self.requestedVisibility = requestedVisibility
	}

}

extension SharedLinkSettings: Encodable {

	private enum CodingKeys: String, CodingKey {
		case requestedVisibility = "requested_visibility"
	}

	private struct TagValue: Encodable {

		var tag: String

		private enum CodingKeys: String, CodingKey {
			case tag = ".tag"
		}

		func encode(to encoder: Encoder) throws {
			var container = encoder.container(keyedBy: CodingKeys.self)
			try container.encode(tag, forKey: .tag)
		}

	}

	func encode(to encoder: Encoder) throws {
		var container = encoder.container(keyedBy: CodingKeys.self)

		if let requestedVisibility {
			try container.encode(TagValue(tag: requestedVisibility.rawValue), forKey: .requestedVisibility)
		}
	}

}
