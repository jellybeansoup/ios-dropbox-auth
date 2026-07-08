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
import DropboxAuth

public enum Move {

	public struct Request: API.Request {

		public typealias Response = Move.Response
		public typealias Error = RelocationError

		public static let endpoint: Endpoint = "/files/move_v2"
		public static let method = Method.post

		public var fromPath: String

		public var toPath: String

		public var autorename: Bool = false

		public init(
			fromPath: String,
			toPath: String,
			autorename: Bool = false
		) {
			self.fromPath = fromPath
			self.toPath = toPath
			self.autorename = autorename
		}

		private enum CodingKeys: String, CodingKey {
			case fromPath = "from_path"
			case toPath = "to_path"
			case autorename
		}

	}

	public struct Response: API.Response {

		public typealias Request = Move.Request

		public var metadata: any Metadata

		init(metadata: any Metadata) {
			self.metadata = metadata
		}

		// MARK: Decodable

		private enum CodingKeys: String, CodingKey {
			case metadata
		}

		public init(from decoder: Decoder) throws {
			let container = try decoder.container(keyedBy: CodingKeys.self)

			self.init(
				metadata: try container.decode(MetadataDecodingContainer.self, forKey: .metadata).value
			)
		}

	}

}
