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

public enum Delete {

	public struct Request: API.Request {

		public typealias Response = Delete.Response
		public typealias Error = Delete.Error

		public static let endpoint: Endpoint = "/files/delete_v2"
		public static let method = Method.post

		public var path: String

		public init(path: String) {
			self.path = path
		}

	}

	public struct Response: API.Response {

		public typealias Request = Delete.Request

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

	public enum Error: API.Error {

		public typealias Request = Delete.Request

		case lookup(LookupError)
		case write(WriteError)
		case tooManyWriteOperations
		case tooManyFiles

		public init(summary: Summary) throws {
			switch summary.component {
			case "path_lookup":
				self = .lookup(try summary.next())
			case "path_write":
				self = .write(try summary.next())
			case "too_many_write_operations":
				self = .tooManyWriteOperations
			case "too_many_files":
				self = .tooManyFiles
			default:
				throw summary
			}
		}

	}

}
