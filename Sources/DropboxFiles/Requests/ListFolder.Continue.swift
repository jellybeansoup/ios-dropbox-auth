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

extension ListFolder {

	enum Continue {

		struct Request: API.Request {

			typealias Response = Continue.Response
			typealias Error = Continue.Error

			static let endpoint: Endpoint = "/files/list_folder/continue"

			static let method = Method.post

			var cursor: Cursor

		}

		struct Response: API.Response {

			typealias Request = Continue.Request

			var cursor: Cursor

			var entries: [any Metadata]

			var hasMore: Bool

			init(
				cursor: Cursor,
				entries: [any Metadata],
				hasMore: Bool
			) {
				self.cursor = cursor
				self.entries = entries
				self.hasMore = hasMore
			}

			// MARK: Decodable

			private enum CodingKeys: String, CodingKey {
				case cursor
				case entries
				case hasMore = "has_more"
			}

			init(from decoder: Decoder) throws {
				let container = try decoder.container(keyedBy: CodingKeys.self)

				self.init(
					cursor: try container.decode(Cursor.self, forKey: .cursor),
					entries: try container.decode([MetadataDecodingContainer].self, forKey: .entries).map { $0.value },
					hasMore: try container.decode(Bool.self, forKey: .hasMore)
				)
			}

		}

		enum Error: API.Error {

			case lookup(LookupError)
			case reset

			init(summary: Summary) throws {
				switch summary.component {
				case "path":
					self = .lookup(try summary.next())
				case "reset":
					self = .reset
				default:
					throw summary
				}
			}

		}

	}

}
