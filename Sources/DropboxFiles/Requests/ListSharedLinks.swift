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

public enum ListSharedLinks {

	public struct Request: API.Request {

		public typealias Response = ListSharedLinks.Response
		public typealias Error = ListSharedLinks.Error

		public static let endpoint: Endpoint = "/sharing/list_shared_links"
		public static let method = Method.post

		/// The path to retrieve links for. If `nil` a list of all shared links for the current user is requested.
		public var path: String? = nil

		/// The cursor returned by the last `ListSharedLinks.Response`. Used to handle paginated results.
		public var cursor: Cursor? = nil

		/// Suppress links to parent folders.
		public var isDirectOnly: Bool? = nil

		public init(
			path: String? = nil,
			cursor: Cursor? = nil,
			isDirectOnly: Bool? = nil
		) {
			self.path = path
			self.cursor = cursor
			self.isDirectOnly = isDirectOnly
		}

		private enum CodingKeys: String, CodingKey {
			case path
			case cursor
			case isDirectOnly = "direct_only"
		}

	}

	public struct Response: API.Response {

		public typealias Request = ListSharedLinks.Request

		public var cursor: Cursor?

		public var links: [any LinkMetadata]

		public var hasMore: Bool

		init(
			cursor: Cursor?,
			links: [any LinkMetadata],
			hasMore: Bool
		) {
			self.cursor = cursor
			self.links = links
			self.hasMore = hasMore
		}

		// MARK: Decodable

		private enum CodingKeys: String, CodingKey {
			case cursor
			case links
			case hasMore = "has_more"
		}

		public init(from decoder: Decoder) throws {
			let container = try decoder.container(keyedBy: CodingKeys.self)

			self.init(
				cursor: try container.decodeIfPresent(Cursor.self, forKey: .cursor),
				links: try container.decode([LinkMetadataDecodingContainer].self, forKey: .links).map { $0.value },
				hasMore: try container.decode(Bool.self, forKey: .hasMore)
			)
		}

	}

	public enum Error: API.Error {

		public typealias Request = ListSharedLinks.Request

		case lookup(LookupError)
		case reset

		public init(summary: Summary) throws {
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

