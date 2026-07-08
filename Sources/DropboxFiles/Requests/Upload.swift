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

public enum Upload {

	/// How an upload should treat an existing file already at the destination path.
	public enum WriteMode: Hashable, Sendable {

		/// Always create a new file, auto-renaming the added file if there's a conflict (does not overwrite).
		case add

		/// Always overwrite the existing file at the destination path, if there is one.
		case overwrite

		/// Overwrite the destination only if its current revision matches the given one, failing otherwise.
		case update(FileMetadata.Revision)

	}

	public struct Request: API.Request {

		public typealias Response = Upload.Response
		public typealias Error = Upload.Error

		public static let endpoint: Endpoint = .content("/files/upload")
		public static let method = Method.post
		public static let parameterPlacement = ParameterPlacement.header

		/// The destination path for the uploaded file.
		public var path: String

		/// How to treat an existing file at the destination path.
		public var mode: WriteMode

		/// Whether to automatically rename the file if there's a conflict at the destination.
		public var autorename: Bool

		/// The raw contents of the file being uploaded.
		public var contents: Data

		public init(
			path: String,
			mode: WriteMode = .add,
			autorename: Bool = false,
			contents: Data
		) {
			self.path = path
			self.mode = mode
			self.autorename = autorename
			self.contents = contents
		}

		private enum CodingKeys: String, CodingKey {
			case path
			case mode
			case autorename
		}

		public func configure(_ urlRequest: inout URLRequest) throws {
			urlRequest.httpBody = contents
			urlRequest.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
		}

	}

	public struct Response: API.Response {

		public typealias Request = Upload.Request

		public var metadata: FileMetadata

		init(metadata: FileMetadata) {
			self.metadata = metadata
		}

		// MARK: Decodable

		public init(from decoder: Decoder) throws {
			self.init(metadata: try FileMetadata(from: decoder))
		}

	}

	public enum Error: API.Error {

		public typealias Request = Upload.Request

		case path(WriteError)
		case propertiesError
		case payloadTooLarge
		case contentHashMismatch
		case tooManyWriteOperations

		public init(summary: Summary) throws {
			switch summary.component {
			case "path":
				self = .path(try summary.next())
			case "properties_error":
				self = .propertiesError
			case "payload_too_large":
				self = .payloadTooLarge
			case "content_hash_mismatch":
				self = .contentHashMismatch
			case "too_many_write_operations":
				self = .tooManyWriteOperations
			default:
				throw summary
			}
		}

	}

}

extension Upload.WriteMode: Encodable {

	private enum CodingKeys: String, CodingKey {
		case update
	}

	public func encode(to encoder: Encoder) throws {
		switch self {
		case .add:
			var container = encoder.singleValueContainer()
			try container.encode("add")

		case .overwrite:
			var container = encoder.singleValueContainer()
			try container.encode("overwrite")

		case .update(let revision):
			var container = encoder.container(keyedBy: CodingKeys.self)
			try container.encode(revision, forKey: .update)
		}
	}

}
