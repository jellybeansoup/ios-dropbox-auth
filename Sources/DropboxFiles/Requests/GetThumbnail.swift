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

public enum GetThumbnail {

	/// The image format for the generated thumbnail.
	///
	/// Only `png` is modelled — the only format GIFwrapped requests — out of Dropbox's larger option set,
	/// matching the legacy (v1) client's argument shape.
	public enum Format: String, Encodable, Hashable, Sendable {

		case png

	}

	/// The target dimensions for the generated thumbnail.
	///
	/// Only `w640h480` is modelled — the only size GIFwrapped requests — out of Dropbox's larger option set,
	/// matching the legacy (v1) client's argument shape.
	public enum Size: String, Encodable, Hashable, Sendable {

		case w640h480

	}

	public struct Request: API.Request {

		public typealias Response = GetThumbnail.Response
		public typealias Error = GetThumbnail.Error

		public static let endpoint: Endpoint = .content("/files/get_thumbnail")
		public static let method = Method.post
		public static let parameterPlacement = ParameterPlacement.header

		/// The path of the file for which a thumbnail should be generated.
		public var path: String

		/// The desired thumbnail image format.
		public var format: Format

		/// The desired thumbnail dimensions.
		public var size: Size

		public init(
			path: String,
			format: Format = .png,
			size: Size = .w640h480
		) {
			self.path = path
			self.format = format
			self.size = size
		}

	}

	public struct Response: API.Response {

		public typealias Request = GetThumbnail.Request

		/// Metadata for the source file, as returned in the `Dropbox-API-Result` response header.
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

		public typealias Request = GetThumbnail.Request

		case path(LookupError)
		case unsupportedExtension
		case unsupportedImage
		case conversionError

		public init(summary: Summary) throws {
			switch summary.component {
			case "path":
				self = .path(try summary.next())
			case "unsupported_extension":
				self = .unsupportedExtension
			case "unsupported_image":
				self = .unsupportedImage
			case "conversion_error":
				self = .conversionError
			default:
				throw summary
			}
		}

	}

}
