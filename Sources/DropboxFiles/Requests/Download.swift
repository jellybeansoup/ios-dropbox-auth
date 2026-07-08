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

public enum Download {

	public struct Request: API.Request {

		public typealias Response = Download.Response
		public typealias Error = Download.Error

		public static let endpoint: Endpoint = .content("/files/download")
		public static let method = Method.post
		public static let parameterPlacement = ParameterPlacement.header

		/// The path of the file to download.
		public var path: String

		public init(path: String) {
			self.path = path
		}

	}

	public struct Response: API.Response {

		public typealias Request = Download.Request

		/// Metadata for the downloaded file, as returned in the `Dropbox-API-Result` response header.
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

		public typealias Request = Download.Request

		case path(LookupError)
		case unsupportedFile

		public init(summary: Summary) throws {
			switch summary.component {
			case "path":
				self = .path(try summary.next())
			case "unsupported_file":
				self = .unsupportedFile
			default:
				throw summary
			}
		}

	}

}
