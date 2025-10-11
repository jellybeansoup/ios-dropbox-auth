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

public struct FileMetadata: Metadata {

	public struct Hash: Codable, Hashable, RawRepresentable, Sendable {

		public var rawValue: String

		public init(rawValue: String) {
			self.rawValue = rawValue
		}

	}

	public struct ID: Codable, Hashable, RawRepresentable, Sendable {

		public var rawValue: String

		public init(rawValue: String) {
			self.rawValue = rawValue
		}

	}

	public struct Revision: Codable, Hashable, RawRepresentable, Sendable {

		public var rawValue: String

		public init(rawValue: String) {
			self.rawValue = rawValue
		}

	}

	public let id: ID

	public let revision: Revision

	public let name: String

	public let pathLower: String?

	public let pathDisplay: String?

	public let numberOfBytes: Int64

	public let dateModifiedOnClient: Date

	public let dateModifiedOnServer: Date

	public let contentHash: Hash?

	init(
		id: ID,
		revision: Revision,
		name: String,
		pathLower: String?,
		pathDisplay: String?,
		numberOfBytes: Int64,
		dateModifiedOnClient: Date,
		dateModifiedOnServer: Date,
		contentHash: Hash
	) {
		self.id = id
		self.revision = revision
		self.name = name
		self.pathLower = pathLower
		self.pathDisplay = pathDisplay
		self.numberOfBytes = numberOfBytes
		self.dateModifiedOnClient = dateModifiedOnClient
		self.dateModifiedOnServer = dateModifiedOnServer
		self.contentHash = contentHash
	}

	// Codable

	private enum CodingKeys: String, CodingKey {
		case id
		case revision = "rev"
		case name = "name"
		case pathLower = "path_lower"
		case pathDisplay = "path_display"
		case numberOfBytes = "size"
		case dateModifiedOnClient = "client_modified"
		case dateModifiedOnServer = "server_modified"
		case contentHash = "content_hash"
	}

	public init(from decoder: Decoder) throws {
		let container = try decoder.container(keyedBy: CodingKeys.self)
		self.id = try container.decode(ID.self, forKey: .id)
		self.revision = try container.decode(Revision.self, forKey: .revision)
		self.name = try container.decode(String.self, forKey: .name)
		self.pathLower = try container.decode(String?.self, forKey: .pathLower)
		self.pathDisplay = try container.decode(String?.self, forKey: .pathDisplay)
		self.numberOfBytes = try container.decode(Int64.self, forKey: .numberOfBytes)
		self.dateModifiedOnClient = try container.decode(Timestamp.self, forKey: .dateModifiedOnClient).rawValue
		self.dateModifiedOnServer = try container.decode(Timestamp.self, forKey: .dateModifiedOnServer).rawValue
		self.contentHash = try container.decode(Hash.self, forKey: .contentHash)
	}

}
