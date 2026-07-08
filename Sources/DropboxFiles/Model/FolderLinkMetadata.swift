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

public struct FolderLinkMetadata: LinkMetadata {

	public let url: URL

	public let name: String

	public let permissions: LinkPermissions

	public let id: FolderMetadata.ID?

	public let pathLower: String?

	public let dateOfExpiry: Date?

	init(
		url: URL,
		name: String,
		permissions: LinkPermissions,
		id: FolderMetadata.ID?,
		pathLower: String?,
		dateOfExpiry: Date?
	) {
		self.url = url
		self.name = name
		self.permissions = permissions
		self.id = id
		self.pathLower = pathLower
		self.dateOfExpiry = dateOfExpiry
	}

	// Codable

	private enum CodingKeys: String, CodingKey {
		case url
		case name
		case permissions = "link_permissions"
		case id
		case pathLower = "path_lower"
		case dateOfExpiry = "expires"
	}

	public init(from decoder: Decoder) throws {
		let container = try decoder.container(keyedBy: CodingKeys.self)
		self.url = try container.decode(URL.self, forKey: .url)
		self.name = try container.decode(String.self, forKey: .name)
		self.permissions = try container.decode(LinkPermissions.self, forKey: .permissions)
		self.id = try container.decodeIfPresent(FolderMetadata.ID.self, forKey: .id)
		self.pathLower = try container.decodeIfPresent(String.self, forKey: .pathLower)
		self.dateOfExpiry = try container.decodeIfPresent(Timestamp.self, forKey: .dateOfExpiry)?.rawValue
	}

}
