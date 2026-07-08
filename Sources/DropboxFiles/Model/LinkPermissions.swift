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

public struct LinkPermissions: Hashable, Sendable {

	public enum Visibility: Hashable, Sendable {

		case `public`
		case teamOnly
		case password
		case teamAndPassword
		case sharedFolderOnly
		case noOne
		case onlyYou
		case other

	}

	public let resolvedVisibility: Visibility

	public let canRevoke: Bool

	init(
		resolvedVisibility: Visibility,
		canRevoke: Bool
	) {
		self.resolvedVisibility = resolvedVisibility
		self.canRevoke = canRevoke
	}

}

extension LinkPermissions: Decodable {

	private enum CodingKeys: String, CodingKey {
		case resolvedVisibility = "resolved_visibility"
		case canRevoke = "can_revoke"
	}

	public init(from decoder: Decoder) throws {
		let container = try decoder.container(keyedBy: CodingKeys.self)

		self.init(
			resolvedVisibility: try container.decode(Visibility.self, forKey: .resolvedVisibility),
			canRevoke: try container.decode(Bool.self, forKey: .canRevoke)
		)
	}

}

extension LinkPermissions.Visibility: Decodable {

	private enum CodingKeys: String, CodingKey {
		case tag = ".tag"
	}

	private enum Tag: String {
		case `public`
		case teamOnly = "team_only"
		case password
		case teamAndPassword = "team_and_password"
		case sharedFolderOnly = "shared_folder_only"
		case noOne = "no_one"
		case onlyYou = "only_you"
		case other
	}

	public init(from decoder: Decoder) throws {
		let container = try decoder.container(keyedBy: CodingKeys.self)

		// Unknown/future tags decode to `.other`, consistent with how Dropbox
		// evolves its union types without breaking older clients. A missing or
		// malformed `.tag` key still throws.
		guard let tag = Tag(rawValue: try container.decode(String.self, forKey: .tag)) else {
			self = .other
			return
		}

		switch tag {
		case .public: self = .public
		case .teamOnly: self = .teamOnly
		case .password: self = .password
		case .teamAndPassword: self = .teamAndPassword
		case .sharedFolderOnly: self = .sharedFolderOnly
		case .noOne: self = .noOne
		case .onlyYou: self = .onlyYou
		case .other: self = .other
		}
	}

}
