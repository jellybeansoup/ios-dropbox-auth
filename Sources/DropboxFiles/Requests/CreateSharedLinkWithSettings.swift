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

public enum CreateSharedLinkWithSettings {

	public struct Request: API.Request {

		public typealias Response = CreateSharedLinkWithSettings.Response
		public typealias Error = CreateSharedLinkWithSettings.Error

		public static let endpoint: Endpoint = "/sharing/create_shared_link_with_settings"
		public static let method = Method.post

		public var path: String

		public var settings: SharedLinkSettings? = nil

		public init(
			path: String,
			settings: SharedLinkSettings? = nil
		) {
			self.path = path
			self.settings = settings
		}

	}

	public struct Response: API.Response {

		public typealias Request = CreateSharedLinkWithSettings.Request

		public var link: any LinkMetadata

		init(link: any LinkMetadata) {
			self.link = link
		}

		// MARK: Decodable

		public init(from decoder: Decoder) throws {
			self.init(link: try LinkMetadataDecodingContainer(from: decoder).value)
		}

	}

	public enum Error: Swift.Error {

		public typealias Request = CreateSharedLinkWithSettings.Request

		case lookup(LookupError)
		case emailNotVerified
		/// The link already exists. When the API includes the existing link's metadata in its response,
		/// it's decoded here so callers can use it directly without a follow-up `ListSharedLinks` request.
		case sharedLinkAlreadyExists(existingLink: (any LinkMetadata)?)
		case settings(SharedLinkSettingsError)
		case accessDenied

		public init(summary: Summary) throws {
			switch summary.component {
			case "path":
				self = .lookup(try summary.next())
			case "email_not_verified":
				self = .emailNotVerified
			case "shared_link_already_exists":
				self = .sharedLinkAlreadyExists(existingLink: nil)
			case "settings_error":
				self = .settings(try summary.next())
			case "access_denied":
				self = .accessDenied
			default:
				throw summary
			}
		}

		/// Extends the default `error_summary`-only decoding so that, for `shared_link_already_exists`,
		/// the existing link's metadata (nested under the response body's `error` key) is also decoded.
		///
		/// The package's generic error pipeline (`API.ErrorResponse`) only carries the `error_summary` tag
		/// chain to `init(summary:)`. This overload receives the full response decoder as well, so this one
		/// error case can reach into the `error` object's payload — without changing behaviour for any other
		/// request's error decoding, which continues to rely on the default `init(summary:decoder:)`.
		public init(summary: Summary, decoder: Decoder) throws {
			guard summary.component == "shared_link_already_exists" else {
				self = try Self(summary: summary)
				return
			}

			self = .sharedLinkAlreadyExists(existingLink: Self.existingLink(from: decoder))
		}

		/// Best-effort decode of the existing link's metadata from the raw error response body.
		///
		/// The payload is optional per the API, and this hook is reached from a context where the shape of
		/// `error` isn't otherwise guaranteed (e.g. it could be a bare string in unusual/legacy payloads) —
		/// so any decoding failure here is treated the same as an absent payload rather than propagated,
		/// keeping the primary `shared_link_already_exists` case reliable either way.
		private static func existingLink(from decoder: Decoder) -> (any LinkMetadata)? {
			enum RootCodingKeys: String, CodingKey {
				case error
			}

			enum TagCodingKeys: String, CodingKey {
				case sharedLinkAlreadyExists = "shared_link_already_exists"
			}

			enum PayloadCodingKeys: String, CodingKey {
				case metadata
			}

			do {
				let root = try decoder.container(keyedBy: RootCodingKeys.self)
				let tagged = try root.nestedContainer(keyedBy: TagCodingKeys.self, forKey: .error)
				let payload = try tagged.nestedContainer(keyedBy: PayloadCodingKeys.self, forKey: .sharedLinkAlreadyExists)
				return try payload.decodeIfPresent(LinkMetadataDecodingContainer.self, forKey: .metadata)?.value
			}
			catch {
				return nil
			}
		}

	}

}

// MARK: - Error: Equatable, Hashable, Sendable

// `any LinkMetadata` doesn't itself conform to `Hashable`/`Sendable` as an existential (only concrete
// conforming types do), so `Equatable`/`Hashable`/`Sendable` can't be synthesized for a case that carries
// one. These conform manually, comparing/hashing the wrapped link via `AnyHashable` (which does support
// opening a `Hashable`-constrained existential) and asserting `Sendable` since `LinkMetadata` itself
// requires `Sendable` conformance from every concrete type that can be stored in the existential.
extension CreateSharedLinkWithSettings.Error: Equatable {

	public static func == (lhs: Self, rhs: Self) -> Bool {
		switch (lhs, rhs) {
		case (.lookup(let lhs), .lookup(let rhs)):
			return lhs == rhs
		case (.emailNotVerified, .emailNotVerified):
			return true
		case (.sharedLinkAlreadyExists(let lhs), .sharedLinkAlreadyExists(let rhs)):
			switch (lhs, rhs) {
			case (nil, nil):
				return true
			case (let lhs?, let rhs?):
				return AnyHashable(lhs) == AnyHashable(rhs)
			default:
				return false
			}
		case (.settings(let lhs), .settings(let rhs)):
			return lhs == rhs
		case (.accessDenied, .accessDenied):
			return true
		default:
			return false
		}
	}

}

extension CreateSharedLinkWithSettings.Error: Hashable {

	public func hash(into hasher: inout Hasher) {
		switch self {
		case .lookup(let error):
			hasher.combine(0)
			hasher.combine(error)
		case .emailNotVerified:
			hasher.combine(1)
		case .sharedLinkAlreadyExists(let existingLink):
			hasher.combine(2)
			if let existingLink {
				hasher.combine(AnyHashable(existingLink))
			}
		case .settings(let error):
			hasher.combine(3)
			hasher.combine(error)
		case .accessDenied:
			hasher.combine(4)
		}
	}

}

extension CreateSharedLinkWithSettings.Error: @unchecked Sendable {}

extension CreateSharedLinkWithSettings.Error: API.Error {}
