import Foundation

struct DecodingContainer: Decodable {

	private enum Tag: String, Decodable {
		case deleted
		case file
		case folder
	}

	var value: any Metadata

	private enum CodingKeys: String, CodingKey {
		case tag = ".tag"
	}

	public init(from decoder: Decoder) throws {
		let container = try decoder.container(keyedBy: CodingKeys.self)
		value = switch try container.decode(Tag.self, forKey: .tag) {
		case .deleted: try DeletedMetadata(from: decoder)
		case .file: try FileMetadata(from: decoder)
		case .folder: try FolderMetadata(from: decoder)
		}
	}

}

public protocol Metadata: Hashable, Sendable {

	var name: String { get }

	var pathLower: String? { get }

	var pathDisplay: String? { get }

}

public struct DeletedMetadata: Metadata {

	/// The last component of the path (including extension). This never contains a slash.
	public let name: String

	/// The lowercased full path in the user's Dropbox.
	public let pathLower: String?

	/// The cased path to be used for display purposes only.
	public let pathDisplay: String?

	init(
		name: String,
		pathLower: String?,
		pathDisplay: String?
	) {
		self.name = name
		self.pathLower = pathLower
		self.pathDisplay = pathDisplay
	}

	// Codable

	private enum CodingKeys: String, CodingKey {
		case name = "name"
		case pathLower = "path_lower"
		case pathDisplay = "path_display"
	}

	public init(from decoder: Decoder) throws {
		let container = try decoder.container(keyedBy: CodingKeys.self)
		self.name = try container.decode(String.self, forKey: .name)
		self.pathLower = try container.decode(String?.self, forKey: .pathLower)
		self.pathDisplay = try container.decode(String?.self, forKey: .pathDisplay)
	}

}

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

public struct FolderMetadata: Metadata {

	public struct ID: Codable, Hashable, RawRepresentable, Sendable {

		public var rawValue: String

		public init(rawValue: String) {
			self.rawValue = rawValue
		}

	}

	public let id: ID

	public let name: String

	public let pathLower: String?

	public let pathDisplay: String?

	init(
		id: ID,
		name: String,
		pathLower: String?,
		pathDisplay: String?
	) {
		self.id = id
		self.name = name
		self.pathLower = pathLower
		self.pathDisplay = pathDisplay
	}

	// Codable

	private enum CodingKeys: String, CodingKey {
		case id
		case name = "name"
		case pathLower = "path_lower"
		case pathDisplay = "path_display"
	}

	public init(from decoder: Decoder) throws {
		let container = try decoder.container(keyedBy: CodingKeys.self)
		self.id = try container.decode(ID.self, forKey: .id)
		self.name = try container.decode(String.self, forKey: .name)
		self.pathLower = try container.decode(String?.self, forKey: .pathLower)
		self.pathDisplay = try container.decode(String?.self, forKey: .pathDisplay)
	}

}
