import Foundation

public struct Cursor: Hashable, Sendable {

	var rawValue: String

	public init(rawValue: String) {
		self.rawValue = rawValue
	}

}

extension Cursor: ExpressibleByStringLiteral {

	public init(stringLiteral value: String) {
		self.init(rawValue: value)
	}

}

extension Cursor: Codable {

	public init(from decoder: Decoder) throws {
		let container = try decoder.singleValueContainer()
		self.init(rawValue: try container.decode(String.self))
	}

	public func encode(to encoder: Encoder) throws {
		var container = encoder.singleValueContainer()
		try container.encode(rawValue)
	}

}
