import Foundation

public extension API {

	struct ErrorSummary: Decodable, Swift.Error, Hashable, Sendable {

		private var components: [String]

		init(components: [String]) {
			self.components = components
		}

		init(string: String) {
			self.init(
				components: string
					.split(separator: "/")
					.filter { $0.isEmpty == false }
					.filter { $0 != "." }
					.map { String($0) }
			)
		}

		public var component: String? {
			components.first
		}

		public func next() -> Self {
			Self(components: Array(components.dropFirst()))
		}

		public func next<T: API.Error>() throws -> T {
			try T(summary: next())
		}

		public init(from decoder: Decoder) throws {
			let container = try decoder.singleValueContainer()
			self.init(string: try container.decode(String.self))
		}

	}

}

extension API.ErrorSummary: CustomStringConvertible {

	public var description: String {
		(components + ["."]).joined(separator: "/")
	}

}
