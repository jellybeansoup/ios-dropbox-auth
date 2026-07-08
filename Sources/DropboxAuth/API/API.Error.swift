import Foundation

public extension API {

	protocol Error: Swift.Error, Hashable, Sendable {

		typealias Summary = ErrorSummary

		init(summary: Summary) throws

		/// Extended decoding hook for errors that need more than the `error_summary` tag chain — e.g. a nested
		/// payload carried alongside the tag under the response body's `error` key.
		///
		/// Most `API.Error` types never need this and can rely on the default implementation, which simply
		/// forwards to `init(summary:)` and ignores `decoder`. Override it only when a specific error case
		/// carries additional data that must be decoded from the full response body.
		/// - Parameters:
		///   - summary: The parsed `error_summary` tag chain.
		///   - decoder: The decoder for the full error response body (the same JSON object that contains
		///     both `error_summary` and `error`).
		init(summary: Summary, decoder: Decoder) throws

	}

}

public extension API.Error {

	init(summary: Summary, decoder: Decoder) throws {
		try self.init(summary: summary)
	}

}

extension API.Error where Self: RawRepresentable, RawValue == String {

	public init(summary: Summary) throws {
		guard
			let component = summary.component,
			let error = Self(rawValue: component)
		else {
			throw summary
		}

		self = error
	}

}
