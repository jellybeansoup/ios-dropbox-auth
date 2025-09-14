import Foundation

public extension API {

	protocol Error: Swift.Error, Hashable, Sendable {

		typealias Summary = ErrorSummary

		init(summary: Summary) throws

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
