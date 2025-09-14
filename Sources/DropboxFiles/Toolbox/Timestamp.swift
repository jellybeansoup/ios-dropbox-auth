import Foundation

struct Timestamp: RawRepresentable, Codable {

	let rawValue: Date

	init(rawValue: Date) {
		self.rawValue = rawValue
	}

	private static let formatter: DateFormatter = {
		let dateFormatter = DateFormatter()
		dateFormatter.locale = Locale(identifier: "en_US_POSIX")
		dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
		//dateFormatter.timeZone = TimeZone(secondsFromGMT: 0)
		return dateFormatter
	}()

	enum DecodingError: Error, Equatable {
		case invalidString(String)
	}

	init(from decoder: Decoder) throws {
		let container = try decoder.singleValueContainer()
		let string = try container.decode(String.self)

		guard let date = Self.formatter.date(from: string) else {
			throw DecodingError.invalidString(string)
		}

		self.rawValue = date
	}

	func encode(to encoder: Encoder) throws {
		var container = encoder.singleValueContainer()
		try container.encode(Self.formatter.string(from: rawValue))
	}

}
