import Foundation
@testable import DropboxFiles
import Testing

@Suite struct TimestampTests {

	@Test func decodeValidString() {
		let jsonString = "\"2020-01-01T09:00:00Z\""
		let jsonData = Data(jsonString.utf8)

		do {
			let timestamp = try JSONDecoder().decode(Timestamp.self, from: jsonData)
			let expectedDate = Date(timeIntervalSince1970: 1577829600) // 2020-01-01T09:00:00Z
			#expect(timestamp.rawValue == expectedDate)
		} catch {
			Issue.record("Failed to decode timestamp: \(error)")
		}
	}

	@Test func decodeInvalidString() {
		let invalidJsonString = "\"invalid_date\""
		let invalidJsonData = Data(invalidJsonString.utf8)

		#expect(throws: Timestamp.DecodingError.invalidString("invalid_date")) {
			try JSONDecoder().decode(Timestamp.self, from: invalidJsonData)
		}
	}

	@Test func encodeToString() {
		let date = Date(timeIntervalSince1970: 1577829600) // 2020-01-01T09:00:00Z
		let timestamp = Timestamp(rawValue: date)

		do {
			let encodedData = try JSONEncoder().encode(timestamp)
			let decodedString = String(data: encodedData, encoding: .utf8)!
			#expect(decodedString == "\"2020-01-01T09:00:00Z\"")
		} catch {
			Issue.record("Failed to encode timestamp: \(error)")
		}
	}

}
