import Foundation

/// Parses a Dropbox-style timestamp string the same way `Timestamp` does, so expectations
/// stay correct regardless of the timezone tests run in.
///
/// Shared by test suites that need to build expected dates from Dropbox API fixtures
/// (e.g. `ListSharedLinksTests`, `TransportListSharedLinksTests`).
func testDate(_ string: String) -> Date {
	let formatter = DateFormatter()
	formatter.locale = Locale(identifier: "en_US_POSIX")
	formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
	formatter.timeZone = TimeZone(secondsFromGMT: 0)
	return formatter.date(from: string)!
}
