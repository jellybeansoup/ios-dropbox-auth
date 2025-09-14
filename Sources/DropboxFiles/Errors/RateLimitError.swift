import Foundation
import DropboxAuth

struct RateLimitError: Error {

	enum Reason: String {
		case tooManyRequests = "too_many_requests"
		case tooManyWriteOperations = "too_many_write_operations"
	}

	var reason: Reason

	var retryAfter: UInt64

	private enum CodingKeys: String, CodingKey {
		case reason
		case retryAfter = "retry_after"
	}

}
