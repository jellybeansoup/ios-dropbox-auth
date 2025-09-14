@preconcurrency import Foundation
import DropboxAuth

extension Transport {

	/// Polls Dropbox for changes to a folder using the provided cursor.
	/// - Parameters:
	///   - cursor: The cursor representing the current state of the folder.
	///   - timeout: The maximum number of seconds to wait for changes before timing out.
	/// - Returns: A `ListFolder.Longpoll.Response` indicating whether changes are present and any backoff suggested.
	/// - Throws: Errors from the Dropbox API, network failures, or a reset (which is handled as a special case).
	func longpoll(
		cursor: Cursor,
		timeout: Int
	) async throws -> ListFolder.Longpoll.Response {
		do {
			return try await response(
				for: ListFolder.Longpoll.Request(
					cursor: cursor,
					timeout: timeout
				),
				needsAuthentication: false
			)
		}
		catch ListFolder.Longpoll.Error.reset {
			return .init(hasChanges: true, backoff: 60)
		}
		catch {
			throw error
		}
	}

}
