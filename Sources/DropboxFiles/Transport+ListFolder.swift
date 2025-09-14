@preconcurrency import Foundation
import DropboxAuth

extension Transport {

	/// Retrieves the contents of a Dropbox folder, handling pagination via the `hasMore` property.
	/// - Parameters:
	///   - path: The path to the Dropbox folder to list.
	///   - isRecursive: Whether to list folder contents recursively.
	/// - Returns: A `ListFolder.Response` containing folder entries and the resulting cursor.
	/// - Throws: Errors from the Dropbox API or network failures.
	func listFolder(
		at path: String,
		isRecursive: Bool
	) async throws -> Snapshot {
		var currentResponse = try await response(
			for: ListFolder.Request(
				path: path,
				isRecursive: isRecursive
			)
		)

		while currentResponse.hasMore {
			let continueResponse = try await response(
				for: ListFolder.Continue.Request(
					cursor: currentResponse.cursor
				)
			)

			currentResponse.cursor = continueResponse.cursor
			currentResponse.entries += continueResponse.entries
			currentResponse.hasMore = continueResponse.hasMore
		}

		return Snapshot(metadata: currentResponse.entries, cursor: currentResponse.cursor)
	}

}
