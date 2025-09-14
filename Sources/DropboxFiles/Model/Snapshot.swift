import Foundation

public struct Snapshot: Sendable {

	/// Metadata values that represent files within the Dropbox account
	/// currently being monitored.
	public let metadata: [any Metadata]

	/// The cursor used by Dropbox to reference the current state of the
	/// account, after applying the included `metadata` changes.
	public let cursor: Cursor

	init(
		metadata: [any Metadata],
		cursor: Cursor
	) {
		self.metadata = metadata
		self.cursor = cursor
	}

}
