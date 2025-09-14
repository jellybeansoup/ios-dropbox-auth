@preconcurrency import Foundation
import DropboxAuth

public extension Transport {

	/// Monitors changes to a Dropbox folder, yielding updates as they occur.
	///
	/// This function creates an `AsyncThrowingStream` that continuously observes a specified Dropbox folder (and
	/// optionally its subfolders) for changes. It uses Dropbox's longpoll API to efficiently wait for updates and
	/// yields each batch of changes as a ``Snapshot``.
	///
	/// - Parameters:
	///    - path: The root path of the folder to monitor. Defaults to the top-level directory.
	///    - isRecursive: Set to `true` to monitor subfolders recursively. Defaults to `true`.
	///    - cursor: An optional starting cursor from which to continue monitoring. If not provided, monitoring starts
	///    		from the current state.
	/// - Returns: An `AsyncThrowingStream` that yields a ``Snapshot`` each time changes are detected in the
	/// 	monitored folder. The stream ends if cancelled or an error is thrown.
	nonisolated func monitor(
		path: String = "",
		isRecursive: Bool = true,
		from cursor: Cursor? = nil
	) -> AsyncThrowingStream<Snapshot, any Error> {
		.init(bufferingPolicy: .bufferingNewest(1)) { continuation in
			Task.detached(
				name: "Dropbox Monitor",
				priority: .background
			) { [self] in
				do {
					var cursor = cursor

					while Task.isCancelled == false {
						var backoff: UInt64?

						if let cursor {
							let longpoll = try await longpoll(
								cursor: cursor,
								timeout: 240
							)

							backoff = longpoll.backoff

							guard longpoll.hasChanges else {
								continue
							}
						}

						let response = try await listFolder(
							at: path,
							isRecursive: isRecursive
						)

						if case .terminated = continuation.yield(response) {
							break
						}

						if let backoff {
							do {
								try await Task.sleep(nanoseconds: backoff * 1_000_000_000)
							}
							catch {
								break
							}
						}

						cursor = response.cursor
					}

					continuation.finish()
				}
				catch {
					continuation.finish(throwing: error)
				}
			}
		}
	}

}
