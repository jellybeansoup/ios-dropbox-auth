//
// Copyright © 2025 Daniel Farrelly
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
// *	Redistributions of source code must retain the above copyright notice, this list
//		of conditions and the following disclaimer.
// *	Redistributions in binary form must reproduce the above copyright notice, this
//		list of conditions and the following disclaimer in the documentation and/or
//		other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
// IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
// OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

import Foundation
import DropboxAuth

public extension Transport {

	/// Monitors changes to a Dropbox folder, yielding updates as they occur.
	///
	/// This function creates an `AsyncThrowingStream` that continuously observes a specified Dropbox folder (and
	/// optionally its subfolders) for changes. It uses Dropbox's longpoll API to efficiently wait for updates,
	/// then fetches only the changed entries via `list_folder/continue` and yields them as an incremental
	/// ``Snapshot`` (`isReset == false`). If Dropbox reports that the cursor is no longer valid (a "reset",
	/// surfaced either from the longpoll call or from `list_folder/continue`), this performs a full re-list and
	/// yields it as a complete ``Snapshot`` (`isReset == true`) before resuming monitoring from the new cursor.
	///
	/// The stream reports only a coarse status via the ``Snapshot`` values it yields (and, implicitly, the time
	/// between them while awaiting the longpoll); it does not distinguish "checking for changes" from "applying a
	/// reset" as separate states. Phase 6 does not need that finer granularity, and it can be added later
	/// additively (e.g. a status enum wrapping `.checking`/`.snapshot(Snapshot)`) without breaking this API.
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
		includeDeleted: Bool = false,
		includeHasExplicitSharedMembers: Bool = false,
		includeMountedFolders: Bool = true,
		includeNonDownloadableFiles: Bool = true,
		from cursor: Cursor? = nil
	) -> AsyncThrowingStream<Snapshot, any Error> {
		// Buffered unbounded rather than `.bufferingNewest(1)`: each snapshot here can be an *incremental* delta
		// (from `list_folder/continue`), so dropping one because the consumer is momentarily slow would silently
		// lose changes rather than merely coalesce redundant full-state updates.
		.init(bufferingPolicy: .unbounded) { continuation in
			let task = Task.detached(
				name: "Dropbox Monitor",
				priority: .background
			) { [self] in
				do {
					var cursor = cursor

					func fullRelist() async throws -> Snapshot {
						try await listFolder(
							at: path,
							isRecursive: isRecursive,
							includeDeleted: includeDeleted,
							includeHasExplicitSharedMembers: includeHasExplicitSharedMembers,
							includeMountedFolders: includeMountedFolders,
							includeNonDownloadableFiles: includeNonDownloadableFiles
						)
					}

					while Task.isCancelled == false {
						let snapshot: Snapshot
						var backoff: UInt64?

						if let currentCursor = cursor {
							do {
								let longpollResponse = try await longpoll(
									cursor: currentCursor,
									timeout: 240
								)

								guard longpollResponse.hasChanges else {
									continue
								}

								backoff = longpollResponse.backoff

								do {
									snapshot = try await listFolder(from: currentCursor)
								}
								catch ListFolder.Continue.Error.reset {
									snapshot = try await fullRelist()
								}
							}
							catch ListFolder.Longpoll.Error.reset {
								snapshot = try await fullRelist()
							}
						}
						else {
							snapshot = try await fullRelist()
						}

						if case .terminated = continuation.yield(snapshot) {
							break
						}

						cursor = snapshot.cursor

						if let backoff {
							do {
								try await Task.sleep(nanoseconds: backoff * 1_000_000_000)
							}
							catch {
								break
							}
						}
					}

					continuation.finish()
				}
				catch is CancellationError {
					continuation.finish()
				}
				catch {
					continuation.finish(throwing: error)
				}
			}

			continuation.onTermination = { _ in
				task.cancel()
			}
		}
	}

}
