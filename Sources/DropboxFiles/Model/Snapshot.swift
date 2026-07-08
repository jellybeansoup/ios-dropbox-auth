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

public struct Snapshot: Sendable {

	/// Metadata values that represent files within the Dropbox account
	/// currently being monitored.
	///
	/// When ``isReset`` is `true`, this is the complete set of entries for the monitored folder. When `false`,
	/// this only contains the entries that changed (or were removed) since the previous snapshot's `cursor`.
	public let metadata: [any Metadata]

	/// The cursor used by Dropbox to reference the current state of the
	/// account, after applying the included `metadata` changes.
	public let cursor: Cursor

	/// Whether `metadata` represents the complete state of the monitored folder, rather than an incremental
	/// delta.
	///
	/// This is `true` for the initial listing and for any snapshot produced after Dropbox reports that the
	/// previous cursor is no longer valid (a "reset"), in which case the caller should replace its local state
	/// entirely rather than merge. It is `false` for snapshots produced from `list_folder/continue`, which only
	/// contain changed or removed entries relative to the previous cursor.
	public let isReset: Bool

	init(
		metadata: [any Metadata],
		cursor: Cursor,
		isReset: Bool = false
	) {
		self.metadata = metadata
		self.cursor = cursor
		self.isReset = isReset
	}

}
