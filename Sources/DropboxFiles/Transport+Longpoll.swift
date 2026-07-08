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

extension Transport {

	/// Polls Dropbox for changes to a folder using the provided cursor.
	/// - Parameters:
	///   - cursor: The cursor representing the current state of the folder.
	///   - timeout: The maximum number of seconds to wait for changes before timing out.
	/// - Returns: A `ListFolder.Longpoll.Response` indicating whether changes are present and any backoff suggested.
	/// - Throws: Errors from the Dropbox API or network failures, including ``ListFolder/Longpoll/Error/reset``
	///   if the cursor is no longer valid. Callers that need reset propagation (e.g. ``Transport/monitor``)
	///   should handle that case explicitly rather than have it masked here.
	func longpoll(
		cursor: Cursor,
		timeout: Int
	) async throws -> ListFolder.Longpoll.Response {
		try await response(
			for: ListFolder.Longpoll.Request(
				cursor: cursor,
				timeout: timeout
			),
			needsAuthentication: false
		)
	}

}
