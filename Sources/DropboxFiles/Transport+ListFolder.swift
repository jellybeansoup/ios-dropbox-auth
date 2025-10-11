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

	/// Retrieves the contents of a Dropbox folder, handling pagination via the `hasMore` property.
	/// - Parameters:
	///   - path: The path to the Dropbox folder to list.
	///   - isRecursive: Whether to list folder contents recursively.
	/// - Returns: A `ListFolder.Response` containing folder entries and the resulting cursor.
	/// - Throws: Errors from the Dropbox API or network failures.
	func listFolder(
		at path: String,
		isRecursive: Bool,
		includeDeleted: Bool = false,
		includeHasExplicitSharedMembers: Bool = false,
		includeMountedFolders: Bool = true,
		includeNonDownloadableFiles: Bool = true
	) async throws -> Snapshot {
		var currentResponse = try await response(
			for: ListFolder.Request(
				path: path,
				isRecursive: isRecursive,
				includeDeleted: includeDeleted,
				includeHasExplicitSharedMembers: includeHasExplicitSharedMembers,
				includeMountedFolders: includeMountedFolders,
				includeNonDownloadableFiles: includeNonDownloadableFiles
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
