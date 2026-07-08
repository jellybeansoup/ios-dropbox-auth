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

	/// Retrieves shared links for a Dropbox path, handling pagination via the `hasMore` property.
	/// - Parameters:
	///   - path: The path to retrieve links for. Pass `nil` to list all shared links for the account.
	///   - isDirectOnly: Suppress links to parent folders.
	/// - Returns: The combined `LinkMetadata` values across all pages of results.
	/// - Throws: Errors from the Dropbox API or network failures.
	func listSharedLinks(
		path: String? = nil,
		isDirectOnly: Bool? = nil
	) async throws -> [any LinkMetadata] {
		var currentResponse = try await response(
			for: ListSharedLinks.Request(
				path: path,
				isDirectOnly: isDirectOnly
			)
		)

		var links = currentResponse.links

		while currentResponse.hasMore, let cursor = currentResponse.cursor {
			currentResponse = try await response(
				for: ListSharedLinks.Request(
					cursor: cursor
				)
			)

			links += currentResponse.links
		}

		return links
	}

}
