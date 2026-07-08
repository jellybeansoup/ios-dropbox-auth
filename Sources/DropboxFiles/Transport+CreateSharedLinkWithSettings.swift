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

	/// Creates a shared link for the file or folder at the given path, with public visibility.
	///
	/// If a shared link already exists at that path, `CreateSharedLinkWithSettings.Error.sharedLinkAlreadyExists`
	/// is thrown — and, when the API includes it, that error carries the existing link's metadata, so callers
	/// can recover the URL directly from the error rather than making a follow-up request.
	/// - Parameter path: The path of the file or folder to create a shared link for.
	/// - Returns: Metadata describing the newly created shared link.
	/// - Throws: Errors from the Dropbox API or network failures.
	func createSharedLinkWithSettings(
		path: String
	) async throws -> any LinkMetadata {
		try await response(
			for: CreateSharedLinkWithSettings.Request(
				path: path,
				settings: SharedLinkSettings(requestedVisibility: .public)
			)
		).link
	}

}
