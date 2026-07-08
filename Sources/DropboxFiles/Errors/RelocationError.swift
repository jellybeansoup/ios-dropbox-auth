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

enum RelocationError: Error, API.Error {

	case fromLookup(LookupError)

	case fromWrite(WriteError)

	case to(WriteError)

	case cantCopySharedFolder

	case cantNestSharedFolder

	case cantMoveFolderIntoItself

	case tooManyFiles

	case duplicatedOrNestedPaths

	case cantTransferOwnership

	case insufficientQuota

	case internalError

	case cantMoveSharedFolder

	init(summary: Summary) throws {
		switch summary.component {
		case "from_lookup":
			self = .fromLookup(try summary.next())
		case "from_write":
			self = .fromWrite(try summary.next())
		case "to":
			self = .to(try summary.next())
		case "cant_copy_shared_folder":
			self = .cantCopySharedFolder
		case "cant_nest_shared_folder":
			self = .cantNestSharedFolder
		case "cant_move_folder_into_itself":
			self = .cantMoveFolderIntoItself
		case "too_many_files":
			self = .tooManyFiles
		case "duplicated_or_nested_paths":
			self = .duplicatedOrNestedPaths
		case "cant_transfer_ownership":
			self = .cantTransferOwnership
		case "insufficient_quota":
			self = .insufficientQuota
		case "internal_error":
			self = .internalError
		case "cant_move_shared_folder":
			self = .cantMoveSharedFolder
		default:
			throw summary
		}
	}

}
