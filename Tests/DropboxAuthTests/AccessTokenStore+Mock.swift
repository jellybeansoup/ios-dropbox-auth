//
// Copyright © 2024 Daniel Farrelly
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

@testable import DropboxAuth
import Foundation
import XCTest

extension AccessTokenStore {

	static func mock(
		appKey: String = "AccessTokenStore.test",
		copyMatching: @escaping CopyMatchingHandler = { _, _ in
			XCTFail("Unexpectedly called `copyMatching` method.")
			return -1
		},
		update: @escaping UpdateHandler = { _, _ in
			XCTFail("Unexpectedly called `update` method.")
			return -1
		},
		add: @escaping AddHandler = { _, _ in
			XCTFail("Unexpectedly called `add` method.")
			return -1
		},
		delete: @escaping DeleteHandler = { _ in
			XCTFail("Unexpectedly called `delete` method.")
			return -1
		}
	) -> Self {
		Self(
			appKey: appKey,
			copyMatching: copyMatching,
			update: update,
			add: add,
			delete: delete
		)
	}

}
