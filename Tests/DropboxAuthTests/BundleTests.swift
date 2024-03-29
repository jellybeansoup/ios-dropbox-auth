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
import XCTest

final class BundleTests: XCTestCase {

	func testHasConfiguredSchemeWithConfiguredScheme() {
		let bundle = MockBundle()
		bundle.urlTypes = [["CFBundleURLSchemes": ["db-test"]]]

		let hasConfiguredScheme = bundle.hasConfiguredScheme("db-test")

		XCTAssertTrue(hasConfiguredScheme)
	}

	func testHasConfiguredSchemeWithUnconfiguredScheme() {
		let bundle = MockBundle()
		bundle.urlTypes = []

		let hasConfiguredScheme = bundle.hasConfiguredScheme("db-test")

		XCTAssertFalse(hasConfiguredScheme)
	}

	func testHasConfiguredSchemeWithDifferentScheme() {
		let bundle = MockBundle()
		bundle.urlTypes = [["CFBundleURLSchemes": ["other-scheme"]]]

		let hasConfiguredScheme = bundle.hasConfiguredScheme("db-test")

		XCTAssertFalse(hasConfiguredScheme)
	}

	func testHasApplicationQueriesSchemeWithConfiguredScheme() {
		let bundle = MockBundle()
		bundle.applicationQueriesSchemes = ["dbapi-2"]

		let hasApplicationQueriesScheme = bundle.hasApplicationQueriesScheme

		XCTAssertTrue(hasApplicationQueriesScheme)
	}

	func testHasApplicationQueriesSchemeWithUnconfiguredScheme() {
		let bundle = MockBundle()
		bundle.applicationQueriesSchemes = []

		let hasApplicationQueriesScheme = bundle.hasApplicationQueriesScheme

		XCTAssertFalse(hasApplicationQueriesScheme)
	}

	func testHasApplicationQueriesSchemeWithDifferentScheme() {
		let bundle = MockBundle()
		bundle.applicationQueriesSchemes = ["other-scheme"]

		let hasApplicationQueriesScheme = bundle.hasApplicationQueriesScheme

		XCTAssertFalse(hasApplicationQueriesScheme)
	}

}

class MockBundle: Bundle {

	var urlTypes: [[String: Any]]?

	var applicationQueriesSchemes: [String]?

	override func object(forInfoDictionaryKey key: String) -> Any? {
		if key == "CFBundleURLTypes" {
			return urlTypes
		} else if key == "LSApplicationQueriesSchemes" {
			return applicationQueriesSchemes
		} else {
			return super.object(forInfoDictionaryKey: key)
		}
	}
}
