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

@testable import DropboxAuth
import Foundation
import Testing

@Suite struct BundleTests {

	@Test func hasConfiguredSchemeWithConfiguredScheme() {
		let bundle = MockBundle()
		bundle.urlTypes = [["CFBundleURLSchemes": ["db-test"]]]

		let hasConfiguredScheme = bundle.hasConfiguredScheme("db-test")

		#expect(hasConfiguredScheme)
	}

	@Test func hasConfiguredSchemeWithUnconfiguredScheme() {
		let bundle = MockBundle()
		bundle.urlTypes = []

		let hasConfiguredScheme = bundle.hasConfiguredScheme("db-test")

		#expect(hasConfiguredScheme == false)
	}

	@Test func hasConfiguredSchemeWithDifferentScheme() {
		let bundle = MockBundle()
		bundle.urlTypes = [["CFBundleURLSchemes": ["other-scheme"]]]

		let hasConfiguredScheme = bundle.hasConfiguredScheme("db-test")

		#expect(hasConfiguredScheme == false)
	}

	@Test func hasConfiguredSchemeWithMissingURLTypesKey() {
		// `urlTypes` is left nil, so `object(forInfoDictionaryKey:)` returns nil and the top-level
		// guard fails, exercising the early-return branch (as opposed to an empty array, which
		// still satisfies the guard).
		let bundle = MockBundle()

		let hasConfiguredScheme = bundle.hasConfiguredScheme("db-test")

		#expect(hasConfiguredScheme == false)
	}

	@Test func hasConfiguredSchemeSkipsEntriesMissingSchemesKeyThenMatchesLater() {
		// The first URL type dictionary has no `CFBundleURLSchemes` key, forcing the inner guard's
		// `continue` branch, before a later entry provides the matching scheme.
		let bundle = MockBundle()
		bundle.urlTypes = [
			["CFBundleName": "Untyped"],
			["CFBundleURLSchemes": ["db-test"]],
		]

		let hasConfiguredScheme = bundle.hasConfiguredScheme("db-test")

		#expect(hasConfiguredScheme)
	}

	@Test func hasApplicationQueriesSchemeWithConfiguredScheme() {
		let bundle = MockBundle()
		bundle.applicationQueriesSchemes = ["dbapi-2"]

		let hasApplicationQueriesScheme = bundle.hasApplicationQueriesScheme

		#expect(hasApplicationQueriesScheme)
	}

	@Test func hasApplicationQueriesSchemeWithUnconfiguredScheme() {
		let bundle = MockBundle()
		bundle.applicationQueriesSchemes = []

		let hasApplicationQueriesScheme = bundle.hasApplicationQueriesScheme

		#expect(hasApplicationQueriesScheme == false)
	}

	@Test func hasApplicationQueriesSchemeWithDifferentScheme() {
		let bundle = MockBundle()
		bundle.applicationQueriesSchemes = ["other-scheme"]

		let hasApplicationQueriesScheme = bundle.hasApplicationQueriesScheme

		#expect(hasApplicationQueriesScheme == false)
	}

	@Test func hasApplicationQueriesSchemeWithMissingKey() {
		// `applicationQueriesSchemes` is left nil, so the top-level guard fails (as opposed to an
		// empty array, which still satisfies the guard).
		let bundle = MockBundle()

		let hasApplicationQueriesScheme = bundle.hasApplicationQueriesScheme

		#expect(hasApplicationQueriesScheme == false)
	}

}

class MockBundle: Bundle, @unchecked Sendable {

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
