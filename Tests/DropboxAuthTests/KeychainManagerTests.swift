//
// Copyright © 2022 Daniel Farrelly
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

import XCTest
@testable import DropboxAuthSwift

class KeychainManagerTests: XCTestCase {

	private var keychain: MockKeychain!

	private var keychainManager: KeychainManager!

	private let value = UUID().uuidString

	private let key = "KeychainManager.test"

	override func setUp() {
		keychain = MockKeychain()
		keychainManager = KeychainManager(keychain: keychain)
	}

	override func tearDown() {
		keychain = nil
		keychainManager = nil
	}

	private class MockKeychain: KeychainProtocol {

		var status: OSStatus = noErr

		var copyMatchingParameters: (query: CFDictionary, result: UnsafeMutablePointer<CFTypeRef?>?)?

		func copyMatching(_ query: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
			copyMatchingParameters = (query: query, result: result)
			return status
		}

		var updateParameters: (query: CFDictionary, attributesToUpdate: CFDictionary)?

		func update(_ query: CFDictionary, _ attributesToUpdate: CFDictionary) -> OSStatus {
			updateParameters = (query: query, attributesToUpdate: attributesToUpdate)
			return status
		}

		var addParameters: (attributes: CFDictionary, result: UnsafeMutablePointer<CFTypeRef?>?)?

		func add(_ attributes: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
			addParameters = (attributes: attributes, result: result)
			return status
		}

		var deleteQuery: CFDictionary?

		func delete(_ query: CFDictionary) -> OSStatus {
			deleteQuery = query
			return status
		}

	}

	func testSetValueForKey() throws {
		let success = keychainManager.setValue(value, forKey: key)
		XCTAssertTrue(success)
	}

	func testValueForKey() throws {
		let result = KeychainManager().string(forKey: "KeychainManager.test")
	}

	func testRemoveValueForKey() throws {
		let result = KeychainManager().removeValue(forKey: "KeychainManager.test")
	}

	func testAll() throws {
		let result = KeychainManager().all
	}

	func testClearAll() throws {
		let result = KeychainManager().removeAll()
	}

}
