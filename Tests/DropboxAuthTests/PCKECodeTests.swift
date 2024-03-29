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

final class PCKECodeTests: XCTestCase {

	func testChallengeGeneration() {
		let pckeCode = PCKECode()

		// Verify challenge is generated
		XCTAssertNotNil(pckeCode.challenge)

		// Verify challenge is base64 encoded
		XCTAssertTrue(isBase64Encoded(pckeCode.challenge))

		// Verify challenge doesn't contain invalid characters
		XCTAssertFalse(pckeCode.challenge.contains("/"))
		XCTAssertFalse(pckeCode.challenge.contains("+"))
		XCTAssertFalse(pckeCode.challenge.contains("="))
	}

	func testVerifierGeneration() {
		let pckeCode = PCKECode()

		// Verify verifier is generated
		XCTAssertNotNil(pckeCode.verifier)

		// Verify verifier has correct length
		XCTAssertEqual(pckeCode.verifier.count, 128)

		// Verify verifier contains only valid characters
		XCTAssertTrue(verifyVerifierCharacters(pckeCode.verifier))
	}

	// MARK: Utilities

	private func isBase64Encoded(_ string: String) -> Bool {
		let regex = try! NSRegularExpression(pattern: "^[A-Za-z0-9-_]*={0,2}$", options: [])
		let range = NSRange(location: 0, length: string.utf16.count)
		return regex.firstMatch(in: string, options: [], range: range) != nil
	}

	private func verifyVerifierCharacters(_ string: String) -> Bool {
		let validCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		return string.allSatisfy { validCharacters.contains($0) }
	}

}
