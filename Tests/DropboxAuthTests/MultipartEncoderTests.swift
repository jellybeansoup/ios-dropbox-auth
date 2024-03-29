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

class MultipartEncoderTests: XCTestCase {

	private struct TestStruct: MultipartEncodable {

		func encode(to encoder: MultipartEncoder) {
			let container = encoder.container(keyedBy: CodingKeys.self)
			container.encode("testData", forKey: .testKey)
			container.encodeIfPresent(nil, forKey: .optionalKey)
			container.encodeIfPresent("testData", forKey: .optionalKey)
		}

		enum CodingKeys: String, CodingKey {
			case testKey
			case optionalKey
		}

	}

	func testMultipartEncoderWithCustomBoundary() throws {
		let encoder = MultipartEncoder(boundary: "testBoundary")
		let encodedData = encoder.encode(TestStruct())

		XCTAssertEqual(
			try XCTUnwrap(String(data: encodedData, encoding: .utf8)),
			"--testBoundary\r\n" +
			"Content-Disposition: form-data; name=\"testKey\"\r\n\r\n" +
			"testData\r\n" +
			"--testBoundary\r\n" +
			"Content-Disposition: form-data; name=\"optionalKey\"\r\n\r\n" +
			"testData\r\n" +
			"--testBoundary--\r\n"
		)
	}

	func testMultipartEncoderWithDefaultBoundary() {
		let encoder = MultipartEncoder()
		let encodedData = encoder.encode(TestStruct())

		XCTAssertEqual(
			try XCTUnwrap(String(data: encodedData, encoding: .utf8)),
			"--\(encoder.boundary)\r\n" +
			"Content-Disposition: form-data; name=\"testKey\"\r\n\r\n" +
			"testData\r\n" +
			"--\(encoder.boundary)\r\n" +
			"Content-Disposition: form-data; name=\"optionalKey\"\r\n\r\n" +
			"testData\r\n" +
			"--\(encoder.boundary)--\r\n"
		)
	}

}
