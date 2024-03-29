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

class StringTests: XCTestCase {

	func testQueryParametersWithNoParameters() {
		let urlString = ""
		let parameters = urlString.queryParameters

		XCTAssertTrue(parameters.isEmpty)
	}

	func testQueryParametersWithSingleParameter() {
		let urlString = "key1=value1"
		let parameters = urlString.queryParameters

		XCTAssertEqual(parameters.count, 1)
		XCTAssertEqual(parameters["key1"], "value1")
	}

	func testQueryParametersWithMultipleParameters() {
		let urlString = "key1=value1&key2=value2&key3=value3"
		let parameters = urlString.queryParameters

		XCTAssertEqual(parameters.count, 3)
		XCTAssertEqual(parameters["key1"], "value1")
		XCTAssertEqual(parameters["key2"], "value2")
		XCTAssertEqual(parameters["key3"], "value3")
	}

	func testQueryParametersWithEncodedValues() {
		let urlString = "key1=hello%20world&key2=this+is+encoded&key3=value3"
		let parameters = urlString.queryParameters

		XCTAssertEqual(parameters.count, 3)
		XCTAssertEqual(parameters["key1"], "hello world")
		XCTAssertEqual(parameters["key2"], "this is encoded")
		XCTAssertEqual(parameters["key3"], "value3")
	}

	func testQueryParametersWithSingleParameterWithoutValue() {
		let urlString = "key1"
		let parameters = urlString.queryParameters

		XCTAssertEqual(parameters.count, 1)
		XCTAssertEqual(parameters["key1"], "true")
	}

	func testQueryParametersWithInvalidParameters() {
		let urlString = "key1=value1&key2"
		let parameters = urlString.queryParameters

		XCTAssertEqual(parameters.count, 2)
		XCTAssertEqual(parameters["key1"], "value1")
		XCTAssertEqual(parameters["key2"], "true")
	}
}
