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

struct APIErrorSummaryTests {

	private enum MockError: String, API.Error {
		case example
	}

	@Test func initWithString() throws {
		#expect(API.ErrorSummary(string: "") == .init(components: []))
		#expect(API.ErrorSummary(string: "example/.") == .init(components: ["example"]))
		#expect(API.ErrorSummary(string: "example") == .init(components: ["example"]))
		#expect(API.ErrorSummary(string: "///example") == .init(components: ["example"]))
		#expect(API.ErrorSummary(string: "summary/example/.") == .init(components: ["summary", "example"]))
	}

	@Test func component() {
		let summary = API.ErrorSummary(components: ["summary", "example"])
		#expect(summary.component == "summary")
	}

	@Test func next() {
		let summary = API.ErrorSummary(components: ["summary", "example"])
		#expect(summary.next() == .init(components: ["example"]))
	}

	@Test func nextThatThrows() throws {
		let summary = API.ErrorSummary(components: ["summary", "example"])
		#expect(try summary.next() == MockError.example)
	}

	@Test func nextThatThrowsInvalidError() {
		let summary = API.ErrorSummary(components: ["summary", "invalid"])
		do {
			let _: MockError = try summary.next()
			Issue.record("Initialising with an invalid summary should throw")
		}
		catch {
			#expect(error as? API.ErrorSummary == .init(components: ["invalid"]))
		}
	}

	@Test func description() throws {
		let summary = API.ErrorSummary(components: ["summary", "example"])
		#expect(summary.description == "summary/example/.")
	}

	@Test func initFromDecoder() throws {
		let json = Data(#""summary/example/.""#.utf8)
		let summary = try JSONDecoder().decode(API.ErrorSummary.self, from: json)
		#expect(summary == .init(components: ["summary", "example"]))
	}

}
