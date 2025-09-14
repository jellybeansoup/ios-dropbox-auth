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

struct APIErrorResponseTests {
	private enum MockError: String, API.Error {
		case example
	}

	@Test func initWithSummary() throws {
		let summary: API.ErrorSummary = .init(components: ["example"])
		#expect(try MockError(summary: summary) == .example)
	}

	@Test func initWithInvalidSummary() {
		let summary: API.ErrorSummary = .init(components: ["invalid"])
		do {
			let _ = try MockError(summary: summary)
			Issue.record("Initialising with an invalid summary should throw")
		}
		catch {
			#expect(error as? API.ErrorSummary == summary)
		}
	}

	@Test func decodesKnownError() throws {
		let json = Data(#"{ "error_summary": "example" }"#.utf8)
		let response = try JSONDecoder().decode(API.ErrorResponse<MockError>.self, from: json)
		#expect(response.error == .example)
	}

	@Test func decodesUnknownSummaryThrows() {
		let json = Data(#"{ "error_summary": "unknown" }"#.utf8)
		do {
			let _ = try JSONDecoder().decode(API.ErrorResponse<MockError>.self, from: json)
			Issue.record("Should throw API.Error.Summary for unrecognized error summary")
		} catch let summary as API.Error.Summary {
			#expect(summary == API.Error.Summary(components: ["unknown"]))
		} catch {
			Issue.record("Expected API.Error.Summary, got: \(type(of: error))")
		}
	}

	@Test func decodingMissingSummaryThrows() {
		let json = Data(#"{}"#.utf8)
		do {
			let _ = try JSONDecoder().decode(API.ErrorResponse<MockError>.self, from: json)
			Issue.record("Should throw DecodingError for missing error_summary")
		} catch {
			#expect(error is DecodingError)
		}
	}
}
