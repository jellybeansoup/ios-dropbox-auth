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
@testable import DropboxAuth
import Testing

@Suite struct APIHeaderEncodingTests {

	@Test func asciiOnlyIsUnescaped() {
		let json = "{\"path\":\"/hello/world.gif\"}"
		#expect(API.headerArgEncodedJSONString(json) == json)
	}

	@Test func emojiPathIsEscaped() {
		let json = "{\"path\":\"/\u{1F389} party.gif\"}"
		// "🎉" (U+1F389) sits outside the Basic Multilingual Plane, so per RFC 8259 it is
		// escaped as a UTF-16 surrogate pair.
		#expect(API.headerArgEncodedJSONString(json) == "{\"path\":\"/\\ud83c\\udf89 party.gif\"}")
	}

	@Test func accentedCharactersAreEscaped() {
		let json = "{\"path\":\"/r\u{00E9}sum\u{00E9}.pdf\"}"
		#expect(API.headerArgEncodedJSONString(json) == "{\"path\":\"/r\\u00e9sum\\u00e9.pdf\"}")
	}

	@Test func mixedAsciiAndNonAsciiOnlyEscapesNonAscii() {
		let json = "{\"path\":\"/na\u{00EF}ve \u{1F600}.png\",\"format\":\"png\"}"
		#expect(API.headerArgEncodedJSONString(json) == "{\"path\":\"/na\\u00efve \\ud83d\\ude00.png\",\"format\":\"png\"}")
	}

	@Test func surrogatePairWithinLongerPathLeavesSurroundingAsciiUntouched() {
		let json = "{\"path\":\"/GIFs/2026/reaction \u{1F602} laughing.gif\",\"format\":\"png\",\"size\":\"w640h480\"}"
		#expect(API.headerArgEncodedJSONString(json) == "{\"path\":\"/GIFs/2026/reaction \\ud83d\\ude02 laughing.gif\",\"format\":\"png\",\"size\":\"w640h480\"}")
	}

	@Test func emptyStringIsUnchanged() {
		#expect(API.headerArgEncodedJSONString("") == "")
	}

}
