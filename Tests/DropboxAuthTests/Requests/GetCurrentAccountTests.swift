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

@Suite struct GetCurrentAccountTests {

	@Test func configureClearsBodyAndContentType() throws {
		let request = GetCurrentAccount.Request()

		var urlRequest = URLRequest(url: try #require(URL(string: "https://api.dropboxapi.com/2/users/get_current_account")))
		urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
		urlRequest.httpBody = Data("{}".utf8)

		try request.configure(&urlRequest)

		#expect(urlRequest.value(forHTTPHeaderField: "Content-Type") == nil)
		#expect(urlRequest.httpBody == nil)
	}

	@Test func urlRequestHasNoBody() throws {
		let request = GetCurrentAccount.Request()

		let urlRequest = try request.urlRequest(signedWith: .mock())

		#expect(urlRequest.url?.absoluteString == "https://api.dropboxapi.com/2/users/get_current_account")
		#expect(urlRequest.httpMethod == "POST")
		#expect(urlRequest.httpBody == nil)
		#expect(urlRequest.value(forHTTPHeaderField: "Content-Type") == nil)
	}

	@Test func decodesFullAccountPayload() throws {
		let data = Data("""
		{
			"account_id": "dbid:AAH4f99T0taONIb-OurWxbNQ6ywGRopQngc",
			"name": {
				"given_name": "Franz",
				"surname": "Ferdinand",
				"familiar_name": "Franz",
				"display_name": "Franz Ferdinand (Personal)",
				"abbreviated_name": "FF"
			},
			"email": "franz@dropbox.com",
			"email_verified": true,
			"disabled": false,
			"locale": "en",
			"referral_link": "https://db.tt/ZITNuhtI",
			"is_paired": true,
			"profile_photo_url": "https://dl-web.dropbox.com/account_photo/get/dbaphid%3AAAHWzr1XSFwvOMdgWG7RvzBCe3EGRs_2v4A?vers=1453416337204&size=128x128",
			"country": "US"
		}
		""".utf8)

		let response = try JSONDecoder().decode(GetCurrentAccount.Response.self, from: data)

		#expect(response.accountID == "dbid:AAH4f99T0taONIb-OurWxbNQ6ywGRopQngc")
		#expect(response.name.givenName == "Franz")
		#expect(response.name.surname == "Ferdinand")
		#expect(response.name.familiarName == "Franz")
		#expect(response.name.displayName == "Franz Ferdinand (Personal)")
		#expect(response.name.abbreviatedName == "FF")
		#expect(response.email == "franz@dropbox.com")
		#expect(response.isEmailVerified == true)
		#expect(response.isDisabled == false)
		#expect(response.locale == "en")
		#expect(response.referralLink.absoluteString == "https://db.tt/ZITNuhtI")
		#expect(response.isPaired == true)
		#expect(response.profilePhotoUrl?.absoluteString == "https://dl-web.dropbox.com/account_photo/get/dbaphid%3AAAHWzr1XSFwvOMdgWG7RvzBCe3EGRs_2v4A?vers=1453416337204&size=128x128")
		#expect(response.country == "US")
	}

	@Test func decodesAccountPayloadWithoutOptionalFields() throws {
		let data = Data("""
		{
			"account_id": "dbid:AAH4f99T0taONIb-OurWxbNQ6ywGRopQngc",
			"name": {
				"given_name": "Franz",
				"surname": "Ferdinand",
				"familiar_name": "Franz",
				"display_name": "Franz Ferdinand (Personal)",
				"abbreviated_name": "FF"
			},
			"email": "franz@dropbox.com",
			"email_verified": false,
			"disabled": false,
			"locale": "en",
			"referral_link": "https://db.tt/ZITNuhtI",
			"is_paired": false
		}
		""".utf8)

		let response = try JSONDecoder().decode(GetCurrentAccount.Response.self, from: data)

		#expect(response.profilePhotoUrl == nil)
		#expect(response.country == nil)
	}

	@Test func errorAlwaysThrowsTheSummary() {
		let summary = API.ErrorSummary(components: ["invalid_account_type"])

		#expect(throws: summary) {
			_ = try GetCurrentAccount.Error(summary: summary)
		}
	}

}
