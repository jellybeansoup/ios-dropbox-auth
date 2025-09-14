import Foundation
import DropboxAuth
import DropboxAuthMocks
@testable import DropboxFiles
import Testing

@Suite struct ListFolderLongpollTests {

	@Test func encoding() throws {
		let request = ListFolder.Longpoll.Request(
			cursor: "abcdefghijklmnopqrstuvwxyz1234567890"
		)

		let urlRequest = try request.urlRequest(signedWith: .mock())

		#expect(urlRequest.url?.absoluteString == "https://notify.dropboxapi.com/2/files/list_folder/longpoll")
		#expect(urlRequest.httpMethod == "POST")

		let data = try #require(urlRequest.httpBody)
		let string = String(data: data, encoding: .utf8)
		#expect(string == "{\"cursor\":\"abcdefghijklmnopqrstuvwxyz1234567890\",\"timeout\":30}")

		#expect(urlRequest.allHTTPHeaderFields == ["Content-Type": "application/json", "Authorization": "Bearer access_token"])
	}

	@Test func decoding() throws {
		let data = Data("""
		{
			"changes": true
		}
		""".utf8)

		let request = ListFolder.Longpoll.Request(cursor: "abcdefghijklmnopqrstuvwxyz1234567890")
		let response = try request.response(from: data)

		#expect(response.hasChanges == true)
	}

	@Test func decodingResetFailure() throws {
		let data = Data("""
		{
			"error_summary": "reset/.",
			"error": {
				".tag": "reset"
			}
		}
		""".utf8)

		let request = ListFolder.Longpoll.Request(cursor: "abcdefghijklmnopqrstuvwxyz1234567890")
		#expect(throws: ListFolder.Longpoll.Error.reset) {
			try request.response(from: data)
		}
	}

	@Test func decodingTokenFailure() throws {
		let data = Data("""
		{
			"error": {
				".tag": "expired_access_token"
			},
			"error_summary": "expired_access_token/"
		}
		""".utf8)

		let request = ListFolder.Longpoll.Request(cursor: "abcdefghijklmnopqrstuvwxyz1234567890")
		#expect(throws: AuthenticationError.expiredAccessToken) {
			try request.response(from: data)
		}
	}

}
