import Foundation
import DropboxAuth
import DropboxAuthMocks
@testable import DropboxFiles
import Testing

@Suite struct ListFolderContinueTests {

	@Test func encoding() throws {
		let request = ListFolder.Continue.Request(
			cursor: "abcdefghijklmnopqrstuvwxyz1234567890"
		)

		let urlRequest = try request.urlRequest(signedWith: .mock())

		#expect(urlRequest.url?.absoluteString == "https://api.dropboxapi.com/2/files/list_folder/continue")
		#expect(urlRequest.httpMethod == "POST")

		let data = try #require(urlRequest.httpBody)
		let string = String(data: data, encoding: .utf8)
		#expect(string == "{\"cursor\":\"abcdefghijklmnopqrstuvwxyz1234567890\"}")

		#expect(urlRequest.allHTTPHeaderFields == ["Content-Type": "application/json", "Authorization": "Bearer access_token"])
	}

	@Test func decoding() throws {
		let data = Data("""
		{
			"cursor": "ZtkX9_EHj3x7PMkVuFIhwKYXEpwpLwyxp9vMKomUhllil9q7eWiAu",
			"entries": [
				{
					".tag": "file",
					"client_modified": "2015-05-12T15:50:38Z",
					"content_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
					"file_lock_info": {
						"created": "2015-05-12T15:50:38Z",
						"is_lockholder": true,
						"lockholder_name": "Imaginary User"
					},
					"has_explicit_shared_members": false,
					"id": "id:a4ayc_80_OEAAAAAAAAAXw",
					"is_downloadable": true,
					"name": "Prime_Numbers.txt",
					"path_display": "/Homework/math/Prime_Numbers.txt",
					"path_lower": "/homework/math/prime_numbers.txt",
					"property_groups": [
						{
							"fields": [
								{
									"name": "Security Policy",
									"value": "Confidential"
								}
							],
							"template_id": "ptid:1a5n2i6d3OYEAAAAAAAAAYa"
						}
					],
					"rev": "a1c10ce0dd78",
					"server_modified": "2015-05-12T15:50:38Z",
					"sharing_info": {
						"modified_by": "dbid:AAH4f99T0taONIb-OurWxbNQ6ywGRopQngc",
						"parent_shared_folder_id": "84528192421",
						"read_only": true
					},
					"size": 7212
				},
				{
					".tag": "folder",
					"id": "id:a4ayc_80_OEAAAAAAAAAXz",
					"name": "math",
					"path_display": "/Homework/math",
					"path_lower": "/homework/math",
					"property_groups": [
						{
							"fields": [
								{
									"name": "Security Policy",
									"value": "Confidential"
								}
							],
							"template_id": "ptid:1a5n2i6d3OYEAAAAAAAAAYa"
						}
					],
					"sharing_info": {
						"no_access": false,
						"parent_shared_folder_id": "84528192421",
						"read_only": false,
						"traverse_only": false
					}
				}
			],
			"has_more": false
		}
		""".utf8)

		let request = ListFolder.Continue.Request(cursor: "abcdefghijklmnopqrstuvwxyz1234567890")
		let response = try request.response(from: data)

		#expect(response.cursor == "ZtkX9_EHj3x7PMkVuFIhwKYXEpwpLwyxp9vMKomUhllil9q7eWiAu")
		#expect(response.entries.count == 2)
		#expect(
			response.entries[0] as? FileMetadata ==
			FileMetadata(
				id: .init(rawValue: "id:a4ayc_80_OEAAAAAAAAAXw"),
				revision: .init(rawValue: "a1c10ce0dd78"),
				name: "Prime_Numbers.txt",
				pathLower: "/homework/math/prime_numbers.txt",
				pathDisplay: "/Homework/math/Prime_Numbers.txt",
				numberOfBytes: 7212,
				dateModifiedOnClient: Date(timeIntervalSince1970: 1431445838), // 2015-05-12T15:50:38Z
				dateModifiedOnServer: Date(timeIntervalSince1970: 1431445838), // 2015-05-12T15:50:38Z
				contentHash: .init(rawValue: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
			)
		)
		#expect(
			response.entries[1] as? FolderMetadata ==
			FolderMetadata(
				id: .init(rawValue: "id:a4ayc_80_OEAAAAAAAAAXz"),
				name: "math",
				pathLower: "/homework/math",
				pathDisplay: "/Homework/math"
			)
		)
		#expect(response.hasMore == false)
	}

	@Test func decodingLookupFailure() throws {
		let data = Data("""
		{
			"error_summary": "path/not_found/.",
			"error": {
				".tag": "path",
				"path": {
					".tag": "not_found"
				}
			}
		}
		""".utf8)

		let request = ListFolder.Continue.Request(cursor: "abcdefghijklmnopqrstuvwxyz1234567890")
		#expect(throws: ListFolder.Continue.Error.lookup(.notFound)) {
			try request.response(from: data)
		}
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

		let request = ListFolder.Continue.Request(cursor: "abcdefghijklmnopqrstuvwxyz1234567890")
		#expect(throws: ListFolder.Continue.Error.reset) {
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

		let request = ListFolder.Continue.Request(cursor: "abcdefghijklmnopqrstuvwxyz1234567890")
		#expect(throws: AuthenticationError.expiredAccessToken) {
			try request.response(from: data)
		}
	}

}
