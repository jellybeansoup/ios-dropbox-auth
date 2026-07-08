import Foundation
import DropboxAuth
import DropboxAuthMocks
@testable import DropboxFiles
import Testing

@Suite struct ListSharedLinksTests {

	@Test func encoding() throws {
		let request = ListSharedLinks.Request(
			path: "/hello/world",
			isDirectOnly: true
		)

		let urlRequest = try request.urlRequest(signedWith: .mock())

		#expect(urlRequest.url?.absoluteString == "https://api.dropboxapi.com/2/sharing/list_shared_links")
		#expect(urlRequest.httpMethod == "POST")

		let data = try #require(urlRequest.httpBody)
		let string = String(data: data, encoding: .utf8)
		#expect(string == "{\"direct_only\":true,\"path\":\"/hello/world\"}")

		#expect(urlRequest.allHTTPHeaderFields == ["Content-Type": "application/json", "Authorization": "Bearer access_token"])
	}

	@Test func encodingWithCursor() throws {
		let request = ListSharedLinks.Request(
			cursor: "abcdefghijklmnopqrstuvwxyz1234567890"
		)

		let urlRequest = try request.urlRequest(signedWith: .mock())

		let data = try #require(urlRequest.httpBody)
		let string = String(data: data, encoding: .utf8)
		#expect(string == "{\"cursor\":\"abcdefghijklmnopqrstuvwxyz1234567890\"}")
	}

	@Test func decoding() throws {
		let data = Data("""
		{
			"links": [
				{
					".tag": "file",
					"url": "https://www.dropbox.com/s/2sn712vy1ovegw8/Prime_Numbers.txt?dl=0",
					"name": "Prime_Numbers.txt",
					"link_permissions": {
						"resolved_visibility": {
							".tag": "public"
						},
						"can_revoke": true
					},
					"client_modified": "2015-05-12T15:50:38Z",
					"server_modified": "2015-05-12T15:50:38Z",
					"rev": "a1c10ce0dd78",
					"id": "id:a4ayc_80_OEAAAAAAAAAXw",
					"path_lower": "/homework/math/prime_numbers.txt",
					"size": 7212,
					"expires": "2020-05-12T15:50:38Z"
				},
				{
					".tag": "folder",
					"url": "https://www.dropbox.com/sh/s6fvw6ol7rmqo1x/AAAgWRSbjmYsFxSHJk4o9CoDa?dl=0",
					"name": "math",
					"link_permissions": {
						"resolved_visibility": {
							".tag": "team_only"
						},
						"can_revoke": false
					},
					"id": "id:a4ayc_80_OEAAAAAAAAAXz",
					"path_lower": "/homework/math"
				}
			],
			"has_more": false
		}
		""".utf8)

		let request = ListSharedLinks.Request()
		let response = try request.response(from: data)

		#expect(response.cursor == nil)
		#expect(response.links.count == 2)
		#expect(response.links[0] as? FileLinkMetadata == FileLinkMetadata(
			url: URL(string: "https://www.dropbox.com/s/2sn712vy1ovegw8/Prime_Numbers.txt?dl=0")!,
			name: "Prime_Numbers.txt",
			permissions: .init(resolvedVisibility: .public, canRevoke: true),
			revision: .init(rawValue: "a1c10ce0dd78"),
			id: .init(rawValue: "id:a4ayc_80_OEAAAAAAAAAXw"),
			pathLower: "/homework/math/prime_numbers.txt",
			numberOfBytes: 7212,
			dateModifiedOnClient: testDate("2015-05-12T15:50:38Z"),
			dateModifiedOnServer: testDate("2015-05-12T15:50:38Z"),
			dateOfExpiry: testDate("2020-05-12T15:50:38Z")
		))
		#expect(response.links[1] as? FolderLinkMetadata == FolderLinkMetadata(
			url: URL(string: "https://www.dropbox.com/sh/s6fvw6ol7rmqo1x/AAAgWRSbjmYsFxSHJk4o9CoDa?dl=0")!,
			name: "math",
			permissions: .init(resolvedVisibility: .teamOnly, canRevoke: false),
			id: .init(rawValue: "id:a4ayc_80_OEAAAAAAAAAXz"),
			pathLower: "/homework/math",
			dateOfExpiry: nil
		))
		#expect(response.hasMore == false)
	}

	@Test func decodingWithoutExpiry() throws {
		let data = Data("""
		{
			"links": [
				{
					".tag": "file",
					"url": "https://www.dropbox.com/s/2sn712vy1ovegw8/Prime_Numbers.txt?dl=0",
					"name": "Prime_Numbers.txt",
					"link_permissions": {
						"resolved_visibility": {
							".tag": "public"
						},
						"can_revoke": true
					},
					"client_modified": "2015-05-12T15:50:38Z",
					"server_modified": "2015-05-12T15:50:38Z",
					"rev": "a1c10ce0dd78",
					"id": "id:a4ayc_80_OEAAAAAAAAAXw",
					"path_lower": "/homework/math/prime_numbers.txt",
					"size": 7212
				}
			],
			"has_more": false
		}
		""".utf8)

		let request = ListSharedLinks.Request()
		let response = try request.response(from: data)

		let file = try #require(response.links.first as? FileLinkMetadata)
		#expect(file.dateOfExpiry == nil)
	}

	@Test func decodingMissingVisibilityTagFailure() throws {
		let data = Data("""
		{
			"links": [
				{
					".tag": "folder",
					"url": "https://www.dropbox.com/sh/s6fvw6ol7rmqo1x/AAAgWRSbjmYsFxSHJk4o9CoDa?dl=0",
					"name": "math",
					"link_permissions": {
						"resolved_visibility": {},
						"can_revoke": false
					},
					"id": "id:a4ayc_80_OEAAAAAAAAAXz",
					"path_lower": "/homework/math"
				}
			],
			"has_more": false
		}
		""".utf8)

		let request = ListSharedLinks.Request()
		#expect(throws: DecodingError.self) {
			try request.response(from: data)
		}
	}

	@Test func decodingUnknownVisibilityTag() throws {
		let data = Data("""
		{
			"links": [
				{
					".tag": "folder",
					"url": "https://www.dropbox.com/sh/s6fvw6ol7rmqo1x/AAAgWRSbjmYsFxSHJk4o9CoDa?dl=0",
					"name": "math",
					"link_permissions": {
						"resolved_visibility": {
							".tag": "some_future_visibility"
						},
						"can_revoke": false
					},
					"id": "id:a4ayc_80_OEAAAAAAAAAXz",
					"path_lower": "/homework/math",
					"expires": "2020-05-12T15:50:38Z"
				}
			],
			"has_more": false,
			"cursor": "ZtkX9_EHj3x7PMkVuFIhwKYXEpwpLwyxp9vMKomUhllil9q7eWiAu"
		}
		""".utf8)

		let request = ListSharedLinks.Request()
		let response = try request.response(from: data)

		#expect(response.cursor == "ZtkX9_EHj3x7PMkVuFIhwKYXEpwpLwyxp9vMKomUhllil9q7eWiAu")
		let folder = try #require(response.links.first as? FolderLinkMetadata)
		#expect(folder.permissions.resolvedVisibility == .other)
	}

	@Test func decodingHasMoreWithoutCursor() throws {
		let data = Data("""
		{
			"links": [],
			"has_more": true
		}
		""".utf8)

		let request = ListSharedLinks.Request()
		let response = try request.response(from: data)

		#expect(response.hasMore == true)
		#expect(response.cursor == nil)
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

		let request = ListSharedLinks.Request()
		#expect(throws: ListSharedLinks.Error.lookup(.notFound)) {
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

		let request = ListSharedLinks.Request()
		#expect(throws: ListSharedLinks.Error.reset) {
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

		let request = ListSharedLinks.Request()
		#expect(throws: AuthenticationError.expiredAccessToken) {
			try request.response(from: data)
		}
	}

}
