import Foundation
import DropboxAuth
import DropboxAuthMocks
@testable import DropboxFiles
import Testing

@Suite struct CreateSharedLinkWithSettingsTests {

	@Test func encoding() throws {
		let request = CreateSharedLinkWithSettings.Request(
			path: "/hello/world",
			settings: .init(requestedVisibility: .public)
		)

		let urlRequest = try request.urlRequest(signedWith: .mock())

		#expect(urlRequest.url?.absoluteString == "https://api.dropboxapi.com/2/sharing/create_shared_link_with_settings")
		#expect(urlRequest.httpMethod == "POST")

		let data = try #require(urlRequest.httpBody)
		let string = String(data: data, encoding: .utf8)
		#expect(string == "{\"path\":\"/hello/world\",\"settings\":{\"requested_visibility\":{\".tag\":\"public\"}}}")

		#expect(urlRequest.allHTTPHeaderFields == ["Content-Type": "application/json", "Authorization": "Bearer access_token"])
	}

	@Test func encodingWithoutSettings() throws {
		let request = CreateSharedLinkWithSettings.Request(path: "/hello/world")

		let urlRequest = try request.urlRequest(signedWith: .mock())

		let data = try #require(urlRequest.httpBody)
		let string = String(data: data, encoding: .utf8)
		#expect(string == "{\"path\":\"/hello/world\"}")
	}

	@Test func decodingFile() throws {
		let data = Data("""
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
		""".utf8)

		let request = CreateSharedLinkWithSettings.Request(path: "/homework/math/prime_numbers.txt")
		let response = try request.response(from: data)

		let file = try #require(response.link as? FileLinkMetadata)
		#expect(file.url == URL(string: "https://www.dropbox.com/s/2sn712vy1ovegw8/Prime_Numbers.txt?dl=0")!)
		#expect(file.name == "Prime_Numbers.txt")
		#expect(file.permissions == .init(resolvedVisibility: .public, canRevoke: true))
	}

	@Test func decodingFolder() throws {
		let data = Data("""
		{
			".tag": "folder",
			"url": "https://www.dropbox.com/sh/s6fvw6ol7rmqo1x/AAAgWRSbjmYsFxSHJk4o9CoDa?dl=0",
			"name": "math",
			"link_permissions": {
				"resolved_visibility": {
					".tag": "public"
				},
				"can_revoke": true
			},
			"id": "id:a4ayc_80_OEAAAAAAAAAXz",
			"path_lower": "/homework/math"
		}
		""".utf8)

		let request = CreateSharedLinkWithSettings.Request(path: "/homework/math")
		let response = try request.response(from: data)

		let folder = try #require(response.link as? FolderLinkMetadata)
		#expect(folder.url == URL(string: "https://www.dropbox.com/sh/s6fvw6ol7rmqo1x/AAAgWRSbjmYsFxSHJk4o9CoDa?dl=0")!)
		#expect(folder.name == "math")
	}

	// MARK: Error-summary parity with the legacy `DropboxError.from(errorSummary:)`

	@Test func decodingLookupNotFoundFailure() throws {
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

		let request = CreateSharedLinkWithSettings.Request(path: "/example")
		#expect(throws: CreateSharedLinkWithSettings.Error.lookup(.notFound)) {
			try request.response(from: data)
		}
	}

	/// Deferred from Phase 2's regression checklist: the legacy `DropboxError.from(errorSummary:)`
	/// recognises `email_not_verified/` as a bare (non-lookup) error summary.
	@Test func decodingEmailNotVerifiedFailure() throws {
		let data = Data("""
		{
			"error_summary": "email_not_verified/",
			"error": {
				".tag": "email_not_verified"
			}
		}
		""".utf8)

		let request = CreateSharedLinkWithSettings.Request(path: "/example")
		#expect(throws: CreateSharedLinkWithSettings.Error.emailNotVerified) {
			try request.response(from: data)
		}
	}

	@Test func decodingSharedLinkAlreadyExistsWithMetadataFailure() throws {
		let data = Data("""
		{
			"error_summary": "shared_link_already_exists/.",
			"error": {
				".tag": "shared_link_already_exists",
				"shared_link_already_exists": {
					"metadata": {
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
				}
			}
		}
		""".utf8)

		let request = CreateSharedLinkWithSettings.Request(path: "/homework/math/prime_numbers.txt")

		do {
			_ = try request.response(from: data)
			Issue.record("Expected shared_link_already_exists to be thrown")
		}
		catch CreateSharedLinkWithSettings.Error.sharedLinkAlreadyExists(let existingLink) {
			let file = try #require(existingLink as? FileLinkMetadata)
			#expect(file.url == URL(string: "https://www.dropbox.com/s/2sn712vy1ovegw8/Prime_Numbers.txt?dl=0")!)
			#expect(file.name == "Prime_Numbers.txt")
		}
	}

	@Test func decodingSharedLinkAlreadyExistsWithoutMetadataFailure() throws {
		let data = Data("""
		{
			"error_summary": "shared_link_already_exists/.",
			"error": {
				".tag": "shared_link_already_exists"
			}
		}
		""".utf8)

		let request = CreateSharedLinkWithSettings.Request(path: "/example")
		#expect(throws: CreateSharedLinkWithSettings.Error.sharedLinkAlreadyExists(existingLink: nil)) {
			try request.response(from: data)
		}
	}

	@Test func decodingSettingsInvalidSettingsFailure() throws {
		let data = Data("""
		{
			"error_summary": "settings_error/invalid_settings/.",
			"error": {
				".tag": "settings_error",
				"settings_error": {
					".tag": "invalid_settings"
				}
			}
		}
		""".utf8)

		let request = CreateSharedLinkWithSettings.Request(path: "/example")
		#expect(throws: CreateSharedLinkWithSettings.Error.settings(.invalidSettings)) {
			try request.response(from: data)
		}
	}

	@Test func decodingAccessDeniedFailure() throws {
		let data = Data("""
		{
			"error_summary": "access_denied/.",
			"error": {
				".tag": "access_denied"
			}
		}
		""".utf8)

		let request = CreateSharedLinkWithSettings.Request(path: "/example")
		#expect(throws: CreateSharedLinkWithSettings.Error.accessDenied) {
			try request.response(from: data)
		}
	}

	@Test func decodingUnknownErrorFailure() throws {
		let data = Data("""
		{
			"error_summary": "some_future_error/.",
			"error": {
				".tag": "some_future_error"
			}
		}
		""".utf8)

		let request = CreateSharedLinkWithSettings.Request(path: "/example")
		#expect(throws: API.ErrorSummary.self) {
			try request.response(from: data)
		}
	}

}
