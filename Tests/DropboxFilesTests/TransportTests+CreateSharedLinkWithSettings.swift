import Foundation
import DropboxAuth
import DropboxAuthMocks
@testable import DropboxFiles
import Testing

@Suite struct TransportCreateSharedLinkWithSettingsTests {

	@Test func success() async throws {
		let transport = MockTransport(
			responses: [
				#"""
				{
					".tag": "file",
					"url": "https://www.dropbox.com/s/2sn712vy1ovegw8/Prime_Numbers.txt?dl=0",
					"name": "Prime_Numbers.txt",
					"link_permissions": {
						"resolved_visibility": {".tag": "public"},
						"can_revoke": true
					},
					"client_modified": "2015-05-12T15:50:38Z",
					"server_modified": "2015-05-12T15:50:38Z",
					"rev": "a1c10ce0dd78",
					"id": "id:a4ayc_80_OEAAAAAAAAAXw",
					"path_lower": "/homework/math/prime_numbers.txt",
					"size": 7212
				}
				"""#,
			]
		)

		let link = try await transport.createSharedLinkWithSettings(path: "/homework/math/prime_numbers.txt")

		let file = try #require(link as? FileLinkMetadata)
		#expect(file.url == URL(string: "https://www.dropbox.com/s/2sn712vy1ovegw8/Prime_Numbers.txt?dl=0")!)
		#expect(file.permissions.resolvedVisibility == .public)
	}

	@Test func failureAlreadyExists() async throws {
		let transport = MockTransport(
			responses: [
				#"""
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
									"resolved_visibility": {".tag": "public"},
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
				"""#,
			]
		)

		do {
			_ = try await transport.createSharedLinkWithSettings(path: "/homework/math/prime_numbers.txt")
			Issue.record("Expected sharedLinkAlreadyExists to be thrown")
		}
		catch CreateSharedLinkWithSettings.Error.sharedLinkAlreadyExists(let existingLink) {
			let file = try #require(existingLink as? FileLinkMetadata)
			#expect(file.url == URL(string: "https://www.dropbox.com/s/2sn712vy1ovegw8/Prime_Numbers.txt?dl=0")!)
		}
	}

	@Test func failureAuthentication() async throws {
		let transport = MockTransport(
			responses: [
				#"{"error": {".tag": "invalid_access_token"}, "error_summary": "invalid_access_token/"}"#,
			]
		)
		await #expect(throws: AuthenticationError.invalidAccessToken) {
			_ = try await transport.createSharedLinkWithSettings(path: "/example")
		}
	}

}
