import Foundation
import DropboxAuth
import DropboxAuthMocks
@testable import DropboxFiles
import Testing

@Suite struct TransportListSharedLinksTests {

	@Test func success() async throws {
		let transport = MockTransport(
			responses: [
				#"{"cursor": "cursor_one", "links": [{".tag": "folder", "url": "https://www.dropbox.com/sh/one?dl=0", "name": "example", "link_permissions": {"resolved_visibility": {".tag": "public"}, "can_revoke": true}, "id": "id:1234", "path_lower": "/example", "expires": "2020-05-12T15:50:38Z"}], "has_more": true}"#,
				#"{"links": [{".tag": "folder", "url": "https://www.dropbox.com/sh/two?dl=0", "name": "alternate", "link_permissions": {"resolved_visibility": {".tag": "team_only"}, "can_revoke": false}, "id": "id:5678", "path_lower": "/alternate", "expires": "2020-05-12T15:50:38Z"}], "has_more": false}"#,
			]
		)

		let links = try await transport.listSharedLinks(path: "/example")

		#expect(links.count == 2)
		#expect(
			links[0] as? FolderLinkMetadata == .init(
				url: URL(string: "https://www.dropbox.com/sh/one?dl=0")!,
				name: "example",
				permissions: .init(resolvedVisibility: .public, canRevoke: true),
				id: .init(rawValue: "id:1234"),
				pathLower: "/example",
				dateOfExpiry: testDate("2020-05-12T15:50:38Z")
			)
		)
		#expect(
			links[1] as? FolderLinkMetadata == .init(
				url: URL(string: "https://www.dropbox.com/sh/two?dl=0")!,
				name: "alternate",
				permissions: .init(resolvedVisibility: .teamOnly, canRevoke: false),
				id: .init(rawValue: "id:5678"),
				pathLower: "/alternate",
				dateOfExpiry: testDate("2020-05-12T15:50:38Z")
			)
		)
	}

	@Test func successWithoutPagination() async throws {
		let transport = MockTransport(
			responses: [
				#"{"links": [], "has_more": false}"#,
			]
		)

		let links = try await transport.listSharedLinks()

		#expect(links.isEmpty)
	}

	@Test func successWithHasMoreButNoCursor() async throws {
		let transport = MockTransport(
			responses: [
				#"{"links": [{".tag": "folder", "url": "https://www.dropbox.com/sh/one?dl=0", "name": "example", "link_permissions": {"resolved_visibility": {".tag": "public"}, "can_revoke": true}, "id": "id:1234", "path_lower": "/example"}], "has_more": true}"#,
			]
		)

		// A response claiming `has_more` without providing a cursor cannot be
		// continued; the loop terminates with the accumulated links.
		let links = try await transport.listSharedLinks(path: "/example")

		#expect(links.count == 1)
		#expect(
			links[0] as? FolderLinkMetadata == .init(
				url: URL(string: "https://www.dropbox.com/sh/one?dl=0")!,
				name: "example",
				permissions: .init(resolvedVisibility: .public, canRevoke: true),
				id: .init(rawValue: "id:1234"),
				pathLower: "/example",
				dateOfExpiry: nil
			)
		)
	}

	@Test func failure() async throws {
		let transport = MockTransport(
			responses: [
				#"{"error": {".tag": "invalid_access_token"}, "error_summary": "invalid_access_token/"}"#,
			]
		)
		await #expect(throws: AuthenticationError.invalidAccessToken) {
			_ = try await transport.listSharedLinks(path: "/example")
		}
	}

}
