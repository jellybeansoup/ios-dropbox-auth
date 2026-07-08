import Foundation
import DropboxAuth
import DropboxAuthMocks
@testable import DropboxFiles
import Testing

@Suite struct TransportDeleteTests {

	@Test func success() async throws {
		let transport = MockTransport(
			responses: [
				#"{"metadata": {".tag": "folder", "id": "id:1234", "name": "example", "path_display": "/example", "path_lower": "/example"}}"#,
			]
		)

		let metadata = try await transport.delete(path: "/example")

		#expect(
			metadata as? FolderMetadata == .init(
				id: .init(rawValue: "id:1234"),
				name: "example",
				pathLower: "/example",
				pathDisplay: "/example"
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
			_ = try await transport.delete(path: "/example")
		}
	}

}
