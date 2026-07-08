import Foundation
import DropboxAuth
import DropboxAuthMocks
@testable import DropboxFiles
import Testing

@Suite struct TransportListFolderTests {

	@Test func success() async throws {
		let transport = MockTransport(
			responses: [
				#"{"cursor": "cursor_one", "entries": [{".tag": "folder", "id": "id:1234", "name": "example", "path_display": "/example", "path_lower": "/example"}], "has_more": true}"#,
				#"{"cursor": "cursor_two", "entries": [{".tag": "folder", "id": "id:5678", "name": "alternate", "path_display": "/alternate", "path_lower": "/alternate"}], "has_more": false}"#,
			]
		)

		let response = try await transport.listFolder(at: "/example", isRecursive: true)

		#expect(response.metadata.count == 2)
		#expect(
			response.metadata[0] as? FolderMetadata == .init(
				id: .init(rawValue: "id:1234"),
				name: "example",
				pathLower: "/example",
				pathDisplay: "/example"
			)
		)
		#expect(
			response.metadata[1] as? FolderMetadata == .init(
				id: .init(rawValue: "id:5678"),
				name: "alternate",
				pathLower: "/alternate",
				pathDisplay: "/alternate"
			)
		)
		#expect(response.cursor == "cursor_two")
		#expect(response.isReset)
	}

	@Test func failure() async throws {
		let transport = MockTransport(
			responses: [
				#"{"error": {".tag": "invalid_access_token"}, "error_summary": "invalid_access_token/"}"#,
			]
		)
		await #expect(throws: AuthenticationError.invalidAccessToken) {
			_ = try await transport.listFolder(at: "/example", isRecursive: true)
		}
	}

	@Test func continueFromCursor() async throws {
		let transport = MockTransport(
			responses: [
				#"{"cursor": "cursor_one", "entries": [{".tag": "folder", "id": "id:1234", "name": "example", "path_display": "/example", "path_lower": "/example"}], "has_more": true}"#,
				#"{"cursor": "cursor_two", "entries": [{".tag": "folder", "id": "id:5678", "name": "alternate", "path_display": "/alternate", "path_lower": "/alternate"}], "has_more": false}"#,
			]
		)

		let response = try await transport.listFolder(from: "cursor_zero")

		#expect(response.metadata.count == 2)
		#expect(response.cursor == "cursor_two")
		#expect(response.isReset == false)
	}

	@Test func continueFromCursorFailure() async throws {
		let transport = MockTransport(
			responses: [
				#"{"error": {".tag": "invalid_access_token"}, "error_summary": "invalid_access_token/"}"#,
			]
		)
		await #expect(throws: AuthenticationError.invalidAccessToken) {
			_ = try await transport.listFolder(from: "cursor_zero")
		}
	}

	@Test func continueFromCursorReset() async throws {
		let transport = MockTransport(
			responses: [
				#"{"error": {".tag": "reset"}, "error_summary": "reset/"}"#,
			]
		)
		await #expect(throws: ListFolder.Continue.Error.reset) {
			_ = try await transport.listFolder(from: "cursor_zero")
		}
	}

}
