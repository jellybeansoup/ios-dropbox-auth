import Foundation
import DropboxAuth
import DropboxAuthMocks
@testable import DropboxFiles
import Testing

@Suite struct TransportMonitorTests {

	@Test func initialSnapshotWithoutCursor() async throws {
		let transport = MockTransport(
			responses: [
				#"{"cursor": "cursor_one", "entries": [{".tag": "folder", "id": "id:1234", "name": "example", "path_display": "/example", "path_lower": "/example"}], "has_more": false}"#,
			]
		)

		let stream = transport.monitor(path: "/example", isRecursive: true, from: nil)

		var iterator = stream.makeAsyncIterator()
		let first = try #require(try await iterator.next())
		#expect(first.metadata.count == 1)
		#expect(first.cursor == "cursor_one")
	}

	@Test func monitorsChangesWithCursorAndLongpoll() async throws {
		let transport = MockTransport(
			responses: [
				#"{"changes": true, "backoff": 1}"#,
				#"{"cursor": "cursor_two", "entries": [{".tag": "folder", "id": "id:5678", "name": "alternate", "path_display": "/alternate", "path_lower": "/alternate"}], "has_more": false}"#,
			]
		)

		let stream = transport.monitor(path: "/example", isRecursive: true, from: "cursor_one")

		var iterator = stream.makeAsyncIterator()
		let first = try #require(try await iterator.next())
		#expect(first.metadata.count == 1)
		#expect(first.cursor == "cursor_two")
	}

	@Test func failureFromLongpoll() async throws {
		let transport = MockTransport(
			responses: [
				#"{"error": {".tag": "invalid_access_token"}, "error_summary": "invalid_access_token/"}"#,
			]
		)

		let stream = transport.monitor(path: "/example", isRecursive: true, from: nil)
		var iterator = stream.makeAsyncIterator()

		await #expect(throws: AuthenticationError.invalidAccessToken) {
			_ = try #require(try await iterator.next())
		}
	}

	@Test func failureFromListFolder() async throws {
		let transport = MockTransport(
			responses: [
				#"{"cursor": "cursor_one", "entries": [], "has_more": false}"#,
				#"{"changes": true}"#,
				#"{"error": {".tag": "invalid_access_token"}, "error_summary": "invalid_access_token/"}"#,
			]
		)

		let stream = transport.monitor(path: "/example", isRecursive: true, from: nil)
		var iterator = stream.makeAsyncIterator()

		let initialSnapshot = try #require(try await iterator.next())
		#expect(initialSnapshot.metadata.isEmpty)
		#expect(initialSnapshot.cursor == "cursor_one")

		await #expect(throws: AuthenticationError.invalidAccessToken) {
			_ = try #require(try await iterator.next())
		}
	}

}
