import Foundation
import DropboxAuth
import DropboxAuthMocks
@testable import DropboxFiles
import Testing

@Suite struct TransportLongpollTests {

	@Test func success() async throws {
		let transport = MockTransport(
			responses: [
				#"{"changes": true}"#,
			]
		)

		let response = try await transport.longpoll(cursor: "cursor", timeout: 10)

		#expect(response.hasChanges)
		#expect(response.backoff == 60)
	}

	@Test func failure() async throws {
		let transport = MockTransport(
			responses: [
				#"{"error": {".tag": "invalid_access_token"}, "error_summary": "invalid_access_token/"}"#,
			]
		)

		await #expect(throws: AuthenticationError.invalidAccessToken) {
			_ = try await transport.longpoll(cursor: "cursor", timeout: 10)
		}
	}

	@Test func reset() async throws {
		let transport = MockTransport(
			responses: [
				#"{"error": {".tag": "reset"}, "error_summary": "reset/"}"#,
			]
		)

		await #expect(throws: ListFolder.Longpoll.Error.reset) {
			_ = try await transport.longpoll(cursor: "cursor", timeout: 10)
		}
	}

}
