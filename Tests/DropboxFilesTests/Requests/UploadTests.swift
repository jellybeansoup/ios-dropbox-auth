import Foundation
import DropboxAuth
import DropboxAuthMocks
@testable import DropboxFiles
import Testing

@Suite struct UploadTests {

	@Test func encodingDefaultsToAddMode() throws {
		let request = Upload.Request(path: "/hello/world.gif", contents: Data("hello".utf8))

		let urlRequest = try request.urlRequest(signedWith: .mock())

		#expect(urlRequest.url?.absoluteString == "https://content.dropboxapi.com/2/files/upload")
		#expect(urlRequest.httpMethod == "POST")
		#expect(urlRequest.value(forHTTPHeaderField: "Dropbox-API-Arg") == "{\"autorename\":false,\"mode\":\"add\",\"path\":\"/hello/world.gif\"}")
		#expect(urlRequest.value(forHTTPHeaderField: "Content-Type") == "application/octet-stream")
		#expect(urlRequest.httpBody == Data("hello".utf8))
	}

	@Test func encodingOverwriteMode() throws {
		let request = Upload.Request(path: "/hello/world.gif", mode: .overwrite, contents: Data())

		let urlRequest = try request.urlRequest(signedWith: .mock())

		#expect(urlRequest.value(forHTTPHeaderField: "Dropbox-API-Arg") == "{\"autorename\":false,\"mode\":\"overwrite\",\"path\":\"/hello/world.gif\"}")
	}

	@Test func encodingUpdateModeCarriesRevision() throws {
		let request = Upload.Request(
			path: "/hello/world.gif",
			mode: .update(.init(rawValue: "a1c10ce0dd78")),
			autorename: true,
			contents: Data()
		)

		let urlRequest = try request.urlRequest(signedWith: .mock())

		#expect(urlRequest.value(forHTTPHeaderField: "Dropbox-API-Arg") == "{\"autorename\":true,\"mode\":{\"update\":\"a1c10ce0dd78\"},\"path\":\"/hello/world.gif\"}")
	}

	@Test func encodingEscapesNonASCIIPathInHeader() throws {
		let request = Upload.Request(path: "/GIFs/reaction \u{1F602}.gif", contents: Data())

		let urlRequest = try request.urlRequest(signedWith: .mock())

		#expect(urlRequest.value(forHTTPHeaderField: "Dropbox-API-Arg") == "{\"autorename\":false,\"mode\":\"add\",\"path\":\"/GIFs/reaction \\ud83d\\ude02.gif\"}")
	}

	@Test func decodingBareFileMetadataBody() throws {
		let data = Data("""
		{
			"name": "Prime_Numbers.txt",
			"path_lower": "/homework/math/prime_numbers.txt",
			"path_display": "/Homework/math/Prime_Numbers.txt",
			"id": "id:a4ayc_80_OEAAAAAAAAAXw",
			"client_modified": "2015-05-12T15:50:38Z",
			"server_modified": "2015-05-12T15:50:38Z",
			"rev": "a1c10ce0dd78",
			"size": 7212,
			"content_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		}
		""".utf8)

		let request = Upload.Request(path: "/homework/math/prime_numbers.txt", contents: Data())
		let response = try request.response(from: data)

		#expect(response.metadata == FileMetadata(
			id: .init(rawValue: "id:a4ayc_80_OEAAAAAAAAAXw"),
			revision: .init(rawValue: "a1c10ce0dd78"),
			name: "Prime_Numbers.txt",
			pathLower: "/homework/math/prime_numbers.txt",
			pathDisplay: "/Homework/math/Prime_Numbers.txt",
			numberOfBytes: 7212,
			dateModifiedOnClient: Date(timeIntervalSince1970: 1431409838),
			dateModifiedOnServer: Date(timeIntervalSince1970: 1431409838),
			contentHash: .init(rawValue: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
		))
	}

	// MARK: Error-summary parity with the legacy `DropboxError.from(errorSummary:)`

	@Test func decodingPathInsufficientSpaceFailure() throws {
		// Legacy parity: `path/insufficient_space/` must map to `.path(.insufficientSpace)`.
		let data = Data("""
		{
			"error_summary": "path/insufficient_space/",
			"error": {
				".tag": "path",
				"reason": {
					".tag": "insufficient_space"
				},
				"upload_session_id": "abc123"
			}
		}
		""".utf8)

		let request = Upload.Request(path: "", contents: Data())
		#expect(throws: Upload.Error.path(.insufficientSpace)) {
			try request.response(from: data)
		}
	}

	@Test func decodingPathConflictFailure() throws {
		let data = Data("""
		{
			"error_summary": "path/conflict/file/",
			"error": {
				".tag": "path",
				"reason": {
					".tag": "conflict",
					"conflict": {
						".tag": "file"
					}
				}
			}
		}
		""".utf8)

		let request = Upload.Request(path: "", contents: Data())
		#expect(throws: Upload.Error.path(.conflict(.file))) {
			try request.response(from: data)
		}
	}

	@Test func decodingTooManyWriteOperationsFailure() throws {
		let data = Data("""
		{
			"error_summary": "too_many_write_operations/",
			"error": {
				".tag": "too_many_write_operations"
			}
		}
		""".utf8)

		let request = Upload.Request(path: "", contents: Data())
		#expect(throws: Upload.Error.tooManyWriteOperations) {
			try request.response(from: data)
		}
	}

	@Test func decodingTokenFailure() throws {
		let data = Data("""
		{
			"error": {
				".tag": "invalid_access_token"
			},
			"error_summary": "invalid_access_token/"
		}
		""".utf8)

		let request = Upload.Request(path: "", contents: Data())
		#expect(throws: AuthenticationError.invalidAccessToken) {
			try request.response(from: data)
		}
	}

}
