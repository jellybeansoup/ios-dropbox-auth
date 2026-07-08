import Foundation
import DropboxAuth
import DropboxAuthMocks
@testable import DropboxFiles
import Testing

@Suite struct DeleteTests {

	@Test func encoding() throws {
		let request = Delete.Request(path: "/hello/world")

		let urlRequest = try request.urlRequest(signedWith: .mock())

		#expect(urlRequest.url?.absoluteString == "https://api.dropboxapi.com/2/files/delete_v2")
		#expect(urlRequest.httpMethod == "POST")

		let data = try #require(urlRequest.httpBody)
		let string = String(data: data, encoding: .utf8)
		#expect(string == "{\"path\":\"/hello/world\"}")

		#expect(urlRequest.allHTTPHeaderFields == ["Content-Type": "application/json", "Authorization": "Bearer access_token"])
	}

	@Test func decodingFile() throws {
		let data = Data("""
		{
			"metadata": {
				".tag": "file",
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
		}
		""".utf8)

		let request = Delete.Request(path: "/homework/math/prime_numbers.txt")
		let response = try request.response(from: data)

		#expect(response.metadata as? FileMetadata == FileMetadata(
			id: .init(rawValue: "id:a4ayc_80_OEAAAAAAAAAXw"),
			revision: .init(rawValue: "a1c10ce0dd78"),
			name: "Prime_Numbers.txt",
			pathLower: "/homework/math/prime_numbers.txt",
			pathDisplay: "/Homework/math/Prime_Numbers.txt",
			numberOfBytes: 7212,
			dateModifiedOnClient: Date(timeIntervalSince1970: 1431445838), // 2015-05-12T15:50:38Z
			dateModifiedOnServer: Date(timeIntervalSince1970: 1431445838), // 2015-05-12T15:50:38Z
			contentHash: .init(rawValue: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
		))
	}

	@Test func decodingFolder() throws {
		let data = Data("""
		{
			"metadata": {
				".tag": "folder",
				"name": "math",
				"path_lower": "/homework/math",
				"path_display": "/Homework/math",
				"id": "id:a4ayc_80_OEAAAAAAAAAXz"
			}
		}
		""".utf8)

		let request = Delete.Request(path: "/homework/math")
		let response = try request.response(from: data)

		#expect(response.metadata as? FolderMetadata == FolderMetadata(
			id: .init(rawValue: "id:a4ayc_80_OEAAAAAAAAAXz"),
			name: "math",
			pathLower: "/homework/math",
			pathDisplay: "/Homework/math"
		))
	}

	// MARK: Error-summary parity with the legacy `DropboxError.from(errorSummary:)`

	@Test func decodingLookupMalformedPathFailure() throws {
		let data = Data("""
		{
			"error_summary": "path_lookup/malformed_path/.",
			"error": {
				".tag": "path_lookup",
				"path_lookup": {
					".tag": "malformed_path"
				}
			}
		}
		""".utf8)

		let request = Delete.Request(path: "")
		#expect(throws: Delete.Error.lookup(.malformedPath)) {
			try request.response(from: data)
		}
	}

	@Test func decodingLookupNotFoundFailure() throws {
		let data = Data("""
		{
			"error_summary": "path_lookup/not_found/.",
			"error": {
				".tag": "path_lookup",
				"path_lookup": {
					".tag": "not_found"
				}
			}
		}
		""".utf8)

		let request = Delete.Request(path: "")
		#expect(throws: Delete.Error.lookup(.notFound)) {
			try request.response(from: data)
		}
	}

	@Test func decodingLookupNotFileFailure() throws {
		let data = Data("""
		{
			"error_summary": "path_lookup/not_file/.",
			"error": {
				".tag": "path_lookup",
				"path_lookup": {
					".tag": "not_file"
				}
			}
		}
		""".utf8)

		let request = Delete.Request(path: "")
		#expect(throws: Delete.Error.lookup(.notFile)) {
			try request.response(from: data)
		}
	}

	@Test func decodingLookupNotFolderFailure() throws {
		let data = Data("""
		{
			"error_summary": "path_lookup/not_folder/.",
			"error": {
				".tag": "path_lookup",
				"path_lookup": {
					".tag": "not_folder"
				}
			}
		}
		""".utf8)

		let request = Delete.Request(path: "")
		#expect(throws: Delete.Error.lookup(.notFolder)) {
			try request.response(from: data)
		}
	}

	@Test func decodingLookupRestrictedContentFailure() throws {
		let data = Data("""
		{
			"error_summary": "path_lookup/restricted_content/.",
			"error": {
				".tag": "path_lookup",
				"path_lookup": {
					".tag": "restricted_content"
				}
			}
		}
		""".utf8)

		let request = Delete.Request(path: "")
		#expect(throws: Delete.Error.lookup(.restrictedContent)) {
			try request.response(from: data)
		}
	}

	@Test func decodingWriteMalformedPathFailure() throws {
		let data = Data("""
		{
			"error_summary": "path_write/malformed_path/.",
			"error": {
				".tag": "path_write",
				"path_write": {
					".tag": "malformed_path"
				}
			}
		}
		""".utf8)

		let request = Delete.Request(path: "")
		#expect(throws: Delete.Error.write(.malformedPath(nil))) {
			try request.response(from: data)
		}
	}

	@Test func decodingWriteConflictFailure() throws {
		let data = Data("""
		{
			"error_summary": "path_write/conflict/file/.",
			"error": {
				".tag": "path_write",
				"path_write": {
					".tag": "conflict",
					"conflict": {
						".tag": "file"
					}
				}
			}
		}
		""".utf8)

		let request = Delete.Request(path: "")
		#expect(throws: Delete.Error.write(.conflict(.file))) {
			try request.response(from: data)
		}
	}

	@Test func decodingWriteNoWritePermissionFailure() throws {
		let data = Data("""
		{
			"error_summary": "path_write/no_write_permission/.",
			"error": {
				".tag": "path_write",
				"path_write": {
					".tag": "no_write_permission"
				}
			}
		}
		""".utf8)

		let request = Delete.Request(path: "")
		#expect(throws: Delete.Error.write(.noWritePermission)) {
			try request.response(from: data)
		}
	}

	@Test func decodingWriteInsufficientSpaceFailure() throws {
		let data = Data("""
		{
			"error_summary": "path_write/insufficient_space/.",
			"error": {
				".tag": "path_write",
				"path_write": {
					".tag": "insufficient_space"
				}
			}
		}
		""".utf8)

		let request = Delete.Request(path: "")
		#expect(throws: Delete.Error.write(.insufficientSpace)) {
			try request.response(from: data)
		}
	}

	@Test func decodingWriteDisallowedNameFailure() throws {
		let data = Data("""
		{
			"error_summary": "path_write/disallowed_name/.",
			"error": {
				".tag": "path_write",
				"path_write": {
					".tag": "disallowed_name"
				}
			}
		}
		""".utf8)

		let request = Delete.Request(path: "")
		#expect(throws: Delete.Error.write(.disallowedName)) {
			try request.response(from: data)
		}
	}

	@Test func decodingTooManyWriteOperationsFailure() throws {
		let data = Data("""
		{
			"error_summary": "too_many_write_operations/.",
			"error": {
				".tag": "too_many_write_operations"
			}
		}
		""".utf8)

		let request = Delete.Request(path: "")
		#expect(throws: Delete.Error.tooManyWriteOperations) {
			try request.response(from: data)
		}
	}

	@Test func decodingTooManyFilesFailure() throws {
		let data = Data("""
		{
			"error_summary": "too_many_files/.",
			"error": {
				".tag": "too_many_files"
			}
		}
		""".utf8)

		let request = Delete.Request(path: "")
		#expect(throws: Delete.Error.tooManyFiles) {
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

		let request = Delete.Request(path: "")
		#expect(throws: AuthenticationError.expiredAccessToken) {
			try request.response(from: data)
		}
	}

}
