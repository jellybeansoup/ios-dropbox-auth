import Foundation
import DropboxAuth
import DropboxAuthMocks
@testable import DropboxFiles
import Testing

@Suite struct MoveTests {

	@Test func encoding() throws {
		let request = Move.Request(
			fromPath: "/hello/world",
			toPath: "/hello/there",
			autorename: true
		)

		let urlRequest = try request.urlRequest(signedWith: .mock())

		#expect(urlRequest.url?.absoluteString == "https://api.dropboxapi.com/2/files/move_v2")
		#expect(urlRequest.httpMethod == "POST")

		let data = try #require(urlRequest.httpBody)
		let string = String(data: data, encoding: .utf8)
		#expect(string == "{\"autorename\":true,\"from_path\":\"/hello/world\",\"to_path\":\"/hello/there\"}")

		#expect(urlRequest.allHTTPHeaderFields == ["Content-Type": "application/json", "Authorization": "Bearer access_token"])
	}

	@Test func encodingDefaultAutorename() throws {
		let request = Move.Request(
			fromPath: "/hello/world",
			toPath: "/hello/there"
		)

		let urlRequest = try request.urlRequest(signedWith: .mock())

		let data = try #require(urlRequest.httpBody)
		let string = String(data: data, encoding: .utf8)
		#expect(string == "{\"autorename\":false,\"from_path\":\"/hello/world\",\"to_path\":\"/hello/there\"}")
	}

	@Test func decoding() throws {
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

		let request = Move.Request(fromPath: "/homework/math/old.txt", toPath: "/homework/math/prime_numbers.txt")
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

	// MARK: Error-summary parity with the legacy `DropboxError.from(errorSummary:)`

	@Test func decodingFromLookupMalformedPathFailure() throws {
		let data = Data("""
		{
			"error_summary": "from_lookup/malformed_path/.",
			"error": {
				".tag": "from_lookup",
				"from_lookup": {
					".tag": "malformed_path"
				}
			}
		}
		""".utf8)

		let request = Move.Request(fromPath: "", toPath: "")
		#expect(throws: RelocationError.fromLookup(.malformedPath)) {
			try request.response(from: data)
		}
	}

	@Test func decodingFromLookupNotFoundFailure() throws {
		let data = Data("""
		{
			"error_summary": "from_lookup/not_found/.",
			"error": {
				".tag": "from_lookup",
				"from_lookup": {
					".tag": "not_found"
				}
			}
		}
		""".utf8)

		let request = Move.Request(fromPath: "", toPath: "")
		#expect(throws: RelocationError.fromLookup(.notFound)) {
			try request.response(from: data)
		}
	}

	@Test func decodingFromLookupNotFileFailure() throws {
		let data = Data("""
		{
			"error_summary": "from_lookup/not_file/.",
			"error": {
				".tag": "from_lookup",
				"from_lookup": {
					".tag": "not_file"
				}
			}
		}
		""".utf8)

		let request = Move.Request(fromPath: "", toPath: "")
		#expect(throws: RelocationError.fromLookup(.notFile)) {
			try request.response(from: data)
		}
	}

	@Test func decodingFromLookupNotFolderFailure() throws {
		let data = Data("""
		{
			"error_summary": "from_lookup/not_folder/.",
			"error": {
				".tag": "from_lookup",
				"from_lookup": {
					".tag": "not_folder"
				}
			}
		}
		""".utf8)

		let request = Move.Request(fromPath: "", toPath: "")
		#expect(throws: RelocationError.fromLookup(.notFolder)) {
			try request.response(from: data)
		}
	}

	@Test func decodingFromLookupRestrictedContentFailure() throws {
		let data = Data("""
		{
			"error_summary": "from_lookup/restricted_content/.",
			"error": {
				".tag": "from_lookup",
				"from_lookup": {
					".tag": "restricted_content"
				}
			}
		}
		""".utf8)

		let request = Move.Request(fromPath: "", toPath: "")
		#expect(throws: RelocationError.fromLookup(.restrictedContent)) {
			try request.response(from: data)
		}
	}

	@Test func decodingFromWriteMalformedPathFailure() throws {
		let data = Data("""
		{
			"error_summary": "from_write/malformed_path/.",
			"error": {
				".tag": "from_write",
				"from_write": {
					".tag": "malformed_path"
				}
			}
		}
		""".utf8)

		let request = Move.Request(fromPath: "", toPath: "")
		#expect(throws: RelocationError.fromWrite(.malformedPath(nil))) {
			try request.response(from: data)
		}
	}

	@Test func decodingFromWriteConflictFailure() throws {
		let data = Data("""
		{
			"error_summary": "from_write/conflict/folder/.",
			"error": {
				".tag": "from_write",
				"from_write": {
					".tag": "conflict",
					"conflict": {
						".tag": "folder"
					}
				}
			}
		}
		""".utf8)

		let request = Move.Request(fromPath: "", toPath: "")
		#expect(throws: RelocationError.fromWrite(.conflict(.folder))) {
			try request.response(from: data)
		}
	}

	@Test func decodingFromWriteNoWritePermissionFailure() throws {
		let data = Data("""
		{
			"error_summary": "from_write/no_write_permission/.",
			"error": {
				".tag": "from_write",
				"from_write": {
					".tag": "no_write_permission"
				}
			}
		}
		""".utf8)

		let request = Move.Request(fromPath: "", toPath: "")
		#expect(throws: RelocationError.fromWrite(.noWritePermission)) {
			try request.response(from: data)
		}
	}

	@Test func decodingFromWriteInsufficientSpaceFailure() throws {
		let data = Data("""
		{
			"error_summary": "from_write/insufficient_space/.",
			"error": {
				".tag": "from_write",
				"from_write": {
					".tag": "insufficient_space"
				}
			}
		}
		""".utf8)

		let request = Move.Request(fromPath: "", toPath: "")
		#expect(throws: RelocationError.fromWrite(.insufficientSpace)) {
			try request.response(from: data)
		}
	}

	@Test func decodingFromWriteDisallowedNameFailure() throws {
		let data = Data("""
		{
			"error_summary": "from_write/disallowed_name/.",
			"error": {
				".tag": "from_write",
				"from_write": {
					".tag": "disallowed_name"
				}
			}
		}
		""".utf8)

		let request = Move.Request(fromPath: "", toPath: "")
		#expect(throws: RelocationError.fromWrite(.disallowedName)) {
			try request.response(from: data)
		}
	}

	@Test func decodingToMalformedPathFailure() throws {
		let data = Data("""
		{
			"error_summary": "to/malformed_path/.",
			"error": {
				".tag": "to",
				"to": {
					".tag": "malformed_path"
				}
			}
		}
		""".utf8)

		let request = Move.Request(fromPath: "", toPath: "")
		#expect(throws: RelocationError.to(.malformedPath(nil))) {
			try request.response(from: data)
		}
	}

	@Test func decodingToConflictFailure() throws {
		let data = Data("""
		{
			"error_summary": "to/conflict/file_ancestor/.",
			"error": {
				".tag": "to",
				"to": {
					".tag": "conflict",
					"conflict": {
						".tag": "file_ancestor"
					}
				}
			}
		}
		""".utf8)

		let request = Move.Request(fromPath: "", toPath: "")
		#expect(throws: RelocationError.to(.conflict(.fileAncestor))) {
			try request.response(from: data)
		}
	}

	@Test func decodingToNoWritePermissionFailure() throws {
		let data = Data("""
		{
			"error_summary": "to/no_write_permission/.",
			"error": {
				".tag": "to",
				"to": {
					".tag": "no_write_permission"
				}
			}
		}
		""".utf8)

		let request = Move.Request(fromPath: "", toPath: "")
		#expect(throws: RelocationError.to(.noWritePermission)) {
			try request.response(from: data)
		}
	}

	@Test func decodingToInsufficientSpaceFailure() throws {
		let data = Data("""
		{
			"error_summary": "to/insufficient_space/.",
			"error": {
				".tag": "to",
				"to": {
					".tag": "insufficient_space"
				}
			}
		}
		""".utf8)

		let request = Move.Request(fromPath: "", toPath: "")
		#expect(throws: RelocationError.to(.insufficientSpace)) {
			try request.response(from: data)
		}
	}

	@Test func decodingToDisallowedNameFailure() throws {
		let data = Data("""
		{
			"error_summary": "to/disallowed_name/.",
			"error": {
				".tag": "to",
				"to": {
					".tag": "disallowed_name"
				}
			}
		}
		""".utf8)

		let request = Move.Request(fromPath: "", toPath: "")
		#expect(throws: RelocationError.to(.disallowedName)) {
			try request.response(from: data)
		}
	}

	@Test func decodingCantCopySharedFolderFailure() throws {
		let data = Data("""
		{
			"error_summary": "cant_copy_shared_folder/.",
			"error": {
				".tag": "cant_copy_shared_folder"
			}
		}
		""".utf8)

		let request = Move.Request(fromPath: "", toPath: "")
		#expect(throws: RelocationError.cantCopySharedFolder) {
			try request.response(from: data)
		}
	}

	@Test func decodingCantNestSharedFolderFailure() throws {
		let data = Data("""
		{
			"error_summary": "cant_nest_shared_folder/.",
			"error": {
				".tag": "cant_nest_shared_folder"
			}
		}
		""".utf8)

		let request = Move.Request(fromPath: "", toPath: "")
		#expect(throws: RelocationError.cantNestSharedFolder) {
			try request.response(from: data)
		}
	}

	@Test func decodingCantMoveFolderIntoItselfFailure() throws {
		let data = Data("""
		{
			"error_summary": "cant_move_folder_into_itself/.",
			"error": {
				".tag": "cant_move_folder_into_itself"
			}
		}
		""".utf8)

		let request = Move.Request(fromPath: "", toPath: "")
		#expect(throws: RelocationError.cantMoveFolderIntoItself) {
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

		let request = Move.Request(fromPath: "", toPath: "")
		#expect(throws: RelocationError.tooManyFiles) {
			try request.response(from: data)
		}
	}

	@Test func decodingDuplicatedOrNestedPathsFailure() throws {
		let data = Data("""
		{
			"error_summary": "duplicated_or_nested_paths/.",
			"error": {
				".tag": "duplicated_or_nested_paths"
			}
		}
		""".utf8)

		let request = Move.Request(fromPath: "", toPath: "")
		#expect(throws: RelocationError.duplicatedOrNestedPaths) {
			try request.response(from: data)
		}
	}

	@Test func decodingCantTransferOwnershipFailure() throws {
		let data = Data("""
		{
			"error_summary": "cant_transfer_ownership/.",
			"error": {
				".tag": "cant_transfer_ownership"
			}
		}
		""".utf8)

		let request = Move.Request(fromPath: "", toPath: "")
		#expect(throws: RelocationError.cantTransferOwnership) {
			try request.response(from: data)
		}
	}

	@Test func decodingInsufficientQuotaFailure() throws {
		let data = Data("""
		{
			"error_summary": "insufficient_quota/.",
			"error": {
				".tag": "insufficient_quota"
			}
		}
		""".utf8)

		let request = Move.Request(fromPath: "", toPath: "")
		#expect(throws: RelocationError.insufficientQuota) {
			try request.response(from: data)
		}
	}

	@Test func decodingInternalErrorFailure() throws {
		let data = Data("""
		{
			"error_summary": "internal_error/.",
			"error": {
				".tag": "internal_error"
			}
		}
		""".utf8)

		let request = Move.Request(fromPath: "", toPath: "")
		#expect(throws: RelocationError.internalError) {
			try request.response(from: data)
		}
	}

	@Test func decodingCantMoveSharedFolderFailure() throws {
		let data = Data("""
		{
			"error_summary": "cant_move_shared_folder/.",
			"error": {
				".tag": "cant_move_shared_folder"
			}
		}
		""".utf8)

		let request = Move.Request(fromPath: "", toPath: "")
		#expect(throws: RelocationError.cantMoveSharedFolder) {
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

		let request = Move.Request(fromPath: "", toPath: "")
		#expect(throws: AuthenticationError.invalidAccessToken) {
			try request.response(from: data)
		}
	}

}
