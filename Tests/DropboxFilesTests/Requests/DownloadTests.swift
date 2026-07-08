import Foundation
import DropboxAuth
import DropboxAuthMocks
@testable import DropboxFiles
import Testing

@Suite struct DownloadTests {

	@Test func encoding() throws {
		let request = Download.Request(path: "/hello/world.gif")

		let urlRequest = try request.urlRequest(signedWith: .mock())

		#expect(urlRequest.url?.absoluteString == "https://content.dropboxapi.com/2/files/download")
		#expect(urlRequest.httpMethod == "POST")
		#expect(urlRequest.value(forHTTPHeaderField: "Dropbox-API-Arg") == "{\"path\":\"/hello/world.gif\"}")
		#expect(urlRequest.httpBody == nil)
		#expect(urlRequest.value(forHTTPHeaderField: "Content-Type") == nil)
	}

	@Test func encodingEscapesNonASCIIPathInHeader() throws {
		let request = Download.Request(path: "/GIFs/reaction \u{1F602}.gif")

		let urlRequest = try request.urlRequest(signedWith: .mock())

		#expect(urlRequest.value(forHTTPHeaderField: "Dropbox-API-Arg") == "{\"path\":\"/GIFs/reaction \\ud83d\\ude02.gif\"}")
	}

	@Test func decodingMetadataFromResultHeaderWithRawBodyContent() throws {
		let metadataJSON = """
		{"name":"Prime_Numbers.txt","path_lower":"/homework/math/prime_numbers.txt","path_display":"/Homework/math/Prime_Numbers.txt","id":"id:a4ayc_80_OEAAAAAAAAAXw","client_modified":"2015-05-12T15:50:38Z","server_modified":"2015-05-12T15:50:38Z","rev":"a1c10ce0dd78","size":7212,"content_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
		"""

		let body = Data("raw file bytes, not JSON".utf8)
		let httpResponse = try #require(HTTPURLResponse(
			url: URL(string: "https://content.dropboxapi.com/2/files/download")!,
			statusCode: 200,
			httpVersion: nil,
			headerFields: ["Dropbox-API-Result": metadataJSON]
		))

		let request = Download.Request(path: "/homework/math/prime_numbers.txt")
		let response = try request.response(from: body, httpResponse: httpResponse)

		#expect(response.metadata == FileMetadata(
			id: .init(rawValue: "id:a4ayc_80_OEAAAAAAAAAXw"),
			revision: .init(rawValue: "a1c10ce0dd78"),
			name: "Prime_Numbers.txt",
			pathLower: "/homework/math/prime_numbers.txt",
			pathDisplay: "/Homework/math/Prime_Numbers.txt",
			numberOfBytes: 7212,
			dateModifiedOnClient: Date(timeIntervalSince1970: 1431445838),
			dateModifiedOnServer: Date(timeIntervalSince1970: 1431445838),
			contentHash: .init(rawValue: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
		))
	}

	// MARK: Error-summary parity with the legacy `DropboxError.from(errorSummary:)`

	@Test func decodingPathNotFoundFailureFromBodyWhenResultHeaderIsAbsent() throws {
		let data = Data("""
		{
			"error_summary": "path/not_found/",
			"error": {
				".tag": "path",
				"path": {
					".tag": "not_found"
				}
			}
		}
		""".utf8)

		let httpResponse = try #require(HTTPURLResponse(
			url: URL(string: "https://content.dropboxapi.com/2/files/download")!,
			statusCode: 409,
			httpVersion: nil,
			headerFields: nil
		))

		let request = Download.Request(path: "/missing.gif")
		#expect(throws: Download.Error.path(.notFound)) {
			try request.response(from: data, httpResponse: httpResponse)
		}
	}

	@Test func decodingUnsupportedFileFailure() throws {
		let data = Data("""
		{
			"error_summary": "unsupported_file/",
			"error": {
				".tag": "unsupported_file"
			}
		}
		""".utf8)

		let httpResponse = try #require(HTTPURLResponse(
			url: URL(string: "https://content.dropboxapi.com/2/files/download")!,
			statusCode: 409,
			httpVersion: nil,
			headerFields: nil
		))

		let request = Download.Request(path: "/some.file")
		#expect(throws: Download.Error.unsupportedFile) {
			try request.response(from: data, httpResponse: httpResponse)
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

		let httpResponse = try #require(HTTPURLResponse(
			url: URL(string: "https://content.dropboxapi.com/2/files/download")!,
			statusCode: 401,
			httpVersion: nil,
			headerFields: nil
		))

		let request = Download.Request(path: "/some.file")
		#expect(throws: AuthenticationError.invalidAccessToken) {
			try request.response(from: data, httpResponse: httpResponse)
		}
	}

}
