import Foundation
import DropboxAuth
import DropboxAuthMocks
@testable import DropboxFiles
import Testing

@Suite struct GetThumbnailTests {

	@Test func encodingDefaultsToPngAndW640H480() throws {
		let request = GetThumbnail.Request(path: "/hello/world.gif")

		let urlRequest = try request.urlRequest(signedWith: .mock())

		#expect(urlRequest.url?.absoluteString == "https://content.dropboxapi.com/2/files/get_thumbnail")
		#expect(urlRequest.httpMethod == "POST")
		#expect(urlRequest.value(forHTTPHeaderField: "Dropbox-API-Arg") == "{\"format\":\"png\",\"path\":\"/hello/world.gif\",\"size\":\"w640h480\"}")
		#expect(urlRequest.httpBody == nil)
		#expect(urlRequest.value(forHTTPHeaderField: "Content-Type") == nil)
	}

	@Test func encodingEscapesNonASCIIPathInHeader() throws {
		let request = GetThumbnail.Request(path: "/GIFs/reaction \u{1F602}.gif")

		let urlRequest = try request.urlRequest(signedWith: .mock())

		#expect(urlRequest.value(forHTTPHeaderField: "Dropbox-API-Arg") == "{\"format\":\"png\",\"path\":\"/GIFs/reaction \\ud83d\\ude02.gif\",\"size\":\"w640h480\"}")
	}

	@Test func decodingMetadataFromResultHeaderWithRawImageBodyContent() throws {
		let metadataJSON = """
		{"name":"world.gif","path_lower":"/hello/world.gif","path_display":"/hello/world.gif","id":"id:a4ayc_80_OEAAAAAAAAAXw","client_modified":"2015-05-12T15:50:38Z","server_modified":"2015-05-12T15:50:38Z","rev":"a1c10ce0dd78","size":7212,"content_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
		"""

		let body = Data("raw png bytes, not JSON".utf8)
		let httpResponse = try #require(HTTPURLResponse(
			url: URL(string: "https://content.dropboxapi.com/2/files/get_thumbnail")!,
			statusCode: 200,
			httpVersion: nil,
			headerFields: ["Dropbox-API-Result": metadataJSON]
		))

		let request = GetThumbnail.Request(path: "/hello/world.gif")
		let response = try request.response(from: body, httpResponse: httpResponse)

		#expect(response.metadata == FileMetadata(
			id: .init(rawValue: "id:a4ayc_80_OEAAAAAAAAAXw"),
			revision: .init(rawValue: "a1c10ce0dd78"),
			name: "world.gif",
			pathLower: "/hello/world.gif",
			pathDisplay: "/hello/world.gif",
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
			url: URL(string: "https://content.dropboxapi.com/2/files/get_thumbnail")!,
			statusCode: 409,
			httpVersion: nil,
			headerFields: nil
		))

		let request = GetThumbnail.Request(path: "/missing.gif")
		#expect(throws: GetThumbnail.Error.path(.notFound)) {
			try request.response(from: data, httpResponse: httpResponse)
		}
	}

	@Test func decodingUnsupportedExtensionFailure() throws {
		let data = Data("""
		{
			"error_summary": "unsupported_extension/",
			"error": {
				".tag": "unsupported_extension"
			}
		}
		""".utf8)

		let httpResponse = try #require(HTTPURLResponse(
			url: URL(string: "https://content.dropboxapi.com/2/files/get_thumbnail")!,
			statusCode: 409,
			httpVersion: nil,
			headerFields: nil
		))

		let request = GetThumbnail.Request(path: "/some.file")
		#expect(throws: GetThumbnail.Error.unsupportedExtension) {
			try request.response(from: data, httpResponse: httpResponse)
		}
	}

	@Test func decodingUnsupportedImageFailure() throws {
		let data = Data("""
		{
			"error_summary": "unsupported_image/",
			"error": {
				".tag": "unsupported_image"
			}
		}
		""".utf8)

		let httpResponse = try #require(HTTPURLResponse(
			url: URL(string: "https://content.dropboxapi.com/2/files/get_thumbnail")!,
			statusCode: 409,
			httpVersion: nil,
			headerFields: nil
		))

		let request = GetThumbnail.Request(path: "/some.file")
		#expect(throws: GetThumbnail.Error.unsupportedImage) {
			try request.response(from: data, httpResponse: httpResponse)
		}
	}

	@Test func decodingConversionErrorFailure() throws {
		let data = Data("""
		{
			"error_summary": "conversion_error/",
			"error": {
				".tag": "conversion_error"
			}
		}
		""".utf8)

		let httpResponse = try #require(HTTPURLResponse(
			url: URL(string: "https://content.dropboxapi.com/2/files/get_thumbnail")!,
			statusCode: 409,
			httpVersion: nil,
			headerFields: nil
		))

		let request = GetThumbnail.Request(path: "/some.file")
		#expect(throws: GetThumbnail.Error.conversionError) {
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
			url: URL(string: "https://content.dropboxapi.com/2/files/get_thumbnail")!,
			statusCode: 401,
			httpVersion: nil,
			headerFields: nil
		))

		let request = GetThumbnail.Request(path: "/some.file")
		#expect(throws: AuthenticationError.invalidAccessToken) {
			try request.response(from: data, httpResponse: httpResponse)
		}
	}

}
