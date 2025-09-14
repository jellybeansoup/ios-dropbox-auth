import Foundation
import Testing

public protocol Stub {

	static func stub(for request: URLRequest) throws -> (Data, URLResponse)

	static func stub(for request: URLRequest) throws -> Data

	static func stub(for request: URLRequest) throws -> String

}

public extension Stub {

	static func stub(for request: URLRequest) throws -> (Data, URLResponse) {
		let data: Data = try stub(for: request)

		let url = try #require(request.url)
		let response = try #require(HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil))
		return (data, response)
	}

	static func stub(for request: URLRequest) throws -> Data {
		.init(try stub(for: request).utf8)
	}

}

public extension URLSession {

	private class StubProtocol<S: Stub>: URLProtocol {

		override class func canInit(with request: URLRequest) -> Bool {
			true
		}

		override class func canonicalRequest(for request: URLRequest) -> URLRequest {
			request
		}

		override func startLoading() {
			guard let client else { return }

			do {
				let (data, response) = try S.stub(for: request)
				client.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
				client.urlProtocol(self, didLoad: data)
				client.urlProtocolDidFinishLoading(self)
			} catch {
				client.urlProtocol(self, didFailWithError: error)
			}
		}

		override func stopLoading() {}

	}

	static func stubbed<S: Stub>(with stub: S.Type) -> URLSession {
		let config = URLSessionConfiguration.ephemeral
		config.protocolClasses = [StubProtocol<S>.self]
		return URLSession(configuration: config)
	}

}
