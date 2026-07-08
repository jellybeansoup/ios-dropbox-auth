import Foundation

/// Some APIs (e.g. `AuthManager`'s completion-handler and browser-redirect `handle(_:)` methods)
/// have no `URLSession` injection point and always go through `.shared`. To exercise them
/// deterministically — without touching the real network — this registers a `URLProtocol`
/// globally for the duration of a test, which `URLSession.shared` consults.
///
/// Callers are responsible for not running two `withStub` blocks concurrently (e.g. by giving the
/// containing `@Suite` the `.serialized` trait), since the stubbed responder is process-global.
public final class GlobalURLProtocolStub: URLProtocol, @unchecked Sendable {

	public nonisolated(unsafe) static var responder: ((URLRequest) throws -> String)?

	override public class func canInit(with request: URLRequest) -> Bool {
		true
	}

	override public class func canonicalRequest(for request: URLRequest) -> URLRequest {
		request
	}

	override public func startLoading() {
		guard let client else { return }

		do {
			guard let responder = Self.responder else {
				throw CancellationError()
			}
			let body = try responder(request)
			guard
				let url = request.url,
				let response = HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil)
			else {
				throw URLError(.badURL)
			}
			client.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
			client.urlProtocol(self, didLoad: Data(body.utf8))
			client.urlProtocolDidFinishLoading(self)
		}
		catch {
			client.urlProtocol(self, didFailWithError: error)
		}
	}

	override public func stopLoading() {}

	/// Serializes access to the process-global responder/registration below, so that concurrently
	/// running tests (in different suites, which Swift Testing may parallelize even when each
	/// suite is individually marked `.serialized`) don't race and serve each other's stubbed
	/// responses.
	private actor Lock {
		private var locked = false
		private var waiters: [CheckedContinuation<Void, Never>] = []

		func acquire() async {
			if !locked {
				locked = true
				return
			}
			await withCheckedContinuation { continuation in
				waiters.append(continuation)
			}
		}

		func release() {
			if waiters.isEmpty {
				locked = false
			}
			else {
				waiters.removeFirst().resume()
			}
		}
	}

	private static let lock = Lock()

	public static func withStub<T>(
		_ responder: @escaping (URLRequest) throws -> String,
		perform: () async throws -> T
	) async throws -> T {
		await lock.acquire()
		Self.responder = responder
		URLProtocol.registerClass(Self.self)

		do {
			let result = try await perform()
			URLProtocol.unregisterClass(Self.self)
			Self.responder = nil
			await lock.release()
			return result
		}
		catch {
			URLProtocol.unregisterClass(Self.self)
			Self.responder = nil
			await lock.release()
			throw error
		}
	}

}
