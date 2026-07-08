import Foundation
@testable import DropboxAuth
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
		#expect(first.isReset)
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
		// A snapshot produced via `list_folder/continue` (delta), not a full re-list.
		#expect(first.isReset == false)
	}

	@Test func monitorPropagatesResetFromLongpoll() async throws {
		let transport = MockTransport(
			responses: [
				#"{"error": {".tag": "reset"}, "error_summary": "reset/"}"#,
				#"{"cursor": "cursor_reset", "entries": [{".tag": "folder", "id": "id:1234", "name": "example", "path_display": "/example", "path_lower": "/example"}], "has_more": false}"#,
			]
		)

		let stream = transport.monitor(path: "/example", isRecursive: true, from: "cursor_one")

		var iterator = stream.makeAsyncIterator()
		let first = try #require(try await iterator.next())
		#expect(first.metadata.count == 1)
		#expect(first.cursor == "cursor_reset")
		#expect(first.isReset)
	}

	@Test func monitorPropagatesResetFromContinue() async throws {
		let transport = MockTransport(
			responses: [
				#"{"changes": true, "backoff": 1}"#,
				#"{"error": {".tag": "reset"}, "error_summary": "reset/"}"#,
				#"{"cursor": "cursor_reset", "entries": [{".tag": "folder", "id": "id:1234", "name": "example", "path_display": "/example", "path_lower": "/example"}], "has_more": false}"#,
			]
		)

		let stream = transport.monitor(path: "/example", isRecursive: true, from: "cursor_one")

		var iterator = stream.makeAsyncIterator()
		let first = try #require(try await iterator.next())
		#expect(first.metadata.count == 1)
		#expect(first.cursor == "cursor_reset")
		#expect(first.isReset)
	}

	@Test func cancellationTerminatesPromptlyWithoutWaitingForBackoff() async throws {
		let transport = MockTransport(
			responses: [
				#"{"changes": true, "backoff": 3600}"#,
				#"{"cursor": "cursor_two", "entries": [], "has_more": false}"#,
			]
		)

		let stream = transport.monitor(path: "/example", isRecursive: true, from: "cursor_one")

		let (firstSnapshotConsumed, firstSnapshotContinuation) = AsyncStream<Void>.makeStream()

		let task = Task<Snapshot?, any Error> {
			var iterator = stream.makeAsyncIterator()
			_ = try await iterator.next()
			firstSnapshotContinuation.finish()
			return try await iterator.next()
		}

		// Deterministic sync point: once the first snapshot has been consumed, the monitor task has
		// already yielded it, so cancellation now provably lands during the (very long) backoff sleep
		// rather than before the first snapshot was ever produced.
		for await _ in firstSnapshotConsumed {}

		let clock = ContinuousClock()
		let start = clock.now

		task.cancel()

		_ = try? await task.value

		#expect(clock.now - start < .seconds(2))
	}

	@Test func cancellationTearsDownInFlightLongpoll() async throws {
		let transport = SuspendingTransport(
			responses: [
				#"{"cursor": "cursor_one", "entries": [], "has_more": false}"#,
			]
		)

		let stream = transport.monitor(path: "/example", isRecursive: true, from: nil)

		let task = Task<Void, any Error> {
			for try await _ in stream {}
		}

		// Deterministic sync point: the transport signals once the longpoll request is genuinely
		// in flight — suspended awaiting a continuation that will never resume with a response.
		var suspensions = transport.suspendedRequests.makeAsyncIterator()
		_ = await suspensions.next()

		task.cancel()

		// The in-flight request must observe cancellation (i.e. the stream's termination handler
		// cancels the monitor task, which cooperatively cancels the suspended longpoll call).
		var cancellations = transport.observedCancellations.makeAsyncIterator()
		_ = await cancellations.next()

		// The stream must finish cleanly rather than surface a `CancellationError`.
		await #expect(throws: Never.self) {
			try await task.value
		}
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

/// A `Transport` stub that serves canned responses until they run out, then suspends indefinitely —
/// simulating an in-flight longpoll request that never returns — resuming (by throwing
/// `CancellationError`) only when the calling task is cancelled.
///
/// `suspendedRequests` signals when a request has genuinely suspended, and `observedCancellations`
/// signals when a suspended request observes cooperative cancellation, giving tests deterministic
/// sync points without wall-clock timing.
private final class SuspendingTransport: Transport, @unchecked Sendable {

	/// Lock-protected mutable state, kept behind synchronous methods so it can be safely accessed from
	/// async contexts, continuation bodies, and cancellation handlers alike.
	private final class State: @unchecked Sendable {

		private let lock = NSLock()
		private var responses: [Data]
		private var pending: CheckedContinuation<Void, any Error>?
		private var isCancelled = false

		init(responses: [Data]) {
			self.responses = responses
		}

		func nextResponse() -> Data? {
			lock.lock()
			defer { lock.unlock() }
			return responses.isEmpty ? nil : responses.removeFirst()
		}

		/// Stores the continuation for later cancellation, returning `true`, or — if cancellation has
		/// already been observed — resumes it immediately by throwing and returns `false`.
		func suspend(_ continuation: CheckedContinuation<Void, any Error>) -> Bool {
			lock.lock()
			if isCancelled {
				lock.unlock()
				continuation.resume(throwing: CancellationError())
				return false
			}
			pending = continuation
			lock.unlock()
			return true
		}

		/// Marks the state as cancelled, returning any suspended continuation for the caller to resume.
		func cancel() -> CheckedContinuation<Void, any Error>? {
			lock.lock()
			defer { lock.unlock() }
			isCancelled = true
			let continuation = pending
			pending = nil
			return continuation
		}

	}

	let suspendedRequests: AsyncStream<Void>
	let observedCancellations: AsyncStream<Void>

	private let state: State

	private let suspendedRequestsContinuation: AsyncStream<Void>.Continuation
	private let observedCancellationsContinuation: AsyncStream<Void>.Continuation

	init(responses: [String]) {
		state = State(responses: responses.map { Data($0.utf8) })
		(suspendedRequests, suspendedRequestsContinuation) = AsyncStream.makeStream()
		(observedCancellations, observedCancellationsContinuation) = AsyncStream.makeStream()

		super.init(
			authManager: .init(
				key: "mock",
				redirectURI: nil,
				store: .mock(
					copyMatching: { _, _ in noErr },
					update: { _, _ in noErr },
					add: { _, _ in noErr },
					delete: { _ in noErr }
				)
			),
			accountID: "account_id",
			urlSession: .init(configuration: .ephemeral)
		)
	}

	override func response<Request: API.Request>(
		for request: Request,
		needsAuthentication: Bool = true
	) async throws -> Request.Response {
		if let data = state.nextResponse() {
			return try request.response(from: data)
		}

		try await withTaskCancellationHandler {
			try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
				if state.suspend(continuation) {
					suspendedRequestsContinuation.yield()
				}
			}
		} onCancel: {
			let continuation = state.cancel()

			observedCancellationsContinuation.yield()
			continuation?.resume(throwing: CancellationError())
		}

		// Unreachable: the suspended continuation only ever resumes by throwing.
		throw CancellationError()
	}

}
