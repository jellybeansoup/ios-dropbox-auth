@testable import DropboxAuth
import Foundation

public final class MockTransport: Transport, @unchecked Sendable {

	private actor ResponseContainer {

		var responses: IndexingIterator<[Data]>

		init(responses: IndexingIterator<[Data]>) {
			self.responses = responses
		}

		func next() -> Data? {
			responses.next()
		}

	}

	private let container: ResponseContainer

	public init(
		accountID: String = "account_id",
		responses: [Data]
	) {
		container = .init(responses: responses.makeIterator())

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
			accountID: accountID,
			urlSession: .init(configuration: .ephemeral)
		)
	}

	public convenience init(
		accountID: String = "account_id",
		responses: [String]
	) {
		self.init(accountID: accountID, responses: responses.map { Data($0.utf8) })
	}

	struct MissingResponseError: Error {}

	public override func response<Request: API.Request>(
		for request: Request,
		needsAuthentication: Bool = true
	) async throws -> Request.Response {
		guard let data = await container.next() else {
			throw MissingResponseError()
		}

		return try request.response(from: data)
	}

}
