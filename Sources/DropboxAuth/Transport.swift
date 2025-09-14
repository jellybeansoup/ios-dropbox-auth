import Foundation

/// Actor responsible for authenticated network transport.
///
/// Provides helpers to execute API requests and a retry mechanism that
/// refreshes an expired access token and retries the operation once.
public class Transport: @unchecked Sendable {

	/// Identifier for the account represented by the `Transport`.
	public let accountID: String

	/// Authentication manager used for token lifecycle.
	public let authManager: AuthManager

	/// Session used for network requests.
	public let urlSession: URLSession

	/// Initializes with an explicit token.
	/// - Parameters:
	///   - authManager: Authentication manager.
	///   - token: Initial access token.
	///   - urlSession: Session for requests (default: `.shared`).
	public init(
		authManager: AuthManager,
		token: AccessToken,
		urlSession: URLSession = .shared
	) {
		self.accountID = token.accountID
		self.authManager = authManager
		self.urlSession = urlSession
	}

	/// Initializes by loading a token from storage for the given account.
	/// - Parameters:
	///   - authManager: Authentication manager.
	///   - accountID: Account identifier whose token will be loaded.
	///   - urlSession: Session for requests (default: `.shared`).
	public init(
		authManager: AuthManager,
		accountID: String,
		urlSession: URLSession = .shared
	) {
		self.accountID = accountID
		self.authManager = authManager
		self.urlSession = urlSession
	}

	/// Executes an API request using the actor’s current token.
	/// - Parameter request: The API request to perform.
	/// - Returns: The decoded response for the request.
	/// - Throws: Network, decoding, or authentication errors.
	public func response<Request: API.Request>(
		for request: Request,
		needsAuthentication: Bool = true
	) async throws -> Request.Response {
		try await withRetry {
			let urlRequest = if needsAuthentication {
				try request.urlRequest(signedWith: authManager.store.accessToken(for: accountID))
			} else {
				try request.urlRequest
			}

			let (data, _) = try await urlSession.data(for: urlRequest)
			return try request.response(from: data)
		}
	}

	/// Runs an operation and retries once after refreshing the token if it has expired.
	///
	/// If the operation throws `AuthenticationError.expiredAccessToken`, the token is refreshed
	/// and the operation is attempted again. Cancellation is checked before and after refresh.
	/// - Parameter handler: The operation to perform.
	/// - Returns: The operation’s result.
	/// - Throws: Errors from the operation or token refresh.
	public final func withRetry<T: Sendable>(handler: () async throws -> T) async rethrows -> T {
		do {
			return try await handler()
		}
		catch AuthenticationError.expiredAccessToken {
			try Task.checkCancellation()

			_ = try await authManager.refresh(
				authManager.store.accessToken(for: accountID),
				force: true,
				urlSession: urlSession
			)

			try Task.checkCancellation()

			return try await handler()
		}
		catch {
			throw error
		}
	}

}
