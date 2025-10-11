import Foundation

public enum GetCurrentAccount {

	public struct Request: API.Request, Encodable {

		public typealias Response = GetCurrentAccount.Response
		public typealias Error = GetCurrentAccount.Error

		public static let endpoint: Endpoint = "/users/get_current_account"
		public static let method = Method.post

		init() {}

		public func configure(_ urlRequest: inout URLRequest) throws {
			urlRequest.setValue(nil, forHTTPHeaderField: "Content-Type")
			urlRequest.httpBody = nil
		}

	}

	public struct Response: API.Response, Decodable {

		public typealias Request = GetCurrentAccount.Request

		public let accountID: String
		public let name: Name
		public let email: String
		public let isEmailVerified: Bool
		public let isDisabled: Bool
		public let locale: String
		public let referralLink: URL
		public let isPaired: Bool
		public let profilePhotoUrl: URL?
		public let country: String?

		public struct Name: Decodable, Sendable {
			public let givenName: String
			public let surname: String
			public let familiarName: String
			public let displayName: String
			public let abbreviatedName: String

			private enum CodingKeys: String, CodingKey {
				case givenName = "given_name"
				case surname
				case familiarName = "familiar_name"
				case displayName = "display_name"
				case abbreviatedName = "abbreviated_name"
			}
		}

		private enum CodingKeys: String, CodingKey {
			case accountID = "account_id"
			case name
			case email
			case isEmailVerified = "email_verified"
			case isDisabled = "disabled"
			case locale
			case referralLink = "referral_link"
			case isPaired = "is_paired"
			case profilePhotoUrl = "profile_photo_url"
			case country
		}

	}

	public enum Error: API.Error {

		typealias Request = GetCurrentAccount.Request

		public init(summary: Summary) throws {
			throw summary
		}

	}

}
