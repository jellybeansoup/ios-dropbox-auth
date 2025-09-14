//
// Copyright © 2025 Daniel Farrelly
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
// *	Redistributions of source code must retain the above copyright notice, this list
//		of conditions and the following disclaimer.
// *	Redistributions in binary form must reproduce the above copyright notice, this
//		list of conditions and the following disclaimer in the documentation and/or
//		other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
// IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
// OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

@testable import DropboxAuth
import DropboxAuthMocks
import Foundation
import Testing

@Suite struct AccessTokenStoreTests {

	// MARK: AccessTokenStore.isEmpty

	@Test func isEmpty() async throws {
		let store = AccessTokenStore.mock(
			copyMatching: { query, result in
				#expect(query == [
					kSecClass: kSecClassGenericPassword,
					kSecMatchLimit: kSecMatchLimitOne,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				#expect(result?.pointee == nil)

				result?.pointee = CFArray.withTokens("token")
				return noErr
			}
		)

		#expect(store.isEmpty == false)
	}

	@Test func isEmptyWhenEmpty() async throws {
		let store = AccessTokenStore.mock(
			copyMatching: { query, result in
				#expect(query == [
					kSecClass: kSecClassGenericPassword,
					kSecMatchLimit: kSecMatchLimitOne,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				#expect(result?.pointee == nil)

				result?.pointee = CFArray.empty
				return noErr
			}
		)

		#expect(store.isEmpty == true)
	}

	@Test func isEmptyWhenQueryThrowsError() async throws {
		let store = AccessTokenStore.mock(
			copyMatching: { query, result in
				#expect(query == [
					kSecClass: kSecClassGenericPassword,
					kSecMatchLimit: kSecMatchLimitOne,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				#expect(result?.pointee == nil)

				return 12345
			}
		)

		#expect(store.isEmpty == true)
	}

	// MARK: AccessTokenStore.accessTokens

	@Test func accessTokens() async throws {
		let appKey = "app_key"
		let token = "token"
		let store = AccessTokenStore.mock(
			appKey: appKey,
			copyMatching: { query, result in
				if let returnData = (query as NSDictionary)[kSecReturnData], (returnData as! CFBoolean) == kCFBooleanTrue  {
					#expect(query == [
						kSecClass: kSecClassGenericPassword,
						kSecAttrAccount: token,
						kSecReturnData: kCFBooleanTrue!,
						kSecMatchLimit: kSecMatchLimitOne,
						kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
					] as CFDictionary)
					#expect(result?.pointee == nil)

					result?.pointee = CFData.mock(accessToken: token, appKey: appKey)
					return noErr
				}
				else {
					#expect(query == [
						kSecClass: kSecClassGenericPassword,
						kSecReturnAttributes: kCFBooleanTrue!,
						kSecMatchLimit: kSecMatchLimitAll,
						kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
					] as CFDictionary)
					#expect(result?.pointee == nil)

					result?.pointee = CFArray.withTokens(token)
					return noErr
				}
			}
		)

		#expect(store.accessTokens == [.mock(accessToken: token, appKey: appKey)])
	}

	@Test func accessTokensWhenEmpty() async throws {
		let store = AccessTokenStore.mock(
			copyMatching: { query, result in
				#expect(query == [
					kSecClass: kSecClassGenericPassword,
					kSecReturnAttributes: kCFBooleanTrue!,
					kSecMatchLimit: kSecMatchLimitAll,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				#expect(result?.pointee == nil)

				result?.pointee = CFArray.empty
				return noErr
			}
		)

		#expect(store.accessTokens == [])
	}

	@Test func accessTokensWhenAttributesQueryThrowsError() async throws {
		let store = AccessTokenStore.mock(
			copyMatching: { query, result in
				#expect(query == [
					kSecClass: kSecClassGenericPassword,
					kSecReturnAttributes: kCFBooleanTrue!,
					kSecMatchLimit: kSecMatchLimitAll,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				#expect(result?.pointee == nil)

				return 12345
			}
		)

		#expect(store.accessTokens == [])
	}

	@Test func accessTokensWhenDataQueryThrowsError() async throws {
		let appKey = "app_key"
		let token = "token"
		let store = AccessTokenStore.mock(
			appKey: appKey,
			copyMatching: { query, result in
				if let returnData = (query as NSDictionary)[kSecReturnData], (returnData as! CFBoolean) == kCFBooleanTrue  {
					#expect(query == [
						kSecClass: kSecClassGenericPassword,
						kSecAttrAccount: token,
						kSecReturnData: kCFBooleanTrue!,
						kSecMatchLimit: kSecMatchLimitOne,
						kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
					] as CFDictionary)
					#expect(result?.pointee == nil)

					return 12345
				}
				else {
					#expect(query == [
						kSecClass: kSecClassGenericPassword,
						kSecReturnAttributes: kCFBooleanTrue!,
						kSecMatchLimit: kSecMatchLimitAll,
						kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
					] as CFDictionary)
					#expect(result?.pointee == nil)

					result?.pointee = CFArray.withTokens(token)
					return noErr
				}
			}
		)

		#expect(store.accessTokens == [])
	}

	// MARK: AccessTokenStore.first

	@Test func first() async throws {
		let appKey = "app_key"
		let token = "token"
		let store = AccessTokenStore.mock(
			appKey: appKey,
			copyMatching: { query, result in
				if let returnData = (query as NSDictionary)[kSecReturnData], (returnData as! CFBoolean) == kCFBooleanTrue  {
					#expect(query == [
						kSecClass: kSecClassGenericPassword,
						kSecAttrAccount: token,
						kSecReturnData: kCFBooleanTrue!,
						kSecMatchLimit: kSecMatchLimitOne,
						kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
					] as CFDictionary)
					#expect(result?.pointee == nil)

					result?.pointee = CFData.mock(accessToken: token, appKey: appKey)
					return noErr
				}
				else {
					#expect(query == [
						kSecClass: kSecClassGenericPassword,
						kSecReturnAttributes: kCFBooleanTrue!,
						kSecMatchLimit: kSecMatchLimitOne,
						kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
					] as CFDictionary)
					#expect(result?.pointee == nil)

					result?.pointee = CFDictionary.withToken(token)
					return noErr
				}
			}
		)

		#expect(store.first == .mock(accessToken: token, appKey: appKey))
	}

	@Test func firstWhenEmpty() async throws {
		let store = AccessTokenStore.mock(
			copyMatching: { query, result in
				#expect(query == [
					kSecClass: kSecClassGenericPassword,
					kSecReturnAttributes: kCFBooleanTrue!,
					kSecMatchLimit: kSecMatchLimitOne,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				#expect(result?.pointee == nil)

				result?.pointee = CFArray.empty
				return noErr
			}
		)

		#expect(store.first == nil)
	}

	@Test func firstWhenAttributesQueryThrowsError() async throws {
		let store = AccessTokenStore.mock(
			copyMatching: { query, result in
				#expect(query == [
					kSecClass: kSecClassGenericPassword,
					kSecReturnAttributes: kCFBooleanTrue!,
					kSecMatchLimit: kSecMatchLimitOne,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				#expect(result?.pointee == nil)

				return 12345
			}
		)

		#expect(store.first == nil)
	}

	@Test func firstWhenDataQueryThrowsError() async throws {
		let appKey = "app_key"
		let token = "token"
		let store = AccessTokenStore.mock(
			appKey: appKey,
			copyMatching: { query, result in
				if let returnData = (query as NSDictionary)[kSecReturnData], (returnData as! CFBoolean) == kCFBooleanTrue  {
					#expect(query == [
						kSecClass: kSecClassGenericPassword,
						kSecAttrAccount: token,
						kSecReturnData: kCFBooleanTrue!,
						kSecMatchLimit: kSecMatchLimitOne,
						kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
					] as CFDictionary)
					#expect(result?.pointee == nil)

					return 12345
				}
				else {
					#expect(query == [
						kSecClass: kSecClassGenericPassword,
						kSecReturnAttributes: kCFBooleanTrue!,
						kSecMatchLimit: kSecMatchLimitOne,
						kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
					] as CFDictionary)
					#expect(result?.pointee == nil)

					result?.pointee = CFDictionary.withToken(token)
					return noErr
				}
			}
		)

		#expect(store.first == nil)
	}

	// MARK: AccessTokenStore.accessToken(for:)

	@Test func accessTokenForAccountID() async throws {
		let appKey = "app_key"
		let token = "token"
		let store = AccessTokenStore.mock(
			appKey: appKey,
			copyMatching: { query, result in
				#expect(query == [
					kSecClass: kSecClassGenericPassword,
					kSecAttrAccount: token,
					kSecReturnData: kCFBooleanTrue!,
					kSecMatchLimit: kSecMatchLimitOne,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				#expect(result?.pointee == nil)

				result?.pointee = CFData.mock(accessToken: token, appKey: appKey)
				return noErr
			}
		)

		#expect(try store.accessToken(for: token) == .mock(accessToken: token, appKey: appKey))
	}

	@Test func accessTokenForAccountIDWhenEmpty() async throws {
		let appKey = "app_key"
		let token = "token"
		let store = AccessTokenStore.mock(
			appKey: appKey,
			copyMatching: { query, result in
				#expect(query == [
					kSecClass: kSecClassGenericPassword,
					kSecAttrAccount: token,
					kSecReturnData: kCFBooleanTrue!,
					kSecMatchLimit: kSecMatchLimitOne,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				#expect(result?.pointee == nil)

				result?.pointee = nil
				return noErr
			}
		)

		do {
			_ = try store.accessToken(for: token)
			Issue.record("Expected to throw AccessTokenStore.OSStatusError with status -25300")
		} catch let error as AccessTokenStore.OSStatusError {
			#expect(error.status == -25300)
		}
	}

	@Test func accessTokenForAccountIDWhenQueryThrowsError() async throws {
		let appKey = "app_key"
		let token = "token"
		let store = AccessTokenStore.mock(
			appKey: appKey,
			copyMatching: { query, result in
				#expect(query == [
					kSecClass: kSecClassGenericPassword,
					kSecAttrAccount: token,
					kSecReturnData: kCFBooleanTrue!,
					kSecMatchLimit: kSecMatchLimitOne,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				#expect(result?.pointee == nil)

				return 12345
			}
		)

		do {
			_ = try store.accessToken(for: token)
			Issue.record("Expected to throw AccessTokenStore.OSStatusError with status 12345")
		} catch let error as AccessTokenStore.OSStatusError {
			#expect(error.status == 12345)
		}
	}

	// MARK: AccessTokenStore.save(_:)

	@Test func saveAccessTokenWhenTokenDoesntExist() async throws {
		let accountID = "account_id"
		let store = AccessTokenStore.mock(
			copyMatching: { query, result in
				#expect(query == [
					kSecClass: kSecClassGenericPassword,
					kSecAttrAccount: accountID,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				#expect(result?.pointee == nil)

				return -25300
			},
			add: { attributes, result in
				#expect(attributes == [
					kSecClass: kSecClassGenericPassword,
					kSecAttrAccount: accountID,
					kSecValueData: CFData.mock(accountID: accountID),
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				#expect(result?.pointee == nil)

				return noErr
			}
		)

		try store.save(.mock(accountID: accountID))
	}

	@Test func saveAccessTokenWhenTokenExists() async throws {
		let accountID = "account_id"
		let store = AccessTokenStore.mock(
			copyMatching: { query, result in
				#expect(query == [
					kSecClass: kSecClassGenericPassword,
					kSecAttrAccount: accountID,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				#expect(result?.pointee == nil)

				return noErr
			},
			update: { query, attributesToUpdate in
				#expect(query == [
					kSecClass: kSecClassGenericPassword,
					kSecAttrAccount: accountID,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				#expect(attributesToUpdate == [
					kSecValueData: CFData.mock(accountID: accountID)
				] as CFDictionary)

				return noErr
			}
		)

		try store.save(.mock(accountID: accountID))
	}

	@Test func saveAccessTokenWhenAttributesQueryThrowsError() async throws {
		let accountID = "account_id"
		let store = AccessTokenStore.mock(
			copyMatching: { query, result in
				#expect(query == [
					kSecClass: kSecClassGenericPassword,
					kSecAttrAccount: accountID,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				#expect(result?.pointee == nil)

				return 12345
			}
		)

		do {
			try store.save(.mock(accountID: accountID))
			Issue.record("Expected to throw AccessTokenStore.OSStatusError with status 12345")
		} catch let error as AccessTokenStore.OSStatusError {
			#expect(error.status == 12345)
		}
	}

	@Test func saveAccessTokenWhenTokenDoesntExistAndAddThrowsError() async throws {
		let accountID = "account_id"
		let store = AccessTokenStore.mock(
			copyMatching: { query, result in
				#expect(query == [
					kSecClass: kSecClassGenericPassword,
					kSecAttrAccount: accountID,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				#expect(result?.pointee == nil)

				return -25300
			},
			add: { attributes, result in
				#expect(attributes == [
					kSecClass: kSecClassGenericPassword,
					kSecAttrAccount: accountID,
					kSecValueData: CFData.mock(accountID: accountID),
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				#expect(result?.pointee == nil)

				return 12345
			}
		)

		do {
			try store.save(.mock(accountID: accountID))
			Issue.record("Expected to throw AccessTokenStore.OSStatusError with status 12345")
		} catch let error as AccessTokenStore.OSStatusError {
			#expect(error.status == 12345)
		}
	}

	@Test func saveAccessTokenWhenTokenExistsAndUpdateThrowsError() async throws {
		let accountID = "account_id"
		let store = AccessTokenStore.mock(
			copyMatching: { query, result in
				#expect(query == [
					kSecClass: kSecClassGenericPassword,
					kSecAttrAccount: accountID,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				#expect(result?.pointee == nil)

				return noErr
			},
			update: { query, attributesToUpdate in
				#expect(query == [
					kSecClass: kSecClassGenericPassword,
					kSecAttrAccount: accountID,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				#expect(attributesToUpdate == [
					kSecValueData: CFData.mock(accountID: accountID)
				] as CFDictionary)

				return 12345
			}
		)

		do {
			try store.save(.mock(accountID: accountID))
			Issue.record("Expected to throw AccessTokenStore.OSStatusError with status 12345")
		} catch let error as AccessTokenStore.OSStatusError {
			#expect(error.status == 12345)
		}
	}

	// MARK: AccessTokenStore.remove(_:)

	@Test func removeAccessToken() async throws {
		let accountID = "account_id"
		let store = AccessTokenStore.mock(
			delete: { query in
				#expect(query == [
					kSecClass: kSecClassGenericPassword,
					kSecAttrAccount: accountID,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)

				return noErr
			}
		)

		try store.remove(.mock(accountID: accountID))
	}

	@Test func removeAccessTokenWhenQueryThrowsError() async throws {
		let accountID = "account_id"
		let store = AccessTokenStore.mock(
			delete: { query in
				#expect(query == [
					kSecClass: kSecClassGenericPassword,
					kSecAttrAccount: accountID,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)

				return 12345
			}
		)

		do {
			try store.remove(.mock(accountID: accountID))
			Issue.record("Expected to throw AccessTokenStore.OSStatusError with status 12345")
		} catch let error as AccessTokenStore.OSStatusError {
			#expect(error.status == 12345)
		}
	}

	// MARK: AccessTokenStore.removeAll()

	@Test func removeAll() async throws {
		let store = AccessTokenStore.mock(
			delete: { query in
				#expect(query == [
					kSecClass: kSecClassGenericPassword,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)

				return noErr
			}
		)

		try store.removeAll()
	}

	@Test func removeAllWhenQueryThrowsError() async throws {
		let store = AccessTokenStore.mock(
			delete: { query in
				#expect(query == [
					kSecClass: kSecClassGenericPassword,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)

				return 12345
			}
		)

		do {
			try store.removeAll()
			Issue.record("Expected to throw AccessTokenStore.OSStatusError with status 12345")
		} catch let error as AccessTokenStore.OSStatusError {
			#expect(error.status == 12345)
		}
	}

}

private extension CFData {

	static func mock(
		accessToken: String = "access_token",
		expiryDate: Date = .init(timeIntervalSince1970: 1577869200), // 2020-01-01 09:00
		scope: String? = nil,
		accountID: String = "account_id",
		teamID: String? = nil,
		refreshToken: String = "refresh_token",
		appKey: String = "app_key"
	) -> CFData {
		do {
			return try PropertyListEncoder().encode(AccessToken.mock(
				accessToken: accessToken,
				expiryDate: expiryDate,
				scope: scope,
				accountID: accountID,
				teamID: teamID,
				refreshToken: refreshToken,
				appKey: appKey
			)) as CFData
		} catch {
			Issue.record(error)
			return Data() as CFData
		}
	}

}

private extension CFArray {

	static var empty: CFArray {
		[] as CFArray
	}

	static func withTokens(_ tokens: String...) -> CFArray {
		tokens.map { CFDictionary.withToken($0) } as CFArray
	}

}

private extension CFDictionary {

	static var empty: CFDictionary {
		[:] as CFDictionary
	}

	static func withToken(_ token: String) -> CFDictionary {
		[kSecAttrAccount: token] as CFDictionary
	}

}
