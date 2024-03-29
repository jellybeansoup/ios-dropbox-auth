//
// Copyright © 2024 Daniel Farrelly
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
import XCTest

final class AccessTokenStoreTests: XCTestCase {

	// MARK: AccessTokenStore.isEmpty

	func testIsEmpty() {
		let store = AccessTokenStore.mock(
			copyMatching: { query, result in
				XCTAssertEqual(query, [
					kSecClass: kSecClassGenericPassword,
					kSecMatchLimit: kSecMatchLimitOne,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				XCTAssertNil(result?.pointee)

				result?.pointee = CFArray.withTokens("token")
				return noErr
			}
		)

		XCTAssertFalse(store.isEmpty)
	}

	func testIsEmptyWhenEmpty() {
		let store = AccessTokenStore.mock(
			copyMatching: { query, result in
				XCTAssertEqual(query, [
					kSecClass: kSecClassGenericPassword,
					kSecMatchLimit: kSecMatchLimitOne,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				XCTAssertNil(result?.pointee)

				result?.pointee = CFArray.empty
				return noErr
			}
		)

		XCTAssertTrue(store.isEmpty)
	}

	func testIsEmptyWhenQueryThrowsError() {
		let store = AccessTokenStore.mock(
			copyMatching: { query, result in
				XCTAssertEqual(query, [
					kSecClass: kSecClassGenericPassword,
					kSecMatchLimit: kSecMatchLimitOne,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				XCTAssertNil(result?.pointee)

				return 12345
			}
		)

		XCTAssertTrue(store.isEmpty)
	}

	// MARK: AccessTokenStore.accessTokens

	func testAccessTokens() {
		let appKey = "app_key"
		let token = "token"
		let store = AccessTokenStore.mock(
			appKey: appKey,
			copyMatching: { query, result in
				if let returnData = (query as NSDictionary)[kSecReturnData], (returnData as! CFBoolean) == kCFBooleanTrue  {
					XCTAssertEqual(query, [
						kSecClass: kSecClassGenericPassword,
						kSecAttrAccount: token,
						kSecReturnData: kCFBooleanTrue!,
						kSecMatchLimit: kSecMatchLimitOne,
						kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
					] as CFDictionary)
					XCTAssertNil(result?.pointee)

					result?.pointee = try! CFData.mock(accessToken: token, appKey: appKey)
					return noErr
				}
				else {
					XCTAssertEqual(query, [
						kSecClass: kSecClassGenericPassword,
						kSecReturnAttributes: kCFBooleanTrue!,
						kSecMatchLimit: kSecMatchLimitAll,
						kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
					] as CFDictionary)
					XCTAssertNil(result?.pointee)

					result?.pointee = CFArray.withTokens(token)
					return noErr
				}
			}
		)

		XCTAssertEqual(store.accessTokens, [.mock(accessToken: token, appKey: appKey)])
	}

	func testAccessTokensWhenEmpty() {
		let store = AccessTokenStore.mock(
			copyMatching: { query, result in
				XCTAssertEqual(query, [
					kSecClass: kSecClassGenericPassword,
					kSecReturnAttributes: kCFBooleanTrue!,
					kSecMatchLimit: kSecMatchLimitAll,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				XCTAssertNil(result?.pointee)

				result?.pointee = CFArray.empty
				return noErr
			}
		)

		XCTAssertEqual(store.accessTokens, [])
	}

	func testAccessTokensWhenAttributesQueryThrowsError() {
		let store = AccessTokenStore.mock(
			copyMatching: { query, result in
				XCTAssertEqual(query, [
					kSecClass: kSecClassGenericPassword,
					kSecReturnAttributes: kCFBooleanTrue!,
					kSecMatchLimit: kSecMatchLimitAll,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				XCTAssertNil(result?.pointee)

				return 12345
			}
		)

		XCTAssertEqual(store.accessTokens, [])
	}

	func testAccessTokensWhenDataQueryThrowsError() {
		let appKey = "app_key"
		let token = "token"
		let store = AccessTokenStore.mock(
			appKey: appKey,
			copyMatching: { query, result in
				if let returnData = (query as NSDictionary)[kSecReturnData], (returnData as! CFBoolean) == kCFBooleanTrue  {
					XCTAssertEqual(query, [
						kSecClass: kSecClassGenericPassword,
						kSecAttrAccount: token,
						kSecReturnData: kCFBooleanTrue!,
						kSecMatchLimit: kSecMatchLimitOne,
						kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
					] as CFDictionary)
					XCTAssertNil(result?.pointee)

					return 12345
				}
				else {
					XCTAssertEqual(query, [
						kSecClass: kSecClassGenericPassword,
						kSecReturnAttributes: kCFBooleanTrue!,
						kSecMatchLimit: kSecMatchLimitAll,
						kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
					] as CFDictionary)
					XCTAssertNil(result?.pointee)

					result?.pointee = CFArray.withTokens(token)
					return noErr
				}
			}
		)

		XCTAssertEqual(store.accessTokens, [])
	}

	// MARK: AccessTokenStore.first

	func testFirst() {
		let appKey = "app_key"
		let token = "token"
		let store = AccessTokenStore.mock(
			appKey: appKey,
			copyMatching: { query, result in
				if let returnData = (query as NSDictionary)[kSecReturnData], (returnData as! CFBoolean) == kCFBooleanTrue  {
					XCTAssertEqual(query, [
						kSecClass: kSecClassGenericPassword,
						kSecAttrAccount: token,
						kSecReturnData: kCFBooleanTrue!,
						kSecMatchLimit: kSecMatchLimitOne,
						kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
					] as CFDictionary)
					XCTAssertNil(result?.pointee)

					result?.pointee = try! CFData.mock(accessToken: token, appKey: appKey)
					return noErr
				}
				else {
					XCTAssertEqual(query, [
						kSecClass: kSecClassGenericPassword,
						kSecReturnAttributes: kCFBooleanTrue!,
						kSecMatchLimit: kSecMatchLimitOne,
						kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
					] as CFDictionary)
					XCTAssertNil(result?.pointee)

					result?.pointee = CFDictionary.withToken(token)
					return noErr
				}
			}
		)

		XCTAssertEqual(store.first, .mock(accessToken: token, appKey: appKey))
	}

	func testFirstWhenEmpty() {
		let store = AccessTokenStore.mock(
			copyMatching: { query, result in
				XCTAssertEqual(query, [
					kSecClass: kSecClassGenericPassword,
					kSecReturnAttributes: kCFBooleanTrue!,
					kSecMatchLimit: kSecMatchLimitOne,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				XCTAssertNil(result?.pointee)

				result?.pointee = CFArray.empty
				return noErr
			}
		)

		XCTAssertNil(store.first)
	}

	func testFirstWhenAttributesQueryThrowsError() {
		let store = AccessTokenStore.mock(
			copyMatching: { query, result in
				XCTAssertEqual(query, [
					kSecClass: kSecClassGenericPassword,
					kSecReturnAttributes: kCFBooleanTrue!,
					kSecMatchLimit: kSecMatchLimitOne,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				XCTAssertNil(result?.pointee)

				return 12345
			}
		)

		XCTAssertNil(store.first)
	}

	func testFirstWhenDataQueryThrowsError() {
		let appKey = "app_key"
		let token = "token"
		let store = AccessTokenStore.mock(
			appKey: appKey,
			copyMatching: { query, result in
				if let returnData = (query as NSDictionary)[kSecReturnData], (returnData as! CFBoolean) == kCFBooleanTrue  {
					XCTAssertEqual(query, [
						kSecClass: kSecClassGenericPassword,
						kSecAttrAccount: token,
						kSecReturnData: kCFBooleanTrue!,
						kSecMatchLimit: kSecMatchLimitOne,
						kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
					] as CFDictionary)
					XCTAssertNil(result?.pointee)

					return 12345
				}
				else {
					XCTAssertEqual(query, [
						kSecClass: kSecClassGenericPassword,
						kSecReturnAttributes: kCFBooleanTrue!,
						kSecMatchLimit: kSecMatchLimitOne,
						kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
					] as CFDictionary)
					XCTAssertNil(result?.pointee)

					result?.pointee = CFDictionary.withToken(token)
					return noErr
				}
			}
		)

		XCTAssertNil(store.first)
	}

	// MARK: AccessTokenStore.accessToken(for:)

	func testAccessTokenForAccountID() {
		let appKey = "app_key"
		let token = "token"
		let store = AccessTokenStore.mock(
			appKey: appKey,
			copyMatching: { query, result in
				XCTAssertEqual(query, [
					kSecClass: kSecClassGenericPassword,
					kSecAttrAccount: token,
					kSecReturnData: kCFBooleanTrue!,
					kSecMatchLimit: kSecMatchLimitOne,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				XCTAssertNil(result?.pointee)

				result?.pointee = try! CFData.mock(accessToken: token, appKey: appKey)
				return noErr
			}
		)

		XCTAssertEqual(try store.accessToken(for: token), .mock(accessToken: token, appKey: appKey))
	}

	func testAccessTokenForAccountIDWhenEmpty() {
		let appKey = "app_key"
		let token = "token"
		let store = AccessTokenStore.mock(
			appKey: appKey,
			copyMatching: { query, result in
				XCTAssertEqual(query, [
					kSecClass: kSecClassGenericPassword,
					kSecAttrAccount: token,
					kSecReturnData: kCFBooleanTrue!,
					kSecMatchLimit: kSecMatchLimitOne,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				XCTAssertNil(result?.pointee)

				result?.pointee = nil
				return noErr
			}
		)

		XCTAssertThrowsError(try store.accessToken(for: token)) {
			XCTAssertEqual(($0 as? AccessTokenStore.OSStatusError)?.status, -25300)
		}
	}

	func testAccessTokenForAccountIDWhenQueryThrowsError() {
		let appKey = "app_key"
		let token = "token"
		let store = AccessTokenStore.mock(
			appKey: appKey,
			copyMatching: { query, result in
				XCTAssertEqual(query, [
					kSecClass: kSecClassGenericPassword,
					kSecAttrAccount: token,
					kSecReturnData: kCFBooleanTrue!,
					kSecMatchLimit: kSecMatchLimitOne,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				XCTAssertNil(result?.pointee)

				return 12345
			}
		)

		XCTAssertThrowsError(try store.accessToken(for: token)) {
			XCTAssertEqual(($0 as? AccessTokenStore.OSStatusError)?.status, 12345)
		}
	}

	// MARK: AccessTokenStore.save(_:)

	func testSaveAccessTokenWhenTokenDoesntExist() {
		let accountID = "account_id"
		let store = AccessTokenStore.mock(
			copyMatching: { query, result in
				XCTAssertEqual(query, [
					kSecClass: kSecClassGenericPassword,
					kSecAttrAccount: accountID,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				XCTAssertNil(result?.pointee)

				return -25300
			},
			add: { attributes, result in
				XCTAssertEqual(attributes, [
					kSecClass: kSecClassGenericPassword,
					kSecAttrAccount: accountID,
					kSecValueData: try! CFData.mock(accountID: accountID),
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				XCTAssertNil(result?.pointee)

				return noErr
			}
		)

		XCTAssertNoThrow(try store.save(.mock(accountID: accountID)))
	}

	func testSaveAccessTokenWhenTokenExists() {
		let accountID = "account_id"
		let store = AccessTokenStore.mock(
			copyMatching: { query, result in
				XCTAssertEqual(query, [
					kSecClass: kSecClassGenericPassword,
					kSecAttrAccount: accountID,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				XCTAssertNil(result?.pointee)

				return noErr
			},
			update: { query, attributesToUpdate in
				XCTAssertEqual(query, [
					kSecClass: kSecClassGenericPassword,
					kSecAttrAccount: accountID,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				XCTAssertEqual(attributesToUpdate, [
					kSecValueData: try! CFData.mock(accountID: accountID)
				] as CFDictionary)

				return noErr
			}
		)

		XCTAssertNoThrow(try store.save(.mock(accountID: accountID)))
	}

	func testSaveAccessTokenWhenAttributesQueryThrowsError() {
		let accountID = "account_id"
		let store = AccessTokenStore.mock(
			copyMatching: { query, result in
				XCTAssertEqual(query, [
					kSecClass: kSecClassGenericPassword,
					kSecAttrAccount: accountID,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				XCTAssertNil(result?.pointee)

				return 12345
			}
		)

		XCTAssertThrowsError(try store.save(.mock(accountID: accountID))) {
			XCTAssertEqual(($0 as? AccessTokenStore.OSStatusError)?.status, 12345)
		}
	}

	func testSaveAccessTokenWhenTokenDoesntExistAndAddThrowsError() {
		let accountID = "account_id"
		let store = AccessTokenStore.mock(
			copyMatching: { query, result in
				XCTAssertEqual(query, [
					kSecClass: kSecClassGenericPassword,
					kSecAttrAccount: accountID,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				XCTAssertNil(result?.pointee)

				return -25300
			},
			add: { attributes, result in
				XCTAssertEqual(attributes, [
					kSecClass: kSecClassGenericPassword,
					kSecAttrAccount: accountID,
					kSecValueData: try! CFData.mock(accountID: accountID),
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				XCTAssertNil(result?.pointee)

				return 12345
			}
		)

		XCTAssertThrowsError(try store.save(.mock(accountID: accountID))) {
			XCTAssertEqual(($0 as? AccessTokenStore.OSStatusError)?.status, 12345)
		}
	}

	func testSaveAccessTokenWhenTokenExistsAndUpdateThrowsError() {
		let accountID = "account_id"
		let store = AccessTokenStore.mock(
			copyMatching: { query, result in
				XCTAssertEqual(query, [
					kSecClass: kSecClassGenericPassword,
					kSecAttrAccount: accountID,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				XCTAssertNil(result?.pointee)

				return noErr
			},
			update: { query, attributesToUpdate in
				XCTAssertEqual(query, [
					kSecClass: kSecClassGenericPassword,
					kSecAttrAccount: accountID,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)
				XCTAssertEqual(attributesToUpdate, [
					kSecValueData: try! CFData.mock(accountID: accountID)
				] as CFDictionary)

				return 12345
			}
		)

		XCTAssertThrowsError(try store.save(.mock(accountID: accountID))) {
			XCTAssertEqual(($0 as? AccessTokenStore.OSStatusError)?.status, 12345)
		}
	}

	// MARK: AccessTokenStore.remove(_:)

	func testRemoveAccessToken() {
		let accountID = "account_id"
		let store = AccessTokenStore.mock(
			delete: { query in
				XCTAssertEqual(query, [
					kSecClass: kSecClassGenericPassword,
					kSecAttrAccount: accountID,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)

				return noErr
			}
		)

		XCTAssertNoThrow(try store.remove(.mock(accountID: accountID)))
	}

	func testRemoveAccessTokenWhenQueryThrowsError() {
		let accountID = "account_id"
		let store = AccessTokenStore.mock(
			delete: { query in
				XCTAssertEqual(query, [
					kSecClass: kSecClassGenericPassword,
					kSecAttrAccount: accountID,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)

				return 12345
			}
		)

		XCTAssertThrowsError(try store.remove(.mock(accountID: accountID))) {
			XCTAssertEqual(($0 as? AccessTokenStore.OSStatusError)?.status, 12345)
		}
	}

	// MARK: AccessTokenStore.removeAll()

	func testRemoveAll() {
		let store = AccessTokenStore.mock(
			delete: { query in
				XCTAssertEqual(query, [
					kSecClass: kSecClassGenericPassword,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)

				return noErr
			}
		)

		XCTAssertNoThrow(try store.removeAll())
	}

	func testRemoveAllWhenQueryThrowsError() {
		let store = AccessTokenStore.mock(
			delete: { query in
				XCTAssertEqual(query, [
					kSecClass: kSecClassGenericPassword,
					kSecAttrService: "com.apple.dt.xctest.tool.dropbox.authv2"
				] as CFDictionary)

				return 12345
			}
		)

		XCTAssertThrowsError(try store.removeAll()) {
			XCTAssertEqual(($0 as? AccessTokenStore.OSStatusError)?.status, 12345)
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
	) throws -> CFData {
		try PropertyListEncoder().encode(AccessToken.mock(
			accessToken: accessToken,
			expiryDate: expiryDate,
			scope: scope,
			accountID: accountID,
			teamID: teamID,
			refreshToken: refreshToken,
			appKey: appKey
		)) as CFData
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
