//
// Copyright © 2022 Daniel Farrelly
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

import Foundation

protocol KeychainProtocol {
	func copyMatching(_ query: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus
	func update(_ query: CFDictionary, _ attributesToUpdate: CFDictionary) -> OSStatus
	func add(_ attributes: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus
	func delete(_ query: CFDictionary) -> OSStatus
}

public class AccessTokenStore {

	let appKey: String

	let keychain: KeychainProtocol

	init(appKey: String, keychain: KeychainProtocol = Keychain()) {
		self.appKey = appKey
		self.keychain = keychain
	}

	private struct Keychain: KeychainProtocol {

		init() {}

		func copyMatching(_ query: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
			SecItemCopyMatching(query, result)
		}

		func update(_ query: CFDictionary, _ attributesToUpdate: CFDictionary) -> OSStatus {
			SecItemUpdate(query, attributesToUpdate)
		}

		func add(_ attributes: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
			SecItemAdd(attributes, result)
		}

		func delete(_ query: CFDictionary) -> OSStatus {
			SecItemDelete(query)
		}

	}

	private struct OSStatusError: Swift.Error, LocalizedError {

		var status: OSStatus

		var localizedDescription: String {
			return String((SecCopyErrorMessageString(status, nil) as NSString?) ?? "unknown")
		}

		static let missing = OSStatusError(status: -25300)

	}

	// MARK: Storing access tokens

	/// A Boolean value indicating whether the store is empty.
	public var isEmpty: Bool {
		let query = self.query(with: [
			kSecMatchLimit: kSecMatchLimitOne,
		])

		var result: CFTypeRef?
		let status = keychain.copyMatching(query, &result)

		guard status == noErr, let result = result as? NSArray else {
			return false
		}

		return result.count == 0
	}

	/// All stored access tokens.
	public var accessTokens: [AccessToken] {
		let query = self.query(with: [
			kSecReturnAttributes: kCFBooleanTrue!,
			kSecMatchLimit: kSecMatchLimitAll,
		])

		var result: CFTypeRef?
		let status = keychain.copyMatching(query, &result)

		guard status == noErr, let result = result as? NSArray else {
			return []
		}

		return result
			.compactMap { $0 as? NSDictionary }
			.compactMap { $0[kSecAttrAccount] as? String }
			.compactMap { try? accessToken(for: $0) }
	}

	/// The first access token found, if available.
	public var first: AccessToken? {
		let query = self.query(with: [
			kSecReturnAttributes: kCFBooleanTrue!,
			kSecMatchLimit: kSecMatchLimitOne,
		])

		var result: CFTypeRef?
		let status = keychain.copyMatching(query, &result)

		guard status == noErr, let result = result as? NSDictionary, let accountID = result[kSecAttrAccount] as? String else {
			return nil
		}

		return try? accessToken(for: accountID)
	}

	/// Retrieve the access token for a particular user identifier
	/// - Parameter userID: The identifier representing the user whose token to retrieve.
	/// - Returns: An access token if present, otherwise `nil`.
	public func accessToken(for accountID: String) throws -> AccessToken {
		let query = query(with: [
			kSecAttrAccount: NSString(string: accountID) as CFString,
			kSecReturnData: kCFBooleanTrue!,
			kSecMatchLimit: kSecMatchLimitOne,
		])

		var result: CFTypeRef?
		let status = keychain.copyMatching(query, &result)

		guard status == noErr else {
			throw OSStatusError(status: status)
		}

		guard let result = result as? Data else {
			throw OSStatusError.missing
		}

		var token = try PropertyListDecoder().decode(AccessToken.self, from: result)
		token.appKey = appKey
		token.store = self
		return token
	}

	/// Add a specific access token
	/// - Parameter accessToken: The access token to add.
	/// - Returns: Flag indicating whether the operation succeeded.
	internal func save(_ accessToken: AccessToken) throws {
		let data = try PropertyListEncoder().encode(accessToken)
		let cfData = NSData(data: data) as CFData

		let query = query(with: [
			kSecAttrAccount: NSString(string: accessToken.accountID) as CFString,
		])

		let status: OSStatus
		if keychain.copyMatching(query as CFDictionary, nil) == noErr {
			status = keychain.update(query, NSDictionary(dictionary: [kSecValueData: cfData]) as CFDictionary)
		}
		else {
			query.setValue(cfData, forKey: kSecValueData as String)
			status = keychain.add(query, nil)
		}

		if status != noErr {
			throw OSStatusError(status: status)
		}
	}

	/// Delete a specific access token
	/// - Parameter accessToken: The access token to delete.
	/// - Returns: Flag indicating whether the operation succeeded.
	public func remove(_ accessToken: AccessToken) throws {
		let query = query(with: [
			kSecAttrAccount: NSString(string: accessToken.accountID) as CFString,
		])

		let status = keychain.delete(query)

		if status != noErr {
			throw OSStatusError(status: status)
		}
	}

	/// Delete all stored access tokens
	/// - Returns: Flag indicating whether the operation succeeded.
	public func removeAll() throws {
		let query = query(with: [:])

		let status = keychain.delete(query)

		if status != noErr {
			throw OSStatusError(status: status)
		}
	}

	// MARK: Utilities

	private func query(with dictionary: NSDictionary) -> NSDictionary {
		var bundle: Bundle? = .main
		if let bundleURL = bundle?.bundleURL, bundleURL.pathExtension == "appex" {
			// Peel off two directory levels - MY_APP.app/PlugIns/MY_APP_EXTENSION.appex
			// <http://stackoverflow.com/questions/26189060/get-the-main-app-bundle-from-within-extension>
			bundle = Bundle(url: bundleURL.deletingLastPathComponent().deletingLastPathComponent())
		}

		let bundleID = bundle?.bundleIdentifier ?? ""
		let dictionary = dictionary.mutableCopy() as! NSMutableDictionary

		dictionary.setValue(kSecClassGenericPassword, forKey: kSecClass as String)
		dictionary.setValue("\(bundleID).dropbox.authv2", forKey: kSecAttrService as String)

		return dictionary
	}

}
