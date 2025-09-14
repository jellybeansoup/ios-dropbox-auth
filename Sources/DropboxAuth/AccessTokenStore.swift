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

import Foundation

/**
 `AccessTokenStore` securely manages the storage, retrieval, updating, and deletion of user access tokens (such as OAuth tokens) using the Keychain Services API. It is designed to handle tokens for different accounts, providing a simple and safe interface for reading and writing sensitive authentication data. The store can be initialized with custom Keychain handler functions for advanced use, but by default uses system Keychain operations. Thread-safe and suitable for use in app extensions and main apps alike.

 - Usage: Use `save(_:)` to add or update tokens, `remove(_:)` or `removeAll()` to delete them, and `accessToken(for:)` to fetch tokens by account identifier. Check `isEmpty`, `accessTokens`, and `first` for store state and quick access.
 - Important: This store is scoped to the app or app extension via a service key derived from the bundle identifier, and can be shared across app extensions as necessary.
*/
public final class AccessTokenStore: Sendable {

	/// Handler for performing a Keychain query (such as searching for a matching item).
	///
	/// - Parameters:
	///   - query: A `CFDictionary` describing the keychain query parameters.
	///   - result: An optional pointer to receive the result if the query is successful (e.g., attributes or data).
	/// - Returns: An OSStatus code indicating success or the nature of the failure.
	typealias CopyMatchingHandler = @Sendable (
		_ query: CFDictionary,
		_ result: UnsafeMutablePointer<CFTypeRef?>?
	) -> OSStatus

	/// Handler for updating an existing Keychain item.
	///
	/// - Parameters:
	///   - query: A `CFDictionary` specifying which item(s) to update.
	///   - attributesToUpdate: A `CFDictionary` containing the attributes to update for the matching item(s).
	/// - Returns: An OSStatus code indicating success or failure.
	typealias UpdateHandler = @Sendable (
		_ query: CFDictionary,
		_ attributesToUpdate: CFDictionary
	) -> OSStatus

	/// Handler for adding a new item to the Keychain.
	///
	/// - Parameters:
	///   - attributes: A `CFDictionary` with the attributes for the new keychain item, including data and metadata.
	///   - result: An optional pointer to receive information about the added item.
	/// - Returns: An OSStatus code indicating success or the reason for failure.
	typealias AddHandler = @Sendable (
		_ attributes: CFDictionary,
		_ result: UnsafeMutablePointer<CFTypeRef?>?
	) -> OSStatus

	/// Handler for deleting a Keychain item.
	///
	/// - Parameter query: A `CFDictionary` describing the item(s) to delete from the keychain.
	/// - Returns: An OSStatus code indicating whether the item(s) were deleted or why the operation failed.
	typealias DeleteHandler = @Sendable (
		_ query: CFDictionary
	) -> OSStatus

	let appKey: String

	let copyMatching: CopyMatchingHandler

	let update: UpdateHandler

	let add: AddHandler

	let delete: DeleteHandler

	/// Initializes an `AccessTokenStore` with custom Keychain operation handlers.
	///
	/// - Parameters:
	///   - appKey: The application key to associate with stored tokens.
	///   - copyMatching: Closure to perform the Keychain copy matching operation.
	///   - update: Closure to perform the Keychain update operation.
	///   - add: Closure to perform the Keychain add operation.
	///   - delete: Closure to perform the Keychain delete operation.
	///
	/// This allows injection of custom Keychain handlers, useful for testing or specialized behaviors.
	init(
		appKey: String,
		copyMatching: @escaping CopyMatchingHandler,
		update: @escaping UpdateHandler,
		add: @escaping AddHandler,
		delete: @escaping DeleteHandler
	) {
		self.appKey = appKey
		self.copyMatching = copyMatching
		self.update = update
		self.add = add
		self.delete = delete
	}

	/// Initializes an `AccessTokenStore` using the default Keychain Services API functions.
	///
	/// - Parameter appKey: The application key to associate with stored tokens.
	///
	/// This convenience initializer sets up the store to use the system's Keychain functions.
	convenience init(
		appKey: String
	) {
		self.init(
			appKey: appKey,
			copyMatching: { SecItemCopyMatching($0, $1) },
			update: { SecItemUpdate($0, $1) },
			add: { SecItemAdd($0, $1) },
			delete: { SecItemDelete($0) }
		)
	}

	/// An error type representing an OSStatus code returned from Keychain operations.
	struct OSStatusError: Swift.Error, LocalizedError, Sendable {

		var status: OSStatus

		var errorDescription: String? {
			return (SecCopyErrorMessageString(status, nil) as NSString?).map(String.init)
		}

		static let missing = OSStatusError(status: -25300)

	}

	// MARK: Storing access tokens

	/// A Boolean value indicating whether the store is empty.
	///
	/// Returns `true` if no access tokens are present in the store, otherwise `false`.
	public var isEmpty: Bool {
		let query = self.query(with: [
			kSecMatchLimit: kSecMatchLimitOne,
		])

		var result: CFTypeRef?
		let status = copyMatching(query, &result)

		guard status == noErr, let result = result as? NSArray else {
			return true
		}

		return result.count == 0
	}

	/// All stored access tokens.
	///
	/// Returns an array of all access tokens currently saved in the store.
	/// If no tokens are found or an error occurs, returns an empty array.
	public var accessTokens: [AccessToken] {
		let query = self.query(with: [
			kSecReturnAttributes: kCFBooleanTrue!,
			kSecMatchLimit: kSecMatchLimitAll,
		])

		var result: CFTypeRef?
		let status = copyMatching(query, &result)

		guard status == noErr, let result = result as? NSArray else {
			return []
		}

		return result
			.compactMap { $0 as? NSDictionary }
			.compactMap { $0[kSecAttrAccount] as? String }
			.compactMap { try? accessToken(for: $0) }
	}

	/// The first access token found, if available.
	///
	/// Returns an optional `AccessToken` representing the first token in the store.
	/// Returns `nil` if no tokens are found or an error occurs.
	public var first: AccessToken? {
		let query = self.query(with: [
			kSecReturnAttributes: kCFBooleanTrue!,
			kSecMatchLimit: kSecMatchLimitOne,
		])

		var result: CFTypeRef?
		let status = copyMatching(query, &result)

		guard status == noErr, let result = result as? NSDictionary, let accountID = result[kSecAttrAccount] as? String else {
			return nil
		}

		return try? accessToken(for: accountID)
	}

	/// Retrieve the access token for a particular account identifier.
	///
	/// - Parameter accountID: The identifier representing the account whose token to retrieve.
	/// - Throws: An `OSStatusError` if the token cannot be found or a Keychain error occurs.
	/// - Returns: An `AccessToken` if present.
	public func accessToken(for accountID: String) throws -> AccessToken {
		let query = query(with: [
			kSecAttrAccount: NSString(string: accountID) as CFString,
			kSecReturnData: kCFBooleanTrue!,
			kSecMatchLimit: kSecMatchLimitOne,
		])

		var result: CFTypeRef?
		let status = copyMatching(query, &result)

		guard status == noErr else {
			throw OSStatusError(status: status)
		}

		guard let result = result as? Data else {
			throw OSStatusError.missing
		}

		var token = try PropertyListDecoder().decode(AccessToken.self, from: result)
		token.appKey = appKey
		return token
	}

	/// Add or update a specific access token in the store.
	///
	/// - Parameter accessToken: The access token to add or update.
	/// - Throws: An `OSStatusError` if the save operation fails.
	///
	/// If the token for the given account already exists, it will be updated. Otherwise, it will be added.
	internal func save(_ accessToken: AccessToken) throws {
		let data = try PropertyListEncoder().encode(accessToken)
		let cfData = NSData(data: data) as CFData

		let query = query(with: [
			kSecAttrAccount: NSString(string: accessToken.accountID) as CFString,
		])

		let saveStatus: OSStatus
		let lookupStatus = copyMatching(query as CFDictionary, nil)
		switch lookupStatus {
		case OSStatusError.missing.status:
			query.setValue(cfData, forKey: kSecValueData as String)
			saveStatus = add(query, nil)

		case noErr:
			saveStatus = update(query, NSDictionary(dictionary: [kSecValueData: cfData]) as CFDictionary)

		default:
			throw OSStatusError(status: lookupStatus)
		}

		if saveStatus != noErr {
			throw OSStatusError(status: saveStatus)
		}
	}

	/// Delete a specific access token from the store.
	///
	/// - Parameter accessToken: The access token to delete.
	/// - Throws: An `OSStatusError` if the delete operation fails.
	public func remove(_ accessToken: AccessToken) throws {
		let query = query(with: [
			kSecAttrAccount: NSString(string: accessToken.accountID) as CFString,
		])

		let status = delete(query)

		if status != noErr {
			throw OSStatusError(status: status)
		}
	}

	/// Delete all stored access tokens from the store.
	///
	/// - Throws: An `OSStatusError` if the delete operation fails.
	public func removeAll() throws {
		let query = query(with: [:])

		let status = delete(query)

		if status != noErr {
			throw OSStatusError(status: status)
		}
	}

	// MARK: Utilities

	/// Constructs a base query dictionary for Keychain operations, scoped to the app or extension.
	///
	/// - Parameter dictionary: A dictionary of additional query parameters to include.
	/// - Returns: A dictionary suitable for Keychain queries with service and class attributes set.
	///
	/// This method adjusts the bundle identifier for app extensions to correctly scope the Keychain service.
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
