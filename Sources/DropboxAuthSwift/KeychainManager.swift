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

class KeychainManager {

	let keychain: KeychainProtocol

	init(keychain: KeychainProtocol = Keychain()) {
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

	func setValue(_ value: String, forKey key: String) -> Bool {
		return setValue(Data(value.utf8), forKey: key)
	}

	func setValue(_ value: Data, forKey key: String) -> Bool {
		let query = query(with: [
			kSecAttrAccount: NSString(string: key) as CFString,
		])

		let status: OSStatus
		if Keychain().copyMatching(query as CFDictionary, nil) == noErr {
			status = Keychain().update(query, NSDictionary(dictionary: [kSecValueData: data]) as CFDictionary)
		}
		else {
			query.setValue(NSData(data: value) as CFData, forKey: kSecValueData as String)
			status = Keychain().add(query, nil)
		}

		return status == noErr
	}

	func string(forKey key: String) -> String? {
		guard let value = data(forKey: key) else {
			return nil
		}

		return String(data: value, encoding: .utf8)
	}

	func data(forKey key: String) -> Data? {
		let query = query(with: [
			kSecAttrAccount: NSString(string: key) as CFString,
			kSecReturnData: kCFBooleanTrue!,
			kSecMatchLimit: kSecMatchLimitOne,
		])

		var result: CFTypeRef?
		let status = Keychain().copyMatching(query, &result)

		guard status == noErr else {
			return nil
		}

		return result as? Data
	}

	func removeValue(forKey key: String) -> Bool {
		let query = query(with: [
			kSecAttrAccount: NSString(string: key) as CFString,
		])

		return Keychain().delete(query) == noErr
	}

	var all: [String] {
		let query = query(with: [
			kSecReturnAttributes: kCFBooleanTrue!,
			kSecMatchLimit: kSecMatchLimitAll,
		])

		var result: CFTypeRef?
		let status = Keychain().copyMatching(query, &result)

		guard status == noErr, let result = result as? NSArray else {
			return []
		}

		return result
			.compactMap { $0 as? NSDictionary }
			.compactMap { $0[kSecAttrAccount] as? String }
	}

	func removeAll() -> Bool {
		let query = query(with: [:])

		return Keychain().delete(query) == noErr
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

	func debug_list() {
		let query = query(with: [
			kSecClass: kSecClassGenericPassword,
			kSecReturnAttributes: kCFBooleanTrue!,
		])

		var result: CFTypeRef?
		let status = Keychain().copyMatching(query as CFDictionary, &result)

		guard status == noErr else { return }

		let results = (result as? NSArray ?? [])
			.compactMap { $0 as? NSDictionary }
			.map { [$0[kSecAttrService], $0[kSecAttrAccount]] }

		print("dbgListAllItems: \(results)")
	}

}
