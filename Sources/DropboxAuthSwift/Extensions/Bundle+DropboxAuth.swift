//
//  File.swift
//  
//
//  Created by Daniel Farrelly on 21/5/2022.
//

import Foundation

extension Bundle {

	func hasConfiguredScheme(_ configuredScheme: String) -> Bool {
		guard let urlTypes = object(forInfoDictionaryKey: "CFBundleURLTypes") as? [[String: Any]] else {
			return false
		}

		for urlType in urlTypes {
			guard let schemes = urlType["CFBundleURLSchemes"] as? [String] else {
				continue
			}

			for scheme in schemes where scheme == configuredScheme {
				return true
			}
		}

		return false
	}

	var hasApplicationQueriesScheme: Bool {
		guard let schemes = Bundle.main.object(forInfoDictionaryKey: "LSApplicationQueriesSchemes") as? [String] else {
			return false
		}

		for scheme in schemes where scheme == "dbapi-2" {
			return true
		}

		return false
	}

}
