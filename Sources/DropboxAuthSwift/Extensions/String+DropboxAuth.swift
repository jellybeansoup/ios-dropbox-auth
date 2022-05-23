//
//  File.swift
//  
//
//  Created by Daniel Farrelly on 21/5/2022.
//

import Foundation

extension String {

	internal var queryParameters: [String: String] {
		var parameters: [String: String] = [:]
		for pair in split(separator: "&") {
			let kv = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: true)

			if kv.count == 2 {
				parameters[String(kv[0])] = kv[1].replacingOccurrences(of: "+", with: " ").removingPercentEncoding
			}
			else if kv.count == 1 {
				parameters[String(kv[0])] = "true"
			}
			else {
				continue
			}
		}
		return parameters
	}

}
