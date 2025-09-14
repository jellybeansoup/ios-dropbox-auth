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

public extension API {

	/// Represents a network API endpoint for Dropbox, combining a subdomain and resource path to create a full URL for API calls.
	///
	/// Use this type to construct strongly-typed, validated endpoint URLs for different categories of Dropbox API requests, such as metadata, file uploads, notifications, and OAuth authentication.
	struct Endpoint: Hashable, Sendable {

		/// The root host and version component for the endpoint (e.g., "api.dropboxapi.com/2").
		/// This typically includes the subdomain and API version, and should not contain the resource path.
		var root: String

		/// The resource-specific path that will be appended to the root (e.g., "/users/list").
		/// This indicates the actual API resource being accessed on the selected root/subdomain.
		var path: String

		/// Initializes an Endpoint with a specific root and resource path.
		/// - Parameters:
		///   - root: The root domain and version component (e.g., "api.dropboxapi.com/2").
		///   - path: The resource path (e.g., "/users/list").
		init(root: String, path: String) {
			self.root = root
			self.path = path
		}

		// MARK: Creating an endpoint

		/// Creates an endpoint scoped to the "api" subdomain (api.dropboxapi.com/2), used for most Dropbox API requests (metadata, user, sharing, and file management).
		/// - Parameter path: The resource path to append (e.g., "/files/get_metadata").
		/// - Returns: An `Endpoint` for the API subdomain and specified path.
		public static func api(_ path: String) -> Self {
			Self(root: "api.dropboxapi.com/2", path: path)
		}

		/// Creates an endpoint scoped to the "content" subdomain (content.dropboxapi.com/2), for file upload/download operations.
		/// - Parameter path: The resource path for the file content API.
		/// - Returns: An `Endpoint` for the content subdomain and specified path.
		public static func content(_ path: String) -> Self {
			Self(root: "content.dropboxapi.com/2", path: path)
		}

		/// Creates an endpoint scoped to the "notify" subdomain (notify.dropboxapi.com/2), for long polling and notification APIs.
		/// - Parameter path: The resource path for the notification API.
		/// - Returns: An `Endpoint` for the notify subdomain and specified path.
		public static func notify(_ path: String) -> Self {
			Self(root: "notify.dropboxapi.com/2", path: path)
		}

		/// Creates an endpoint for Dropbox OAuth token authentication.
		/// - Returns: An `Endpoint` for OAuth token requests ("api.dropbox.com/oauth/token").
		static var oauth: Self {
			Self(root: "api.dropbox.com/oauth2", path: "/token")
		}

		// MARK: Preparing a URL

		/// Errors that may occur when constructing a URL from an endpoint.
		enum URLError: Swift.Error, Equatable {

			/// The root could not be used to form a valid base URL.
			case invalidRoot(String)

		}

		/// The full URL for the endpoint, assembled from the root and path.
		/// - Throws: `URLError.invalidRoot` if the root does not form a valid URL.
		/// - Returns: A fully-qualified, standardized URL for the endpoint.
		var url: URL {
			get throws(URLError) {
				guard let url = URL(string: "https://\(root)") else {
					throw URLError.invalidRoot(root)
				}
				return url.appendingPathComponent(path).absoluteURL.standardized
			}
		}

	}

}

extension API.Endpoint: ExpressibleByStringLiteral {

	/// Constructs an API endpoint from a string literal representing the resource path.
	///
	/// Using a string literal creates an Endpoint scoped to the "api" subdomain (as with `Endpoint.api(_:)`).
	/// For example: `let endpoint: Endpoint = "/files/list_folder"`
	/// - Parameter value: The resource path for the API endpoint.
	public init(stringLiteral value: String) {
		self = Self.api(value)
	}

}
