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
import DropboxAuth

extension ListFolder {

	enum Longpoll {

		struct Request: API.Request {

			typealias Response = Longpoll.Response
			typealias Error = Longpoll.Error

			static let endpoint = Endpoint.notify("/files/list_folder/longpoll")

			static let method = Method.post

			func configure(_ urlRequest: inout URLRequest) throws {
				urlRequest.cachePolicy = .reloadIgnoringLocalCacheData
				urlRequest.timeoutInterval = TimeInterval(timeout + 60)
			}

			var cursor: Cursor

			var timeout: Int = 30

		}

		struct Response: API.Response {

			typealias Request = Longpoll.Request

			var hasChanges: Bool

			var backoff: UInt64

			init(
				hasChanges: Bool,
				backoff: UInt64
			) {
				self.hasChanges = hasChanges
				self.backoff = backoff
			}

			// MARK: Decodable

			private enum CodingKeys: String, CodingKey {
				case hasChanges = "changes"
				case backoff
			}

			init(from decoder: any Decoder) throws {
				let container = try decoder.container(keyedBy: CodingKeys.self)

				self.init(
					hasChanges: try container.decode(Bool.self, forKey: .hasChanges),
					backoff: try container.decodeIfPresent(UInt64.self, forKey: .backoff) ?? 60
				)
			}

		}

		enum Error: API.Error {

			case reset

			init(summary: Summary) throws {
				switch summary.component {
				case "reset":
					self = .reset
				default:
					throw summary
				}
			}

		}

	}

}
