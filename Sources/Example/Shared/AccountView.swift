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

import SwiftUI
import DropboxAuth

struct AccountView: View {

	@State var string: String = "Loading account details…"

	let accessToken: AccessToken

	var body: some View {
		Text(string)
			.onAppear(perform: loadAccountDetails)
	}

	enum Response: Decodable {
		case account(email: String)
		case error(summary: String)

		enum CodingKeys: String, CodingKey {
			case email
			case errorSummary = "error_summary"
		}

		init(from decoder: Decoder) throws {
			let container = try decoder.container(keyedBy: CodingKeys.self)

			do {
				self = .account(email: try container.decode(String.self, forKey: .email))
			}
			catch {
				self = .error(summary: try container.decode(String.self, forKey: .errorSummary))
			}
		}

	}

	private func loadAccountDetails() {
		Task {
			let url = URL(string: "https://api.dropboxapi.com/2/users/get_current_account")!

			let accessToken: AccessToken
			do {
				accessToken = try await self.accessToken.refreshed(force: true)
			}
			catch {
				print("Refreshing access token failed: \(error)")
				accessToken = self.accessToken
			}

			var request = accessToken.signedRequest(with: url)
			request.httpMethod = "POST"

			do {
				let (data, _) = try await URLSession.shared.data(for: request)
				let response = try JSONDecoder().decode(Response.self, from: data)

				switch response {
				case .account(let email):
					string = email

				case .error(let summary):
					string = "Failed to load account details: \(summary)"
				}
			}
			catch {
				string = "Failed to load account details: \(error)"
			}
		}
	}

}
