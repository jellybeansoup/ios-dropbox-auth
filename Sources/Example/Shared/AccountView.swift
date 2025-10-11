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

import SwiftUI
import DropboxAuth

struct AccountView: View {

	@MainActor
	class ViewModel: ObservableObject {

		private enum Response: Decodable {
			case account(email: String)
			case error(AuthenticationError)

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
					let errorSummary = try container.decode(API.ErrorSummary.self, forKey: .errorSummary)
					let error = try AuthenticationError(summary: errorSummary)
					self = .error(error)
				}
			}

		}

		private let authManager: AuthManager

		private let transport: Transport

		private var accessToken: AccessToken

		@Published var string: String = "Loading account details…"

		var loadAccountTask: Task<Void, Never>?

		init(accessToken: AccessToken) {
			self.authManager = AuthManager(key: "d25u9w2pgql046o")
			self.transport = Transport(authManager: authManager, token: accessToken)
			self.accessToken = accessToken
		}

		func loadAccountDetails() async {
			do {
				let currentAccount = try await transport.getCurrentAccount()
				update(with: currentAccount.email)
			}
			catch {
				update(with: "Failed to decode account details: \(error.localizedDescription)")
			}
		}

		@MainActor
		private func update(with string: String) {
			self.string = string
		}

	}

	@ObservedObject private var viewModel: ViewModel

	init(accessToken: AccessToken) {
		self.viewModel = ViewModel(accessToken: accessToken)
	}

	var body: some View {
		Text(viewModel.string)
			.onAppear {
				viewModel.loadAccountTask = Task {
					await viewModel.loadAccountDetails()
				}
			}
	}

}
