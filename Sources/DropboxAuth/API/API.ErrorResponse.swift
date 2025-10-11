import Foundation

extension API {

	struct ErrorResponse<Error: API.Error>: Decodable {

		var error: Error

		private enum CodingKeys: String, CodingKey {
			case error
			case errorSummary = "error_summary"
		}

		init(from decoder: Decoder) throws {
			let container = try decoder.container(keyedBy: CodingKeys.self)

			let summary: API.Error.Summary
			do {
				summary = try container.decode(API.Error.Summary.self, forKey: .errorSummary)
			}
			catch {
				summary = try container.decode(API.Error.Summary.self, forKey: .error)
			}

			do {
				self.error = try Error(summary: summary)
			}
			catch is API.Error.Summary {
				throw summary
			}
			catch {
				throw error
			}
		}

	}

}
