import Foundation

extension API {

	struct ErrorResponse<Error: API.Error>: Decodable {

		var error: Error

		private enum CodingKeys: String, CodingKey {
			case errorSummary = "error_summary"
		}

		init(from decoder: Decoder) throws {
			let container = try decoder.container(keyedBy: CodingKeys.self)
			let summary = try container.decode(API.Error.Summary.self, forKey: .errorSummary)

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
