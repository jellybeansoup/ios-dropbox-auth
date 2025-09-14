import Foundation
import DropboxAuth

enum LookupError: String, Error, API.Error {

	case malformedPath = "malformed_path"

	case notFound = "not_found"

	case notFile = "not_file"

	case notFolder = "not_folder"

	case restrictedContent = "restricted_content"

	case unsupportedContentType = "unsupported_content_type"

	case locked

}
