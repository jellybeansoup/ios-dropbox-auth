import Foundation
import DropboxAuth

enum TemplateError: String, Error, API.Error {

	case notFound = "template_not_found"

	case restrictedContent = "restricted_content"

}
