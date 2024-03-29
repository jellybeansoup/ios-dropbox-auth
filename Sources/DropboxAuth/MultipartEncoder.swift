import Foundation

protocol MultipartEncodable {

	func encode(to encoder: MultipartEncoder)

}

final class MultipartEncoder {

	private let store: MultipartStore

	init(boundary: String) {
		self.store = .init(boundary: boundary)
	}

	convenience init() {
		self.init(boundary: UUID().uuidString)
	}

	var boundary: String {
		store.boundary
	}

	func encode<T: MultipartEncodable>(_ value: T) -> Data {
		value.encode(to: self)
		return store.finalize()
	}

	func container<Key: CodingKey>(keyedBy: Key.Type) -> KeyedContainer<Key> {
		.init(store: store)
	}

	struct KeyedContainer<Key: CodingKey> {

		fileprivate let store: MultipartStore

		func encode(_ string: String, forKey key: Key) {
			store.encode(key: key, value: string)
		}

		func encodeIfPresent(_ string: String?, forKey key: Key) {
			guard let string else {
				return
			}

			encode(string, forKey: key)
		}

	}

}

private final class MultipartStore {

	let boundary: String

	private var data = Data()

	init(boundary: String) {
		self.boundary = boundary.replacingOccurrences(of: "\\W", with: "_", options: .regularExpression)
	}

	func encode(key codingKey: CodingKey, value: String) {
		data += Data("--\(boundary)\r\n".utf8)
		data += Data("Content-Disposition: form-data; name=\"\(codingKey.stringValue)\"\r\n\r\n".utf8)
		data += Data("\(value)\r\n".utf8)
	}

	func finalize() -> Data {
		data + Data("--\(boundary)--\r\n".utf8)
	}

}
