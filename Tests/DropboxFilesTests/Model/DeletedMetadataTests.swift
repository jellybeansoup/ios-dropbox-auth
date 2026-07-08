import Foundation
@testable import DropboxFiles
import Testing

@Suite struct DeletedMetadataTests {

	@Test func memberwiseInitializerAssignsAllFields() {
		let metadata = DeletedMetadata(
			name: "Prime_Numbers.txt",
			pathLower: "/homework/math/prime_numbers.txt",
			pathDisplay: "/Homework/math/Prime_Numbers.txt"
		)

		#expect(metadata.name == "Prime_Numbers.txt")
		#expect(metadata.pathLower == "/homework/math/prime_numbers.txt")
		#expect(metadata.pathDisplay == "/Homework/math/Prime_Numbers.txt")
	}

	// `DeletedMetadata` doesn't declare direct `Decodable` conformance (its `init(from:)` is only
	// ever invoked via the polymorphic `MetadataDecodingContainer`, keyed on `.tag`), so decoding
	// is exercised through that container — the live decode path for delta-snapshot deletions.

	@Test func decoding() throws {
		let data = Data("""
		{
			".tag": "deleted",
			"name": "Prime_Numbers.txt",
			"path_lower": "/homework/math/prime_numbers.txt",
			"path_display": "/Homework/math/Prime_Numbers.txt"
		}
		""".utf8)

		let container = try JSONDecoder().decode(MetadataDecodingContainer.self, from: data)

		let metadata = try #require(container.value as? DeletedMetadata)
		#expect(metadata.name == "Prime_Numbers.txt")
		#expect(metadata.pathLower == "/homework/math/prime_numbers.txt")
		#expect(metadata.pathDisplay == "/Homework/math/Prime_Numbers.txt")
	}

	@Test func decodingWithoutPaths() throws {
		let data = Data("""
		{
			".tag": "deleted",
			"name": "Prime_Numbers.txt",
			"path_lower": null,
			"path_display": null
		}
		""".utf8)

		let container = try JSONDecoder().decode(MetadataDecodingContainer.self, from: data)

		let metadata = try #require(container.value as? DeletedMetadata)
		#expect(metadata.name == "Prime_Numbers.txt")
		#expect(metadata.pathLower == nil)
		#expect(metadata.pathDisplay == nil)
	}

}
