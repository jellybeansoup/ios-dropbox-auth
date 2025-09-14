// swift-tools-version:6.2
import PackageDescription

let package = Package(
    name: "DropboxAuth",
	defaultLocalization: "en",
	platforms: [
		.iOS("13.0"),
		.macOS("10.15"),
	],
    products: [
		.library(name: "DropboxAuth", targets: ["DropboxAuth"]),
		.library(name: "DropboxFiles", targets: ["DropboxFiles"]),
    ],
    targets: [

		.target(
			name: "DropboxAuth"
		),
		.target(
			name: "DropboxAuthMocks",
			dependencies: ["DropboxAuth"],
			path: "Tests/DropboxAuthMocks"
		),
		.testTarget(
			name: "DropboxAuthTests",
			dependencies: ["DropboxAuthMocks", "DropboxAuth"]
		),

		.target(
			name: "DropboxFiles",
			dependencies: ["DropboxAuth"]
		),
		.testTarget(
			name: "DropboxFilesTests",
			dependencies: ["DropboxAuthMocks", "DropboxFiles"]
		)

	]
)
