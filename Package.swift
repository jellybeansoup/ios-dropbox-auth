// swift-tools-version:5.1
import PackageDescription

let package = Package(
    name: "DropboxAuth",
	platforms: [.iOS("13.0")],
    products: [
		.library(name: "DropboxAuth", targets: ["DropboxAuth"])
    ],
    targets: [
		.target(
			name: "DropboxAuth"
		),
		.testTarget(
			name: "DropboxAuthTests",
			dependencies: ["DropboxAuth"]
		)
    ]
)
