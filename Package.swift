// swift-tools-version:5.1
import PackageDescription

let package = Package(
    name: "DropboxAuth",
	platforms: [.iOS("13.0")],
    products: [
        .library(name: "DropboxAuth", targets: ["DropboxAuthSwift"])
    ],
    targets: [
		.target(
			name: "DropboxAuth",
			dependencies: [],
			//sources: ["DropboxAuth.h"],
			publicHeadersPath: "."
		),
		.target(
			name: "DropboxAuthSwift"
		),
		.testTarget(
			name: "DropboxAuthTests",
			dependencies: ["DropboxAuthSwift"]
		)
    ]
)
