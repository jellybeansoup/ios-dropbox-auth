// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "DropboxAuth",
	platforms: [.iOS("13.0")],
    products: [
		.library(name: "DropboxAuth", targets: ["DropboxAuth"])
    ],
    targets: [
		.target(
			name: "DropboxAuth",
			swiftSettings: [
				.enableExperimentalFeature("StrictConcurrency")
			]
		),
		.testTarget(
			name: "DropboxAuthTests",
			dependencies: ["DropboxAuth"],
			swiftSettings: [
				.enableExperimentalFeature("StrictConcurrency")
			]
		)
    ]
)
