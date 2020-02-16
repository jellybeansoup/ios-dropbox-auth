// swift-tools-version:5.1
import PackageDescription

let package = Package(
    name: "DropboxAuth",
	platforms: [.iOS("8.4")],
    products: [
        .library(name: "DropboxAuth", targets: ["DropboxAuth"])
    ],
    targets: [
        .target(
            name: "DropboxAuth",
			dependencies: [],
            path: "src/DropboxAuth",
            //sources: ["DropboxAuth.h"],
			publicHeadersPath: "."
        )
    ]
)
