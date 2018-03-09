// swift-tools-version:4.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "HMCryptoKit",
    products: [
        .library(name: "HMCryptoKit", targets: ["HMCryptoKit"]),
    ],
    dependencies: [
        .package(url: "https://github.com/highmobility/copenssl", .branch("master")),
    ],
    targets: [
        .target(name: "HMCryptoKit", dependencies: []),
        .target(name: "HMCryptoKitCLT", dependencies: ["HMCryptoKit"]),
        .testTarget(name: "HMCryptoKitTests", dependencies: ["HMCryptoKit"]),
    ]
)
