// swift-tools-version:4.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "HMCryptoKit",
    products: [
        .library(name: "HMCryptoKit", targets: ["HMCryptoKit"]),
        .library(name: "HMCryptoKitCommandsInfo", targets: ["HMCryptoKitCommandsInfo"]),
    ],
    dependencies: [
        .package(url: "https://github.com/IBM-Swift/CommonCrypto", from: "1.0.0"),
        .package(url: "https://github.com/vapor/copenssl", .branch("master")),
        .package(url: "https://github.com/highmobility/hm-utilities-swift", .branch("master")),
    ],
    targets: [
        .target(name: "HMCryptoKit", dependencies: ["HMUtilities"]),
        .target(name: "HMCryptoKitCommandsInfo", dependencies: ["HMCryptoKit"]),
        .target(name: "HMCryptoKitCLT", dependencies: ["HMCryptoKit", "HMCryptoKitCommandsInfo"]),
        .testTarget(name: "HMCryptoKitTests", dependencies: ["HMCryptoKit"]),
    ]
)
