// swift-tools-version:5.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "HMCryptoKit",
    platforms: [
        .iOS(.v10)
    ],
    products: [
        .library(name: "HMCryptoKit", targets: ["HMCryptoKit"]),
        .library(name: "HMCryptoKitCommandsInfo", targets: ["HMCryptoKitCommandsInfo"]),
    ],
    dependencies: [
        .package(url: "https://github.com/highmobility/hm-utilities-swift", .upToNextMinor(from: "1.4.1")),
    ],
    targets: [
        .target(name: "HMCryptoKit", dependencies: ["HMUtilities"]),
        .target(name: "HMCryptoKitCommandsInfo", dependencies: ["HMCryptoKit"]),
        .testTarget(name: "HMCryptoKitTests", dependencies: ["HMCryptoKit"]),
    ]
)
