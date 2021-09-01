// swift-tools-version:5.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "HMCryptoKit",
    platforms: [
        .iOS(.v10),
        .macOS(.v10_13)
    ],
    products: [
        .library(name: "HMCryptoKit", targets: ["HMCryptoKit"]),
    ],
    dependencies: [
        .package(url: "https://github.com/highmobility/hmutilities-swift", .upToNextMinor(from: "1.4.1")),
    ],
    targets: [
        .target(name: "HMCryptoKit", dependencies: ["HMUtilities"]),
        .testTarget(name: "HMCryptoKitTests", dependencies: ["HMCryptoKit"]),
    ]
)
