# HMCryptoKit iOS SDK

The HMCryptoKit iOS SDK is a collection of cryptographic functions, centered around Elliptic Curve Cryptography, needed in [HMKit](https://github.com/highmobility/hmkit-swift) and is based on Apple's [Security](https://developer.apple.com/documentation/Security) and [CommonCrypto](https://developer.apple.com/library/archive/documentation/Security/Conceptual/cryptoservices/Introduction/Introduction.html) libraries.

Security overview can be read [here](https://high-mobility.com/learn/documentation/security/overview/).

Table of contents
=================
<!--ts-->
   * [Features](#features)
   * [Integration](#integration)
   * [Requirements](#requirements)
   * [Contributing](#contributing)
   * [Licence](#licence)
<!--te-->


## Features

**ECC**: Uses well established *Elliptic Curve Cryptography*'s curve *p256* (that is as secure as RSA, while having a smaller footprint).

**De-/Encrypt**: Enables simple encryption and decryption with *AES128*.

**Keys**: Perform *Diffie-Hellman*'s key exchange using *X9.63 SHA256* algorithm. Additionally 
convert keys back and forth between bytes and Apple's `SecKey` format.

**Random**: Create pseudo-random bytes for cryptographic functions or as unique IDs.

**Signatures**: Create and verify *Elliptic Curve Digital Signature Algorithm* (ECDSA) *X9.62 SHA256* or *HMAC* signatures.


## Integration

It's **recommended** to use the library through *Swift Package Manager* (SPM), which is now also built-in to Xcode and accessible in `File > Swift Packages > ...` or  going to project settings and selecting `Swift Packages` in the top-center.  
When targeting a Swift package, the `Package.swift` file must include `.package(url: "https://github.com/highmobility/hmcryptokit-swift", .upToNextMinor(from: "[__version__]")),` under *dependencies*.
  

If SPM is not possible, the source can be downloaded directly from Github
and built into an `.xcframework` using an accompaning script: [XCFrameworkBuilder.sh](https://github.com/highmobility/hmcryptokit-swift/tree/master/Scripts/XCFrameworkBuilder.sh). The created package includes both the simulator and device binaries, which must then be dropped (linked) to the target Xcode project.

Furthermore, when `.xcframework` is also not suitable, the library can be made into a *fat binary* (`.framework`) by running [UniversalBuildScript.sh](https://github.com/highmobility/hmcryptokit-swift/tree/master/Scripts/UniversalBuildScript.sh). This combines both simulator and device slices into one binary, but requires the simulator slice to be removed *before* being able to upload to *App Store Connect* – for this there is a [AppStoreCompatible.sh](https://github.com/highmobility/hmcryptokit-swift/tree/master/Scripts/AppStoreCompatible.sh) script included inside the created `.framework` folder.


## Requirements

HMCryptoKit iOS SDK requires Xcode 11.0 or later and is compatible with apps targeting iOS 10.0 or above.


## Contributing

We would love to accept your patches and contributions to this project. Before getting to work, please first discuss the changes that you wish to make with us via [GitHub Issues](https://github.com/highmobility/hmcryptokit-swift/issues), [Spectrum](https://spectrum.chat/high-mobility/) or [Slack](https://slack.high-mobility.com/).

To start developing HMCryptoKit, please run `git clone git@github.com:highmobility/hmcryptokit-swift.git` and open the Xcode project (Xcode will handle the dependencies itself). Releases are done by tagged commits (as required by SPM, please read more about it [here](https://swift.org/getting-started/#using-the-package-manager) and [here](https://github.com/apple/swift-package-manager/tree/master/Documentation)).

See more in [CONTRIBUTING.md](https://github.com/highmobility/hmcryptokit-swift/tree/master/CONTRIBUTING.md)


## Licence

This repository is using MIT licence. See more in [LICENCE](https://github.com/highmobility/hmcryptokit-swift/tree/master/LICENSE)
