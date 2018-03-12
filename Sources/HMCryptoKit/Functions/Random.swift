//
//  Random.swift
//  HMCryptoKit
//
//  Created by Mikk Rätsep on 06/03/2018.
//

import Foundation

#if os(iOS) || os(tvOS) || os(watchOS)
    import CommonCrypto
#else
    import COpenSSL
#endif


public let kNonceSize           = 9
public let kSerialNumberSize    = 9


public extension HMCryptoKit {

    static func nonce(_ length: Int = kNonceSize) throws -> [UInt8] {
        return try randomBytes(length)
    }

    static func serial(_ length: Int = kSerialNumberSize) throws -> [UInt8] {
        return try randomBytes(length)
    }
}

private extension HMCryptoKit {

    static func randomBytes(_ length: Int) throws -> [UInt8] {
        var bytes = [UInt8](zeroFilledTo: length)

        #if os(iOS) || os(tvOS) || os(watchOS)
            guard CCRandomGenerateBytes(&bytes, length) == kCCSuccess else {
                throw HMCryptoKitError.internalSecretError
            }
        #else
            guard RAND_bytes(&bytes, Int32(length)) == 1 else {
                // TODO: Get the error from ERR_get_error
                throw HMCryptoKitError.internalSecretError
            }
        #endif

        return bytes
    }
}
