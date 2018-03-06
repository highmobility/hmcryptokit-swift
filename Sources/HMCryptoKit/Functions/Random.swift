//
//  Random.swift
//  HMCryptoKit
//
//  Created by Mikk Rätsep on 06/03/2018.
//

import Foundation

#if os(Linux)
    import COpenSSL
#else
    import Security
#endif


public let kNonceSize           = 9
public let kSerialNumberSize    = 9


public extension HMCryptoKit {

    static func nonce(_ length: Int = kNonceSize) throws -> [UInt8] {
        return try GenerateRandomBytes(length)
    }

    static func serial(_ length: Int = kSerialNumberSize) throws -> [UInt8] {
        return try GenerateRandomBytes(length)
    }
}

private extension HMCryptoKit {

    static func GenerateRandomBytes(_ length: Int) throws -> [UInt8] {
        var bytes = [UInt8](repeating: 0x00, count: length)

        #if os(Linux)
            guard RAND_bytes(&bytes, Int32(length)) == 1 else {
                // TODO: Get the error from ERR_get_error
                throw HMCryptoKitError.internalSecretError
            }
        #else
            guard SecRandomCopyBytes(kSecRandomDefault, length, &bytes) == 0 else {
                throw HMCryptoKitError.systemError(errno)
            }
        #endif

        return bytes
    }
}
