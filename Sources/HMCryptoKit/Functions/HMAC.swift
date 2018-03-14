//
//  HMAC.swift
//  HMCryptoKit
//
//  Created by Mikk Rätsep on 07/03/2018.
//

import Foundation

#if os(iOS) || os(tvOS) || os(watchOS)
    import CommonCrypto
#else
    import COpenSSL
#endif


public extension HMCryptoKit {

    static func hmac<C: Collection>(message: C, key: C) throws -> [UInt8] where C.Element == UInt8 {
        guard key.count == 32 else {
            throw HMCryptoKitError.invalidInputSize("key")
        }

        let paddedMessage = message.bytes + [UInt8](zeroFilledTo: 64 - (Int(message.count) % 64))
        var digest = [UInt8](zeroFilledTo: 32)

        #if os(iOS) || os(tvOS) || os(watchOS)
            CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), key.bytes, Int(key.count), paddedMessage.bytes, Int(paddedMessage.count), &digest)

            guard digest != [UInt8](zeroFilledTo: 32) else {
                throw HMCryptoKitError.commonCryptoError(CCCryptorStatus(kCCUnspecifiedError))
            }
        #else
            guard let hashFunction = EVP_sha256(),
                HMAC(hashFunction, key.bytes, Int32(key.count), paddedMessage.bytes, Int(paddedMessage.count), &digest, nil) != nil else {
                    throw HMCryptoKitError.openSSLError(getOpenSSLError())
            }
        #endif

        return digest
    }

    static func verify<C: Collection>(hmac: C, message: C, key: C) throws -> Bool where C.Element == UInt8 {
        return try self.hmac(message: message, key: key) == hmac.bytes
    }
}
