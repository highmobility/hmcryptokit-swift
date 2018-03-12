//
//  SHA.swift
//  HMCryptoKit
//
//  Created by Mikk Rätsep on 12/03/2018.
//

import Foundation

#if os(iOS) || os(tvOS) || os(watchOS)
    import CommonCrypto

    let kDigestLength = CC_SHA256_DIGEST_LENGTH
#else
    import COpenSSL

    let kDigestLength = SHA256_DIGEST_LENGTH
#endif


extension HMCryptoKit {

    static func sha256<C: Collection>(message: C) throws -> [UInt8] where C.Element == UInt8 {
        var digest = [UInt8](zeroFilledTo: Int(kDigestLength))

        #if os(iOS) || os(tvOS) || os(watchOS)
            guard CC_SHA256(message.bytes, CC_LONG(message.count), &digest) != nil else {
                throw HMCryptoKitError.internalSecretError
            }
        #else
            guard SHA256(message.bytes, Int(message.count), &digest) != nil else {
                throw HMCryptoKitError.internalSecretError
            }
        #endif

        return digest
    }
}
