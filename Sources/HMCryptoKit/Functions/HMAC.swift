//
//  HMAC.swift
//  HMCryptoKit
//
//  Created by Mikk Rätsep on 07/03/2018.
//

import COpenSSL
import Foundation


public extension HMCryptoKit {

    static func hmac<C: Collection>(message: C, key: C) throws -> [UInt8] where C.Element == UInt8 {
        guard let hashFunction = EVP_sha256() else {
            throw HMCryptoKitError.internalSecretError
        }

        var digest = [UInt8](repeating: 0x00, count: 32)
        
        guard HMAC(hashFunction, key.bytes, Int32(key.count), message.bytes, Int(message.count), &digest, nil) != nil else {
            throw HMCryptoKitError.internalSecretError
        }

        return digest
    }

    // TODO: Delete after testing
    static func hmac2<C: Collection>(message: C, key: C) throws -> [UInt8] where C.Element == UInt8 {
        guard let hashFunction = EVP_sha256() else {
            throw HMCryptoKitError.internalSecretError
        }

        let paddedMessage = message.bytes + [UInt8](repeating: 0x00, count: (256 - Int(message.count % 256)))
        var ctx = HMAC_CTX()
        var digest = [UInt8](repeating: 0x00, count: 32)

        HMAC_CTX_init(&ctx)

        defer {
            HMAC_CTX_cleanup(&ctx)
        }

        guard HMAC_Init_ex(&ctx, key.bytes, Int32(key.count), hashFunction, nil) == 1,
            HMAC_Update(&ctx, paddedMessage, paddedMessage.count) == 1,
            HMAC_Final(&ctx, &digest, nil) == 1 else {
                throw HMCryptoKitError.internalSecretError
        }

        return digest
    }

    static func verify<C: Collection>(hmac: C, message: C, key: C) throws -> Bool where C.Element == UInt8 {
        return try self.hmac(message: message, key: key) == hmac.bytes
    }
}
