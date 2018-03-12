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

        var digest = [UInt8](zeroFilledTo: 32)
        
        guard HMAC(hashFunction, key.bytes, Int32(key.count), message.bytes, Int(message.count), &digest, nil) != nil else {
            throw HMCryptoKitError.internalSecretError
        }

        return digest
    }

    static func verify<C: Collection>(hmac: C, message: C, key: C) throws -> Bool where C.Element == UInt8 {
        return try self.hmac(message: message, key: key) == hmac.bytes
    }
}
