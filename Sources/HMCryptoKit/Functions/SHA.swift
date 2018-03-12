//
//  SHA.swift
//  HMCryptoKit
//
//  Created by Mikk Rätsep on 12/03/2018.
//

import Foundation
import COpenSSL


extension HMCryptoKit {

    static func sha256<C: Collection>(message: C) throws -> [UInt8] where C.Element == UInt8 {
        var digest = [UInt8](zeroFilledTo: Int(SHA256_DIGEST_LENGTH))

        guard SHA256(message.bytes, Int(message.count), &digest) != nil else {
            throw HMCryptoKitError.internalSecretError
        }

        return digest
    }
}
