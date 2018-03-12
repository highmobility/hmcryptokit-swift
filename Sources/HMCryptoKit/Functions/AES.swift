//
//  AES.swift
//  HMCryptoKit
//
//  Created by Mikk Rätsep on 09/03/2018.
//

import COpenSSL
import Foundation


public let kBlockCipherKeySize = 128

public var kEncryptionBlockSize: Int {
    return kBlockCipherKeySize / 8
}


public extension HMCryptoKit {

    static func encryptDecrypt<C: Collection>(message: C, iv: C, key: C) throws -> [UInt8] where C.Element == UInt8 {
        guard (key.count >= kEncryptionBlockSize) && (iv.count == kEncryptionBlockSize) else {
            throw HMCryptoKitError.internalSecretError
        }

        let additionalCount = Int(message.count) % kEncryptionBlockSize
        var output = [UInt8](zeroFilledTo: Int(message.count))
        var additionalOutput = [UInt8](zeroFilledTo: additionalCount)
        var len: Int32 = 0

        guard let ctx = EVP_CIPHER_CTX_new(),
            EVP_EncryptInit(ctx, EVP_aes_128_ctr(), key.bytes.prefix(16).bytes, iv.bytes) == 1,
            EVP_EncryptUpdate(ctx, &output, &len, message.bytes, Int32(message.count)) == 1,
            EVP_EncryptFinal(ctx, &additionalOutput, &len) == 1 else {
                throw HMCryptoKitError.internalSecretError
        }

        return output + additionalOutput
    }
}
