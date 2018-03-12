//
//  AES.swift
//  HMCryptoKit
//
//  Created by Mikk Rätsep on 09/03/2018.
//

import Foundation

#if os(iOS) || os(tvOS) || os(watchOS)
    import CommonCrypto
#else
    import COpenSSL
#endif


public let kBlockCipherKeySize = 128

public var kEncryptionBlockSize: Int {
    return kBlockCipherKeySize / 8
}


public extension HMCryptoKit {

    static func encryptDecrypt<C: Collection>(message: C, iv: C, key: C) throws -> [UInt8] where C.Element == UInt8 {
        guard key.count >= kEncryptionBlockSize,
               iv.count == kEncryptionBlockSize else {
                throw HMCryptoKitError.internalSecretError
        }

        #if os(iOS) || os(tvOS) || os(watchOS)
            var cipher = [UInt8](zeroFilledTo: kEncryptionBlockSize)
            let status = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionECBMode),    // Configuration
                                 key.bytes.prefix(kEncryptionBlockSize).bytes, kEncryptionBlockSize,                    // Key
                                 nil,                                                                                   // ECB doesn't use an IV
                                 iv.bytes, Int(iv.count),                                                               // IV as the "dataIn"
                                 &cipher, cipher.count,                                                                 // Cipher output
                                 nil)                                                                                   // Output length

            guard status == CCCryptorStatus(kCCSuccess) else {
                throw HMCryptoKitError.internalSecretError
            }

            return message.enumerated().map {
                $0.element ^ cipher.bytes[$0.offset % kEncryptionBlockSize]
            }
        #else
            let additionalCount = Int(message.count) % kEncryptionBlockSize
            var output = [UInt8](zeroFilledTo: Int(message.count))
            var additionalOutput = [UInt8](zeroFilledTo: additionalCount)
            var len: Int32 = 0

            guard let ctx = EVP_CIPHER_CTX_new(),
                EVP_EncryptInit(ctx, EVP_aes_128_ctr(), key.bytes.prefix(kEncryptionBlockSize).bytes, iv.bytes) == 1,
                EVP_EncryptUpdate(ctx, &output, &len, message.bytes, Int32(message.count)) == 1,
                EVP_EncryptFinal(ctx, &additionalOutput, &len) == 1 else {
                    throw HMCryptoKitError.internalSecretError
            }

            return output + additionalOutput
        #endif
    }

    static func iv<C: Collection>(nonce: C, transactionNonce: C) -> [UInt8] where C.Element == UInt8 {
        return nonce.bytes.prefix(7).bytes + transactionNonce
    }
}
