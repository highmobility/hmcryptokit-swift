//
// HMCryptoKit
// Copyright (C) 2019 High-Mobility GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.
//
// Please inquire about commercial licensing options at
// licensing@high-mobility.com
//
//
//  AES.swift
//  HMCryptoKit
//
//  Created by Mikk Rätsep on 09/03/2018.
//  Copyright © 2019 High Mobility GmbH. All rights reserved.
//

import Foundation

#if os(iOS) || os(tvOS) || os(watchOS)
    import CommonCrypto

    public let kCipherAndKeySize = kCCKeySizeAES128
#else
    import COpenSSL

    public let kCipherAndKeySize = 128 / 8
#endif


public extension HMCryptoKit {

    /// En-/decrypt the message using an injection vector and the key.
    ///
    /// - Parameters:
    ///   - message: A message to be en-/decrypted.
    ///   - iv: Injection vector, pseudounique 16 bytes for seeding the encryption cipher.
    ///   - key: Key to use for en-/decryption, must be at least 16 bytes.
    /// - Returns: The ciphertext (en-/decrypted message) as bytes, same length as the message.
    /// - Throws: `HMCryptoKitError`
    /// - SeeAlso: `iv(nonce:transactionNonce:)`
    static func encryptDecrypt<C: Collection>(message: C, iv: C, key: C) throws -> [UInt8] where C.Element == UInt8 {
        guard iv.count == kCipherAndKeySize else {
            throw HMCryptoKitError.invalidInputSize("iv")
        }

        guard key.count >= kCipherAndKeySize else {
            throw HMCryptoKitError.invalidInputSize("key")
        }

        let keyBytes = Array(key.prefix(kCipherAndKeySize))
        let ivBytes = Array(iv)

        #if os(iOS) || os(tvOS) || os(watchOS)
            var cipher = [UInt8](zeroFilledTo: kCipherAndKeySize)
            let status = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionECBMode),    // Configuration
                                 keyBytes, kCipherAndKeySize,                                                           // Key
                                 nil,                                                                                   // ECB doesn't use an IV
                                 ivBytes, Int(iv.count),                                                                // IV as the "dataIn"
                                 &cipher, cipher.count,                                                                 // Cipher output
                                 nil)                                                                                   // Output length

            guard status == CCCryptorStatus(kCCSuccess) else {
                throw HMCryptoKitError.commonCryptoError(status)
            }

            return message.enumerated().map {
                $0.element ^ cipher[$0.offset % kCipherAndKeySize]
            }
        #else
            let additionalCount = Int(message.count) % kCipherAndKeySize
            let messageBytes = Array(message)
            var output = [UInt8](zeroFilledTo: Int(message.count))
            var additionalOutput = [UInt8](zeroFilledTo: additionalCount)
            var len: Int32 = 0

            guard let ctx = EVP_CIPHER_CTX_new(),
                EVP_EncryptInit(ctx, EVP_aes_128_ctr(), keyBytes, ivBytes) == 1,
                EVP_EncryptUpdate(ctx, &output, &len, messageBytes, Int32(message.count)) == 1,
                EVP_EncryptFinal(ctx, &additionalOutput, &len) == 1 else {
                    throw HMCryptoKitError.openSSLError(getOpenSSLError())
            }

            return output + additionalOutput
        #endif
    }

    /// Combine an injection vector.
    ///
    /// - Parameters:
    ///   - nonce: Pseudounique bytes (number only once), at least 7 bytes.
    ///   - transactionNonce: Pseudounique bytes (number only once), at least 9 bytes.
    /// - Returns: The 16 bytes of an injection vector.
    /// - Throws: `HMCryptoKitError`
    /// - SeeAlso: `encryptDecrypt(message:iv:key:)`
    static func iv<C: Collection>(nonce: C, transactionNonce: C) throws -> [UInt8] where C.Element == UInt8 {
        guard nonce.count >= 7 else {
            throw HMCryptoKitError.invalidInputSize("nonce")
        }

        guard transactionNonce.count >= 9 else {
            throw HMCryptoKitError.invalidInputSize("transactionNonce")
        }

        let nonceBytes = Array(nonce)
        let transactionNonceBytes = Array(transactionNonce)

        return Array(nonceBytes.prefix(7) + transactionNonceBytes.prefix(9))
    }
}
