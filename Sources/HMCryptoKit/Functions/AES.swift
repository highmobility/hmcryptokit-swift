//
//  The MIT License
//
//  Copyright (c) 2014- High-Mobility GmbH (https://high-mobility.com)
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
//
//
//  AES.swift
//  HMCryptoKit
//
//  Created by Mikk Rätsep on 09/03/2018.
//

import Foundation
import CommonCrypto

public let kCipherAndKeySize = kCCKeySizeAES128


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
