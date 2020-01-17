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
//  HMAC.swift
//  HMCryptoKit
//
//  Created by Mikk Rätsep on 07/03/2018.
//

import Foundation
import CommonCrypto


public extension HMCryptoKit {

    /// Generate an HMAC (hashed message authentication code) for the message.
    ///
    /// The HMAC is generated with SHA256.
    ///
    /// - Parameters:
    ///   - message: Message to generated the code for.
    ///   - key: Key to use for generation, must be 32 bytes.
    /// - Returns: The 32 bytes of the HMAC.
    /// - Throws: `HMCryptoKitError`
    /// - SeeAlso: `verify(hmac:message:key:)`
    static func hmac<C: Collection>(message: C, key: C) throws -> [UInt8] where C.Element == UInt8 {
        guard key.count == 32 else {
            throw HMCryptoKitError.invalidInputSize("key")
        }

        let keyBytes = Array(key)
        let messageBytes = Array(message)

        let modulo = message.count % 64
        let paddedMessage = messageBytes + [UInt8](zeroFilledTo: (modulo == 0) ? 0 : (64 - modulo))
        var digest = [UInt8](zeroFilledTo: 32)
        
        CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), keyBytes, Int(key.count), paddedMessage, paddedMessage.count, &digest)
        
        guard digest != [UInt8](zeroFilledTo: 32) else {
            throw HMCryptoKitError.commonCryptoError(CCCryptorStatus(kCCUnspecifiedError))
        }

        return digest
    }

    /// Verifies an HMAC for a message with the key.
    ///
    /// - Parameters:
    ///   - hmac: The HMAC to verify, must be 32 bytes.
    ///   - message: The message the HMAC was for.
    ///   - key: The key used to generate the HMAC, must be 32 bytes.
    /// - Returns: Bool value if the verification succeeded.
    /// - Throws: `HMCryptoKitError`
    /// - SeeAlso: `hmac(message:key:)`
    static func verify<C: Collection>(hmac: C, message: C, key: C) throws -> Bool where C.Element == UInt8 {
        return try self.hmac(message: message, key: key) == Array(hmac)
    }
}
