//
// HMCryptoKit
// Copyright (C) 2018 High-Mobility GmbH
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

        let modulo = message.count % 64
        let paddedMessage = message.bytes + [UInt8](zeroFilledTo: (modulo == 0) ? 0 : (64 - modulo))
        var digest = [UInt8](zeroFilledTo: 32)

        #if os(iOS) || os(tvOS) || os(watchOS)
            CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), key.bytes, Int(key.count), paddedMessage.bytes, paddedMessage.count, &digest)

            guard digest != [UInt8](zeroFilledTo: 32) else {
                throw HMCryptoKitError.commonCryptoError(CCCryptorStatus(kCCUnspecifiedError))
            }
        #else
            guard let hashFunction = EVP_sha256(),
                HMAC(hashFunction, key.bytes, Int32(key.count), paddedMessage.bytes, paddedMessage.count, &digest, nil) != nil else {
                    throw HMCryptoKitError.openSSLError(getOpenSSLError())
            }
        #endif

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
        return try self.hmac(message: message, key: key) == hmac.bytes
    }
}
