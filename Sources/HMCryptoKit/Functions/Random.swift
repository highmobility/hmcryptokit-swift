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
//  Random.swift
//  HMCryptoKit
//
//  Created by Mikk Rätsep on 06/03/2018.
//  Copyright © 2019 High Mobility GmbH. All rights reserved.
//

import Foundation

#if os(iOS) || os(tvOS) || os(watchOS)
    import CommonCrypto
#else
    import COpenSSL
#endif


public let kNonceSize           = 9
public let kSerialNumberSize    = 9


public extension HMCryptoKit {

    /// Generate a nonce (number only once).
    ///
    /// - Parameter length: The length of the desired nonce, defaults to 9 bytes.
    /// - Returns: The nonce bytes.
    /// - Throws: `HMCryptoKitError`
    /// - SeeAlso: `randomBytes(_:)`
    static func nonce(_ length: Int = kNonceSize) throws -> [UInt8] {
        return try randomBytes(length)
    }

    /// Generate random bytes array of input length.
    ///
    /// - Parameter length: The length of the array.
    /// - Returns: The random bytes.
    /// - Throws: `HMCryptoKitError`
    static func randomBytes(_ length: Int) throws -> [UInt8] {
        var bytes = [UInt8](zeroFilledTo: length)

        #if os(iOS) || os(tvOS) || os(watchOS)
            guard CCRandomGenerateBytes(&bytes, length) == kCCSuccess else {
                throw HMCryptoKitError.systemError(errno)
            }
        #else
            guard RAND_bytes(&bytes, Int32(length)) == 1 else {
                throw HMCryptoKitError.openSSLError(getOpenSSLError())
            }
        #endif

        return bytes
    }

    /// Generate a serial number.
    ///
    /// - Parameter length: The length of the desired serial number, defaults to 9 bytes.
    /// - Returns: The serial number bytes.
    /// - Throws: `HMCryptoKitError`
    /// - SeeAlso: `randomBytes(_:)`
    static func serial(_ length: Int = kSerialNumberSize) throws -> [UInt8] {
        return try randomBytes(length)
    }
}
