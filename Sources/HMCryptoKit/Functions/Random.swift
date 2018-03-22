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
//  Random.swift
//  HMCryptoKit
//
//  Created by Mikk Rätsep on 06/03/2018.
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

    static func nonce(_ length: Int = kNonceSize) throws -> [UInt8] {
        return try randomBytes(length)
    }

    static func serial(_ length: Int = kSerialNumberSize) throws -> [UInt8] {
        return try randomBytes(length)
    }
}

private extension HMCryptoKit {

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
}
