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
//  Random.swift
//  HMCryptoKit
//
//  Created by Mikk Rätsep on 06/03/2018.
//

import Foundation
import CommonCrypto


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
        
        guard CCRandomGenerateBytes(&bytes, length) == kCCSuccess else {
            throw HMCryptoKitError.systemError(errno)
        }

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
