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
//  SecKey+Extensions.swift
//  HMCryptoKit
//
//  Created by Mikk Rätsep on 12/03/2018.
//

import Foundation
import HMUtilities
import Security


public extension SecKey {

    /// The bytes of the key.
    var bytes: [UInt8] {
        // Check that the key suits us
        guard let attributes = SecKeyCopyAttributes(self) as NSDictionary?,
            let keyType = attributes[kSecAttrKeyType] as? String, keyType == String(kSecAttrKeyTypeECSECPrimeRandom),   // Key type
            let keySize = attributes[kSecAttrKeySizeInBits] as? Int, keySize == 256,                                    // Key size
            let keyClass = attributes.value(forKey: String(kSecAttrKeyClass)) as? String,
            let externalRepresentation = SecKeyCopyExternalRepresentation(self, nil) as Data? else {
                return []
        }

        switch keyClass {
        case String(kSecAttrKeyClassPublic):
            return Array(externalRepresentation.suffix(from: 1))

        case String(kSecAttrKeyClassPrivate):
            return Array(externalRepresentation.suffix(from: 65))

        default:
            return []
        }
    }

    /// The number of bytes of the key.
    var count: Int {
        return bytes.count
    }

    /// Data of the key.
    var data: Data {
        return Data(bytes)
    }

    /// The hex string representing the bytes of the key.
    var hex: String {
        return bytes.hex
    }
}
