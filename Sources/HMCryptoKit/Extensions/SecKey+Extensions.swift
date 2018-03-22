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
//  SecKey+Extensions.swift
//  HMCryptoKit
//
//  Created by Mikk Rätsep on 12/03/2018.
//

import Foundation


#if os(iOS) || os(watchOS) || os(tvOS)
    import Security


    public extension SecKey {

        var hex: String {
            return bytes.hex
        }

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
                return externalRepresentation.suffix(from: 1).bytes

            case String(kSecAttrKeyClassPrivate):
                return externalRepresentation.suffix(from: 65).bytes

            default:
                return []
            }
        }

        var count: Int {
            return bytes.count
        }

        var data: Data {
            return bytes.data
        }
    }
#endif
