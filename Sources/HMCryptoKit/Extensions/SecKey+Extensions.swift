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

        var data: Data {
            return bytes.data
        }
    }
#endif
