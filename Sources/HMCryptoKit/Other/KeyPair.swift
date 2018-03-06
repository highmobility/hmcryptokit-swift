//
//  KeyPair.swift
//  HMCryptoKit
//
//  Created by Mikk Rätsep on 06/03/2018.
//

import Foundation

// WHY DO I EVEN BOTHER WITH NON-OPENSSL STUFF?!

//#if os(Linux)
    public typealias Key = [UInt8]
//#else
//    public typealias Key = SecKey
//#endif


/// Combined *public* and *private* key pair.
public struct KeyPair {

    /// The *private* part of the keypair (that should never be shared with others)
    public let privateKey: Key

    /// The *public* part of the keypair (that can be shared with others)
    public let publicKey: Key
}

//#if !os(Linux)
//public extension Key {
//
//    @available(macOS 10.12, iOS 10, watchOS 3, tvOS 10, *)
//    var bytes: [UInt8] {
//        // Get the key's attributes
//        guard let attributes = SecKeyCopyAttributes(self) as NSDictionary? else {
//            return []
//        }
//
//        // Make sure the key is an elliptic curve prime one
//        guard let keyType = attributes.value(forKey: String(kSecAttrKeyType)) as? String, keyType == String(kSecAttrKeyTypeECSECPrimeRandom) else {
//            return []
//        }
//
//        // Make sure the key is 256 bits long
//        guard let keySize = attributes.value(forKey: String(kSecAttrKeySizeInBits)) as? Int, keySize == 256 else {
//            return []
//        }
//
//        // Get the key's class (public or private)
//        guard let keyClass = attributes.value(forKey: String(kSecAttrKeyClass)) as? String else {
//            return []
//        }
//
//        let externalRepresentation = SecKeyCopyExternalRepresentation(self, nil) as Data?
//
//        switch keyClass {
//        case String(kSecAttrKeyClassPublic):
//            return externalRepresentation?.suffix(from: 1).bytes ?? []
//
//        case String(kSecAttrKeyClassPrivate):
//            return externalRepresentation?.suffix(from: 65).bytes ?? []
//
//        default:
//            return []
//        }
//    }
//
//    var data: Data {
//        return bytes.data
//    }
//
//    var hex: String {
//        return bytes.hex
//    }
//}
//#endif

