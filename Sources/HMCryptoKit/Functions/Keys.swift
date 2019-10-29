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
//  Keys.swift
//  HMCryptoKit
//
//  Created by Mikk Rätsep on 06/03/2018.
//  Copyright © 2019 High Mobility GmbH. All rights reserved.
//

import Foundation
import Security

#if canImport(CryptoKit)
import CryptoKit
#endif


public extension HMCryptoKit {

    /// Generated a new keypair.
    ///
    /// The keypair is of an *elliptic curve p256* type.
    ///
    /// - Returns: The tuple containing a private key, and it's public key.
    /// - Throws: `HMCryptoKitError`
    /// - SeeAlso:
    ///     - `HMECKey`
    ///     - `keys(privateKey:)`
    static func keys() throws -> (privateKey: SecKey, publicKey: SecKey) {
        let params: NSDictionary = [kSecAttrKeyType : kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits : 256]
        var publicKey: SecKey?
        var privateKey: SecKey?
        
        let status = SecKeyGeneratePair(params, &publicKey, &privateKey)
        
        switch status {
        case errSecSuccess:
            guard let publicKey = publicKey,
                let privateKey = privateKey else {
                    throw HMCryptoKitError.osStatusError(errSecParam)
            }
            
            return (privateKey: privateKey, publicKey: publicKey)
            
        default:
            throw HMCryptoKitError.osStatusError(status)
        }
    }

    /// Generate a keypair from the private key.
    ///
    /// The keypair is of an *elliptic curve p256* type.
    ///
    /// - Parameter privateKey: The `HMECKey` type of private key.
    /// - Returns: The tuple containing a private key, and it's public key.
    /// - Throws: `HMCryptoKitError`
    /// - SeeAlso:
    ///     - `HMECKey`
    ///     - `keys()`
    static func keys(privateKey: SecKey) throws -> (privateKey: SecKey, publicKey: SecKey) {
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw HMCryptoKitError.osStatusError(errSecInvalidKeyRef)
        }

        return (privateKey: privateKey, publicKey: publicKey)
    }

    /// Convert a binary representaion of a public key to `HMECKey` type.
    ///
    /// - Parameter binary: The public key binary, must be 64 bytes.
    /// - Returns: The converted public key.
    /// - Throws: `HMCryptoKitError`
    /// - SeeAlso: `HMECKey`
    static func publicKey<C: Collection>(binary: C) throws -> SecKey where C.Element == UInt8 {
        guard binary.count == 64 else {
            throw HMCryptoKitError.invalidInputSize("binary")
        }

        let binaryBytes = Array(binary)
        let attributes: NSDictionary = [kSecAttrKeyType : kSecAttrKeyTypeECSECPrimeRandom,
                                        kSecAttrKeyClass : kSecAttrKeyClassPublic,
                                        kSecAttrKeySizeInBits : 256]
        let bytes = [0x04] + binaryBytes
        var error: Unmanaged<CFError>?

        // Data format: 04 || X || Y
        guard let publicKey = SecKeyCreateWithData((Data(bytes) as CFData), attributes, &error) else {
            throw HMCryptoKitError.secKeyError(error!.takeRetainedValue())
        }

        return publicKey
    }

    /// Convert a binary representation of a private key, with it's public key,
    /// to an `HMECKey` type.
    ///
    /// - Parameters:
    ///   - privateKeyBinary: The private key binary, must be 32 bytes.
    ///   - publicKeyBinary: The public key binary, must be 64 bytes.
    /// - Returns: The converted private key.
    /// - Throws: `HMCryptoKitError`
    /// - SeeAlso: `HMECKey`
    static func privateKey<C: Collection>(privateKeyBinary: C, publicKeyBinary: C) throws -> SecKey where C.Element == UInt8 {
        guard privateKeyBinary.count == 32 else {
            throw HMCryptoKitError.invalidInputSize("privateKeyBinary")
        }

        let publicKeyBytes = Array(publicKeyBinary)
        let privateKeyBytes = Array(privateKeyBinary)

        guard publicKeyBinary.count == 64 else {
            throw HMCryptoKitError.invalidInputSize("publicKeyBinary")
        }

        let attributes: NSDictionary = [kSecAttrKeyType : kSecAttrKeyTypeECSECPrimeRandom,
                                        kSecAttrKeyClass : kSecAttrKeyClassPrivate,
                                        kSecAttrKeySizeInBits : 256]
        let keyBytes = [0x04] + publicKeyBytes + privateKeyBytes  // Format: 04 || X || Y || K
        var error: Unmanaged<CFError>?

        guard let privateKey = SecKeyCreateWithData((Data(keyBytes) as CFData), attributes, &error) else {
            throw HMCryptoKitError.secKeyError(error!.takeRetainedValue())
        }

        return privateKey
    }


    /// Generate a shared key.
    ///
    /// The shared key is generated by using Alice's private key and Bob's public key,
    /// using elliptic curve Diffie-Hellman X9.63 SHA256 algorithm.
    ///
    /// - Parameters:
    ///   - privateKey: Private key from *one*.
    ///   - publicKey: Public key from *another*
    /// - Returns: The generated shared key, 32 bytes.
    /// - Throws: `HMCryptoKitError`
    /// - SeeAlso: `HMECKey`
    static func sharedKey(privateKey: SecKey, publicKey: SecKey) throws -> [UInt8] {
        #if canImport(CryptoKit)
            if #available(iOS 13.0, *) {
                // TODO: enum case for CryptoKitError
                let privateKey = try P256.KeyAgreement.PrivateKey.init(rawRepresentation: privateKey.bytes)
                let publicKey = try P256.KeyAgreement.PublicKey.init(rawRepresentation: publicKey.bytes)
                let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)

                return sharedSecret.withUnsafeBytes { $0.bytes }
            }
            else {
                return try pre13sharedKey(privateKey: privateKey, publicKey: publicKey)
            }
        #else
            return try pre13sharedKey(privateKey: privateKey, publicKey: publicKey)
        #endif
    }
}

private extension HMCryptoKit {

    static func pre13sharedKey(privateKey: SecKey, publicKey: SecKey) throws -> [UInt8] {
        let params: [String : Any] = [:]
        var error: Unmanaged<CFError>?

        guard let sharedKey = SecKeyCopyKeyExchangeResult(privateKey, .ecdhKeyExchangeStandardX963SHA256, publicKey, params as CFDictionary, &error) else {
            throw HMCryptoKitError.secKeyError(error!.takeRetainedValue())
        }

        return Array(sharedKey as Data)
    }
}
