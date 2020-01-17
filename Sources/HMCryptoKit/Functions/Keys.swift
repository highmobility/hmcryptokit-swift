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
//  Keys.swift
//  HMCryptoKit
//
//  Created by Mikk Rätsep on 06/03/2018.
//

import Foundation
import Security


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
        let params: [String : Any] = [SecKeyKeyExchangeParameter.requestedSize.rawValue as String : 32]
        var error: Unmanaged<CFError>?

        guard let sharedKey = SecKeyCopyKeyExchangeResult(privateKey, .ecdhKeyExchangeStandard, publicKey, params as CFDictionary, &error) else {
            throw HMCryptoKitError.secKeyError(error!.takeRetainedValue())
        }

        return Array(sharedKey as Data)
    }
}
