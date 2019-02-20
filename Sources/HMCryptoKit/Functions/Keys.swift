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

#if os(iOS) || os(tvOS) || os(watchOS)
    import Security
#else
    import COpenSSL
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
    static func keys() throws -> (privateKey: HMECKey, publicKey: HMECKey) {
        #if os(iOS) || os(tvOS) || os(watchOS)
            let params: NSDictionary = [kSecAttrKeyType : kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits : 256]
            var publicKey: HMECKey?
            var privateKey: HMECKey?

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
        #else
            // Create the key
            guard let key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1),
                EC_KEY_generate_key(key) == 1,
                EC_KEY_check_key(key) == 1,
                let privateBN = EC_KEY_get0_private_key(key) else {
                    throw HMCryptoKitError.openSSLError(getOpenSSLError())
            }

            let privateOffset = 32 - Int(ceil(Float(BN_num_bits(privateBN)) / 8.0))
            var privateKey = [UInt8](zeroFilledTo: 32)

            guard BN_bn2bin(privateBN, &privateKey + privateOffset) == 32 else {
                throw HMCryptoKitError.openSSLError(getOpenSSLError())
            }

            return try keys(privateKey: privateKey)
        #endif
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
    static func keys(privateKey: HMECKey) throws -> (privateKey: HMECKey, publicKey: HMECKey) {
        #if os(iOS) || os(tvOS) || os(watchOS)
            guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
                throw HMCryptoKitError.osStatusError(errSecInvalidKeyRef)
            }

            return (privateKey: privateKey, publicKey: publicKey)
        #else
            guard privateKey.count == 32 else {
                throw HMCryptoKitError.invalidInputSize("privateKey")
            }

            // Handle public key values extraction
            guard let publicBN = BN_new(),
                let bnCtx = BN_CTX_new() else {
                    throw HMCryptoKitError.openSSLError(getOpenSSLError())
            }

            let values = try extractGroupAndPoint(privateKey: privateKey)
            var publicKeyZXY = [UInt8](zeroFilledTo: 65)

            guard EC_POINT_point2bn(values.group, values.point, POINT_CONVERSION_UNCOMPRESSED, publicBN, bnCtx) != nil,
                BN_bn2bin(publicBN, &publicKeyZXY) == 65 else {
                    throw HMCryptoKitError.openSSLError(getOpenSSLError())
            }

            // POINT_CONVERSION_UNCOMPRESSED produces Z||X||Y, where Z == 0x04
            return (privateKey: privateKey, publicKey: publicKeyZXY.suffix(from: 1).bytes)
        #endif
    }

    /// Convert a binary representaion of a public key to `HMECKey` type.
    ///
    /// - Parameter binary: The public key binary, must be 64 bytes.
    /// - Returns: The converted public key.
    /// - Throws: `HMCryptoKitError`
    /// - SeeAlso: `HMECKey`
    static func publicKey<C: Collection>(binary: C) throws -> HMECKey where C.Element == UInt8 {
        guard binary.count == 64 else {
            throw HMCryptoKitError.invalidInputSize("binary")
        }

        #if os(iOS) || os(tvOS) || os(watchOS)
            let attributes: NSDictionary = [kSecAttrKeyType : kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass : kSecAttrKeyClassPublic, kSecAttrKeySizeInBits : 256]
            let bytes = [0x04] + binary.bytes
            var error: Unmanaged<CFError>?

            // Data format: 04 || X || Y
            guard let publicKey = SecKeyCreateWithData((bytes.data as CFData), attributes, &error) else {
                throw HMCryptoKitError.secKeyError(error!.takeRetainedValue())
            }

            return publicKey
        #else
            return binary.bytes
        #endif
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
    static func privateKey<C: Collection>(privateKeyBinary: C, publicKeyBinary: C) throws -> HMECKey where C.Element == UInt8 {
        guard privateKeyBinary.count == 32 else {
            throw HMCryptoKitError.invalidInputSize("privateKeyBinary")
        }

        #if os(iOS) || os(tvOS) || os(watchOS)
            guard publicKeyBinary.count == 64 else {
                throw HMCryptoKitError.invalidInputSize("publicKeyBinary")
            }

            let attributes: NSDictionary = [kSecAttrKeyType : kSecAttrKeyTypeECSECPrimeRandom,
                                            kSecAttrKeyClass : kSecAttrKeyClassPrivate,
                                            kSecAttrKeySizeInBits : 256]
            let keyBytes = [0x04] + publicKeyBinary.bytes + privateKeyBinary.bytes  // Format: 04 || X || Y || K
            var error: Unmanaged<CFError>?

            guard let privateKey = SecKeyCreateWithData((keyBytes.data as CFData), attributes, &error) else {
                throw HMCryptoKitError.secKeyError(error!.takeRetainedValue())
            }

            return privateKey
        #else
            return privateKeyBinary.bytes
        #endif
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
    static func sharedKey(privateKey: HMECKey, publicKey: HMECKey) throws -> [UInt8] {
        #if os(iOS) || os(tvOS) || os(watchOS)
            let params: NSDictionary = [SecKeyKeyExchangeParameter.requestedSize : 32]
            var error: Unmanaged<CFError>?

            guard let sharedKey = SecKeyCopyKeyExchangeResult(privateKey, .ecdhKeyExchangeStandardX963SHA256, publicKey, params, &error) else {
                throw HMCryptoKitError.secKeyError(error!.takeRetainedValue())
            }

            return (sharedKey as Data).bytes
        #else
            guard privateKey.count == 32 else {
                throw HMCryptoKitError.invalidInputSize("private key")
            }

            guard publicKey.count == 64 else {
                throw HMCryptoKitError.invalidInputSize("public key")
            }

            let publicKeyY = publicKey.suffix(from: 32).bytes

            // Extract some vectors
            guard let key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1),
                let privateBN = BN_bin2bn(privateKey, 32, nil),
                let publicXBN = BN_bin2bn(publicKey, 32, nil),
                let publicYBN = BN_bin2bn(publicKeyY, 32, nil) else {
                    throw HMCryptoKitError.openSSLError(getOpenSSLError())
            }

            guard EC_KEY_set_private_key(key, privateBN) == 1 else {
                throw HMCryptoKitError.openSSLError(getOpenSSLError())
            }

            guard let group = EC_KEY_get0_group(key),
                let point = EC_POINT_new(group),
                let bnCtx = BN_CTX_new() else {
                    throw HMCryptoKitError.openSSLError(getOpenSSLError())
            }

            var sharedKey = [UInt8](zeroFilledTo: 32)

            guard EC_POINT_set_affine_coordinates_GFp(group, point, publicXBN, publicYBN, bnCtx) == 1,
                ECDH_compute_key(&sharedKey, 32, point, key, nil) != -1 else {
                    throw HMCryptoKitError.openSSLError(getOpenSSLError())
            }

            return sharedKey
        #endif
    }
}

#if os(iOS) || os(tvOS) || os(watchOS)
#else
private extension HMCryptoKit {

    static func extractGroupAndPoint<C: Collection>(privateKey: C) throws -> (group: OpaquePointer, point: OpaquePointer) where C.Element == UInt8 {
        guard let group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1),
            let privateBN = BN_bin2bn(privateKey.bytes, 32, nil),
            let key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1),
            let point = EC_POINT_new(group) else {
                throw HMCryptoKitError.openSSLError(getOpenSSLError())
        }

        guard EC_KEY_set_private_key(key, privateBN) == 1,
            EC_KEY_generate_key(key) == 1,
            EC_KEY_check_key(key) == 1,
            EC_POINT_mul(group, point, privateBN, nil, nil, nil) == 1 else {
                throw HMCryptoKitError.openSSLError(getOpenSSLError())
        }

        return (group: group, point: point)
    }
}
#endif
