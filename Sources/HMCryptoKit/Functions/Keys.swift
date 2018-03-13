//
//  Keys.swift
//  HMCryptoKit
//
//  Created by Mikk Rätsep on 06/03/2018.
//

import Foundation

#if os(iOS) || os(tvOS) || os(watchOS)
    import Security
#else
    import COpenSSL
#endif


public extension HMCryptoKit {

    static func keys() throws -> (privateKey: ECKey, publicKey: ECKey) {
        #if os(iOS) || os(tvOS) || os(watchOS)
            let params: NSDictionary = [kSecAttrKeyType : kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits : 256]
            var publicKey: ECKey?
            var privateKey: ECKey?

            let status = SecKeyGeneratePair(params, &publicKey, &privateKey)

            switch status {
            case errSecSuccess:
                guard let publicKey = publicKey,
                    let privateKey = privateKey else {
                        throw HMCryptoKitError.internalSecretError
                }

                return (privateKey: privateKey, publicKey: publicKey)

            default:
                throw HMCryptoKitError.internalSecretError
            }
        #else
            // Create the key
            guard let key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1),
                EC_KEY_generate_key(key) == 1,
                EC_KEY_check_key(key) == 1,
                let privateBN = EC_KEY_get0_private_key(key) else {
                    throw HMCryptoKitError.internalSecretError
            }

            let privateOffset = 32 - Int(ceil(Float(BN_num_bits(privateBN)) / 8.0))
            var privateKey = [UInt8](zeroFilledTo: 32)

            guard BN_bn2bin(privateBN, &privateKey + privateOffset) == 32 else {
                throw HMCryptoKitError.internalSecretError
            }

            return try keys(privateKey: privateKey)
        #endif
    }

    static func keys(privateKey: ECKey) throws -> (privateKey: ECKey, publicKey: ECKey) {
        #if os(iOS) || os(tvOS) || os(watchOS)
            guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
                throw HMCryptoKitError.internalSecretError
            }

            return (privateKey: privateKey, publicKey: publicKey)
        #else
            // Handle public key values extraction
            guard let publicBN = BN_new(),
                let bnCtx = BN_CTX_new() else {
                    throw HMCryptoKitError.internalSecretError
            }

            let values = try extractGroupAndPoint(privateKey: privateKey)
            var publicKeyZXY = [UInt8](zeroFilledTo: 65)

            guard EC_POINT_point2bn(values.group, values.point, POINT_CONVERSION_UNCOMPRESSED, publicBN, bnCtx) != nil,
                BN_bn2bin(publicBN, &publicKeyZXY) == 65 else {
                    throw HMCryptoKitError.internalSecretError
            }

            // POINT_CONVERSION_UNCOMPRESSED produces Z||X||Y, where Z == 0x04
            return (privateKey: privateKey, publicKey: publicKeyZXY.suffix(from: 1).bytes)
        #endif
    }


    static func publicKey<C: Collection>(binary: C) throws -> ECKey where C.Element == UInt8 {
        #if os(iOS) || os(tvOS) || os(watchOS)
            guard binary.count == 64 else {
                throw HMCryptoKitError.internalSecretError
            }

            let attributes: NSDictionary = [kSecAttrKeyType : kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass : kSecAttrKeyClassPublic, kSecAttrKeySizeInBits : 256]
            let bytes = [0x04] + binary.bytes
            var error: Unmanaged<CFError>?

            guard let publicKey = SecKeyCreateWithData((bytes.data as CFData), attributes, &error) else {
                throw HMCryptoKitError.internalSecretError // HMCryptoKitError.secKeyError(error!.takeRetainedValue())
            }

            return publicKey
        #else
            return binary.bytes
        #endif
    }

    static func privateKey<C: Collection>(privateKeyBinary: C, publicKeyBinary: C) throws -> ECKey where C.Element == UInt8 {
        #if os(iOS) || os(tvOS) || os(watchOS)
            guard privateKeyBinary.count == 32,
                publicKeyBinary.count == 64 else {
                    throw HMCryptoKitError.internalSecretError
            }

            let attributes: NSDictionary = [kSecAttrKeyType : kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass : kSecAttrKeyClassPrivate, kSecAttrKeySizeInBits : 256]
            var error: Unmanaged<CFError>?

            // Data format: 04 || X || Y || K
            guard let privateKey = SecKeyCreateWithData((([0x04] + publicKeyBinary.bytes + privateKeyBinary.bytes).data as CFData), attributes, &error) else {
                throw HMCryptoKitError.internalSecretError //  HMCryptoKitError.secKeyError(error!.takeRetainedValue())
            }

            return privateKey
        #else
            return privateKeyBinary.bytes
        #endif
    }


    static func sharedKey(privateKey: ECKey, publicKey: ECKey) throws -> [UInt8] {
        #if os(iOS) || os(tvOS) || os(watchOS)
            let params: NSDictionary = [SecKeyKeyExchangeParameter.requestedSize : 32]
            var error: Unmanaged<CFError>?

            guard let sharedKey = SecKeyCopyKeyExchangeResult(privateKey, .ecdhKeyExchangeStandardX963SHA256, publicKey, params, &error) else {
                throw HMCryptoKitError.internalSecretError // throw the wrapped error: HMCryptoKitError.secKeyError(error!.takeRetainedValue())
            }

            return (sharedKey as Data).bytes
        #else
            let publicKeyY = publicKey.suffix(from: 32).bytes

            // Extract some vectors
            guard let key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1),
                let privateBN = BN_bin2bn(privateKey, 32, nil),
                let publicXBN = BN_bin2bn(publicKey, 32, nil),
                let publicYBN = BN_bin2bn(publicKeyY, 32, nil) else {
                    throw HMCryptoKitError.internalSecretError
            }

            guard EC_KEY_set_private_key(key, privateBN) == 1 else {
                throw HMCryptoKitError.internalSecretError
            }

            guard let group = EC_KEY_get0_group(key),
                let point = EC_POINT_new(group),
                let bnCtx = BN_CTX_new() else {
                    throw HMCryptoKitError.internalSecretError
            }

            var sharedKey = [UInt8](zeroFilledTo: 32)

            guard EC_POINT_set_affine_coordinates_GFp(group, point, publicXBN, publicYBN, bnCtx) == 1,
                ECDH_compute_key(&sharedKey, 32, point, key, nil) != -1 else {
                    throw HMCryptoKitError.internalSecretError
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
                throw HMCryptoKitError.internalSecretError
        }

        guard EC_KEY_set_private_key(key, privateBN) == 1,
            EC_KEY_generate_key(key) == 1,
            EC_KEY_check_key(key) == 1,
            EC_POINT_mul(group, point, privateBN, nil, nil, nil) == 1 else {
                throw HMCryptoKitError.internalSecretError
        }

        return (group: group, point: point)
    }
}
#endif
