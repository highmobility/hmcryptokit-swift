//
//  Keys.swift
//  HMCryptoKit
//
//  Created by Mikk Rätsep on 06/03/2018.
//

import Foundation

// WHY DO I EVEN BOTHER WITH NON-OPENSSL STUFF?!

//#if os(Linux)
    import COpenSSL
//#else
//    import Security
//#endif


public extension HMCryptoKit {

    static func keys(_ privateKey: Key? = nil) throws -> KeyPair {
//        #if os(Linux)
        let group: OpaquePointer
        let point: OpaquePointer
        let privateKeyResolved: Key

        if let privateKey = privateKey {
            guard let groupTemp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1),
                let privateBN = BN_bin2bn(privateKey, 32, nil),
                let key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1),
                let pointTemp = EC_POINT_new(groupTemp) else {
                    throw HMCryptoKitError.internalSecretError
            }

            guard EC_KEY_set_private_key(key, privateBN) == 1,
                EC_KEY_generate_key(key) == 1,
                EC_KEY_check_key(key) == 1,
                EC_POINT_mul(groupTemp, pointTemp, privateBN, nil, nil, nil) == 1 else {
                    throw HMCryptoKitError.internalSecretError
            }

            group = groupTemp
            point = pointTemp
            privateKeyResolved = privateKey
        }
        else {
            // Create the key
            guard let key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1),
                EC_KEY_generate_key(key) == 1,
                EC_KEY_check_key(key) == 1 else {
                    throw HMCryptoKitError.internalSecretError
            }

            // Extract the private key
            guard let privateBN = EC_KEY_get0_private_key(key) else {
                throw HMCryptoKitError.internalSecretError
            }

            let privateSize = Int(ceil(Float(BN_num_bits(privateBN)) / 8.0))
            var privateKeyTemp = [UInt8](repeating: 0x00, count: 32)

            guard BN_bn2bin(privateBN, &privateKeyTemp + (32 - privateSize)) == 32 else {
                throw HMCryptoKitError.internalSecretError
            }

            // Extract the public key (after creating the vars)
            guard let groupTemp = EC_KEY_get0_group(key),
                let pointTemp = EC_KEY_get0_public_key(key) else {
                    throw HMCryptoKitError.internalSecretError
            }

            group = groupTemp
            point = pointTemp
            privateKeyResolved = privateKeyTemp
        }

        // Handle public key values extraction
        guard let publicBN = BN_new(),
            let bnCtx = BN_CTX_new() else {
                throw HMCryptoKitError.internalSecretError
        }

        var publicKeyZXY = [UInt8](repeating: 0x00, count: 65)

        guard EC_POINT_point2bn(group, point, POINT_CONVERSION_UNCOMPRESSED, publicBN, bnCtx) != nil,
            BN_bn2bin(publicBN, &publicKeyZXY) == 65 else {
                throw HMCryptoKitError.internalSecretError
        }

        // POINT_CONVERSION_UNCOMPRESSED produces z|x|y, where z == 0x04
        return KeyPair(privateKey: privateKeyResolved, publicKey: publicKeyZXY.suffix(from: 1).bytes)

//        #else
//            var pubKey: Key?
//            var privKey: Key?
//            let parameters: NSDictionary = [kSecAttrType : kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits : 256]
//            let status = SecKeyGeneratePair(parameters, &pubKey, &privKey)
//
//            switch status {
//            case errSecSuccess:
//                guard let publicKey = pubKey, let privateKey = privKey else {
//                    throw HMCryptoKitError.internalSecretError
//                }
//
//                return KeyPair(privateKey: privateKey, publicKey: publicKey)
//
//            default:
//                throw HMCryptoKitError.osStatusError(status)
//            }
//        #endif
    }

    static func sharedKey(_ privateKey: Key, _ publicKey: Key) throws -> [UInt8] {
        let publicKeyY = publicKey.suffix(from: 32).bytes

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

        var sharedKey = [UInt8](repeating: 0x00, count: 32)

        guard EC_POINT_set_affine_coordinates_GFp(group, point, publicXBN, publicYBN, bnCtx) == 1,
            ECDH_compute_key(&sharedKey, 32, point, key, nil) != -1 else {
                throw HMCryptoKitError.internalSecretError
        }

        return sharedKey
    }
}













