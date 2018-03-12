//
//  Signature.swift
//  HMCryptoKit
//
//  Created by Mikk Rätsep on 12/03/2018.
//

import Foundation
import COpenSSL


public extension HMCryptoKit {

    static func createSignature<C: Collection>(message: C, privateKey: C) throws -> [UInt8] where C.Element == UInt8 {
        // Manage the key
        guard privateKey.count == 32,
            let key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1),
            let keyBN = BN_bin2bn(privateKey.bytes, 32, nil),
            EC_KEY_set_private_key(key, keyBN) == 1 else {
                throw HMCryptoKitError.internalSecretError
        }

        // Pad the message to be a multiple of 64 and hash it
        let paddedMessage = message.bytes + [UInt8](zeroFilledTo: 64 - (Int(message.count) % 64))
        let digest = try sha256(message: paddedMessage)

        // Create the signature
        guard let sig = ECDSA_do_sign(digest, SHA256_DIGEST_LENGTH, key) else {
            throw HMCryptoKitError.internalSecretError
        }

        // Extract the signature
        let rvOffset = 32 - Int(ceil(Double(BN_num_bits(sig.pointee.r)) / 8.0))
        let svOffset = 32 - Int(ceil(Double(BN_num_bits(sig.pointee.s)) / 8.0))
        var rVector = [UInt8](zeroFilledTo: 32)
        var sVector = [UInt8](zeroFilledTo: 32)

        // Because the OpenSSL returns the SHORTEST possible format (meaning it cuts 0-bits from the vector's front)
        guard BN_bn2bin(sig.pointee.r, &rVector + rvOffset) != 0,
            BN_bn2bin(sig.pointee.s, &sVector + svOffset) != 0 else {
                throw HMCryptoKitError.internalSecretError
        }

        return rVector + sVector
    }

    static func verify<C: Collection>(signature: C, message: C, publicKey: C) throws -> Bool where C.Element == UInt8 {
        guard signature.count == 64,
            publicKey.count == 64 else {
                throw HMCryptoKitError.internalSecretError
        }

        // Extract the vectors
        guard let rVector = BN_bin2bn(signature.bytes.prefix(32).bytes, 32, nil),
            let sVector = BN_bin2bn(signature.bytes.suffix(32).bytes, 32, nil),
            let xVector = BN_bin2bn(publicKey.bytes.prefix(32).bytes, 32, nil),
            let yVector = BN_bin2bn(publicKey.bytes.suffix(32).bytes, 32, nil) else {
                throw HMCryptoKitError.internalSecretError
        }

        // Create the key and sig
        guard let key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1),
            let sig = ECDSA_SIG_new(),
            EC_KEY_set_public_key_affine_coordinates(key, xVector, yVector) == 1,
            EC_KEY_check_key(key) == 1 else {
                throw HMCryptoKitError.internalSecretError
        }

        // Pad the message to be a multiple of 64 and hash it
        let paddedMessage = message.bytes + [UInt8](zeroFilledTo: 64 - (Int(message.count) % 64))
        let digest = try sha256(message: paddedMessage)

        sig.pointee.r = rVector
        sig.pointee.s = sVector

        return ECDSA_do_verify(digest, SHA256_DIGEST_LENGTH, sig, key) == 1
    }
}
