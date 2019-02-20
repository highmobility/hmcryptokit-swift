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
//  Signature.swift
//  HMCryptoKit
//
//  Created by Mikk Rätsep on 12/03/2018.
//  Copyright © 2019 High Mobility GmbH. All rights reserved.
//

import Foundation

#if os(iOS) || os(tvOS) || os(watchOS)
    import Security
#else
    import COpenSSL
#endif


public extension HMCryptoKit {

    /// Generate a signature for a message.
    ///
    /// The *elliptic curve DSA (digital signature algorithm) X9.62 SHA256* is used for the generation.
    ///
    /// - Parameters:
    ///   - message: The message to generate a signature for.
    ///   - privateKey: The private key to use for signature generation.
    ///   - padded: If the message will be *padded* or not, defaults to `true`.
    /// - Returns: The signature's 64 bytes.
    /// - Throws: `HMCryptoKitError`
    /// - SeeAlso:
    ///     - `HMECKey`
    ///     - `verify(signature:message:publicKey:)`
    static func signature<C: Collection>(message: C, privateKey: HMECKey, padded: Bool = true) throws -> [UInt8] where C.Element == UInt8 {
        if padded {
            // Pad the message to be a multiple of 64
            let modulo = message.count % 64
            let paddedMessage = message.bytes + [UInt8](zeroFilledTo: (modulo == 0) ? 0 : (64 - modulo))

            return try createSignature(message: paddedMessage, privateKey: privateKey)
        }
        else {
            return try createSignature(message: message, privateKey: privateKey)
        }
    }


    /// Verifies the signature for a message with the public key.
    ///
    /// The *elliptic curve DSA X9.62 SHA256* is used for the verification.
    ///
    /// - Parameters:
    ///   - signature: The signature for the message, must be 64 bytes.
    ///   - message: The message associated with the signature.
    ///   - publicKey: The public key of the keypair used to create the signature.
    /// - Returns: Bool value if the verification succeeded.
    /// - Throws: `HMCryptoKitError`
    /// - SeeAlso:
    ///     - `HMECKey`
    ///     - `signature(message:privateKey:)`
    static func verify<C: Collection>(signature: C, message: C, publicKey: HMECKey) throws -> Bool where C.Element == UInt8 {
        guard signature.count == 64 else {
            throw HMCryptoKitError.invalidInputSize("signature")
        }

        // Pad the message to be a multiple of 64
        let modulo = message.count % 64
        let paddedMessage = message.bytes + [UInt8](zeroFilledTo: (modulo == 0) ? 0 : (64 - modulo))

        #if os(iOS) || os(tvOS) || os(watchOS)
            var error: Unmanaged<CFError>?

            // DER encoding structure: 0x30 b1 0x02 b2 (vR) 0x02 b3 (vS) - http://crypto.stackexchange.com/a/1797/44274
            // b1 - length of the remaining bytes
            // b2 - length of vR
            // b3 - length of vS

            var vR = signature.bytes[0..<32].bytes
            var vS = signature.bytes[32..<64].bytes

            // Removes all the 0x00 bytes from the front for the SHORTEST possible representation
            vR = vR.drop { $0 == 0x00 }.bytes
            vS = vS.drop { $0 == 0x00 }.bytes

            // If the first bit of the vector is 1, we'll need to prefix that vector with a 0x00
            if vR[0] > 0b0111_1111 { vR.insert(0x00, at: 0) }
            if vS[0] > 0b0111_1111 { vS.insert(0x00, at: 0) }

            // The size of the vectors
            let b2 = UInt8(truncatingIfNeeded: vR.count)
            let b3 = UInt8(truncatingIfNeeded: vS.count)
            let b1 = 4 + b2 + b3

            // Combine the bytes
            let signatureBytes: [UInt8] = [0x30, b1, 0x02, b2] + vR + [0x02, b3] + vS
            let verified = SecKeyVerifySignature(publicKey, .ecdsaSignatureMessageX962SHA256, (paddedMessage.data as CFData), (signatureBytes.data as CFData), &error)

            guard error == nil else {
                throw HMCryptoKitError.secKeyError(error!.takeRetainedValue())
            }

            return verified
        #else
            guard signature.count == 64 else {
                throw HMCryptoKitError.invalidInputSize("signature")
            }

            guard publicKey.count == 64 else {
                throw HMCryptoKitError.invalidInputSize("publicKey")
            }

            // Extract the vectors
            guard let rVector = BN_bin2bn(signature.bytes.prefix(32).bytes, 32, nil),
                let sVector = BN_bin2bn(signature.bytes.suffix(32).bytes, 32, nil),
                let xVector = BN_bin2bn(publicKey.bytes.prefix(32).bytes, 32, nil),
                let yVector = BN_bin2bn(publicKey.bytes.suffix(32).bytes, 32, nil) else {
                    throw HMCryptoKitError.openSSLError(getOpenSSLError())
            }

            // Create the key and sig
            guard let key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1),
                let sig = ECDSA_SIG_new(),
                EC_KEY_set_public_key_affine_coordinates(key, xVector, yVector) == 1,
                EC_KEY_check_key(key) == 1 else {
                    throw HMCryptoKitError.openSSLError(getOpenSSLError())
            }

            let digest = try sha256(message: paddedMessage)

            sig.pointee.r = rVector
            sig.pointee.s = sVector

            return ECDSA_do_verify(digest, SHA256_DIGEST_LENGTH, sig, key) == 1
        #endif
    }
}

private extension HMCryptoKit {

    static func createSignature<C: Collection>(message: C, privateKey: HMECKey) throws -> [UInt8] where C.Element == UInt8 {
        #if os(iOS) || os(tvOS) || os(watchOS)
            var error: Unmanaged<CFError>?

            // "CFData -> Data" cast always succeeds - this has the "as?" just to do the conversion
            guard let signature = SecKeyCreateSignature(privateKey, .ecdsaSignatureMessageX962SHA256, (message.data as CFData), &error) as Data? else {
                throw HMCryptoKitError.secKeyError(error!.takeRetainedValue())
            }

            /*
             The format: 0x30 b1 0x02 b2 (vr) 0x02 b3 (vs)
             */
            let b2 = signature[3]           // Length of vR
            let b3 = signature[5 + Int(b2)] // Length of vS

            var vR = signature[4 ..< (4 + Int(b2))].bytes
            var vS = signature[(6 + Int(b2)) ..< (6 + Int(b2) + Int(b3))].bytes

            // Removes the front 0x00 bytes (if the vector's 1st bit is 1, there's a 0x00 byte prefixed to it)
            vR = vR.drop { $0 == 0x00 }.bytes
            vS = vS.drop { $0 == 0x00 }.bytes

            // Expands the vectors to our desired size of 32 bytes
            while vR.count < 32 { vR.insert(0x00, at: 0) }
            while vS.count < 32 { vS.insert(0x00, at: 0) }

            return vR + vS
        #else
            // Manage the key
            guard privateKey.count == 32 else {
                throw HMCryptoKitError.invalidInputSize("privateKey")
            }

            guard let key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1),
                let keyBN = BN_bin2bn(privateKey.bytes, 32, nil),
                EC_KEY_set_private_key(key, keyBN) == 1 else {
                    throw HMCryptoKitError.openSSLError(getOpenSSLError())
            }

            let digest = try sha256(message: paddedMessage)

            // Create the signature
            guard let sig = ECDSA_do_sign(digest, SHA256_DIGEST_LENGTH, key) else {
                throw HMCryptoKitError.openSSLError(getOpenSSLError())
            }

            // Extract the signature
            let rvOffset = 32 - Int(ceil(Double(BN_num_bits(sig.pointee.r)) / 8.0))
            let svOffset = 32 - Int(ceil(Double(BN_num_bits(sig.pointee.s)) / 8.0))
            var rVector = [UInt8](zeroFilledTo: 32)
            var sVector = [UInt8](zeroFilledTo: 32)

            // Because the OpenSSL returns the SHORTEST possible format (meaning it cuts 0-bits from the vector's front)
            guard BN_bn2bin(sig.pointee.r, &rVector + rvOffset) != 0,
                BN_bn2bin(sig.pointee.s, &sVector + svOffset) != 0 else {
                    throw HMCryptoKitError.openSSLError(getOpenSSLError())
            }

            return rVector + sVector
        #endif
    }
}
