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
import Security


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
    static func signature<C: Collection>(message: C, privateKey: SecKey, padded: Bool = true) throws -> [UInt8] where C.Element == UInt8 {
        if padded {
            // Pad the message to be a multiple of 64
            let modulo = message.count % 64
            let messageBytes = Array(message)
            let paddedMessage = messageBytes + [UInt8](zeroFilledTo: (modulo == 0) ? 0 : (64 - modulo))

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
    static func verify<C: Collection>(signature: C, message: C, publicKey: SecKey) throws -> Bool where C.Element == UInt8 {
        guard signature.count == 64 else {
            throw HMCryptoKitError.invalidInputSize("signature")
        }

        let messageBytes = Array(message)
        let signatureBytes = Array(signature)
        // Pad the message to be a multiple of 64
        let modulo = message.count % 64
        let paddedMessage = messageBytes + [UInt8](zeroFilledTo: (modulo == 0) ? 0 : (64 - modulo))
        var error: Unmanaged<CFError>?

        // DER encoding structure: 0x30 b1 0x02 b2 (vR) 0x02 b3 (vS) - http://crypto.stackexchange.com/a/1797/44274
        // b1 - length of the remaining bytes
        // b2 - length of vR
        // b3 - length of vS

        // Removes all the 0x00 bytes from the front for the SHORTEST possible representation
        var vR = Array(signatureBytes[0..<32].drop { $0 == 0x00 })
        var vS = Array(signatureBytes[32..<64].drop { $0 == 0x00 })

        // If the first bit of the vector is 1, we'll need to prefix that vector with a 0x00
        if vR[0] > 0b0111_1111 { vR.insert(0x00, at: 0) }
        if vS[0] > 0b0111_1111 { vS.insert(0x00, at: 0) }

        // The size of the vectors
        let b2 = UInt8(truncatingIfNeeded: vR.count)
        let b3 = UInt8(truncatingIfNeeded: vS.count)
        let b1 = 4 + b2 + b3

        // Combine the bytes
        let outputSignatureBytes: [UInt8] = [0x30, b1, 0x02, b2] + vR + [0x02, b3] + vS
        let verified = SecKeyVerifySignature(publicKey, .ecdsaSignatureMessageX962SHA256, (Data(paddedMessage) as CFData), (Data(outputSignatureBytes) as CFData), &error)

        // Error -67808 notes that the EC signature verification failed, no match
        guard (error == nil) ||
            CFErrorGetCode(error!.takeRetainedValue()) == -67808 else {
                throw HMCryptoKitError.secKeyError(error!.takeRetainedValue())
        }

        return verified
    }
}

private extension HMCryptoKit {

    static func createSignature<C: Collection>(message: C, privateKey: SecKey) throws -> [UInt8] where C.Element == UInt8 {
        var error: Unmanaged<CFError>?
        let messageBytes = Array(message)
        
        // "CFData -> Data" cast always succeeds - this has the "as?" just to do the conversion
        guard let signature = SecKeyCreateSignature(privateKey, .ecdsaSignatureMessageX962SHA256, (Data(messageBytes) as CFData), &error) as Data? else {
            throw HMCryptoKitError.secKeyError(error!.takeRetainedValue())
        }
        
        /*
         The format: 0x30 b1 0x02 b2 (vr) 0x02 b3 (vs)
         */
        let b2 = signature[3]           // Length of vR
        let b3 = signature[5 + Int(b2)] // Length of vS
        let vREndIdx = 4 + Int(b2)
        let vSStartIdx = 6 + Int(b2)
        let vSEndIdx = vSStartIdx + Int(b3)
        
        var vR = signature[4 ..< vREndIdx]
        var vS = signature[vSStartIdx ..< vSEndIdx]
        
        // Removes the front 0x00 bytes (if the vector's 1st bit is 1, there's a 0x00 byte prefixed to it)
        vR = vR.drop { $0 == 0x00 }
        vS = vS.drop { $0 == 0x00 }

        // Expands the vectors to our desired size of 32 bytes
        if vR.count < 32 { vR = [UInt8](repeating: 0x00, count: max(32 - vR.count, 0)) + vR }
        if vS.count < 32 { vS = [UInt8](repeating: 0x00, count: max(32 - vS.count, 0)) + vS }
        
        return Array(vR + vS)
    }
}
