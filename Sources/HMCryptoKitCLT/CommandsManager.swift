//
// HMCryptoKit CLT
// Copyright (C) 2018 High-Mobility GmbH
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
//  CommandsManager.swift
//  HMCryptoKitCLT
//
//  Created by Mikk Rätsep on 21/03/2018.
//

import Foundation
import HMCryptoKit
import HMUtilities


struct CommandsManager {

    static let shared = CommandsManager()

    var commands: [CommandInfoType] = []


    // MARK: Init

    private init() {
        commands.append(keysCommand)
        commands.append(keysPublicCommand)
        commands.append(keysSharedCommand)

        commands.append(signatureCommand)
        commands.append(signatureVerifyCommand)

        commands.append(hmacCommand)
        commands.append(hmacVerifyCommand)

        commands.append(nonceCommand)
        commands.append(randomBytesCommand)
        commands.append(serialCommand)

        commands.append(encryptDecryptCommand)
        commands.append(ivCommand)
    }
}

private extension CommandsManager {

    // MARK: AES

    var encryptDecryptCommand: CommandInfo<BytesArrays, [UInt8]> {
        return CommandInfo(name: "encrypt",
                           parameters: ["message", "iv", "key"],
                           description: "Encrypt or Decrypt a Message",
                           inputsDesc: [("message", .nBytes), ("iv", .int(16)), ("key", .int(16))],
                           parser: { try HMCryptoKit.encryptDecrypt(message: $0[0], iv: $0[1], key: $0[2]) })
    }

    var ivCommand: CommandInfo<BytesArrays, [UInt8]> {
        return CommandInfo(name: "iv",
                           parameters: ["nonce", "transaction nonce"],
                           description: "Generate an Injection Vector for Encryption",
                           inputsDesc: [("nonce", .int(7)), ("transaction nonce", .int(9))],
                           parser: { try HMCryptoKit.iv(nonce: $0[0], transactionNonce: $0[1]) })
    }


    // MARK: HMAC

    var hmacCommand: CommandInfo<BytesArrays, [UInt8]> {
        return CommandInfo(name: "hmac",
                           parameters: ["message", "key"],
                           description: "Generate an HMAC for a Message",
                           inputsDesc: [("message", .nBytes), ("key", .int(32))],
                           parser: { try HMCryptoKit.hmac(message: $0[0], key: $0[1]) })
    }

    var hmacVerifyCommand: CommandInfo<BytesArrays, Bool> {
        return CommandInfo(name: "verify-hmac",
                           parameters: ["message", "hmac", "key"],
                           description: "Verify an HMAC for a Message",
                           inputsDesc: [("message", .nBytes), ("hmac", .int(32)), ("key", .int(32))],
                           parser: { try HMCryptoKit.verify(hmac: $0[1], message: $0[0], key: $0[2]) })
    }


    // MARK: Keys

    var keysCommand: CommandInfo<Void, (privateKey: [UInt8], publicKey: [UInt8])> {
        return CommandInfo(name: "keys",
                           parameters: [],
                           description: "Generate Private and Public keys",
                           inputsDesc: [],
                           parser: { return try HMCryptoKit.keys() })
    }

    var keysPublicCommand: CommandInfo<BytesArrays, [UInt8]> {
        return CommandInfo(name: "keys-public",
                           parameters: ["private key"],
                           description: "Generate the Public key from a Private key",
                           inputsDesc: [("private key", .int(64))],
                           parser: { try HMCryptoKit.keys(privateKey: $0[0]).publicKey })
    }

    var keysSharedCommand: CommandInfo<BytesArrays, [UInt8]> {
        return CommandInfo(name: "keys-shared",
                           parameters: ["private key", "public key"],
                           description: "Generate a Shared key from a Private and a Public key using Diffie-Hellman",
                           inputsDesc: [("private key", .int(32)), ("public key", .int(64))],
                           parser: { try HMCryptoKit.sharedKey(privateKey: $0[0], publicKey: $0[1]) })
    }


    // MARK: Random

    var nonceCommand: CommandInfo<Void, [UInt8]> {
        return CommandInfo(name: "nonce",
                           parameters: [],
                           description: "Generate a cryptographicly secure Nonce",
                           inputsDesc: [],
                           parser: { try HMCryptoKit.nonce() })
    }

    var randomBytesCommand: CommandInfo<Int, [UInt8]> {
        return CommandInfo(name: "random",
                           parameters: ["count"],
                           description: "Generate cryptographicly secure random bytes",
                           inputsDesc: [("count", .string("int"))],
                           parser: { try HMCryptoKit.nonce($0) })
    }

    var serialCommand: CommandInfo<Void, [UInt8]> {
        return CommandInfo(name: "serial",
                           parameters: [],
                           description: "Generate a cryptographicly secure Serial Number",
                           inputsDesc: [],
                           parser: { try HMCryptoKit.serial() })
    }


    // MARK: Signature

    var signatureCommand: CommandInfo<BytesArrays, [UInt8]> {
        return CommandInfo(name: "sign",
                           parameters: ["message", "private key"],
                           description: "Generate a Signature for a Message",
                           inputsDesc: [("message", .nBytes), ("private key", .int(32))],
                           parser: { try HMCryptoKit.signature(message: $0[0], privateKey: $0[1]) })
    }

    var signatureVerifyCommand: CommandInfo<BytesArrays, Bool> {
        return CommandInfo(name: "verify",
                           parameters: ["message", "signature", "public key"],
                           description: "Verify a Signature for a Message",
                           inputsDesc: [("message", .nBytes), ("signature", .int(64)), ("public key", .int(64))],
                           parser: { try HMCryptoKit.verify(signature: $0[1], message: $0[0], publicKey: $0[2]) })
    }
}
