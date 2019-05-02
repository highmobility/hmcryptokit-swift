//
// HMCryptoKitTests
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
//  SignatureTests.swift
//  HMCryptoKitTests
//
//  Created by Mikk Rätsep on 26/03/2018.
//  Copyright © 2019 High Mobility GmbH. All rights reserved.
//

import HMCryptoKit
import HMUtilities
import XCTest


class SignatureTests: XCTestCase {

    static var allTests = [("testSignature", testSignature),
                           ("testVerifySignature", testVerifySignature)]
    

    // MARK: XCTestCase

    func testSignature() {
        let msgBytes = "00112233445566778899AABBCCDDEEFF".hexBytes
        let privateKeyBytes = "4E5AEF5FD084921404E289A8E2DACA3A7708925910129032A250A01907D545C3".hexBytes
        let publicKeyBytes = "CC2992B5406DFFE2AA0B9B202889DEBFDDC13250B75EE8E1BA8DAFEC62CA914CC5F28A810A63C6EC9242E1E0C8C983042775C7D1EC46D362B8806DBFBEA52281".hexBytes

        guard let privateKey = try? HMCryptoKit.privateKey(privateKeyBinary: privateKeyBytes, publicKeyBinary: publicKeyBytes) else {
            return XCTFail("Failed to create the Private key from bytes")
        }

        do {
            let signature = try HMCryptoKit.signature(message: msgBytes, privateKey: privateKey)

            XCTAssertEqual(signature.count, 64)

            guard let publicKey = try? HMCryptoKit.publicKey(binary: publicKeyBytes) else {
                return XCTFail("Failed to create the Public key from bytes")
            }

            guard let isVerified = try? HMCryptoKit.verify(signature: signature, message: msgBytes, publicKey: publicKey) else {
                return XCTFail("Failed to verify Signature")
            }

            XCTAssertTrue(isVerified)
        }
        catch {
            XCTFail("Failed to create Signature: \(error)")
        }
    }

    func testVerifySignature() {
        let msgBytes = "00112233445566778899AABBCCDDEEFF".hexBytes
        let publicKeyBytes = "CC2992B5406DFFE2AA0B9B202889DEBFDDC13250B75EE8E1BA8DAFEC62CA914CC5F28A810A63C6EC9242E1E0C8C983042775C7D1EC46D362B8806DBFBEA52281".hexBytes
        let signatureBytes = "FD04F11E45D8206B2C9D343101EE373F5F5C5E696D9BC0E1D03FC26C29945CC26AD5BA5D64EF3CAD3D51422B5B870E0B1895FD140BC9B3B55018FA4E22055684".hexBytes

        guard let publicKey = try? HMCryptoKit.publicKey(binary: publicKeyBytes) else {
            return XCTFail("Failed to create the Public key from bytes")
        }

        do {
            let isVerified = try HMCryptoKit.verify(signature: signatureBytes, message: msgBytes, publicKey: publicKey)

            XCTAssertTrue(isVerified)
        }
        catch {
            XCTFail("Failed to verify Signature: \(error)")
        }
    }
}
