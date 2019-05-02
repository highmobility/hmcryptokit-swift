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
//  KeysTests.swift
//  HMCryptoKitTests
//
//  Created by Mikk Rätsep on 26/03/2018.
//  Copyright © 2019 High Mobility GmbH. All rights reserved.
//

import HMCryptoKit
import HMUtilities
import XCTest


class KeysTests: XCTestCase {

    static var allTests = [("testKeys", testKeys),
                           ("testKeysFromPrivate", testKeysFromPrivate),
                           ("testPublicKey", testPublicKey),
                           ("testPrivateKey", testPrivateKey),
                           ("testSharedKey", testSharedKey)]
    

    // MARK: XCTestCase

    func testKeys() {
        do {
            let keys = try HMCryptoKit.keys()

            XCTAssertEqual(keys.privateKey.count, 32)
            XCTAssertEqual(keys.publicKey.count, 64)

            XCTAssertNotEqual(Array(keys.privateKey), [UInt8](repeating: 0x00, count: 32))
            XCTAssertNotEqual(Array(keys.publicKey), [UInt8](repeating: 0x00, count: 64))

            // What else could be tested here?
        }
        catch {
            XCTFail("Failed to create keys: \(error)")
        }
    }

    func testKeysFromPrivate() {
        let privateKeyBytes = "4E5AEF5FD084921404E289A8E2DACA3A7708925910129032A250A01907D545C3".hexBytes
        let publicKeyBytes = "CC2992B5406DFFE2AA0B9B202889DEBFDDC13250B75EE8E1BA8DAFEC62CA914CC5F28A810A63C6EC9242E1E0C8C983042775C7D1EC46D362B8806DBFBEA52281".hexBytes

        guard let privateKey = try? HMCryptoKit.privateKey(privateKeyBinary: privateKeyBytes, publicKeyBinary: publicKeyBytes) else {
            return XCTFail("Failed to create the Private key from bytes")
        }

        do {
            let keys = try HMCryptoKit.keys(privateKey: privateKey)

            XCTAssertEqual(keys.privateKey.count, 32)
            XCTAssertEqual(keys.publicKey.count, 64)

            XCTAssertEqual(Array(keys.privateKey), privateKeyBytes)
            XCTAssertEqual(Array(keys.publicKey), publicKeyBytes)
        }
        catch {
            XCTFail("Failed to create the Public key: \(error)")
        }
    }

    func testPublicKey() {
        let publicKeyBytes = "CC2992B5406DFFE2AA0B9B202889DEBFDDC13250B75EE8E1BA8DAFEC62CA914CC5F28A810A63C6EC9242E1E0C8C983042775C7D1EC46D362B8806DBFBEA52281".hexBytes

        do {
            let publicKey = try HMCryptoKit.publicKey(binary: publicKeyBytes)

            XCTAssertEqual(publicKey.count, 64)
            XCTAssertEqual(Array(publicKey), publicKeyBytes)
        }
        catch {
            XCTFail("Failed to create the Public key: \(error)")
        }
    }

    func testPrivateKey() {
        let privateKeyBytes = "4E5AEF5FD084921404E289A8E2DACA3A7708925910129032A250A01907D545C3".hexBytes
        let publicKeyBytes = "CC2992B5406DFFE2AA0B9B202889DEBFDDC13250B75EE8E1BA8DAFEC62CA914CC5F28A810A63C6EC9242E1E0C8C983042775C7D1EC46D362B8806DBFBEA52281".hexBytes

        do {
            let privateKey = try HMCryptoKit.privateKey(privateKeyBinary: privateKeyBytes, publicKeyBinary: publicKeyBytes)

            XCTAssertEqual(privateKey.count, 32)
            XCTAssertEqual(Array(privateKey), privateKeyBytes)
        }
        catch {
            XCTFail("Failed to create the Private key: \(error)")
        }
    }

    func testSharedKey() {
        let privateKeyBytes = "4E5AEF5FD084921404E289A8E2DACA3A7708925910129032A250A01907D545C3".hexBytes
        let publicKeyBytes = "CC2992B5406DFFE2AA0B9B202889DEBFDDC13250B75EE8E1BA8DAFEC62CA914CC5F28A810A63C6EC9242E1E0C8C983042775C7D1EC46D362B8806DBFBEA52281".hexBytes
        let sharedKeyBytes = "146CA6F959C8263198769E987922741507502239780A886ACF82FA4CC1EF3C02".hexBytes

        guard let privateKey = try? HMCryptoKit.privateKey(privateKeyBinary: privateKeyBytes, publicKeyBinary: publicKeyBytes) else {
            return XCTFail("Failed to create the Private key from bytes")
        }

        guard let publicKey = try? HMCryptoKit.publicKey(binary: publicKeyBytes) else {
            return XCTFail("Failed to create the Public key from bytes")
        }

        do {
            let sharedKey = try HMCryptoKit.sharedKey(privateKey: privateKey, publicKey: publicKey)

            XCTAssertEqual(sharedKey.count, 32)
            XCTAssertEqual(Array(sharedKey), sharedKeyBytes)
        }
        catch {
            XCTFail("Failed to create the Shared key: \(error)")
        }
    }
}
