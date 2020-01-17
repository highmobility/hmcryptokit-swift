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
//  KeysTests.swift
//  HMCryptoKitTests
//
//  Created by Mikk Rätsep on 26/03/2018.
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

            XCTAssertNotEqual(keys.privateKey.bytes, [UInt8](repeating: 0x00, count: 32))
            XCTAssertNotEqual(keys.publicKey.bytes, [UInt8](repeating: 0x00, count: 64))

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

            XCTAssertEqual(keys.privateKey.bytes, privateKeyBytes)
            XCTAssertEqual(keys.publicKey.bytes, publicKeyBytes)
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
            XCTAssertEqual(publicKey.bytes, publicKeyBytes)
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
            XCTAssertEqual(privateKey.bytes, privateKeyBytes)
        }
        catch {
            XCTFail("Failed to create the Private key: \(error)")
        }
    }

    func testSharedKey() {
        let privateKeyBytes = "4e5aef5fd084921404e289a8e2daca3a7708925910129032a250a01907d545c3".hexBytes
        let publicKeyBytes = "cc2992b5406dffe2aa0b9b202889debfddc13250b75ee8e1ba8dafec62ca914cc5f28a810a63c6ec9242e1e0c8c983042775c7d1ec46d362b8806dbfbea52281".hexBytes
        let sharedKeyBytes = "146ca6f959c8263198769e987922741507502239780a886acf82fa4cc1ef3c02".hexBytes

        guard let privateKey = try? HMCryptoKit.privateKey(privateKeyBinary: privateKeyBytes, publicKeyBinary: publicKeyBytes) else {
            return XCTFail("Failed to create the Private key from bytes")
        }

        guard let publicKey = try? HMCryptoKit.publicKey(binary: publicKeyBytes) else {
            return XCTFail("Failed to create the Public key from bytes")
        }

        do {
            let sharedKey = try HMCryptoKit.sharedKey(privateKey: privateKey, publicKey: publicKey)

            XCTAssertEqual(sharedKey.count, 32)
            XCTAssertEqual(sharedKey, sharedKeyBytes)
        }
        catch {
            XCTFail("Failed to create the Shared key: \(error)")
        }
    }
}
