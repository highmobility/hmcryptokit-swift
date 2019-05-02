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
//  AESTests.swift
//  HMCryptoKitTests
//
//  Created by Mikk Rätsep on 26/03/2018.
//  Copyright © 2019 High Mobility GmbH. All rights reserved.
//

import HMCryptoKit
import HMUtilities
import XCTest


class AESTests: XCTestCase {

    static var allTests = [("testEncrypt", testEncrypt),
                           ("testIV", testIV)]
    

    // MARK: XCTestCase

    func testEncrypt() {
        let msg = "00112233445566778899AABBCCDDEEFF".hexBytes
        let iv = "1804AD6A40A372FE430293CC7B236BA8".hexBytes
        let key = "146CA6F959C8263198769E987922741507502239780A886ACF82FA4CC1EF3C02".hexBytes
        let encryptedBytes = "0F6B2AFE7B9A51F4955D89BADEE5ED25".hexBytes

        do {
            let cipherText = try HMCryptoKit.encryptDecrypt(message: msg, iv: iv, key: key)

            XCTAssertEqual(cipherText.count, msg.count)
            XCTAssertEqual(cipherText, encryptedBytes)
        }
        catch {
            XCTFail("Failed to Encrypt / Decrypt: \(error)")
        }
    }

    func testIV() {
        let nonce = "001122334455667788".hexBytes
        let tNonce = "FFEEDDCCBBAA998877".hexBytes

        do {
            let iv = try HMCryptoKit.iv(nonce: nonce, transactionNonce: tNonce)

            XCTAssertEqual(iv, Array(nonce.prefix(upTo: 7) + tNonce.prefix(upTo: 9)))
        }
        catch {
            XCTFail("Failed to create the Injection Vector: \(error)")
        }
    }
}
