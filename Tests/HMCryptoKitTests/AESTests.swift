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
//  AESTests.swift
//  HMCryptoKitTests
//
//  Created by Mikk Rätsep on 26/03/2018.
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
