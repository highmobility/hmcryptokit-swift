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
//  HMACTests.swift
//  HMCryptoKitTests
//
//  Created by Mikk Rätsep on 26/03/2018.
//

import HMCryptoKit
import HMUtilities
import XCTest


class HMACTests: XCTestCase {

    static var allTests = [("testHMAC", testHMAC),
                           ("testVerifyHMAC", testVerifyHMAC)]
    

    // MARK: XCTestCase

    func testHMAC() {
        let msgBytes = "00112233445566778899AABBCCDDEEFF".hexBytes
        let keyBytes = "146CA6F959C8263198769E987922741507502239780A886ACF82FA4CC1EF3C02".hexBytes
        let hmacBytes = "520542F3B93046AC39E304B9EE493B0632356E3171366B70F4E5540B2574A249".hexBytes

        do {
            let hmac = try HMCryptoKit.hmac(message: msgBytes, key: keyBytes)

            XCTAssertEqual(hmac.count, 32)
            XCTAssertEqual(hmac, hmacBytes)
        }
        catch {
            XCTFail("Failed to create HMAC: \(error)")
        }
    }

    func testVerifyHMAC() {
        let hmacBytes = "520542F3B93046AC39E304B9EE493B0632356E3171366B70F4E5540B2574A249".hexBytes
        let msgBytes = "00112233445566778899AABBCCDDEEFF".hexBytes
        let keyBytes = "146CA6F959C8263198769E987922741507502239780A886ACF82FA4CC1EF3C02".hexBytes

        do {
            let isVerified = try HMCryptoKit.verify(hmac: hmacBytes, message: msgBytes, key: keyBytes)

            XCTAssertTrue(isVerified)
        }
        catch {
            XCTFail("Failed to verify HMAC: \(error)")
        }
    }
}
