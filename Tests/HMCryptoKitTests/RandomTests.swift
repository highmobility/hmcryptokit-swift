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
//  RandomTests.swift
//  HMCryptoKitTests
//
//  Created by Mikk Rätsep on 26/03/2018.
//

import HMCryptoKit
import XCTest


class RandomTests: XCTestCase {

    static var allTests = [("testNonce", testNonce),
                           ("testRandom", testRandom),
                           ("testSerial", testSerial)]
    

    // MARK: XCTestCase

    func testNonce() {
        do {
            let nonce = try HMCryptoKit.nonce()

            XCTAssertNotEqual(nonce, [UInt8](repeating: 0x00, count: kNonceSize))
        }
        catch {
            XCTFail("Failed to create a Nonce: \(error)")
        }
    }

    func testRandom() {
        do {
            let bytes = try HMCryptoKit.randomBytes(100)

            XCTAssertNotEqual(bytes, [UInt8](repeating: 0x00, count: 100))
        }
        catch {
            XCTFail("Failed to create Random bytes: \(error)")
        }
    }

    func testSerial() {
        do {
            let serial = try HMCryptoKit.serial()

            XCTAssertNotEqual(serial, [UInt8](repeating: 0x00, count: kSerialNumberSize))
        }
        catch {
            XCTFail("Failed to create a Serial: \(error)")
        }
    }
}
