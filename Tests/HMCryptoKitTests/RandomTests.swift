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
//  RandomTests.swift
//  HMCryptoKitTests
//
//  Created by Mikk Rätsep on 26/03/2018.
//  Copyright © 2019 High Mobility GmbH. All rights reserved.
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
