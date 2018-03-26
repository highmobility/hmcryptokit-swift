//
// HMCryptoKitTests
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
        let msgBytes = "00112233445566778899AABBCCDDEEFF".bytes
        let keyBytes = "146CA6F959C8263198769E987922741507502239780A886ACF82FA4CC1EF3C02".bytes
        let hmacBytes = "520542F3B93046AC39E304B9EE493B0632356E3171366B70F4E5540B2574A249".bytes

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
        let hmacBytes = "520542F3B93046AC39E304B9EE493B0632356E3171366B70F4E5540B2574A249".bytes
        let msgBytes = "00112233445566778899AABBCCDDEEFF".bytes
        let keyBytes = "146CA6F959C8263198769E987922741507502239780A886ACF82FA4CC1EF3C02".bytes

        do {
            let isVerified = try HMCryptoKit.verify(hmac: hmacBytes, message: msgBytes, key: keyBytes)

            XCTAssertTrue(isVerified)
        }
        catch {
            XCTFail("Failed to verify HMAC: \(error)")
        }
    }
}
