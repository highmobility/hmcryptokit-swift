//
//  UInt8Collection+Extensions.swift
//  HMCryptoKit
//
//  Created by Mikk Rätsep on 06/03/2018.
//

import Foundation


extension Array where Element == UInt8 {

    init(zeroFilledTo size: Int) {
        self.init(repeating: 0x00, count: size)
    }
}
