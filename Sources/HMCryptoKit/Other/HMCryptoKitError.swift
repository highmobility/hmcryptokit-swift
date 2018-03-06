//
//  HMCryptoKitError.swift
//  HMCryptoKit
//
//  Created by Mikk Rätsep on 06/03/2018.
//

import Foundation


public enum HMCryptoKitError: Error {

//    case commonCryptoError(CCCryptorStatus)

    case internalSecretError

    case invalidInputSize(String)

    case secKeyError(CFError)

    case osStatusError(OSStatus)

    case systemError(Int32)

    case unavailableInPlaygrounds
}
