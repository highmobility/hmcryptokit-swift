//
//  HMCryptoKitError.swift
//  HMCryptoKit
//
//  Created by Mikk Rätsep on 06/03/2018.
//

import Foundation

#if os(iOS) || os(watchOS) || os(tvOS)
    import CommonCrypto
#else
    import COpenSSL


    func getOpenSSLError() -> String {
        SSL_load_error_strings()

        let buffer = ERR_error_string(ERR_get_error(), nil)

        ERR_free_strings()

        guard let errorAddress = buffer,
            let string = String(validatingUTF8: errorAddress) else {
                return "unknown"
        }

        print(string)

        return string
    }
#endif


public enum HMCryptoKitError: Error {

    #if os(iOS) || os(watchOS) || os(tvOS)
        case commonCryptoError(CCCryptorStatus)

        case secKeyError(CFError)
    #else
        case openSSLError(String)
    #endif

    case invalidInputSize(String)

    case osStatusError(OSStatus)

    case systemError(Int32)
}
