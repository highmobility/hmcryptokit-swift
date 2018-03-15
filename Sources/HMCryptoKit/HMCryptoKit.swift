//
//  HMCryptoKit.swift
//  HMCryptoKit
//
//  Created by Mikk Rätsep on 06/03/2018.
//
//

import Foundation
import HMUtilities


#if os(iOS) || os(tvOS) || os(watchOS)
    import Security

    public typealias ECKey = SecKey
#else
    public typealias ECKey = [UInt8]
#endif


public struct HMCryptoKit {

}
