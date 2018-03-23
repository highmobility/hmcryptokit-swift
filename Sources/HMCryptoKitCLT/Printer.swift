//
// HMCryptoKit CLT
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
//  Misc.swift
//  HMCryptoKitCLT
//
//  Created by Mikk Rätsep on 21/03/2018.
//

import Foundation
import HMCryptoKitCommandsInfo


struct Printer {

    static func printHelp() {
        let text = """
          Enter HEX data after the command to execute it.

            Commands:
                \(CommandsManager.shared.commandsDescriptions.joined(separator: "\n        "))

            Flags:
                -h, --help  Print the help for a command
                -d, --dev   Output hexadecimal array: 0xA1, 0xB2, 0xC3...

            Example:
                verify-hmac 36010003001000 1EF76A3941D52615F7720B35928EC97603A18DD2F8D35E8F7631BE98B3F3A064 50C253814598FAECABFC732341290D09B4AEF0DAF4D44349A26448A484EBE1B6
        """

        print(text)
    }

    static func printHelp(command: CommandInfoType) {
        let longestName = command.inputsDesc.reduce(0) { max($0, $1.name.count) }
        let inputs: [String] = command.inputsDesc.map {
            let info: String

            switch $0.size {
            case .int(let size):
                info = String(format: "%2d bytes", size)

            case .nBytes:
                info = " n bytes"

            case .string(let text):
                info = text
            }

            return "<\($0.name)>  " + String(repeating: " ", count: (longestName - $0.name.count)) + info
        }

        let text = """
          \(command.description)
          \(String(repeating: "-", count: command.description.count))

           \(command.name) <\(command.parameters.joined(separator: "> <"))>


           \(inputs.joined(separator: "\n   "))
        """

        print(text)
    }
}
