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
//  main.swift
//  HMCryptoKitCLT
//
//  Created by Mikk Rätsep on 06/02/2018.
//

import Foundation
import HMCryptoKit
import HMUtilities


var devOutput = false

func main() {
    let arguments = CommandLine.arguments

    // Verify required input count
    guard arguments.count >= 2 else {
        return Printer.printHelp()
    }

    let commandName = arguments[1]
    let flags = arguments[2...].filter { $0.starts(with: "-") }
    let input = arguments[2...].filter { !$0.starts(with: "-") }

    // Find the command
    guard let command = CommandsManager.shared.commands.first(where: { $0.name == commandName }) else {
        return Printer.printHelp()
    }

    guard !flags.contains("-h") && !flags.contains("--help") else {
        return Printer.printHelp(command: command)
    }

    if flags.contains("-d") || flags.contains("--dev") {
        devOutput = true
    }

    // Try to parse the command
    do {
        let result = try command.parse(input: input)

        print(result)
    }
    catch let error as ParsingError {
        switch error {
        case .error(let reason):
            print("  Error:", reason)
        }
    }
    catch {
        print("  Error: \(error)")
    }
}


print()
main()
print()
