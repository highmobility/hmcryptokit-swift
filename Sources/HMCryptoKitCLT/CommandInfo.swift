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
//  CommandInfo.swift
//  HMCryptoKitCLT
//
//  Created by Mikk Rätsep on 21/03/2018.
//

import Foundation


enum SizeType {
    case int(Int)
    case nBytes
    case string(String)
}

enum ParsingError: Error {
    case error(String)
}


typealias BytesArrays = [[UInt8]]
typealias InputPair = (name: String, size: SizeType)


protocol CommandInfoType {

    var description: String { get }
    var inputsDesc: [InputPair] { get }
    var name: String { get }
    var parameters: [String] { get }

    func parse(input: [String]) throws -> String
}


struct CommandInfo<InputType, OutputType>: CommandInfoType {
    let description: String
    let inputsDesc: [InputPair]
    let name: String
    let parameters: [String]

    private let parser: (InputType) throws -> OutputType


    // MARK: Methods

    func parse(input: [String]) throws -> String {
        // Check if the input count is correct
        let expectedCount = parameters.count

        guard input.count == expectedCount else {
            if expectedCount == 0 {
                throw ParsingError.error("parameters must be empty")
            }
            else if expectedCount == 1 {
                throw ParsingError.error("parameters must have 1 value")
            }
            else {
                throw ParsingError.error("parameters must have \(expectedCount) values")
            }
        }

        // Try to convert the string-input to a desired type
        let convertedInput: InputType

        switch InputType.self {
        case is BytesArrays.Type:
            guard let arrays = input.map({ $0.bytes }) as? InputType else {
                throw ParsingError.error("input conversion failed")
            }

            convertedInput = arrays

        case is Int.Type:
            guard let int = Int(input[0]) as? InputType else {
                throw ParsingError.error("input conversion failed")
            }

            convertedInput = int

        case is Void.Type:
            convertedInput = Void() as! InputType

        default:
            throw ParsingError.error("invalid input")
        }

        // Try to parse the command
        do {
            let result = try parser(convertedInput)

            // Convert the output to a desired form
            switch result.self {
            case let boolean as Bool:
                if devOutput {
                    return boolean ? "0x01" : "0x00"
                }
                else {
                    return boolean ? "CORRECT" : "INVALID"
                }

            case let bytes as [UInt8]:
                if devOutput {
                    return bytes.map { String(format: "0x%02X", $0) }.joined(separator: ", ")
                }
                else {
                    return bytes.hex
                }

            case let keys as (privateKey: [UInt8], publicKey: [UInt8]):
                if devOutput {
                    let privateKey = keys.privateKey.map { String(format: "0x%02X", $0) }.joined(separator: ", ")
                    let publicKey = keys.publicKey.map { String(format: "0x%02X", $0) }.joined(separator: ", ")

                    return privateKey + "\n" + publicKey
                }
                else {
                    return keys.privateKey.hex + "\n" + keys.publicKey.hex
                }

            default:
                return "output conversion failed"
            }
        }
        catch {
            throw ParsingError.error("\(error)")
        }
    }


    // MARK: Init

    init(name: String, parameters: [String], description: String, inputsDesc: [InputPair], parser: @escaping (InputType) throws -> OutputType) {
        self.name = name
        self.parameters = parameters
        self.description = description
        self.inputsDesc = inputsDesc
        self.parser = parser
    }
}
