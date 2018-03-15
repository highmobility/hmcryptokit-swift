
import Foundation
import HMCryptoKit
import HMUtilities


let nonce = try? HMCryptoKit.nonce()
print("Nonce:", nonce?.hex ?? "nil")
print()

let keys = try? HMCryptoKit.keys()
print("Private key:", keys?.privateKey.hex ?? "nil")
print("Public key: ", keys?.publicKey.hex ?? "nil")
print()


let newKeys = try? HMCryptoKit.keys(privateKey: keys!.privateKey)
print("Private key:", newKeys?.privateKey.hex ?? "nil")
print("Public key: ", newKeys?.publicKey.hex ?? "nil")
print()

let sharedKey = try? HMCryptoKit.sharedKey(privateKey: keys!.privateKey, publicKey: keys!.publicKey)
print("Shared key: ", sharedKey?.hex ?? "nil")
print()

let msg: [UInt8] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
let key = "36C96B4E8B2A031022853BC029A7EA49F65BB0824A05D486E39A04E90D80B9BE".bytes
let hmac = try? HMCryptoKit.hmac(message: msg, key: key)
print("MSG: ", msg.hex)
print("HMAC:", hmac?.hex ?? "nil", " == ", (try? HMCryptoKit.verify(hmac: hmac!, message: msg, key: key)) ?? "nil")
print()

let iv: [UInt8] = msg.reversed()
let encypted = try? HMCryptoKit.encryptDecrypt(message: msg, iv: iv, key: key)
print("MSG:", msg.hex)
print("IV: ", iv.hex)
print("KEY:", key.hex)
print("OUT:", encypted?.hex ?? "nil")
print()

let sig = try? HMCryptoKit.signature(message: msg, privateKey: keys!.privateKey)
print("MSG:", msg.hex)
print("KEY:", keys?.privateKey.hex ?? "nil")
print("SIG:", sig?.hex ?? "nil")
print()

let verified = try? HMCryptoKit.verify(signature: sig!, message: msg, publicKey: keys!.publicKey)
print("MSG:", msg.hex)
print("SIG:", sig?.hex ?? "nil")
print("PUB:", keys?.publicKey.hex ?? "nil")
print("OK: ", verified ?? "nil")
print()

