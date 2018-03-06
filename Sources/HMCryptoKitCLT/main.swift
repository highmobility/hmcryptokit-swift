
import HMCryptoKit
import Foundation


let nonce = try? HMCryptoKit.nonce()
print("Nonce:", nonce?.hex ?? "nil")
print()

let keys = try? HMCryptoKit.keys()
print("Private key:", keys?.privateKey.hex ?? "nil")
print("Public key: ", keys?.publicKey.hex ?? "nil")
print()

let newKeys = try? HMCryptoKit.keys(keys?.privateKey)
print("Private key:", newKeys?.privateKey.hex ?? "nil")
print("Public key: ", newKeys?.publicKey.hex ?? "nil")
print()

let sharedKey = try? HMCryptoKit.sharedKey(keys!.privateKey, keys!.publicKey)
print("Shared key: ", sharedKey?.hex ?? "nil")
print()
