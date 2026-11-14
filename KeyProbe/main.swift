// Key-consistency check: the RouterInfo "s" option, the message-3 static key
// and the identity's encryption key must be the same bytes. Not part of the
// app target.

import Foundation
import CryptoKit

@main
struct KeyProbe {
    static func main() async {
        let context = I2PRouterAppContext.shared
        let raw = context.mainnetEncryptionKey.publicKey.rawRepresentation
        let canonical = I2PCrypto.canonicalX25519PublicKey(raw)
        let ri = context.mainnetSignedRouterInfo
        let s = ri.addresses.first?.options["s"] ?? "-"
        let published = I2PCrypto.i2pBase64Decode(s) ?? Data()
        print("raw public key      : \(raw.hex)  msb=\(raw[31] & 0x80)")
        print("canonical public key: \(canonical.hex)")
        print("RouterInfo s        : \(s)")
        print("decoded s           : \(published.hex)")
        print("raw == decoded s    : \(raw == published)")
        print("canonical == s      : \(canonical == published)")
        print("transport key arg   : identity.encryptionPublicKey == raw: \(context.mainnetEncryptionKey.publicKey.rawRepresentation == raw)")
        exit(0)
    }
}
