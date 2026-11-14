//
//  I2PStructures.swift
//  Core I2P data structures: Certificate, KeysAndCert (Destination / RouterIdentity),
//  RouterAddress, RouterInfo and LeaseSet, all serialized in the I2P binary
//  format and signature-verified on parse.
//

import Foundation

// MARK: - Certificate

struct I2PCertificate: Equatable {
    var sigType: I2PSigType
    /// The crypto key type code exactly as it rides the wire (2 bytes). A
    /// LeaseSet2-era destination publishes code 0 beside a modern signing key:
    /// proposal 123 leaves the destination's crypto field unused ("The
    /// encryption type is not specified in the Destination key certificate, it
    /// will remain 0") and carries the usable encryption key in the LeaseSet2
    /// key list instead. Keeping the code verbatim lets such an identity parse
    /// and re-serialize byte-for-byte, while `encType` stays nil — no crypto
    /// algorithm is invented for a field nothing here may use.
    var encTypeRawValue: UInt16
    /// Payload bytes beyond sigType/encType (empty for keys that fit the standard fields).
    var extra: Data

    /// The crypto algorithm this router implements, or nil for the unused code.
    var encType: I2PEncType? { I2PEncType(rawValue: encTypeRawValue) }

    /// The crypto public key length the certificate declares; 0 when the field
    /// is the unused legacy one, i.e. the identity carries no usable crypto key.
    var cryptoPublicKeyLength: Int { encType?.publicKeyLength ?? 0 }

    init(sigType: I2PSigType = .ed25519, encType: I2PEncType = .x25519, extra: Data = Data()) {
        self.init(sigType: sigType, encTypeRawValue: encType.rawValue, extra: extra)
    }

    init(sigType: I2PSigType, encTypeRawValue: UInt16, extra: Data = Data()) {
        self.sigType = sigType
        self.encTypeRawValue = encTypeRawValue
        self.extra = extra
    }

    func serialize(into w: inout I2PWriter) {
        var payload = Data()
        payload.append(UInt8((sigType.rawValue >> 8) & 0xff))
        payload.append(UInt8(sigType.rawValue & 0xff))
        payload.append(UInt8((encTypeRawValue >> 8) & 0xff))
        payload.append(UInt8(encTypeRawValue & 0xff))
        payload.append(extra)
        w.byte(5) // key certificate
        w.short(UInt16(payload.count))
        w.raw(payload)
    }

    static func parse(_ r: inout I2PReader) throws -> I2PCertificate {
        let type = try r.byte()
        let length = Int(try r.short())
        let payload = try r.raw(length)
        switch type {
        case 5: // key certificate
            guard payload.count >= 4 else { throw I2PWireError.invalidFormat }
            let sigRaw = (UInt16(payload[0]) << 8) | UInt16(payload[1])
            let encRaw = (UInt16(payload[2]) << 8) | UInt16(payload[3])
            // The signing key is what authenticates the structure, and only the
            // modern types are implemented: a legacy SigType is rejected whole.
            guard let sigType = I2PSigType(rawValue: sigRaw) else {
                throw I2PWireError.unsupportedAlgorithm
            }
            // Code 0 is the spec's unused crypto field, which every long-lived
            // mainnet destination publishes; any other code must be one this
            // router implements. Rejecting 0 made every real LeaseSet2
            // unparseable, so no well-known destination ever resolved.
            guard encRaw == 0 || I2PEncType(rawValue: encRaw) != nil else {
                throw I2PWireError.unsupportedAlgorithm
            }
            return I2PCertificate(sigType: sigType, encTypeRawValue: encRaw, extra: payload.dropFirst(4))
        case 0: // null certificate: legacy DSA-SHA1 identities are rejected
            throw I2PWireError.unsupportedAlgorithm
        default:
            throw I2PWireError.unsupportedAlgorithm
        }
    }
}

// MARK: - KeysAndCert (shared by Destination and RouterIdentity)

struct I2PKeysAndCert {
    /// X25519 public key (EncType 4), read out of the 256-byte legacy field.
    /// Empty when the certificate names the unused crypto field (EncType 0, the
    /// LeaseSet2-era shape): such an identity publishes no usable crypto key of
    /// its own — the LeaseSet2 it points at carries the real key.
    let encryptionPublicKey: Data
    /// Ed25519 public key (SigType 7), stored in the 128-byte legacy field, zero-padded.
    let signingPublicKey: Data
    let certificate: I2PCertificate
    /// Serialized form (256 + 128 + certificate bytes).
    let raw: Data

    init(encryptionPublicKey: Data, signingPublicKey: Data) {
        precondition(encryptionPublicKey.count == 32, "X25519 public key must be 32 bytes")
        precondition(signingPublicKey.count == 32, "Ed25519 public key must be 32 bytes")
        // RFC 7748: the top bit of an X25519 public key's final byte is not
        // part of the u-coordinate. Peers validate it on NTCP2 `s` and on some
        // LeaseSet paths, so every key this router serializes is canonical.
        let canonicalKey = I2PCrypto.canonicalX25519PublicKey(encryptionPublicKey)
        self.encryptionPublicKey = canonicalKey
        self.signingPublicKey = signingPublicKey
        self.certificate = I2PCertificate(sigType: .ed25519, encType: .x25519)
        self.raw = I2PKeysAndCert.buildRaw(
            encryptionPublicKey: canonicalKey,
            signingPublicKey: signingPublicKey,
            certificate: certificate
        )
    }

    private init(encryptionPublicKey: Data, signingPublicKey: Data, certificate: I2PCertificate, raw: Data) {
        self.encryptionPublicKey = encryptionPublicKey
        self.signingPublicKey = signingPublicKey
        self.certificate = certificate
        self.raw = raw
    }

    static func parse(_ r: inout I2PReader) throws -> I2PKeysAndCert {
        let publicKeyField = try r.raw(256)
        let signingField = try r.raw(128)
        let certificate = try I2PCertificate.parse(&r)
        guard certificate.cryptoPublicKeyLength <= publicKeyField.count,
              certificate.sigType.publicKeyLength <= signingField.count else {
            throw I2PWireError.unsupportedAlgorithm
        }
        // An unused crypto field yields no key at all, rather than 256 bytes of
        // legacy ElGamal material nothing here may use.
        let encryptionKey = certificate.encType.map { publicKeyField.prefix($0.publicKeyLength) } ?? Data()
        // Per the common-structures spec the crypto key is aligned at the START
        // of the 256-byte field and the signing key at the END of the 128-byte
        // field, with random padding in the middle. Reading the signing key from
        // the prefix instead takes padding bytes for Ed25519 keys and makes
        // every real RouterInfo/Destination signature fail to verify.
        let signingKey = signingField.suffix(certificate.sigType.publicKeyLength)
        var cw = I2PWriter()
        certificate.serialize(into: &cw)
        var full = publicKeyField
        full.append(signingField)
        full.append(cw.data)
        return I2PKeysAndCert(
            encryptionPublicKey: encryptionKey,
            signingPublicKey: signingKey,
            certificate: certificate,
            raw: full
        )
    }

    /// SHA-256 of the serialized keys-and-certificate.
    var hash: Data { I2PCrypto.sha256(raw) }

    /// The signature type code a serialized KeysAndCert declares, read from its
    /// certificate at the fixed offset — 256-byte crypto field, 128-byte signing
    /// field, then certificate type, u16 length and payload. A LeaseSet2 payload
    /// begins with its destination, so this classifies a netdb entry too. Used for
    /// diagnostics: it separates "this identity signs with a legacy type this
    /// router does not implement" from "this entry is malformed".
    static func declaredSignatureTypeCode(in raw: Data) -> UInt16? {
        let bytes = Array(raw)
        guard bytes.count >= 387 else { return nil }
        let certificateType = bytes[384]
        let length = (Int(bytes[385]) << 8) | Int(bytes[386])
        guard bytes.count >= 387 + length else { return nil }
        // A null certificate is the legacy 384-byte DSA-SHA1 identity shape.
        if certificateType == 0 { return 0 }
        guard length >= 2 else { return nil }
        return (UInt16(bytes[387]) << 8) | UInt16(bytes[388])
    }

    func serialize(into w: inout I2PWriter) { w.raw(raw) }
    func serialized() -> Data { raw }

    private static func buildRaw(encryptionPublicKey: Data, signingPublicKey: Data, certificate: I2PCertificate) -> Data {
        var w = I2PWriter()
        // Crypto key first, then padding to 256 bytes; then padding to 96 bytes
        // and the signing key last — the spec's alignment (padding repeats the
        // 32-byte key material, which keeps the structure highly compressible).
        var enc = encryptionPublicKey
        while enc.count + encryptionPublicKey.count <= 256 { enc.append(encryptionPublicKey) }
        if enc.count < 256 { enc.append(encryptionPublicKey.prefix(256 - enc.count)) }
        var sig = Data()
        let signingPadding = 128 - signingPublicKey.count
        while sig.count < signingPadding {
            sig.append(signingPublicKey.prefix(min(signingPublicKey.count, signingPadding - sig.count)))
        }
        sig.append(signingPublicKey)
        w.raw(enc)
        w.raw(sig)
        certificate.serialize(into: &w)
        return w.data
    }
}

typealias I2PDestination = I2PKeysAndCert
typealias I2PRouterIdentity = I2PKeysAndCert

// MARK: - RouterAddress

struct I2PRouterAddress: Equatable {
    var cost: UInt8
    var transportStyle: String
    var expiration: Date?
    var options: [String: String]

    func serialize(into w: inout I2PWriter) {
        // Spec order: cost, expiration Date, transport style String, options.
        w.byte(cost)
        w.date(expiration)
        w.string(transportStyle)
        w.mapping(options)
    }

    static func parse(_ r: inout I2PReader) throws -> I2PRouterAddress {
        let cost = try r.byte()
        let expiration = try r.date()
        let style = try r.string()
        let options = try r.mapping()
        return I2PRouterAddress(cost: cost, transportStyle: style, expiration: expiration, options: options)
    }
}

// MARK: - RouterInfo

struct I2PRouterInfo {
    let identity: I2PRouterIdentity
    let published: Date
    let addresses: [I2PRouterAddress]
    /// Legacy "peer size" list (unused by the network, always empty): the spec
    /// carries a 1-byte count plus that many 32-byte hashes before the options.
    let peers: [Data]
    let options: [String: String]
    var signature: Data

    init(identity: I2PRouterIdentity, published: Date, addresses: [I2PRouterAddress],
         peers: [Data] = [], options: [String: String], signature: Data = Data()) {
        self.identity = identity
        self.published = published
        self.addresses = addresses
        self.peers = peers
        self.options = options
        self.signature = signature
    }

    /// Everything covered by the signature (identity through options).
    func serializedBody() -> Data {
        var w = I2PWriter()
        identity.serialize(into: &w)
        w.date(published)
        w.byte(UInt8(addresses.count))
        addresses.forEach { $0.serialize(into: &w) }
        w.byte(UInt8(peers.count))
        peers.forEach { w.hash($0) }
        w.mapping(options)
        return w.data
    }

    mutating func sign(withSeed seed: Data) throws {
        signature = try I2PCrypto.ed25519Sign(serializedBody(), seed: seed)
    }

    func serialize() -> Data {
        var data = serializedBody()
        data.append(signature)
        return data
    }

    /// Ed25519 (SigType 7) verification with the identity's signing public key.
    func verifySignature() -> Bool {
        I2PCrypto.ed25519Verify(
            signature: signature,
            message: serializedBody(),
            publicKey: identity.signingPublicKey
        )
    }

    /// Parses and verifies the signature; throws on any mismatch.
    static func parse(_ data: Data) throws -> I2PRouterInfo {
        var r = I2PReader(data)
        let identity = try I2PKeysAndCert.parse(&r)
        let published = try r.date() ?? Date(timeIntervalSince1970: 0)
        let count = Int(try r.byte())
        var addresses: [I2PRouterAddress] = []
        for _ in 0..<count {
            addresses.append(try I2PRouterAddress.parse(&r))
        }
        // Legacy peer list: 1-byte count followed by that many hashes.
        let peerCount = Int(try r.byte())
        var peers: [Data] = []
        for _ in 0..<peerCount {
            peers.append(try r.hash())
        }
        let options = try r.mapping()
        let signature = try r.raw(64)
        guard r.remaining == 0 else { throw I2PWireError.trailingData }
        let info = I2PRouterInfo(
            identity: identity,
            published: published,
            addresses: addresses,
            peers: peers,
            options: options,
            signature: signature
        )
        guard info.verifySignature() else { throw I2PWireError.invalidSignature }
        return info
    }
}

// MARK: - Lease & LeaseSet

struct I2PLease: Equatable {
    /// SHA-256 hash of the gateway router's identity (32 bytes).
    var gatewayHash: Data
    var tunnelId: UInt32
    var expiration: Date
}

struct I2PLeaseSet {
    let destination: I2PDestination
    let published: Date
    let leases: [I2PLease]
    var signature: Data

    init(destination: I2PDestination, published: Date, leases: [I2PLease], signature: Data = Data()) {
        precondition(!leases.isEmpty, "LeaseSet requires at least one lease")
        self.destination = destination
        self.published = published
        self.leases = leases
        self.signature = signature
    }

    func serializedBody() -> Data {
        var w = I2PWriter()
        destination.serialize(into: &w)
        w.date(published)
        w.byte(UInt8(leases.count))
        for lease in leases {
            w.hash(lease.gatewayHash)
            w.integer(lease.tunnelId)
            w.date(lease.expiration)
        }
        return w.data
    }

    mutating func sign(withSeed seed: Data) throws {
        signature = try I2PCrypto.ed25519Sign(serializedBody(), seed: seed)
    }

    func serialize() -> Data {
        var data = serializedBody()
        data.append(signature)
        return data
    }

    /// Signed by the destination's own private signing key.
    func verifySignature() -> Bool {
        I2PCrypto.ed25519Verify(
            signature: signature,
            message: serializedBody(),
            publicKey: destination.signingPublicKey
        )
    }

    /// Parses and verifies the signature; throws on any mismatch.
    static func parse(_ data: Data) throws -> I2PLeaseSet {
        var r = I2PReader(data)
        let destination = try I2PKeysAndCert.parse(&r)
        let published = try r.date() ?? Date(timeIntervalSince1970: 0)
        let count = Int(try r.byte())
        guard count >= 1 else { throw I2PWireError.invalidFormat }
        var leases: [I2PLease] = []
        for _ in 0..<count {
            let gatewayHash = try r.hash()
            let tunnelId = try r.integer()
            let expiration = try r.date() ?? Date(timeIntervalSince1970: 0)
            leases.append(I2PLease(gatewayHash: gatewayHash, tunnelId: tunnelId, expiration: expiration))
        }
        let signature = try r.raw(64)
        guard r.remaining == 0 else { throw I2PWireError.trailingData }
        let leaseSet = I2PLeaseSet(destination: destination, published: published, leases: leases, signature: signature)
        guard leaseSet.verifySignature() else { throw I2PWireError.invalidSignature }
        return leaseSet
    }
}