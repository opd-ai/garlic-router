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
    var encType: I2PEncType
    /// Payload bytes beyond sigType/encType (empty for keys that fit the standard fields).
    var extra: Data

    init(sigType: I2PSigType = .ed25519, encType: I2PEncType = .x25519, extra: Data = Data()) {
        self.sigType = sigType
        self.encType = encType
        self.extra = extra
    }

    func serialize(into w: inout I2PWriter) {
        var payload = Data()
        payload.append(UInt8((sigType.rawValue >> 8) & 0xff))
        payload.append(UInt8(sigType.rawValue & 0xff))
        payload.append(UInt8((encType.rawValue >> 8) & 0xff))
        payload.append(UInt8(encType.rawValue & 0xff))
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
            guard let sigType = I2PSigType(rawValue: sigRaw), let encType = I2PEncType(rawValue: encRaw) else {
                throw I2PWireError.unsupportedAlgorithm
            }
            return I2PCertificate(sigType: sigType, encType: encType, extra: payload.dropFirst(4))
        case 0: // null certificate: legacy DSA-SHA1 identities are rejected
            throw I2PWireError.unsupportedAlgorithm
        default:
            throw I2PWireError.unsupportedAlgorithm
        }
    }
}

// MARK: - KeysAndCert (shared by Destination and RouterIdentity)

struct I2PKeysAndCert {
    /// X25519 public key (EncType 4), stored in the 256-byte legacy field, zero-padded.
    let encryptionPublicKey: Data
    /// Ed25519 public key (SigType 7), stored in the 128-byte legacy field, zero-padded.
    let signingPublicKey: Data
    let certificate: I2PCertificate
    /// Serialized form (256 + 128 + certificate bytes).
    let raw: Data

    init(encryptionPublicKey: Data, signingPublicKey: Data) {
        precondition(encryptionPublicKey.count == 32, "X25519 public key must be 32 bytes")
        precondition(signingPublicKey.count == 32, "Ed25519 public key must be 32 bytes")
        self.encryptionPublicKey = encryptionPublicKey
        self.signingPublicKey = signingPublicKey
        self.certificate = I2PCertificate(sigType: .ed25519, encType: .x25519)
        self.raw = I2PKeysAndCert.buildRaw(
            encryptionPublicKey: encryptionPublicKey,
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
        guard certificate.encType.publicKeyLength <= publicKeyField.count,
              certificate.sigType.publicKeyLength <= signingField.count else {
            throw I2PWireError.unsupportedAlgorithm
        }
        let encryptionKey = publicKeyField.prefix(certificate.encType.publicKeyLength)
        let signingKey = signingField.prefix(certificate.sigType.publicKeyLength)
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

    func serialize(into w: inout I2PWriter) { w.raw(raw) }
    func serialized() -> Data { raw }

    private static func buildRaw(encryptionPublicKey: Data, signingPublicKey: Data, certificate: I2PCertificate) -> Data {
        var w = I2PWriter()
        var enc = encryptionPublicKey
        enc.append(Data(repeating: 0, count: 256 - enc.count))
        var sig = signingPublicKey
        sig.append(Data(repeating: 0, count: 128 - sig.count))
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
        w.byte(cost)
        w.string(transportStyle)
        w.date(expiration)
        w.mapping(options)
    }

    static func parse(_ r: inout I2PReader) throws -> I2PRouterAddress {
        let cost = try r.byte()
        let style = try r.string()
        let expiration = try r.date()
        let options = try r.mapping()
        return I2PRouterAddress(cost: cost, transportStyle: style, expiration: expiration, options: options)
    }
}

// MARK: - RouterInfo

struct I2PRouterInfo {
    let identity: I2PRouterIdentity
    let published: Date
    let addresses: [I2PRouterAddress]
    let options: [String: String]
    var signature: Data

    init(identity: I2PRouterIdentity, published: Date, addresses: [I2PRouterAddress],
         options: [String: String], signature: Data = Data()) {
        self.identity = identity
        self.published = published
        self.addresses = addresses
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
        let options = try r.mapping()
        let signature = try r.raw(64)
        guard r.remaining == 0 else { throw I2PWireError.trailingData }
        let info = I2PRouterInfo(
            identity: identity,
            published: published,
            addresses: addresses,
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