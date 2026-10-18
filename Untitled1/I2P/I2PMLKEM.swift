//
//  I2PMLKEM.swift
//  ML-KEM (FIPS 203) in pure Swift for the SSU2 post-quantum hybrid leg.
//
//  Layers:
//  • Keccak-f[1600] sponge — SHA3-256, SHA3-512, SHAKE-128, SHAKE-256.
//  • Ring arithmetic over Z_q[X]/(X^256 + 1) (q = 3329) with the number-
//    theoretic transform: forward Cooley–Tukey butterflies consume the
//    twiddle table ζ^brv7(k) sequentially (ζ = 17, a primitive 256-th root
//    of unity — ζ^128 ≡ −1 mod q); the inverse uses Gentleman–Sande
//    butterflies with twiddles −ζ^brv7(k) plus a final 128^−1 scale; the
//    pointwise product reduces the (2i, 2i+1) coefficient pair modulo the
//    i-th quadratic factor X^2 − ζ^(2·brv7(i)+1).
//  • ML-KEM-512 and ML-KEM-768: key generation, encapsulation and fail-closed
//    decapsulation with implicit rejection, byte-exact FIPS 203 wire shapes
//    (encapsulation keys 800/1184 bytes, ciphertexts 768/1088 bytes, 32-byte
//    shared secrets).
//
//  Conventions (FIPS 203 / the Kyber reference):
//  • Matrix entries Â[i][j] = SampleNTT(SHAKE-128(ρ ∥ j ∥ i)); key generation
//    computes t = Â·ŝ + e, encryption the transposed application u = Â^T·r.
//  • Encapsulation key ek = encode12(t) ∥ ρ (ρ last, 32 bytes).
//  • PRF(η, s, b) = SHAKE-256(s ∥ b) with 64·η output bytes; the CBD sums η
//    bits against η bits read LSB-first.
//  • Encapsulation: m ← random 32; (K, r) = SHA3-512(m ∥ H(ek));
//    c = Encrypt(ek, m, r). Decapsulation re-encrypts m′ = Decrypt(c) and
//    compares: on mismatch the implicitly rejected key SHA3-256(J(z) ∥ c)
//    is returned, so decapsulation never fails open.
//

import Foundation

// MARK: - Keccak-f[1600] sponge (SHA-3 / SHAKE)

enum Keccak {
    enum Mode {
        case sha3_256, sha3_512, shake128, shake256

        var rate: Int {
            switch self {
            case .sha3_256: return 136
            case .sha3_512: return 72
            case .shake128: return 168
            case .shake256: return 136
            }
        }

        /// Domain separator byte: SHA-3 pads with 0x06, SHAKE with 0x1F.
        var padByte: UInt8 {
            (self == .sha3_256 || self == .sha3_512) ? 0x06 : 0x1F
        }
    }

    private static let roundConstants: [UInt64] = [
        0x0000_0000_0000_0001, 0x0000_0000_0000_8082, 0x8000_0000_0000_808A,
        0x8000_0000_8000_8000, 0x0000_0000_0000_808B, 0x0000_0000_8000_0001,
        0x8000_0000_8000_8081, 0x8000_0000_0000_8009, 0x0000_0000_0000_008A,
        0x0000_0000_0000_0088, 0x0000_0000_8000_8009, 0x0000_0000_8000_000A,
        0x0000_0000_8000_808B, 0x8000_0000_0000_008B, 0x8000_0000_0000_8089,
        0x8000_0000_0000_8003, 0x8000_0000_0000_8002, 0x8000_0000_0000_0080,
        0x0000_0000_0000_800A, 0x8000_0000_8000_000A, 0x8000_0000_8000_8081,
        0x8000_0000_0000_8080, 0x0000_0000_8000_0001, 0x8000_0000_8000_8008
    ]

    private static let rhoOffsets: [Int] = [
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
        27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
    ]

    private static let piLanes: [Int] = [
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
        15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
    ]

    private static func rotl(_ value: UInt64, _ bits: Int) -> UInt64 {
        (value << UInt64(bits)) | (value >> UInt64(64 - bits))
    }

    /// The 24-round Keccak-f[1600] permutation over 25 little-endian lanes.
    static func permute(_ state: inout [UInt64]) {
        for round in 0..<24 {
            // Theta
            var c = [UInt64](repeating: 0, count: 5)
            for i in 0..<5 {
                c[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20]
            }
            for i in 0..<5 {
                let t = c[(i + 4) % 5] ^ rotl(c[(i + 1) % 5], 1)
                for j in stride(from: 0, to: 25, by: 5) { state[j + i] ^= t }
            }
            // Rho + pi
            var last = state[1]
            for i in 0..<24 {
                let lane = piLanes[i]
                let tmp = state[lane]
                state[lane] = rotl(last, rhoOffsets[i])
                last = tmp
            }
            // Chi
            for j in stride(from: 0, to: 25, by: 5) {
                var row = [UInt64](repeating: 0, count: 5)
                for i in 0..<5 { row[i] = state[j + i] }
                for i in 0..<5 { state[j + i] ^= (~row[(i + 1) % 5]) & row[(i + 2) % 5] }
            }
            // Iota
            state[0] ^= roundConstants[round]
        }
    }

    /// Absorbs the padded input into a fresh state, permuting per rate block.
    private static func absorbPadPermute(mode: Mode, input: [UInt8]) -> [UInt64] {
        var state = [UInt64](repeating: 0, count: 25)
        let rate = mode.rate
        var block = input
        let gap = rate - block.count % rate
        if gap == 1 {
            block.append(mode.padByte ^ 0x80)
        } else {
            block.append(mode.padByte)
            block.append(contentsOf: repeatElement(UInt8(0), count: gap - 2))
            block.append(0x80)
        }
        var offset = 0
        while offset < block.count {
            for i in 0..<(rate / 8) {
                var lane: UInt64 = 0
                for b in 0..<8 {
                    lane |= UInt64(block[offset + i * 8 + b]) << (8 * UInt64(b))
                }
                state[i] ^= lane
            }
            permute(&state)
            offset += rate
        }
        return state
    }

    /// Squeezes `count` bytes; successive calls must request rate-sized blocks.
    private static func squeeze(state: inout [UInt64], rate: Int, count: Int) -> [UInt8] {
        var out: [UInt8] = []
        while out.count < count {
            for i in 0..<(rate / 8) {
                var lane = state[i].littleEndian
                withUnsafeBytes(of: &lane) { out.append(contentsOf: $0) }
            }
            if out.count < count { permute(&state) }
        }
        return Array(out[0..<count])
    }

    static func sha3_256(_ input: Data) -> Data {
        var state = absorbPadPermute(mode: .sha3_256, input: [UInt8](input))
        return Data(squeeze(state: &state, rate: Mode.sha3_256.rate, count: 32))
    }

    static func sha3_512(_ input: Data) -> Data {
        var state = absorbPadPermute(mode: .sha3_512, input: [UInt8](input))
        return Data(squeeze(state: &state, rate: Mode.sha3_512.rate, count: 64))
    }

    static func shake256(_ input: Data, outputLength: Int) -> Data {
        var state = absorbPadPermute(mode: .shake256, input: [UInt8](input))
        return Data(squeeze(state: &state, rate: Mode.shake256.rate, count: outputLength))
    }

    /// A streaming SHAKE-128 expandable-output function (SampleNTT's XOF).
    /// `next(_:)` must be called with rate-sized (168-byte) requests.
    struct XOF {
        private var state: [UInt64]
        private let rate: Int

        init(input: Data) {
            rate = Mode.shake128.rate
            state = Keccak.absorbPadPermute(mode: .shake128, input: [UInt8](input))
        }

        mutating func next(_ count: Int) -> [UInt8] {
            Keccak.squeeze(state: &state, rate: rate, count: count)
        }
    }
}

// MARK: - ML-KEM (FIPS 203)

enum MLKEM {
    struct Parameters {
        let k: Int
        let eta1: Int
        let eta2: Int
        let du: Int
        let dv: Int

        /// Encapsulation-key wire length: 384·k coefficients + 32-byte ρ.
        var ekLength: Int { 384 * k + 32 }
        /// Ciphertext wire length: 32·du bytes per û polynomial + 32·dv for v.
        var ctLength: Int { 32 * (du * k + dv) }

        static let mlKem512 = Parameters(k: 2, eta1: 3, eta2: 2, du: 10, dv: 4)
        static let mlKem768 = Parameters(k: 3, eta1: 2, eta2: 2, du: 10, dv: 4)
    }

    static let q = 3329
    static let n = 256
    /// ζ = 17 is a primitive 256-th root of unity mod q (ζ^128 ≡ −1).
    private static let zeta = 17
    /// 128^−1 mod q — the inverse-NTT normalization factor.
    private static let inverse128 = 3303
    /// ⌈q/2⌉ — the message-embedding weight.
    private static let halfQ = 1665

    typealias Poly = [Int]

    private static func brv7(_ x: Int) -> Int {
        var result = 0
        var value = x
        for _ in 0..<7 {
            result = (result << 1) | (value & 1)
            value >>= 1
        }
        return result
    }

    private static func powMod(_ base: Int, _ exponent: Int, _ modulus: Int) -> Int {
        var result = 1
        var b = base % modulus
        var e = exponent
        while e > 0 {
            if e & 1 == 1 { result = result * b % modulus }
            b = b * b % modulus
            e >>= 1
        }
        return result
    }

    /// NTT twiddles: ζ^brv7(k), consumed sequentially by the forward butterflies.
    private static let zetas: [Int] = (0..<128).map { powMod(zeta, brv7($0), q) }
    /// Quadratic-factor roots: γ_i = ζ^(2·brv7(i)+1) for the (2i, 2i+1) pair.
    private static let gammas: [Int] = (0..<128).map { powMod(zeta, 2 * brv7($0) + 1, q) }

    // MARK: Ring arithmetic

    /// The Cooley–Tukey NTT over Z_q[X]/(X^256 + 1).
    static func ntt(_ a: Poly) -> Poly {
        var r = a
        var k = 1
        var len = 128
        while len >= 2 {
            var start = 0
            while start < n {
                let z = zetas[k]
                k += 1
                for j in start..<(start + len) {
                    let t = z * r[j + len] % q
                    r[j + len] = (r[j] - t + q) % q
                    r[j] = (r[j] + t) % q
                }
                start += 2 * len
            }
            len /= 2
        }
        return r
    }

    /// The Gentleman–Sande inverse NTT (twiddles −ζ^brv7(k), scale 128^−1).
    static func inverseNTT(_ a: Poly) -> Poly {
        var r = a
        var k = 127
        var len = 2
        while len <= 128 {
            var start = 0
            while start < n {
                let z = q - zetas[k]
                k -= 1
                for j in start..<(start + len) {
                    let t = r[j]
                    r[j] = (t + r[j + len]) % q
                    r[j + len] = (t - r[j + len] + q) % q * z % q
                }
                start += 2 * len
            }
            len *= 2
        }
        for i in 0..<n { r[i] = r[i] * inverse128 % q }
        return r
    }

    /// The pointwise product: pair (2i, 2i+1) reduces modulo X^2 − γ_i.
    static func multiplyNTTs(_ a: Poly, _ b: Poly) -> Poly {
        var c = Poly(repeating: 0, count: n)
        for i in 0..<128 {
            let a0 = a[2 * i], a1 = a[2 * i + 1]
            let b0 = b[2 * i], b1 = b[2 * i + 1]
            let gamma = gammas[i]
            c[2 * i] = (a0 * b0 + gamma * a1 * b1) % q
            c[2 * i + 1] = (a0 * b1 + a1 * b0) % q
        }
        return c
    }

    // MARK: Sampling

    /// SampleNTT: rejection-samples 256 coefficients from SHAKE-128(seed),
    /// 12-bit little-endian candidates, values ≥ q rejected.
    static func sampleNTT(_ seed: [UInt8]) -> Poly {
        precondition(seed.count == 34, "SampleNTT seed is ρ ∥ i ∥ j (34 bytes)")
        var xof = Keccak.XOF(input: Data(seed))
        var coefficients = Poly()
        coefficients.reserveCapacity(n)
        while coefficients.count < n {
            let block = xof.next(168)
            var index = 0
            while index < 168 && coefficients.count < n {
                let b0 = Int(block[index])
                let b1 = Int(block[index + 1])
                let b2 = Int(block[index + 2])
                let d1 = b0 + ((b1 & 0x0F) << 8)
                let d2 = (b1 >> 4) + (b2 << 4)
                if d1 < q { coefficients.append(d1) }
                if d2 < q && coefficients.count < n { coefficients.append(d2) }
                index += 3
            }
        }
        return coefficients
    }

    /// PRF(η, s, b) = SHAKE-256(s ∥ b) with 64·η output bytes.
    private static func prf(_ sigma: [UInt8], _ eta: Int, _ counter: Int) -> [UInt8] {
        var input = sigma
        input.append(UInt8(counter))
        return [UInt8](Keccak.shake256(Data(input), outputLength: 64 * eta))
    }

    /// SamplePolyCBD: sums η bits against η bits (LSB-first), x − y mod q.
    static func samplePolyCBD(_ bytes: [UInt8], eta: Int) -> Poly {
        func bit(_ index: Int) -> Int {
            Int((bytes[index / 8] >> (index % 8)) & 1)
        }
        var poly = Poly(repeating: 0, count: n)
        for i in 0..<n {
            var x = 0
            var y = 0
            for j in 0..<eta { x += bit(2 * eta * i + j) }
            for j in 0..<eta { y += bit(2 * eta * i + eta + j) }
            poly[i] = (x - y + q) % q
        }
        return poly
    }

    // MARK: Serialization

    /// Compress(x, d) = round(x·2^d / q) mod 2^d.
    static func compress(_ x: Int, d: Int) -> Int {
        (((x << d) + (q - 1) / 2) / q) & ((1 << d) - 1)
    }

    /// Decompress(y, d) = round(y·q / 2^d).
    static func decompress(_ y: Int, d: Int) -> Int {
        (y * q + (1 << (d - 1))) >> d
    }

    /// Compress(x, 1): a single message bit.
    private static func compress1(_ x: Int) -> Int {
        ((2 * x + (q - 1) / 2) / q) % 2
    }

    /// 12-bit coefficient packing, 3 bytes per coefficient pair.
    private static func encode12(_ poly: Poly) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 384)
        for i in 0..<128 {
            let t0 = poly[2 * i]
            let t1 = poly[2 * i + 1]
            out[3 * i] = UInt8(t0 & 0xFF)
            out[3 * i + 1] = UInt8((t0 >> 8) | ((t1 & 0x0F) << 4))
            out[3 * i + 2] = UInt8(t1 >> 4)
        }
        return out
    }

    private static func decode12(_ bytes: [UInt8]) -> Poly {
        var poly = Poly(repeating: 0, count: n)
        for i in 0..<128 {
            poly[2 * i] = Int(bytes[3 * i]) | ((Int(bytes[3 * i + 1]) & 0x0F) << 8)
            poly[2 * i + 1] = (Int(bytes[3 * i + 1]) >> 4) | (Int(bytes[3 * i + 2]) << 4)
        }
        return poly
    }

    /// FIPS 203 BitPack/BitUnpack: d-bit values, LSB-first bit stream.
    static func packBits(_ values: [Int], d: Int) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: (n * d + 7) / 8)
        var position = 0
        for value in values {
            for b in 0..<d {
                if (value >> b) & 1 == 1 {
                    out[position / 8] |= UInt8(1 << (position % 8))
                }
                position += 1
            }
        }
        return out
    }

    static func unpackBits(_ bytes: [UInt8], d: Int) -> [Int] {
        var values = [Int]()
        values.reserveCapacity(n)
        var position = 0
        for _ in 0..<n {
            var value = 0
            for b in 0..<d {
                let bit = Int((bytes[position / 8] >> (position % 8)) & 1)
                value |= bit << b
                position += 1
            }
            values.append(value)
        }
        return values
    }

    /// The 256 message bits, LSB-first per byte, weighted by ⌈q/2⌉.
    private static func messagePolynomial(_ m: [UInt8]) -> Poly {
        var mu = Poly(repeating: 0, count: n)
        for i in 0..<n {
            if (m[i / 8] >> (i % 8)) & 1 == 1 { mu[i] = halfQ }
        }
        return mu
    }

    // MARK: K-PKE

    /// K-PKE.Encrypt: û = Â^T·r̂ + ê1, v = t̂ᵀr̂ + ê2 + μ, packed at du/dv bits.
    static func encrypt(_ p: Parameters, ek: [UInt8], m: [UInt8], r: [UInt8]) -> [UInt8] {
        var tHat: [Poly] = []
        for i in 0..<p.k {
            tHat.append(decode12(Array(ek[(384 * i)..<(384 * i + 384)])))
        }
        let rho = Array(ek[(384 * p.k)..<(384 * p.k + 32)])

        var counter = 0
        var rHat: [Poly] = []
        for _ in 0..<p.k {
            rHat.append(ntt(samplePolyCBD(prf(r, p.eta1, counter), eta: p.eta1)))
            counter += 1
        }
        var e1: [Poly] = []
        for _ in 0..<p.k {
            e1.append(samplePolyCBD(prf(r, p.eta2, counter), eta: p.eta2))
            counter += 1
        }
        let e2 = samplePolyCBD(prf(r, p.eta2, counter), eta: p.eta2)

        var out = [UInt8]()
        let uBytes = 32 * p.du
        for i in 0..<p.k {
            // û_i = invNTT(Σ_j SampleNTT(ρ∥i∥j) ⊙ r̂_j) + ê1_i  (the transposed row)
            var accHat = Poly(repeating: 0, count: n)
            for j in 0..<p.k {
                let entry = sampleNTT(rho + [UInt8(i), UInt8(j)])
                let prod = multiplyNTTs(entry, rHat[j])
                for c in 0..<n { accHat[c] = (accHat[c] + prod[c]) % q }
            }
            let u = inverseNTT(accHat)
            var ui = Poly(repeating: 0, count: n)
            for c in 0..<n { ui[c] = (u[c] + e1[i][c]) % q }
            out.append(contentsOf: packBits(ui.map { compress($0, d: p.du) }, d: p.du))
        }
        // v = invNTT(Σ_j t̂_j ⊙ r̂_j) + ê2 + μ
        var vHat = Poly(repeating: 0, count: n)
        for j in 0..<p.k {
            let prod = multiplyNTTs(tHat[j], rHat[j])
            for c in 0..<n { vHat[c] = (vHat[c] + prod[c]) % q }
        }
        let vBase = inverseNTT(vHat)
        let mu = messagePolynomial(m)
        var v = Poly(repeating: 0, count: n)
        for c in 0..<n { v[c] = (vBase[c] + e2[c] + mu[c]) % q }
        out.append(contentsOf: packBits(v.map { compress($0, d: p.dv) }, d: p.dv))
        return out
    }

    // MARK: Key generation

    static func keyGen(_ p: Parameters) -> KeyPair {
        keyGen(d: [UInt8](I2PCrypto.randomBytes(32)),
               z: [UInt8](I2PCrypto.randomBytes(32)), parameters: p)
    }

    /// K-PKE.KeyGen + ML-KEM key wrapping from explicit (d, z) seeds.
    static func keyGen(d: [UInt8], z: [UInt8], parameters p: Parameters) -> KeyPair {
        let g = [UInt8](Keccak.sha3_512(Data(d)))
        let rho = Array(g[0..<32])
        let sigma = Array(g[32..<64])

        // Â[i][j] = SampleNTT(ρ ∥ j ∥ i)
        var matrix: [[Poly]] = Array(repeating: [], count: p.k)
        for i in 0..<p.k {
            matrix[i] = (0..<p.k).map { j in sampleNTT(rho + [UInt8(j), UInt8(i)]) }
        }
        var counter = 0
        var sHat: [Poly] = []
        for _ in 0..<p.k {
            sHat.append(ntt(samplePolyCBD(prf(sigma, p.eta1, counter), eta: p.eta1)))
            counter += 1
        }
        var e: [Poly] = []
        for _ in 0..<p.k {
            e.append(samplePolyCBD(prf(sigma, p.eta1, counter), eta: p.eta1))
            counter += 1
        }
        // t = Â·ŝ + e
        var t = [Poly]()
        for i in 0..<p.k {
            var accHat = Poly(repeating: 0, count: n)
            for j in 0..<p.k {
                let prod = multiplyNTTs(matrix[i][j], sHat[j])
                for c in 0..<n { accHat[c] = (accHat[c] + prod[c]) % q }
            }
            var ti = inverseNTT(accHat)
            for c in 0..<n { ti[c] = (ti[c] + e[i][c]) % q }
            t.append(ti)
        }
        var ek = Data()
        for i in 0..<p.k { ek.append(contentsOf: encode12(t[i])) }
        ek.append(contentsOf: rho)
        return KeyPair(parameters: p, ek: ek, sHat: sHat, z: z)
    }

    // MARK: Encapsulation / decapsulation

    static func encapsulate(encapsulationKey ek: Data) throws -> (ciphertext: Data, sharedSecret: Data) {
        let parameters: Parameters
        switch ek.count {
        case Parameters.mlKem512.ekLength: parameters = .mlKem512
        case Parameters.mlKem768.ekLength: parameters = .mlKem768
        default: throw I2PWireError.invalidFormat
        }
        let m = [UInt8](I2PCrypto.randomBytes(32))
        let h = [UInt8](Keccak.sha3_256(ek))
        let g = [UInt8](Keccak.sha3_512(Data(m) + Data(h)))
        let k = Array(g[0..<32])
        let r = Array(g[32..<64])
        let c = encrypt(parameters, ek: [UInt8](ek), m: m, r: r)
        return (Data(c), Data(k))
    }

    /// The ML-KEM secret key: ŝ (NTT domain), ek, h = H(ek) and the
    /// implicit-rejection seed z. Decapsulation is fail-closed: a ciphertext
    /// that fails re-encryption yields the rejected key, never an error or
    /// partial material.
    final class KeyPair {
        let parameters: Parameters
        let ek: Data
        private let sHat: [Poly]
        private let z: [UInt8]
        private let h: [UInt8]

        init(parameters: Parameters, ek: Data, sHat: [Poly], z: [UInt8]) {
            self.parameters = parameters
            self.ek = ek
            self.sHat = sHat
            self.z = z
            self.h = [UInt8](Keccak.sha3_256(ek))
        }

        func decapsulate(_ ciphertext: Data) -> Data {
            let c = [UInt8](ciphertext)
            guard c.count == parameters.ctLength else {
                return implicitRejection(c)
            }
            let mPrime = decrypt(c)
            let g = [UInt8](Keccak.sha3_512(Data(mPrime) + Data(h)))
            let kPrime = Array(g[0..<32])
            let rPrime = Array(g[32..<64])
            let cPrime = MLKEM.encrypt(parameters, ek: [UInt8](ek), m: mPrime, r: rPrime)
            if cPrime == c { return Data(kPrime) }
            return implicitRejection(c)
        }

        private func implicitRejection(_ c: [UInt8]) -> Data {
            let jz = [UInt8](Keccak.shake256(Data(z), outputLength: 32))
            return Keccak.sha3_256(Data(jz) + Data(c))
        }

        /// K-PKE.Decrypt: m′ = Compress_1(v′ − ŝᵀ·û′).
        private func decrypt(_ c: [UInt8]) -> [UInt8] {
            let p = parameters
            let uBytes = 32 * p.du
            var uPrime: [Poly] = []
            for i in 0..<p.k {
                let chunk = Array(c[(uBytes * i)..<(uBytes * (i + 1))])
                uPrime.append(unpackBits(chunk, d: p.du).map { decompress($0, d: p.du) })
            }
            let vChunk = Array(c[(uBytes * p.k)..<c.count])
            let vPrime = unpackBits(vChunk, d: p.dv).map { decompress($0, d: p.dv) }
            var accHat = Poly(repeating: 0, count: n)
            for j in 0..<p.k {
                let prod = multiplyNTTs(sHat[j], ntt(uPrime[j]))
                for c2 in 0..<n { accHat[c2] = (accHat[c2] + prod[c2]) % q }
            }
            let w = inverseNTT(accHat)
            var bits = [UInt8](repeating: 0, count: 32)
            for i in 0..<n {
                let value = (vPrime[i] - w[i] + q) % q
                if compress1(value) == 1 {
                    bits[i / 8] |= UInt8(1 << (i % 8))
                }
            }
            return bits
        }
    }
}
