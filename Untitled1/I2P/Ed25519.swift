//
//  Ed25519.swift
//  Pure-Swift Ed25519 (RFC 8032) with Ed25519ph (pre-hashed, SigType 11) support.
//
//  Field arithmetic mod p = 2^255 - 19 using five 51-bit limbs, point arithmetic
//  in extended coordinates on the twisted Edwards curve (a = -1), and scalar
//  arithmetic mod the group order L. CryptoKit's SHA-512 is used for hashing.
//

import Foundation
import CryptoKit

// MARK: - 128-bit unsigned accumulator

struct U128 {
    var lo: UInt64 = 0
    var hi: UInt64 = 0

    static func += (lhs: inout U128, rhs: U128) {
        let (sum, overflow) = lhs.lo.addingReportingOverflow(rhs.lo)
        lhs.lo = sum
        lhs.hi = lhs.hi &+ rhs.hi &+ (overflow ? 1 : 0)
    }

    static func addProduct(_ acc: inout U128, _ a: UInt64, _ b: UInt64) {
        let product = a.multipliedFullWidth(by: b)
        acc += U128(lo: product.low, hi: product.high)
    }

    func shiftedRight51() -> U128 {
        U128(lo: (lo >> 51) | (hi &<< 13), hi: hi >> 51)
    }
}

// MARK: - Field element

struct Fe {
    static let mask51: UInt64 = (1 << 51) - 1
    static let pLimbs: [UInt64] = [(1 << 51) - 19, mask51, mask51, mask51, mask51]

    var l: [UInt64]

    init(_ value: UInt64 = 0) { l = [value & Self.mask51, 0, 0, 0, 0] }
    init(_ limbs: [UInt64]) { l = limbs }

    static func add(_ a: Fe, _ b: Fe) -> Fe {
        var r = [UInt64](repeating: 0, count: 5)
        var carry: UInt64 = 0
        for i in 0..<5 {
            let sum = a.l[i] &+ b.l[i] &+ carry
            r[i] = sum & mask51
            carry = sum >> 51
        }
        r[0] = r[0] &+ carry &* 19
        let c = r[0] >> 51
        r[0] &= mask51
        r[1] = r[1] &+ c
        return Fe(r)
    }

    /// a - b via a per-limb borrow chain with the correct direction: d = a_i - b_i - borrow,
    /// r_i = d mod 2^51, and borrow = 1 when d < 0 (the borrow flows into the next limb
    /// as a subtraction). A final borrow means V = a - b + 2^255; since 2^255 ≡ 19 (mod p),
    /// the residue is V - 19 for every input whose value exceeds -p (always true when
    /// a ≥ 0 and b ≤ 2^255 - 1). The subtrahend's limbs are carry-normalized into
    /// [0, 2^51) first, so d never dips below -2^51 and the conversions cannot trap
    /// even for lazily reduced inputs (mul leaves limbs up to 2^51 + carry).
    static func sub(_ a: Fe, _ b: Fe) -> Fe {
        var bLimbs = b.l
        for i in 0..<4 {
            let carry = bLimbs[i] >> 51
            bLimbs[i] &= Self.mask51
            bLimbs[i + 1] = bLimbs[i + 1] &+ carry
        }
        bLimbs[4] &= Self.mask51
        let top = bLimbs[4] >> 51
        if top > 0 {
            bLimbs[4] &= Self.mask51
            bLimbs[0] = bLimbs[0] &+ top &* 19
            let c = bLimbs[0] >> 51
            bLimbs[0] &= Self.mask51
            bLimbs[1] = bLimbs[1] &+ c
        }

        var r = [UInt64](repeating: 0, count: 5)
        var borrow: Int64 = 0
        for i in 0..<5 {
            let d = Int64(a.l[i]) - Int64(bLimbs[i]) - borrow
            if d < 0 {
                r[i] = UInt64(d &+ (1 << 51))
                borrow = 1
            } else {
                r[i] = UInt64(d)
                borrow = 0
            }
        }
        if borrow > 0 {
            if r[0] >= 19 {
                r[0] -= 19
            } else if r[1] > 0 {
                // Limb 0 underflows the -19 fold: borrow from limb 1.
                r[0] = r[0] &+ (1 << 51) &- 19
                r[1] -= 1
            } else {
                // Degenerate subtrahend within 19 of 2^255: fold by adding p
                // first so the subtraction stays in range (never traps).
                var carry: UInt64 = 0
                for i in 0..<5 {
                    let sum = r[i] &+ Self.pLimbs[i] &+ carry
                    r[i] = sum & Self.mask51
                    carry = sum >> 51
                }
                r[0] = r[0] &+ carry &* 19
                let c = r[0] >> 51
                r[0] &= Self.mask51
                r[1] = r[1] &+ c
                if r[0] >= 19 {
                    r[0] -= 19
                } else if r[1] > 0 {
                    r[0] = r[0] &+ (1 << 51) &- 19
                    r[1] -= 1
                }
            }
        }
        return Fe(r)
    }

    static func mul(_ a: Fe, _ b: Fe) -> Fe {
        let a0 = a.l[0], a1 = a.l[1], a2 = a.l[2], a3 = a.l[3], a4 = a.l[4]
        let b0 = b.l[0], b1 = b.l[1], b2 = b.l[2], b3 = b.l[3], b4 = b.l[4]
        let a1_19 = a1 &* 19, a2_19 = a2 &* 19, a3_19 = a3 &* 19, a4_19 = a4 &* 19

        var acc0 = U128(), acc1 = U128(), acc2 = U128(), acc3 = U128(), acc4 = U128()

        U128.addProduct(&acc0, a0, b0)
        U128.addProduct(&acc0, a1_19, b4)
        U128.addProduct(&acc0, a2_19, b3)
        U128.addProduct(&acc0, a3_19, b2)
        U128.addProduct(&acc0, a4_19, b1)

        U128.addProduct(&acc1, a0, b1)
        U128.addProduct(&acc1, a1, b0)
        U128.addProduct(&acc1, a2_19, b4)
        U128.addProduct(&acc1, a3_19, b3)
        U128.addProduct(&acc1, a4_19, b2)

        U128.addProduct(&acc2, a0, b2)
        U128.addProduct(&acc2, a1, b1)
        U128.addProduct(&acc2, a2, b0)
        U128.addProduct(&acc2, a3_19, b4)
        U128.addProduct(&acc2, a4_19, b3)

        U128.addProduct(&acc3, a0, b3)
        U128.addProduct(&acc3, a1, b2)
        U128.addProduct(&acc3, a2, b1)
        U128.addProduct(&acc3, a3, b0)
        U128.addProduct(&acc3, a4_19, b4)

        U128.addProduct(&acc4, a0, b4)
        U128.addProduct(&acc4, a1, b3)
        U128.addProduct(&acc4, a2, b2)
        U128.addProduct(&acc4, a3, b1)
        U128.addProduct(&acc4, a4, b0)

        var out = [UInt64](repeating: 0, count: 5)
        var carry: U128

        out[0] = acc0.lo & mask51
        carry = acc0.shiftedRight51()
        acc1 += carry
        out[1] = acc1.lo & mask51
        carry = acc1.shiftedRight51()
        acc2 += carry
        out[2] = acc2.lo & mask51
        carry = acc2.shiftedRight51()
        acc3 += carry
        out[3] = acc3.lo & mask51
        carry = acc3.shiftedRight51()
        acc4 += carry
        out[4] = acc4.lo & mask51

        let top = acc4.shiftedRight51()
        var fold = U128(lo: out[0], hi: 0)
        U128.addProduct(&fold, top.lo, 19)
        out[0] = fold.lo & mask51
        let c0 = fold.shiftedRight51()
        out[1] = out[1] &+ c0.lo
        let c1 = out[1] >> 51
        out[1] &= mask51
        out[2] = out[2] &+ c1
        return Fe(out)
    }

    static func square(_ a: Fe) -> Fe { mul(a, a) }
    static func negate(_ a: Fe) -> Fe { sub(Fe(0), a) }

    /// Modular exponentiation by a square-and-multiply chain (exponent bits, MSB first).
    static func pow(_ base: Fe, _ exponentBitsMSBFirst: [Bool]) -> Fe {
        var result = Fe(1)
        for bit in exponentBitsMSBFirst {
            result = mul(result, result)
            if bit { result = mul(result, base) }
        }
        return result
    }

    // p - 2  = 2^255 - 21  (250 ones, then 0 1 0 1 1)
    static let invertExponent: [Bool] = Array(repeating: true, count: 250) + [false, true, false, true, true]
    // (p - 5) / 8 = 2^252 - 3  (250 ones, then 0 1)
    static let pow22523Exponent: [Bool] = Array(repeating: true, count: 250) + [false, true]
    // (p - 1) / 4 = 2^253 - 5  (250 ones, then 0 1 1)
    static let sqrtM1Exponent: [Bool] = Array(repeating: true, count: 250) + [false, true, true]

    static func invert(_ a: Fe) -> Fe { pow(a, invertExponent) }

    static func fromBytes(_ bytes: [UInt8]) -> Fe {
        var limbs = [UInt64](repeating: 0, count: 5)
        var buffer: UInt64 = 0
        var bits = 0
        var index = 0
        for byte in bytes {
            buffer |= UInt64(byte) << UInt64(bits)
            bits += 8
            if bits >= 51 && index < 5 {
                limbs[index] = buffer & mask51
                buffer >>= 51
                bits -= 51
                index += 1
            }
        }
        return Fe(limbs)
    }

    /// Fully reduces the value and serializes it as 32 little-endian bytes.
    func toBytes() -> [UInt8] {
        var l = self.l
        for _ in 0..<3 {
            var carry: UInt64 = 0
            for i in 0..<4 {
                let sum = l[i] &+ carry
                l[i] = sum & Self.mask51
                carry = sum >> 51
            }
            let sum4 = l[4] &+ carry
            l[4] = sum4 & Self.mask51
            let top = sum4 >> 51
            l[0] = l[0] &+ top &* 19
        }
        for _ in 0..<2 {
            if Self.geq(l, Self.pLimbs) {
                l = Self.subtract(l, Self.pLimbs)
            } else {
                break
            }
        }
        var out = [UInt8](repeating: 0, count: 32)
        var buffer: UInt64 = 0
        var bits = 0
        var outIndex = 0
        for limb in l {
            var remaining = 51
            var value = limb
            while remaining > 0 {
                let take = min(remaining, 8 - bits)
                let chunk = value & ((1 << UInt64(take)) - 1)
                buffer |= chunk << UInt64(bits)
                bits += take
                value >>= UInt64(take)
                remaining -= take
                if bits == 8 {
                    out[outIndex] = UInt8(buffer & 0xff)
                    outIndex += 1
                    buffer = 0
                    bits = 0
                }
            }
        }
        if bits > 0 && outIndex < 32 { out[outIndex] = UInt8(buffer & 0xff) }
        return out
    }

    static func geq(_ l: [UInt64], _ p: [UInt64]) -> Bool {
        for i in stride(from: 4, through: 0, by: -1) {
            if l[i] != p[i] { return l[i] > p[i] }
        }
        return true
    }

    static func subtract(_ l: [UInt64], _ p: [UInt64]) -> [UInt64] {
        var r = l
        var borrow: Int64 = 0
        for i in 0..<5 {
            let d = Int64(r[i]) - Int64(p[i]) - borrow
            if d < 0 {
                r[i] = UInt64(d + (1 << 51))
                borrow = 1
            } else {
                r[i] = UInt64(d)
                borrow = 0
            }
        }
        return r
    }

    static func equal(_ a: Fe, _ b: Fe) -> Bool { a.toBytes() == b.toBytes() }
    var isZero: Bool { toBytes().allSatisfy { $0 == 0 } }
}

// MARK: - Curve constants

enum Ed25519Curve {
    /// d = -121665 / 121666 mod p
    static let d: Fe = {
        Fe.mul(Fe.negate(Fe(121665)), Fe.invert(Fe(121666)))
    }()
    static let twoD: Fe = Fe.mul(d, Fe(2))
    /// sqrt(-1) = 2^((p-1)/4) mod p
    static let sqrtM1: Fe = Fe.pow(Fe(2), Fe.sqrtM1Exponent)
    /// Base point: y = 4/5 mod p, x even.
    static let base: GePoint = {
        let y = Fe.mul(Fe(4), Fe.invert(Fe(5)))
        var bytes = y.toBytes()
        bytes[31] &= 127
        guard let point = GePoint(compressed: bytes) else {
            fatalError("Ed25519 base point decompression failed")
        }
        return point
    }()
}

// MARK: - Group point (extended coordinates)

struct GePoint {
    var X: Fe, Y: Fe, Z: Fe, T: Fe

    init(X: Fe, Y: Fe, Z: Fe, T: Fe) {
        self.X = X
        self.Y = Y
        self.Z = Z
        self.T = T
    }

    static func identity() -> GePoint { GePoint(X: Fe(0), Y: Fe(1), Z: Fe(1), T: Fe(0)) }

    /// Unified addition (complete for a = -1).
    static func add(_ a: GePoint, _ b: GePoint) -> GePoint {
        let A = Fe.mul(Fe.sub(a.Y, a.X), Fe.sub(b.Y, b.X))
        let B = Fe.mul(Fe.add(a.Y, a.X), Fe.add(b.Y, b.X))
        let C = Fe.mul(Fe.mul(a.T, Ed25519Curve.twoD), b.T)
        let D = Fe.mul(Fe.mul(a.Z, Fe(2)), b.Z)
        let E = Fe.sub(B, A)
        let F = Fe.sub(D, C)
        let G = Fe.add(D, C)
        let H = Fe.add(B, A)
        return GePoint(X: Fe.mul(E, F), Y: Fe.mul(G, H), Z: Fe.mul(F, G), T: Fe.mul(E, H))
    }

    static func double(_ a: GePoint) -> GePoint {
        let A = Fe.mul(a.X, a.X)
        let B = Fe.mul(a.Y, a.Y)
        let C = Fe.mul(Fe(2), Fe.mul(a.Z, a.Z))
        let H = Fe.add(A, B)
        let E = Fe.sub(H, Fe.mul(Fe.add(a.X, a.Y), Fe.add(a.X, a.Y)))
        let G = Fe.sub(A, B)
        let F = Fe.add(C, G)
        return GePoint(X: Fe.mul(E, F), Y: Fe.mul(G, H), Z: Fe.mul(F, G), T: Fe.mul(E, H))
    }

    /// Variable-time double-and-add over a 32-byte little-endian scalar.
    static func multiply(_ point: GePoint, _ scalarLE32: [UInt8]) -> GePoint {
        var result = GePoint.identity()
        for i in stride(from: 255, through: 0, by: -1) {
            result = double(result)
            let bit = (scalarLE32[i / 8] >> UInt64(i % 8)) & 1
            if bit == 1 { result = add(result, point) }
        }
        return result
    }

    /// RFC 8032 §5.1.3: an encoding is canonical only when its y coordinate —
    /// little-endian, high bit masked off — is below p = 2^255 − 19. Without
    /// this check the same point could be written as y + p and decode to the
    /// same point, so one key would have more than one valid byte string,
    /// which RFC 8032 forbids (and which makes signatures mutable).
    static func isCanonicalEncoding(_ bytes: [UInt8]) -> Bool {
        guard bytes.count == 32 else { return false }
        var y = bytes
        y[31] &= 127
        // p = 2^255 − 19, little-endian.
        let p: [UInt8] = [0xed] + [UInt8](repeating: 0xff, count: 30) + [0x7f]
        for index in stride(from: 31, through: 0, by: -1) {
            if y[index] != p[index] { return y[index] < p[index] }
        }
        // y == p is not a field element: not canonical.
        return false
    }

    func encode() -> [UInt8] {
        let zInv = Fe.invert(Z)
        let x = Fe.mul(X, zInv)
        let y = Fe.mul(Y, zInv)
        var out = y.toBytes()
        out[31] |= UInt8((x.l[0] & 1) << 7)
        return out
    }

    static func == (lhs: GePoint, rhs: GePoint) -> Bool {
        Fe.equal(Fe.mul(lhs.X, rhs.Z), Fe.mul(rhs.X, lhs.Z)) &&
        Fe.equal(Fe.mul(lhs.Y, rhs.Z), Fe.mul(rhs.Y, lhs.Z))
    }

    /// Point decompression per RFC 8032 §5.1.3.
    init?(compressed bytes: [UInt8]) {
        guard bytes.count == 32 else { return nil }
        guard GePoint.isCanonicalEncoding(bytes) else { return nil }
        var yBytes = bytes
        let sign = (yBytes[31] >> 7) & 1
        yBytes[31] &= 127
        let y = Fe.fromBytes(yBytes)
        let y2 = Fe.mul(y, y)
        let u = Fe.sub(y2, Fe(1))
        let v = Fe.add(Fe.mul(Ed25519Curve.d, y2), Fe(1))
        let v3 = Fe.mul(Fe.mul(v, v), v)
        let v7 = Fe.mul(v3, Fe.mul(v3, v))
        let uv7 = Fe.mul(u, v7)
        var x = Fe.mul(Fe.mul(u, v3), Fe.pow(uv7, Fe.pow22523Exponent))
        let vxx = Fe.mul(v, Fe.mul(x, x))
        if !Fe.equal(vxx, u) {
            if Fe.equal(vxx, Fe.negate(u)) {
                x = Fe.mul(x, Ed25519Curve.sqrtM1)
            } else {
                return nil
            }
        }
        if x.isZero && sign == 1 { return nil }
        if (x.l[0] & 1) != UInt64(sign) {
            x = Fe.negate(x)
        }
        self.init(X: x, Y: y, Z: Fe(1), T: Fe.mul(x, y))
    }
}

// MARK: - Scalar arithmetic mod L

enum Ed25519Scalar {
    /// Group order L = 2^252 + 27742317777372353535851937790883648493 (4 little-endian limbs).
    static let L: [UInt64] = [0x5812_631a_5cf5_d3ed, 0x14de_f9de_a2f7_9cd6, 0, 0x1000_0000_0000_0000]

    static func bytesToLimbs(_ bytes: [UInt8], limbCount: Int) -> [UInt64] {
        var out = [UInt64](repeating: 0, count: limbCount)
        for i in 0..<limbCount {
            let base = i * 8
            guard base < bytes.count else { continue }
            var value: UInt64 = 0
            for j in stride(from: min(base + 7, bytes.count - 1), through: base, by: -1) {
                value = (value << 8) | UInt64(bytes[j])
            }
            out[i] = value
        }
        return out
    }

    static func limbsToBytes(_ limbs: [UInt64]) -> [UInt8] {
        var out: [UInt8] = []
        for limb in limbs {
            for shift in stride(from: 0, through: 56, by: 8) {
                out.append(UInt8((limb >> UInt64(shift)) & 0xff))
            }
        }
        return out
    }

    static func geqL(_ r: [UInt64]) -> Bool {
        for i in stride(from: r.count - 1, through: 0, by: -1) {
            let lv = i < L.count ? L[i] : 0
            if r[i] != lv { return r[i] > lv }
        }
        return true
    }

    static func subL(_ r: [UInt64]) -> [UInt64] {
        var out = r
        var borrow: UInt64 = 0
        for i in 0..<out.count {
            let lv = i < L.count ? L[i] : 0
            let (s1, o1) = out[i].subtractingReportingOverflow(lv)
            let (s2, o2) = s1.subtractingReportingOverflow(borrow)
            out[i] = s2
            borrow = (o1 || o2) ? 1 : 0
        }
        return out
    }

    /// Reduce a wide little-endian value (up to 8 limbs) modulo L.
    static func reduceModL(_ wide: [UInt64]) -> [UInt64] {
        var padded = wide
        while padded.count < 8 { padded.append(0) }
        var r = [UInt64](repeating: 0, count: 4)
        for bitIndex in stride(from: 511, through: 0, by: -1) {
            let bit = (padded[bitIndex / 64] >> UInt64(bitIndex % 64)) & 1
            var carry = bit
            for i in 0..<4 {
                let shifted = (r[i] << 1) | carry
                carry = r[i] >> 63
                r[i] = shifted
            }
            if geqL(r) { r = subL(r) }
        }
        return r
    }

    static func mulWide(_ a: [UInt64], _ b: [UInt64]) -> [UInt64] {
        var out = [UInt64](repeating: 0, count: a.count + b.count)
        for i in 0..<a.count {
            var carry: UInt64 = 0
            for j in 0..<b.count {
                let product = a[i].multipliedFullWidth(by: b[j])
                let (s1, o1) = out[i + j].addingReportingOverflow(product.low)
                let (s2, o2) = s1.addingReportingOverflow(carry)
                out[i + j] = s2
                carry = product.high &+ (o1 ? 1 : 0) &+ (o2 ? 1 : 0)
            }
            var index = i + b.count
            while carry != 0 && index < out.count {
                let (s, o) = out[index].addingReportingOverflow(carry)
                out[index] = s
                carry = o ? 1 : 0
                index += 1
            }
        }
        return out
    }

    static func addWide(_ a: [UInt64], _ b: [UInt64]) -> [UInt64] {
        var out = [UInt64](repeating: 0, count: max(a.count, b.count))
        var carry: UInt64 = 0
        for i in 0..<out.count {
            let av = i < a.count ? a[i] : 0
            let bv = i < b.count ? b[i] : 0
            let (s1, o1) = av.addingReportingOverflow(bv)
            let (s2, o2) = s1.addingReportingOverflow(carry)
            out[i] = s2
            carry = (o1 ? 1 : 0) &+ (o2 ? 1 : 0)
        }
        return out
    }
}

// MARK: - Ed25519 / Ed25519ph

enum Ed25519Pure {
    static func sha512(_ bytes: [UInt8]) -> [UInt8] {
        SHA512.hash(data: Data(bytes)).withUnsafeBytes { Array($0) }
    }

    /// dom2(f, c) = "SigEd25519 no Ed25519 collisions" || octet(f) || octet(c); empty for plain Ed25519.
    static func dom2(prehashed: Bool) -> [UInt8] {
        guard prehashed else { return [] }
        var prefix = Array("SigEd25519 no Ed25519 collisions".utf8)
        prefix.append(contentsOf: [1, 0])
        return prefix
    }

    static func clampScalar(_ expanded: [UInt8]) -> [UInt8] {
        var a = expanded
        a[0] &= 248
        a[31] &= 127
        a[31] |= 64
        return a
    }

    static func publicKey(seed: [UInt8]) -> [UInt8] {
        let h = sha512(seed)
        let a = clampScalar(Array(h[0..<32]))
        return GePoint.multiply(Ed25519Curve.base, a).encode()
    }

    /// Whether a 32-byte public-key (or R) encoding is canonical per RFC 8032
    /// §5.1.3: the masked y coordinate is below p. Exposed so the spec
    /// conformance audit can pin the rule instead of guessing at it.
    static func isCanonicalEncoding(_ bytes: [UInt8]) -> Bool {
        GePoint.isCanonicalEncoding(bytes)
    }

    static func sign(message: [UInt8], seed: [UInt8], prehashed: Bool) -> [UInt8]? {
        guard seed.count == 32 else { return nil }
        let h = sha512(seed)
        let a = clampScalar(Array(h[0..<32]))
        let prefix = Array(h[32..<64])
        let publicKey = GePoint.multiply(Ed25519Curve.base, a).encode()
        let ph = prehashed ? sha512(message) : message
        let dom = dom2(prehashed: prehashed)
        let r = Ed25519Scalar.reduceModL(Ed25519Scalar.bytesToLimbs(sha512(dom + prefix + ph), limbCount: 8))
        let rBytes = Ed25519Scalar.limbsToBytes(r)
        let R = GePoint.multiply(Ed25519Curve.base, rBytes).encode()
        let k = Ed25519Scalar.reduceModL(Ed25519Scalar.bytesToLimbs(sha512(dom + R + publicKey + ph), limbCount: 8))
        let aLimbs = Ed25519Scalar.bytesToLimbs(a, limbCount: 4)
        let ka = Ed25519Scalar.mulWide(k, aLimbs)
        let sum = Ed25519Scalar.addWide(ka, r)
        let S = Ed25519Scalar.reduceModL(sum)
        return R + Ed25519Scalar.limbsToBytes(S)
    }

    /// Signs with an explicit scalar and a secret nonce prefix — the blinded
    /// private key path of the encrypted LeaseSet blinding spec, where the
    /// signing key is the derived scalar k' = alpha·k mod L rather than an
    /// RFC 8032 seed. The scalar must already be clamped and reduced mod L;
    /// the nonce prefix is the signer's secret per-signature nonce material.
    /// Verification is unchanged: the signature checks against K' = k'·G.
    static func signWithScalar(message: [UInt8], scalar: [UInt8], noncePrefix: [UInt8]) -> [UInt8]? {
        guard scalar.count == 32, noncePrefix.count == 32 else { return nil }
        let publicKey = GePoint.multiply(Ed25519Curve.base, scalar).encode()
        let r = Ed25519Scalar.reduceModL(Ed25519Scalar.bytesToLimbs(sha512(noncePrefix + message), limbCount: 8))
        let R = GePoint.multiply(Ed25519Curve.base, Ed25519Scalar.limbsToBytes(r)).encode()
        let k = Ed25519Scalar.reduceModL(Ed25519Scalar.bytesToLimbs(sha512(R + publicKey + message), limbCount: 8))
        let aLimbs = Ed25519Scalar.bytesToLimbs(scalar, limbCount: 4)
        let S = Ed25519Scalar.reduceModL(Ed25519Scalar.addWide(
            Ed25519Scalar.mulWide(k, aLimbs), r))
        return R + Ed25519Scalar.limbsToBytes(S)
    }

    static func verify(message: [UInt8], signature: [UInt8], publicKey: [UInt8], prehashed: Bool) -> Bool {
        guard signature.count == 64, publicKey.count == 32 else { return false }
        let sLimbs = Ed25519Scalar.bytesToLimbs(Array(signature[32..<64]), limbCount: 4)
        if Ed25519Scalar.geqL(sLimbs) { return false }
        guard let aPoint = GePoint(compressed: publicKey) else { return false }
        guard let rPoint = GePoint(compressed: Array(signature[0..<32])) else { return false }
        let ph = prehashed ? sha512(message) : message
        let dom = dom2(prehashed: prehashed)
        let k = Ed25519Scalar.reduceModL(Ed25519Scalar.bytesToLimbs(sha512(dom + Array(signature[0..<32]) + publicKey + ph), limbCount: 8))
        let lhs = GePoint.multiply(Ed25519Curve.base, Array(signature[32..<64]))
        let rhs = GePoint.add(GePoint.multiply(aPoint, Ed25519Scalar.limbsToBytes(k)), rPoint)
        return lhs == rhs
    }
}