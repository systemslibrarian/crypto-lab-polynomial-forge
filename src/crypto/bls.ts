/**
 * A thin, documented wrapper over @noble/curves' BLS12-381.
 *
 * WHY A LIBRARY HERE. The pairing is not the teaching subject of this lab -
 * crypto-lab-pairing-gate already takes it apart - and a hand-rolled optimal
 * Ate pairing over an Fp12 tower would be several thousand lines of code whose
 * bugs would be invisible to a learner. @noble/curves is audited, has no
 * dependencies, and is what the rest of this fleet uses for BLS12-381.
 *
 * WHAT IS HAND-ROLLED. Everything above the group operations: the SRS layout,
 * the commitment, the quotient, the verification equation, the degree-bound
 * check, the ceremony and its pairing consistency checks, both attacks, the
 * inner-product argument, and FRI. Those are the inspectable parts.
 */
import { bls12_381 } from '@noble/curves/bls12-381.js'
import { pippenger } from '@noble/curves/abstract/curve.js'
import { Fr, frOf } from './fr.js'

export const G1 = bls12_381.G1.Point
export const G2 = bls12_381.G2.Point
export const Fp12 = bls12_381.fields.Fp12

export type G1Point = typeof G1.BASE
export type G2Point = typeof G2.BASE

/** Compressed encoding sizes, which are what the size comparison reports. */
export const G1_BYTES = 48
export const G2_BYTES = 96

/**
 * Scalar multiplication that accepts 0.
 *
 * noble's `multiply` rejects a zero scalar on purpose (it is almost always a
 * bug in signature code). Here a zero coefficient is completely ordinary - a
 * polynomial is allowed to have them - so we map 0 to the identity ourselves
 * instead of special-casing at every call site.
 */
export function g1Mul(P: G1Point, k: bigint): G1Point {
  const s = frOf(k)
  return Fr.is0(s) ? G1.ZERO : P.multiply(s)
}

export function g2Mul(P: G2Point, k: bigint): G2Point {
  const s = frOf(k)
  return Fr.is0(s) ? G2.ZERO : P.multiply(s)
}

/**
 * Multi-scalar multiplication: sum_i k_i * P_i.
 *
 * This IS the commitment operation for both KZG and IPA, so it is on the hot
 * path of every act. Uses noble's Pippenger bucket method; a naive loop is
 * about 5x slower and makes the degree slider feel broken at 512 coefficients.
 * Zero scalars are dropped first because Pippenger, like `multiply`, rejects
 * them.
 */
export function g1Msm(points: readonly G1Point[], scalars: readonly bigint[]): G1Point {
  if (points.length !== scalars.length) throw new Error('msm: length mismatch')
  const ps: G1Point[] = []
  const ss: bigint[] = []
  for (let i = 0; i < scalars.length; i++) {
    const s = frOf(scalars[i])
    if (Fr.is0(s)) continue
    ps.push(points[i])
    ss.push(s)
  }
  if (ps.length === 0) return G1.ZERO
  if (ps.length === 1) return ps[0].multiply(ss[0])
  return pippenger(G1, ps, ss)
}

/**
 * Check e(a1, a2) * e(b1, b2) == 1 in G_T.
 *
 * Every pairing equation on this page is checked in this batched form: one
 * Miller loop over both pairs and a single final exponentiation, rather than
 * two full pairings compared for equality. It is the same predicate and about
 * half the cost, which matters because the comparison act times it.
 *
 * The identity in G_T is Fp12.ONE, so "the equation holds" is literally
 * "the product of the two pairings is one".
 */
export function pairingEq2(a1: G1Point, a2: G2Point, b1: G1Point, b2: G2Point): boolean {
  // The point at infinity is the identity of G1 and G2, so a pairing with it is
  // the identity of G_T. That is not a special case of the maths - it is what
  // the maths says - but noble throws on it rather than returning 1, so the
  // degenerate pairs are dropped here and the remaining ones batched.
  //
  // This matters for correctness, not just tidiness: the EIP-4844 vectors
  // include the zero polynomial, whose commitment AND opening proof are both
  // the point at infinity and whose expected verdict is VALID. A verifier that
  // rejected an infinity input would fail that upstream vector. blst, which the
  // reference implementation uses, does the same thing.
  const pairs: { g1: G1Point; g2: G2Point }[] = []
  if (!a1.is0() && !a2.is0()) pairs.push({ g1: a1, g2: a2 })
  if (!b1.is0() && !b2.is0()) pairs.push({ g1: b1, g2: b2 })
  if (pairs.length === 0) return true
  const gt = bls12_381.pairingBatch(pairs)
  return Fp12.eql(gt, Fp12.ONE)
}

/** e(a1, a2) == e(b1, b2), expressed as e(a1,a2) * e(-b1,b2) == 1. */
export function pairingEqual(a1: G1Point, a2: G2Point, b1: G1Point, b2: G2Point): boolean {
  return pairingEq2(a1, a2, b1.negate(), b2)
}

/** Raw two-pairing product, exposed so tests can assert the batched form matches. */
export function pairing(g1: G1Point, g2: G2Point): ReturnType<typeof bls12_381.pairing> {
  return bls12_381.pairing(g1, g2)
}

export function g1ToHex(P: G1Point): string {
  return bytesToHex(P.toBytes())
}

export function g2ToHex(P: G2Point): string {
  return bytesToHex(P.toBytes())
}

export function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
}

export function hexToBytes(h: string): Uint8Array {
  const s = h.startsWith('0x') ? h.slice(2) : h
  if (s.length % 2 !== 0) throw new Error('hex: odd length')
  const out = new Uint8Array(s.length / 2)
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(s.slice(i * 2, i * 2 + 2), 16)
    if (Number.isNaN(byte)) throw new Error('hex: non-hex character')
    out[i] = byte
  }
  return out
}

/**
 * Strict G1 decode: on the curve AND in the prime-order subgroup.
 *
 * The subgroup check is the one that matters adversarially. BLS12-381's G1 has
 * cofactor h != 1, so there are points that satisfy the curve equation but sit
 * outside the order-r subgroup; feeding one into a pairing equation is a
 * standard way to make a check pass that should not. `assertValidity()` runs
 * both checks.
 */
export function g1FromBytesStrict(b: Uint8Array): G1Point {
  if (b.length !== G1_BYTES) throw new Error(`G1 point must be ${G1_BYTES} bytes, got ${b.length}`)
  const P = G1.fromBytes(b)
  P.assertValidity()
  return P
}

export function g2FromBytesStrict(b: Uint8Array): G2Point {
  if (b.length !== G2_BYTES) throw new Error(`G2 point must be ${G2_BYTES} bytes, got ${b.length}`)
  const P = G2.fromBytes(b)
  P.assertValidity()
  return P
}

/**
 * A list of G1 points with no known discrete-log relation between them, derived
 * by hash-to-curve from a domain separation tag. This is the "nothing up my
 * sleeve" setup the IPA needs, and the reason IPA is called transparent: there
 * is no secret anywhere in this function, so there is nothing anyone could have
 * kept.
 */
export function hashToG1Generators(dst: string, count: number, label: string): G1Point[] {
  const enc = new TextEncoder()
  const out: G1Point[] = []
  for (let i = 0; i < count; i++) {
    const msg = enc.encode(`${label}:${i}`)
    out.push(bls12_381.G1.hashToCurve(msg, { DST: dst }) as unknown as G1Point)
  }
  return out
}
