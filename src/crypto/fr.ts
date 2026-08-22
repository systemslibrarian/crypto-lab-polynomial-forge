/**
 * Fr — the BLS12-381 scalar field.
 *
 * Every one of the three commitment schemes on this page commits to the SAME
 * polynomial, so all three have to agree on which field its coefficients live
 * in. Fr is the natural common ground:
 *
 *   - KZG needs a scalar field for a pairing-friendly curve. Fr is BLS12-381's.
 *   - IPA needs the scalar field of whatever group it commits in. We commit in
 *     BLS12-381 G1, so that is Fr again.
 *   - FRI needs a field with a large power-of-two multiplicative subgroup, so
 *     an evaluation domain of size 2^k exists. Fr - 1 = 2^32 * odd, so Fr has
 *     2-adicity 32 and supports domains up to 2^32 points.
 *
 * The field arithmetic itself comes from @noble/curves (audited, constant-time
 * where it claims to be). The teaching-visible parts - polynomial division,
 * the commitment/opening algebra, the ceremony, the two attacks - are
 * hand-rolled in this directory so they can be read and stepped.
 */
import { bls12_381 } from '@noble/curves/bls12-381.js'

/** The scalar field of BLS12-381. Prime, 255 bits. */
export const Fr = bls12_381.fields.Fr

/** r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001 */
export const FR_ORDER: bigint = Fr.ORDER

/** Canonical byte length of an Fr element (big-endian, 32 bytes). */
export const FR_BYTES = 32

/**
 * 2-adicity of Fr: the largest s with 2^s | (r - 1). For BLS12-381 this is 32,
 * which is the ceiling on FRI's evaluation-domain size.
 */
export const FR_TWO_ADICITY = 32

/**
 * A generator of the 2^32-order subgroup of Fr*, i.e. a primitive 2^32-th root
 * of unity. Derived as g^((r-1)/2^32) for the smallest quadratic non-residue
 * g = 5; the value is checked in fr.test.ts rather than trusted here.
 */
export const FR_ROOT_OF_UNITY_2_32 =
  0x0212d79e5b416b6f0fd56dc8d168d6c0c4024ff270b3e0941b788f500b912f1fn

/** Reduce an arbitrary bigint into [0, r). Handles negatives. */
export function frOf(x: bigint): bigint {
  const m = x % FR_ORDER
  return m < 0n ? m + FR_ORDER : m
}

/** A primitive 2^k-th root of unity in Fr, for 0 <= k <= 32. */
export function rootOfUnity(k: number): bigint {
  if (!Number.isInteger(k) || k < 0 || k > FR_TWO_ADICITY) {
    throw new RangeError(`Fr has 2-adicity ${FR_TWO_ADICITY}; no 2^${k}-th root of unity exists`)
  }
  // Square down from the 2^32-th root: (w_{2^32})^(2^(32-k)) has order 2^k.
  return Fr.pow(FR_ROOT_OF_UNITY_2_32, 1n << BigInt(FR_TWO_ADICITY - k))
}

/** Big-endian 32-byte encoding of an Fr element. */
export function frToBytes(x: bigint): Uint8Array {
  const v = frOf(x)
  const out = new Uint8Array(FR_BYTES)
  for (let i = FR_BYTES - 1; i >= 0; i--) out[i] = Number((v >> BigInt(8 * (FR_BYTES - 1 - i))) & 0xffn)
  return out
}

/**
 * Strict big-endian decode. Rejects a non-canonical encoding (a 32-byte value
 * >= r) rather than reducing it, so a malformed proof is a MALFORMED_PROOF and
 * not a silently different-but-valid one.
 */
export function frFromBytesStrict(b: Uint8Array): bigint {
  if (b.length !== FR_BYTES) throw new Error(`scalar must be ${FR_BYTES} bytes, got ${b.length}`)
  let v = 0n
  for (const byte of b) v = (v << 8n) | BigInt(byte)
  if (v >= FR_ORDER) throw new Error('scalar is not canonical: value >= r')
  return v
}

/** Non-strict decode used for Fiat-Shamir challenges, where reduction is correct. */
export function frFromBytesReduce(b: Uint8Array): bigint {
  let v = 0n
  for (const byte of b) v = (v << 8n) | BigInt(byte)
  return frOf(v)
}

/** Lowercase 0x-less hex of an Fr element. */
export function frToHex(x: bigint): string {
  return Array.from(frToBytes(x), (b) => b.toString(16).padStart(2, '0')).join('')
}

/** A uniform Fr element from the platform CSPRNG. Rejection-free: 64 bytes reduced. */
export function frRandom(): bigint {
  const b = new Uint8Array(64)
  crypto.getRandomValues(b)
  // 512 bits reduced mod a 255-bit prime: bias below 2^-255, i.e. unobservable.
  return frFromBytesReduce(b)
}

/** Batch inversion by Montgomery's trick: n multiplications and one inversion. */
export function frInvertBatch(xs: readonly bigint[]): bigint[] {
  const n = xs.length
  const prefix = new Array<bigint>(n + 1)
  prefix[0] = 1n
  for (let i = 0; i < n; i++) {
    if (Fr.is0(xs[i])) throw new Error('cannot invert zero')
    prefix[i + 1] = Fr.mul(prefix[i], xs[i])
  }
  let running = Fr.inv(prefix[n])
  const out = new Array<bigint>(n)
  for (let i = n - 1; i >= 0; i--) {
    out[i] = Fr.mul(running, prefix[i])
    running = Fr.mul(running, xs[i])
  }
  return out
}
