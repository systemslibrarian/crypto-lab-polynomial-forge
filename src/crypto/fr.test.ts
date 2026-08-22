import { describe, expect, it } from 'vitest'
import {
  FR_ORDER,
  FR_ROOT_OF_UNITY_2_32,
  FR_TWO_ADICITY,
  Fr,
  frFromBytesReduce,
  frFromBytesStrict,
  frInvertBatch,
  frOf,
  frRandom,
  frToBytes,
  frToHex,
  rootOfUnity,
} from './fr.js'

describe('Fr — the BLS12-381 scalar field', () => {
  it('has the modulus published in the BLS12-381 specification', () => {
    expect(frToHex(FR_ORDER - 1n)).toBe('73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000')
    expect(FR_ORDER).toBe(0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n)
  })

  it('has 2-adicity exactly 32 — derived, not asserted', () => {
    let t = FR_ORDER - 1n
    let s = 0
    while (t % 2n === 0n) {
      t /= 2n
      s++
    }
    expect(s).toBe(FR_TWO_ADICITY)
    expect(t % 2n).toBe(1n)
  })

  it('the pinned root of unity really has order 2^32', () => {
    // Order 2^32 means: w^(2^32) = 1 but w^(2^31) != 1.
    expect(Fr.pow(FR_ROOT_OF_UNITY_2_32, 1n << 32n)).toBe(1n)
    expect(Fr.pow(FR_ROOT_OF_UNITY_2_32, 1n << 31n)).not.toBe(1n)
  })

  it('re-derives the pinned root from the smallest quadratic non-residue', () => {
    // Independent re-derivation: find g with g^((r-1)/2) = -1, then g^((r-1)/2^32).
    let t = FR_ORDER - 1n
    while (t % 2n === 0n) t /= 2n
    let g = 2n
    while (Fr.pow(g, (FR_ORDER - 1n) / 2n) !== FR_ORDER - 1n) g += 1n
    expect(g).toBe(5n)
    expect(Fr.pow(g, t)).toBe(FR_ROOT_OF_UNITY_2_32)
  })

  it('gives a root of the right order at every level', () => {
    for (const k of [1, 2, 3, 8, 16, 32]) {
      const w = rootOfUnity(k)
      expect(Fr.pow(w, 1n << BigInt(k))).toBe(1n)
      if (k > 0) expect(Fr.pow(w, 1n << BigInt(k - 1))).not.toBe(1n)
    }
    expect(rootOfUnity(1)).toBe(FR_ORDER - 1n) // the only element of order 2
  })

  it("refuses a domain larger than the field's 2-adicity allows", () => {
    expect(() => rootOfUnity(33)).toThrow(/2-adicity/)
  })

  it('round-trips through bytes', () => {
    for (let i = 0; i < 32; i++) {
      const x = frRandom()
      expect(frFromBytesStrict(frToBytes(x))).toBe(x)
    }
  })

  it('rejects a non-canonical 32-byte scalar rather than reducing it', () => {
    const atModulus = new Uint8Array(32)
    let v = FR_ORDER
    for (let i = 31; i >= 0; i--) {
      atModulus[i] = Number(v & 0xffn)
      v >>= 8n
    }
    expect(() => frFromBytesStrict(atModulus)).toThrow(/canonical/)
    // r - 1 is the largest legal value and must be accepted.
    atModulus[31] -= 1
    expect(frFromBytesStrict(atModulus)).toBe(FR_ORDER - 1n)
  })

  it('reduces rather than rejects where reduction is correct', () => {
    const wide = new Uint8Array(64).fill(0xff)
    const reduced = frFromBytesReduce(wide)
    expect(reduced).toBeLessThan(FR_ORDER)
    expect(reduced).toBeGreaterThanOrEqual(0n)
  })

  it('normalises negatives into the field', () => {
    expect(frOf(-1n)).toBe(FR_ORDER - 1n)
    expect(frOf(-FR_ORDER)).toBe(0n)
  })

  it('batch inversion agrees with one-at-a-time inversion', () => {
    const xs = Array.from({ length: 17 }, () => frRandom())
    const batch = frInvertBatch(xs)
    xs.forEach((x, i) => {
      expect(batch[i]).toBe(Fr.inv(x))
      expect(Fr.mul(x, batch[i])).toBe(1n)
    })
  })

  it('batch inversion refuses a zero', () => {
    expect(() => frInvertBatch([1n, 0n, 2n])).toThrow(/zero/)
  })
})
