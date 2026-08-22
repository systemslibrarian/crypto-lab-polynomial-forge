import { describe, expect, it } from 'vitest'
import { Transcript } from './transcript.js'
import { G1, bytesToHex, g1Mul } from './bls.js'
import { FR_ORDER } from './fr.js'

describe('the Fiat-Shamir transcript', () => {
  it('two transcripts with the same history agree', () => {
    const a = new Transcript('t').absorbScalar('x', 5n).absorbPoint('P', G1.BASE)
    const b = new Transcript('t').absorbScalar('x', 5n).absorbPoint('P', G1.BASE)
    expect(a.challenge('c')).toBe(b.challenge('c'))
  })

  it('a different domain gives a different challenge', () => {
    expect(new Transcript('a').challenge('c')).not.toBe(new Transcript('b').challenge('c'))
  })

  it('absorbing anything changes every later challenge', () => {
    const base = new Transcript('t')
    const c0 = base.challenge('c')
    const other = new Transcript('t').absorbScalar('x', 1n)
    expect(other.challenge('c')).not.toBe(c0)
  })

  it('two challenges in a row differ', () => {
    const t = new Transcript('t')
    expect(t.challenge('c')).not.toBe(t.challenge('c'))
  })

  it('length-prefixing keeps concatenations distinct', () => {
    // "ab" + "c" and "a" + "bc" must not hash the same.
    const enc = (s: string) => new TextEncoder().encode(s)
    const a = new Transcript('t').absorb('l', enc('ab')).absorb('l', enc('c'))
    const b = new Transcript('t').absorb('l', enc('a')).absorb('l', enc('bc'))
    expect(bytesToHex(a.digest())).not.toBe(bytesToHex(b.digest()))
  })

  it('different labels give different challenges from the same state', () => {
    const a = new Transcript('t')
    const b = new Transcript('t')
    expect(a.challenge('one')).not.toBe(b.challenge('two'))
  })

  it('challenges land inside the field and are never zero', () => {
    const t = new Transcript('t')
    for (let i = 0; i < 200; i++) {
      const c = t.challenge(`c${i}`)
      expect(c).toBeGreaterThan(0n)
      expect(c).toBeLessThan(FR_ORDER)
    }
  })

  it('index challenges stay in range and move around', () => {
    const t = new Transcript('t')
    const seen = new Set<number>()
    for (let i = 0; i < 200; i++) {
      const idx = t.challengeIndex(`q${i}`, 64)
      expect(idx).toBeGreaterThanOrEqual(0)
      expect(idx).toBeLessThan(64)
      seen.add(idx)
    }
    // 200 draws over 64 slots should touch well over half of them.
    expect(seen.size).toBeGreaterThan(32)
  })

  it('refuses a non-positive range', () => {
    expect(() => new Transcript('t').challengeIndex('q', 0)).toThrow(/positive/)
  })

  it('absorbing a point actually depends on the point', () => {
    const a = new Transcript('t').absorbPoint('P', G1.BASE)
    const b = new Transcript('t').absorbPoint('P', g1Mul(G1.BASE, 2n))
    expect(a.challenge('c')).not.toBe(b.challenge('c'))
  })

  it('absorbing a scalar list depends on the order', () => {
    const a = new Transcript('t').absorbScalars('s', [1n, 2n])
    const b = new Transcript('t').absorbScalars('s', [2n, 1n])
    expect(a.challenge('c')).not.toBe(b.challenge('c'))
  })
})
