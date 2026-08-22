import { describe, expect, it } from 'vitest'
import { Fr, frRandom } from './fr.js'
import { G1, g1Msm } from './bls.js'
import {
  IPA_COMMITMENT_BYTES,
  ipaCommit,
  ipaOpen,
  ipaProofBytes,
  ipaScalarVector,
  ipaSetup,
  ipaVerify,
  padToLength,
  powerVector,
} from './ipa.js'
import { polyEval } from './poly.js'

const N = 16
const SETUP = ipaSetup(N)
const P = [3n, 1n, 4n, 1n, 5n, 9n, 2n, 6n, 5n, 3n, 5n, 8n, 9n, 7n, 9n, 3n]

describe('IPA setup — transparent by construction', () => {
  it('derives generators deterministically from a public tag', () => {
    const again = ipaSetup(N)
    SETUP.generators.forEach((G, i) => expect(G.equals(again.generators[i])).toBe(true))
    expect(SETUP.u.equals(again.u)).toBe(true)
    expect(SETUP.derivation).toContain('hash_to_curve')
  })

  it('the generators are distinct, valid, prime-order points', () => {
    const seen = new Set<string>()
    for (const G of SETUP.generators) {
      G.assertValidity()
      expect(G.isTorsionFree()).toBe(true)
      const hex = Buffer.from(G.toBytes()).toString('hex')
      expect(seen.has(hex)).toBe(false)
      seen.add(hex)
    }
    expect(seen.has(Buffer.from(SETUP.u.toBytes()).toString('hex'))).toBe(false)
  })

  it('refuses a non-power-of-two length', () => {
    expect(() => ipaSetup(12)).toThrow(/power of two/)
  })
})

describe('IPA — evaluation as an inner product', () => {
  it('the power vector turns evaluation into a dot product', () => {
    for (const z of [0n, 1n, 5n, frRandom()]) {
      const b = powerVector(z, N)
      let dot = 0n
      for (let i = 0; i < N; i++) dot = Fr.add(dot, Fr.mul(P[i], b[i]))
      expect(dot).toBe(polyEval(P, z))
    }
  })

  it('the commitment is one group element', () => {
    expect(ipaCommit(SETUP, P).toBytes().length).toBe(IPA_COMMITMENT_BYTES)
    expect(ipaCommit(SETUP, [7n]).toBytes().length).toBe(IPA_COMMITMENT_BYTES)
  })

  it('is additively homomorphic', () => {
    const A = [1n, 2n, 3n]
    const B = [10n, 20n, 30n, 40n]
    const sum = [11n, 22n, 33n, 40n]
    expect(ipaCommit(SETUP, A).add(ipaCommit(SETUP, B)).equals(ipaCommit(SETUP, sum))).toBe(true)
  })

  it('an honest opening verifies at every point tried', () => {
    const C = ipaCommit(SETUP, P)
    for (const z of [0n, 1n, 2n, 999n, frRandom()]) {
      const proof = ipaOpen(SETUP, P, z)
      expect(proof.y).toBe(polyEval(P, z))
      expect(ipaVerify(SETUP, C, z, proof.y, proof).ok).toBe(true)
    }
  })

  it('rejects a wrong value', () => {
    const C = ipaCommit(SETUP, P)
    const proof = ipaOpen(SETUP, P, 5n)
    const lie = Fr.add(proof.y, 1n)
    const result = ipaVerify(SETUP, C, 5n, lie, { ...proof, y: lie })
    expect(result.ok).toBe(false)
  })

  it('rejects a tampered folding element', () => {
    const C = ipaCommit(SETUP, P)
    const proof = ipaOpen(SETUP, P, 5n)
    const tampered = { ...proof, l: proof.l.map((L, i) => (i === 1 ? L.add(G1.BASE) : L)) }
    const result = ipaVerify(SETUP, C, 5n, proof.y, tampered)
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.code).toBe('PAIRING_FAIL')
  })

  it('rejects a tampered final scalar', () => {
    const C = ipaCommit(SETUP, P)
    const proof = ipaOpen(SETUP, P, 5n)
    const result = ipaVerify(SETUP, C, 5n, proof.y, { ...proof, a: Fr.add(proof.a, 1n) })
    expect(result.ok).toBe(false)
  })

  it('rejects a proof against a different commitment', () => {
    const proof = ipaOpen(SETUP, P, 5n)
    const other = ipaCommit(SETUP, P.map((c, i) => (i === 0 ? Fr.add(c, 1n) : c)))
    expect(ipaVerify(SETUP, other, 5n, proof.y, proof).ok).toBe(false)
  })

  it('rejects a proof for a different point with POINT_MISMATCH', () => {
    const C = ipaCommit(SETUP, P)
    const proof = ipaOpen(SETUP, P, 5n)
    const result = ipaVerify(SETUP, C, 6n, polyEval(P, 6n), proof)
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.code).toBe('POINT_MISMATCH')
  })

  it('rejects the wrong number of folding rounds with MALFORMED_PROOF', () => {
    const C = ipaCommit(SETUP, P)
    const proof = ipaOpen(SETUP, P, 5n)
    const result = ipaVerify(SETUP, C, 5n, proof.y, { ...proof, l: proof.l.slice(1) })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.code).toBe('MALFORMED_PROOF')
  })

  it('produces exactly log2(n) folding rounds', () => {
    const proof = ipaOpen(SETUP, P, 5n)
    expect(proof.l.length).toBe(Math.log2(N))
    expect(proof.r.length).toBe(Math.log2(N))
  })

  it('the reported proof size is what a real proof actually contains', () => {
    // Deliberately NOT `2 * log2(n) * 48 + 96` - that is the expression the
    // source uses, and a test that re-derives it would agree with a bug in it.
    // Count the bytes of the parts a real proof holds instead.
    const proof = ipaOpen(SETUP, P, 5n)
    let counted = 0
    for (const P1 of [...proof.l, ...proof.r]) {
      const encoded = P1.toBytes()
      expect(encoded.length).toBe(48)
      counted += encoded.length
    }
    // z, y and the final scalar a, at the field's canonical 32-byte encoding.
    for (const scalar of [proof.z, proof.y, proof.a]) {
      expect(scalar).toBeLessThan(Fr.ORDER)
      counted += 32
    }
    expect(ipaProofBytes(N)).toBe(counted)
  })

  it('a shorter polynomial is zero-padded and still opens correctly', () => {
    const short = [7n, 0n, 5n]
    const C = ipaCommit(SETUP, short)
    const proof = ipaOpen(SETUP, short, 4n)
    expect(proof.y).toBe(polyEval(short, 4n))
    expect(ipaVerify(SETUP, C, 4n, proof.y, proof).ok).toBe(true)
    expect(padToLength(short, N).length).toBe(N)
  })

  it('refuses a polynomial longer than the setup', () => {
    expect(() => padToLength(new Array(N + 1).fill(1n), N)).toThrow(/setup holds/)
  })
})

describe('IPA — the linear part of verification', () => {
  it('the scalar vector rebuilds the folded generator', () => {
    // Independent re-derivation: fold the generators by hand with the same
    // challenges and compare with <s, G>.
    const challenges = Array.from({ length: Math.log2(N) }, () => frRandom())
    let g = SETUP.generators.slice()
    for (const x of challenges) {
      const half = g.length / 2
      const next = []
      const xInv = Fr.inv(x)
      for (let i = 0; i < half; i++) {
        next.push(g[i].multiply(xInv).add(g[i + half].multiply(x)))
      }
      g = next
    }
    const s = ipaScalarVector(challenges, N)
    expect(g1Msm(SETUP.generators, s).equals(g[0])).toBe(true)
  })

  it('the scalar vector has n entries, each a product of one challenge per round', () => {
    const challenges = [2n, 3n, 5n, 7n]
    const s = ipaScalarVector(challenges, 16)
    expect(s.length).toBe(16)
    // s_0 uses every inverse; s_{n-1} uses every challenge.
    let allInv = 1n
    let allFwd = 1n
    for (const x of challenges) {
      allInv = Fr.mul(allInv, Fr.inv(x))
      allFwd = Fr.mul(allFwd, x)
    }
    expect(s[0]).toBe(allInv)
    expect(s[15]).toBe(allFwd)
  })
})
