import { describe, expect, it } from 'vitest'
import { G1 } from './bls.js'
import { Fr, FR_ORDER } from './fr.js'
import { commit, open, srsFromTau, verify } from './kzg.js'
import { batchChallenge, forgePrematureBatch, verifyBatch, type Pair } from './batch.js'

describe('last-challenge two-opening attack', () => {
  for (const tau of [13n, 29n, 101n]) {
    const srs = srsFromTau(tau, 3)
    const p = [3n, 2n, 1n]
    const C = commit(srs, p)
    const honest: Pair = [2n, 5n].map(z => ({ commitment: C, proof: open(srs, p, z) })) as unknown as Pair
    it(`accepts honest openings with either challenge at setup ${tau}`, () => {
      expect(honest.map(e => e.proof.y)).toEqual([11n, 38n])
      for (const bound of [false, true]) expect(verifyBatch(srs, honest, bound).ok).toBe(true)
    })
    it(`accepts false claims only with a premature challenge at setup ${tau}`, () => {
      const claims = honest.map((e, i) => ({ ...e, proof: { ...e.proof, y: Fr.add(e.proof.y, BigInt(i + 1)) } })) as unknown as Pair
      const forged = forgePrematureBatch(srs, claims)
      expect(forged.map(e => verify(srs, C, e.proof.z, e.proof.y, e.proof).ok)).toEqual([false, false])
      const early = verifyBatch(srs, forged, false)
      expect(early.ok).toBe(true)
      // Independently assert the two solved group equations, not just a verdict.
      expect(early.weightedWitness.equals(G1.BASE)).toBe(true)
      expect(early.weightedClaim.equals(srs.g1Powers[1])).toBe(true)
      expect(verifyBatch(srs, forged, true).ok).toBe(false)
      expect(batchChallenge(srs, claims, false)).toBe(batchChallenge(srs, forged, false))
      expect(batchChallenge(srs, claims, true)).not.toBe(batchChallenge(srs, forged, true))
    })
    it(`rejects bad metadata and the attack's equal-point precondition at setup ${tau}`, () => {
      const replace = (proof: typeof honest[0]['proof']): Pair => [{ ...honest[0], proof }, honest[1]]
      expect(() => verifyBatch(srs, replace({ ...honest[0].proof, srsDigest: 'different' }), true)).toThrow('SETUP_MISMATCH')
      expect(() => verifyBatch(srs, replace({ ...honest[0].proof, y: FR_ORDER }), true)).toThrow('non-canonical')
      expect(() => forgePrematureBatch(srs, replace({ ...honest[0].proof, z: honest[1].proof.z }))).toThrow('distinct')
    })
  }
})
