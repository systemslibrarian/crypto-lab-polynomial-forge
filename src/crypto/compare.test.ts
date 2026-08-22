import { describe, expect, it } from 'vitest'
import { Fr } from './fr.js'
import { GROTH16_CONTRAST, runComparison } from './compare.js'
import { srsFromTau } from './kzg.js'
import { ipaSetup } from './ipa.js'
import { DEFAULT_FRI_PARAMS, friProofBytes, friProve } from './fri.js'
import { ipaProofBytes } from './ipa.js'
import { polyEval } from './poly.js'

const TAU = 0x6b21ff70c4e5d9138a02c7be45f19d63e08a25c7b4d1936f0ae52c8d7b613f04n % Fr.ORDER
const SRS = srsFromTau(TAU, 16)
const IPA = ipaSetup(16)
const P = [3n, 1n, 4n, 1n, 5n, 9n, 2n, 6n, 5n, 3n, 5n, 8n, 9n, 7n, 9n, 3n]

describe('the three-way comparison', () => {
  const result = runComparison({ srs: SRS, coefficients: P, z: 11n, ipa: IPA, repeats: 1 })

  it('runs all three on the same polynomial and the same point', () => {
    expect(result.rows.length).toBe(3)
    expect(result.z).toBe(11n)
    expect(result.y).toBe(polyEval(P, 11n))
    expect(result.degree).toBe(P.length - 1)
  })

  it('all three actually verify — a comparison of three failures would prove nothing', () => {
    for (const row of result.rows) {
      expect(row.verified).toBe(true)
      expect(row.detail.length).toBeGreaterThan(0)
    }
  })

  it('reports the sizes the schemes really produce', () => {
    const kzg = result.rows.find((r) => r.id === 'kzg')!
    const ipa = result.rows.find((r) => r.id === 'ipa')!
    const fri = result.rows.find((r) => r.id === 'fri')!
    expect(kzg.commitmentBytes).toBe(48)
    expect(kzg.proofBytes).toBe(112)
    expect(ipa.commitmentBytes).toBe(48)
    expect(ipa.proofBytes).toBe(ipaProofBytes(16))
    expect(fri.commitmentBytes).toBe(32)
    // Independent re-derivation: rebuild a FRI proof and count its bytes again.
    const rebuilt = friProve(P, 11n, DEFAULT_FRI_PARAMS)
    expect(fri.proofBytes).toBe(friProofBytes(rebuilt.proof))
  })

  it('the size ordering is the one the asymptotics predict', () => {
    const [kzg, ipa, fri] = ['kzg', 'ipa', 'fri'].map((id) => result.rows.find((r) => r.id === id)!)
    expect(kzg.proofBytes).toBeLessThan(ipa.proofBytes)
    expect(ipa.proofBytes).toBeLessThan(fri.proofBytes)
  })

  it('labels setup and post-quantum status correctly', () => {
    const byId = Object.fromEntries(result.rows.map((r) => [r.id, r]))
    expect(byId.kzg.setup).toBe('trusted, universal')
    expect(byId.ipa.setup).toBe('transparent')
    expect(byId.fri.setup).toBe('transparent')
    expect(byId.kzg.postQuantum).toBe(false)
    expect(byId.ipa.postQuantum).toBe(false)
    expect(byId.fri.postQuantum).toBe(true)
  })

  it('every timing is a real non-negative measurement', () => {
    for (const row of result.rows) {
      for (const ms of [row.commitMs, row.openMs, row.verifyMs]) {
        expect(Number.isFinite(ms)).toBe(true)
        expect(ms).toBeGreaterThanOrEqual(0)
      }
    }
  })

  it('reports FRI soundness as a heuristic with its caveat attached', () => {
    expect(result.friHeuristicBits).toBe(60) // 20 queries x log2(8)
    expect(result.friCaveat).toMatch(/Not a security claim/)
  })
})

describe('why Groth16 is not a fourth row', () => {
  it('names the structural reason, not a preference', () => {
    expect(GROTH16_CONTRAST.claims.length).toBe(4)
    const text = GROTH16_CONTRAST.claims.map((c) => `${c.label} ${c.body}`).join(' ')
    expect(text).toMatch(/QAP/)
    expect(text).toMatch(/circuit-specific|one specific circuit/)
    expect(text).toMatch(/universal/)
  })
})
