import { describe, expect, it } from 'vitest'
import { Fr } from './fr.js'
import { agreementTable, buildOverDegreeWitness, BINDING_IS_INTACT, type ConstraintSet } from './degree-attack.js'
import { commit, open, srsFromTau, verify } from './kzg.js'
import { polyDegree, polyEval } from './poly.js'

const TAU = 0x51f0c4a9b3e27d6815ca03f7e942b8d6017ac5e2934bd8f71062ea4c5b93d708n % Fr.ORDER
const D = 24 // the SRS supports degree up to 24
const SRS = srsFromTau(TAU, D)

// The application needs degree <= 5, pinned by 4 constraint points.
const CONSTRAINTS: ConstraintSet = {
  xs: [2n, 3n, 5n, 7n],
  ys: [11n, 13n, 17n, 19n],
  bound: 5,
}

describe('Attack 2 — the omitted degree bound', () => {
  const witness = buildOverDegreeWitness(CONSTRAINTS, 16, D, [1n, 1n, 1n, 1n, 1n, 1n, 1n, 1n, 1n, 1n, 1n, 1n, 1n])

  it('the honest witness is the interpolant and respects the bound', () => {
    expect(polyDegree(witness.honest)).toBe(CONSTRAINTS.xs.length - 1)
    expect(polyDegree(witness.honest)).toBeLessThanOrEqual(CONSTRAINTS.bound)
    CONSTRAINTS.xs.forEach((x, i) => expect(polyEval(witness.honest, x)).toBe(CONSTRAINTS.ys[i]))
  })

  it('the cheating witness exceeds the bound but hits every constraint', () => {
    expect(witness.cheatingDegree).toBe(16)
    expect(witness.cheatingDegree).toBeGreaterThan(CONSTRAINTS.bound)
    CONSTRAINTS.xs.forEach((x, i) => expect(polyEval(witness.cheating, x)).toBe(CONSTRAINTS.ys[i]))
  })

  it('the vanishing polynomial is what makes them agree', () => {
    for (const x of CONSTRAINTS.xs) expect(polyEval(witness.vanishing, x)).toBe(0n)
    // Independent re-derivation: cheating - honest must equal Z * h everywhere.
    for (const x of [11n, 13n, 101n]) {
      const diff = Fr.sub(polyEval(witness.cheating, x), polyEval(witness.honest, x))
      expect(diff).toBe(Fr.mul(polyEval(witness.vanishing, x), polyEval(witness.multiplier, x)))
    }
  })

  it('EVERY KZG opening of the cheating witness verifies when enforcement is off', () => {
    const C = commit(SRS, witness.cheating)
    for (const x of CONSTRAINTS.xs) {
      const proof = open(SRS, witness.cheating, x)
      const idx = CONSTRAINTS.xs.indexOf(x)
      expect(proof.y).toBe(CONSTRAINTS.ys[idx])
      expect(verify(SRS, C, x, proof.y, proof).ok).toBe(true)
    }
  })

  it('DEGREE_EXCEEDED appears only once enforcement is switched on', () => {
    const C = commit(SRS, witness.cheating)
    const proof = open(SRS, witness.cheating, 3n)
    expect(verify(SRS, C, 3n, proof.y, proof).ok).toBe(true)
    const enforced = verify(SRS, C, 3n, proof.y, proof, { degreeBound: CONSTRAINTS.bound })
    expect(enforced.ok).toBe(false)
    if (!enforced.ok) expect(enforced.code).toBe('DEGREE_EXCEEDED')
  })

  it('the cheating prover cannot build the shifted commitment at all', () => {
    expect(() => open(SRS, witness.cheating, 3n, { degreeBound: CONSTRAINTS.bound })).toThrow(/beyond the SRS/)
  })

  it('the honest prover can, and passes enforcement', () => {
    const C = commit(SRS, witness.honest)
    const proof = open(SRS, witness.honest, 3n, { degreeBound: CONSTRAINTS.bound })
    expect(verify(SRS, C, 3n, proof.y, proof, { degreeBound: CONSTRAINTS.bound }).ok).toBe(true)
  })

  /**
   * NEG-1, as a test. The tempting wrong lesson is that the missing check lets
   * ONE commitment open two ways at the same point. It does not. These
   * assertions are the difference.
   */
  it('NEG-1: evaluation binding is intact — the two witnesses have DIFFERENT commitments', () => {
    const Ch = commit(SRS, witness.honest)
    const Cc = commit(SRS, witness.cheating)
    expect(Ch.equals(Cc)).toBe(false)
  })

  it('NEG-1: neither commitment opens to two values at the same point', () => {
    const Cc = commit(SRS, witness.cheating)
    const z = 3n
    const good = open(SRS, witness.cheating, z)
    expect(verify(SRS, Cc, z, good.y, good).ok).toBe(true)
    // Any other claimed value at the same point is rejected outright.
    for (const delta of [1n, 2n, 999n]) {
      const lie = Fr.add(good.y, delta)
      expect(verify(SRS, Cc, z, lie, { ...good, y: lie }).ok).toBe(false)
    }
  })

  it('the two witnesses differ everywhere the protocol does not look', () => {
    const extras = [11n, 13n, 101n, 4242n]
    const rows = agreementTable(witness, CONSTRAINTS, extras)
    const constraintRows = rows.filter((r) => r.isConstraint)
    const otherRows = rows.filter((r) => !r.isConstraint)
    expect(constraintRows.length).toBe(CONSTRAINTS.xs.length)
    expect(otherRows.length).toBe(extras.length)
    expect(constraintRows.every((r) => r.agrees)).toBe(true)
    expect(otherRows.every((r) => !r.agrees)).toBe(true)
  })

  it('states plainly what broke and what did not', () => {
    expect(BINDING_IS_INTACT.claim).toMatch(/binding is intact/i)
    expect(BINDING_IS_INTACT.whatBroke).toMatch(/low-degree claim/)
  })

  it('refuses to build a "cheat" that does not actually exceed the bound', () => {
    expect(() => buildOverDegreeWitness(CONSTRAINTS, 4, D)).toThrow(/does not exceed/)
  })

  it('refuses to build a cheat the SRS cannot even commit to', () => {
    expect(() => buildOverDegreeWitness(CONSTRAINTS, D + 1, D)).toThrow(/exceeds the SRS/)
  })

  it('a random multiplier reaches the requested degree too', () => {
    const w = buildOverDegreeWitness(CONSTRAINTS, 20, D)
    expect(w.cheatingDegree).toBe(20)
    CONSTRAINTS.xs.forEach((x, i) => expect(polyEval(w.cheating, x)).toBe(CONSTRAINTS.ys[i]))
  })
})
