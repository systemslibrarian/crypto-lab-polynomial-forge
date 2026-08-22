import { describe, expect, it } from 'vitest'
import { Fr, frRandom } from './fr.js'
import { G1, G2, g1Mul, pairingEqual } from './bls.js'
import {
  auditTranscript,
  contribute,
  initialPowers,
  recoverTau,
  runCeremony,
  tauMatchesSrs,
  transcriptByteLength,
  type CeremonyOptions,
} from './ceremony.js'
import { commit, open, verify } from './kzg.js'
import { forgeOpening, forgeWithoutTau } from './forge.js'
import { polyEval } from './poly.js'

const NAMES = ['Ada', 'Grace', 'Katherine', 'Dorothy', 'Annie']
const honest = (n: number): CeremonyOptions => ({
  maxDegree: 8,
  participants: NAMES.slice(0, n).map((name) => ({ name, mode: 'erase' as const })),
})
const toxic = (n: number): CeremonyOptions => ({
  maxDegree: 8,
  participants: NAMES.slice(0, n).map((name) => ({ name, mode: 'retain' as const })),
})

describe('powers of tau — the ceremony itself', () => {
  it('starts from a trivial SRS that secures nothing', () => {
    const { g1Powers, g2Powers } = initialPowers(4)
    for (const P of g1Powers) expect(P.equals(G1.BASE)).toBe(true)
    for (const P of g2Powers) expect(P.equals(G2.BASE)).toBe(true)
  })

  it('a single contribution rescales every power by r^j', () => {
    const r = frRandom()
    const { contribution } = contribute(initialPowers(6), 1, 'solo', 'seed', 'retain', r)
    let rj = 1n
    for (let j = 0; j <= 6; j++) {
      expect(contribution.g1Powers[j].equals(g1Mul(G1.BASE, rj))).toBe(true)
      rj = Fr.mul(rj, r)
    }
  })

  it('produces a valid SRS whose tau is the product of the factors', () => {
    const c = runCeremony(toxic(4))
    const tau = recoverTau(c)
    expect(tau).not.toBeNull()
    // Independent re-derivation: multiply the factors ourselves and rebuild.
    let product = 1n
    for (const r of c.retained) product = Fr.mul(product, r.factor)
    expect(tau).toBe(product)
    expect(tauMatchesSrs(c, product)).toBe(true)
    for (let j = 0; j <= c.maxDegree; j++) {
      expect(c.srs.g1Powers[j].equals(g1Mul(G1.BASE, Fr.pow(product, BigInt(j))))).toBe(true)
    }
  })

  it('needs at least one participant and at least degree 1', () => {
    expect(() => runCeremony({ maxDegree: 0, participants: [{ name: 'x', mode: 'erase' }] })).toThrow()
    expect(() => runCeremony({ maxDegree: 4, participants: [] })).toThrow()
  })
})

describe('the transcript audit', () => {
  it('passes on an honest ceremony', () => {
    const audit = auditTranscript(runCeremony(honest(5)))
    expect(audit.ok).toBe(true)
    expect(audit.rows.every((r) => r.ok)).toBe(true)
  })

  it('runs every check it claims: four per participant plus two on the SRS', () => {
    const audit = auditTranscript(runCeremony(honest(3)))
    expect(audit.rows.length).toBe(3 * 4 + 2)
  })

  /**
   * NEG-2, as a test. This is the claim the whole of Act 4 rests on, so it is
   * asserted rather than described: the audit of a completely dishonest
   * ceremony is INDISTINGUISHABLE from the audit of an honest one.
   */
  it('NEG-2: an all-toxic ceremony produces a transcript audit identical to an honest one', () => {
    const clean = auditTranscript(runCeremony(honest(5)))
    const dirty = auditTranscript(runCeremony(toxic(5)))
    expect(dirty.ok).toBe(true)
    expect(dirty.rows.length).toBe(clean.rows.length)
    clean.rows.forEach((row, i) => {
      expect(dirty.rows[i].ok).toBe(row.ok)
      expect(dirty.rows[i].equation).toBe(row.equation)
      expect(dirty.rows[i].label).toBe(row.label)
      expect(dirty.rows[i].detail).toBe(row.detail)
    })
    expect(dirty.erasureIsUnobservable).toBe(true)
  })

  it('catches a tampered SRS: a power that does not follow from its predecessor', () => {
    const c = runCeremony(honest(2))
    const broken = {
      ...c,
      srs: { ...c.srs, g1Powers: c.srs.g1Powers.map((P, j) => (j === 3 ? P.add(G1.BASE) : P)) },
    }
    const audit = auditTranscript(broken)
    expect(audit.ok).toBe(false)
    const failing = audit.rows.filter((r) => !r.ok)
    expect(failing.some((r) => r.label.includes('geometric series'))).toBe(true)
  })

  it('catches a contribution that lies about its factor', () => {
    const c = runCeremony(toxic(2))
    // Keep the published proof of knowledge but scale the SRS by a different r.
    const rogue = frRandom()
    const tampered = {
      ...c,
      contributions: c.contributions.map((k, i) =>
        i === 1 ? { ...k, g1Powers: k.g1Powers.map((P) => g1Mul(P, rogue)) } : k,
      ),
    }
    const audit = auditTranscript(tampered)
    expect(audit.ok).toBe(false)
    expect(audit.rows.some((r) => !r.ok && r.label.includes('applied that factor'))).toBe(true)
  })

  it('catches a proof of knowledge that does not use one consistent scalar', () => {
    const c = runCeremony(toxic(1))
    const tampered = {
      ...c,
      contributions: c.contributions.map((k) => ({ ...k, sx: k.sx.add(G1.BASE) })),
    }
    const audit = auditTranscript(tampered)
    expect(audit.ok).toBe(false)
    expect(audit.rows.some((r) => !r.ok && r.label.includes('knows the factor'))).toBe(true)
  })

  it('catches a challenge point that was not derived from the transcript', () => {
    const c = runCeremony(toxic(1))
    const tampered = {
      ...c,
      contributions: c.contributions.map((k) => ({ ...k, s: k.s.add(G1.BASE) })),
    }
    const audit = auditTranscript(tampered)
    expect(audit.ok).toBe(false)
    expect(audit.rows.some((r) => !r.ok && r.label.includes('challenge binds'))).toBe(true)
  })

  it('the audit consults only public points — its own pairing checks re-derive', () => {
    // Re-derive the geometric-series check by a different route than the audit:
    // pair every consecutive pair independently.
    const c = runCeremony(honest(2))
    for (let j = 1; j <= c.maxDegree; j++) {
      expect(pairingEqual(c.srs.g1Powers[j], G2.BASE, c.srs.g1Powers[j - 1], c.srs.g2Powers[1])).toBe(true)
    }
  })

  it('reports a transcript size that matches its parts', () => {
    const c = runCeremony(honest(3))
    expect(transcriptByteLength(c)).toBe(3 * (48 * 2 + 96 * 2 + 32) + (c.maxDegree + 1) * (48 + 96))
  })
})

describe('erasure — the property the transcript cannot reach', () => {
  it('one honest participant is enough: tau is unrecoverable', () => {
    const mixed = runCeremony({
      maxDegree: 8,
      participants: [
        { name: 'A', mode: 'retain' },
        { name: 'B', mode: 'retain' },
        { name: 'C', mode: 'erase' },
        { name: 'D', mode: 'retain' },
      ],
    })
    expect(recoverTau(mixed)).toBeNull()
    expect(mixed.allErased).toBe(false)
    expect(auditTranscript(mixed).ok).toBe(true)
  })

  it('an erased factor really is gone from the record', () => {
    const c = runCeremony(honest(3))
    for (const r of c.retained) {
      expect(r.erased).toBe(true)
      expect(r.factor).toBe(0n)
    }
    expect(recoverTau(c)).toBeNull()
  })
})

describe('Attack 1 — forging an opening with a recovered trapdoor', () => {
  const P = [3n, 1n, 4n, 1n, 5n, 9n, 2n, 6n]

  it('every check is green and the forgery is accepted anyway', () => {
    const c = runCeremony(toxic(5))
    expect(auditTranscript(c).ok).toBe(true)

    const tau = recoverTau(c)
    expect(tau).not.toBeNull()
    expect(tauMatchesSrs(c, tau!)).toBe(true)

    const C = commit(c.srs, P)
    const z = 12n
    const trueY = polyEval(P, z)
    const lie = Fr.add(trueY, 1_000_000n)
    expect(lie).not.toBe(trueY)

    const forged = forgeOpening({ srs: c.srs, coefficients: P, tau: tau!, z, claimedY: lie })
    expect(forged.trueY).toBe(trueY)

    const verdict = verify(c.srs, C, z, lie, forged.proof)
    expect(verdict.ok).toBe(true) // the real verifier accepts a value that is false
  })

  it('the same commitment still opens honestly — the forgery adds a lie, it does not corrupt the commitment', () => {
    const c = runCeremony(toxic(3))
    const tau = recoverTau(c)!
    const C = commit(c.srs, P)
    const z = 5n
    const honestProof = open(c.srs, P, z)
    expect(verify(c.srs, C, z, honestProof.y, honestProof).ok).toBe(true)
    const forged = forgeOpening({ srs: c.srs, coefficients: P, tau, z, claimedY: 1n })
    expect(verify(c.srs, C, z, 1n, forged.proof).ok).toBe(true)
    // Both accepted, from ONE commitment, at ONE point, for TWO values. That is
    // a genuine binding break, and it is what knowing tau costs.
    expect(honestProof.y).not.toBe(1n)
  })

  it('forges for any y a caller asks for', () => {
    const c = runCeremony(toxic(2))
    const tau = recoverTau(c)!
    const C = commit(c.srs, P)
    for (const lie of [0n, 1n, 42n, frRandom()]) {
      const forged = forgeOpening({ srs: c.srs, coefficients: P, tau, z: 7n, claimedY: lie })
      expect(verify(c.srs, C, 7n, lie, forged.proof).ok).toBe(true)
    }
  })

  it('the forged witness is exactly (p(tau) - y)/(tau - z) in the exponent', () => {
    const c = runCeremony(toxic(2))
    const tau = recoverTau(c)!
    const forged = forgeOpening({ srs: c.srs, coefficients: P, tau, z: 7n, claimedY: 3n })
    const expected = Fr.mul(Fr.sub(polyEval(P, tau), 3n), Fr.inv(Fr.sub(tau, 7n)))
    expect(forged.witnessScalar).toBe(expected)
    expect(forged.proof.witness.equals(g1Mul(G1.BASE, expected))).toBe(true)
  })

  it('refuses the degenerate z = tau', () => {
    const c = runCeremony(toxic(1))
    const tau = recoverTau(c)!
    expect(() => forgeOpening({ srs: c.srs, coefficients: P, tau, z: tau, claimedY: 1n })).toThrow(/z = tau/)
  })

  it('without a trapdoor there is nothing to forge from', () => {
    const c = runCeremony(honest(3))
    expect(recoverTau(c)).toBeNull()
    const attempt = forgeWithoutTau()
    expect(attempt.possible).toBe(false)
    expect(attempt.reason).toMatch(/not a polynomial/)
  })
})
