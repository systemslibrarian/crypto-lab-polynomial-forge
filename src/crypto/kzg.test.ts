import { describe, expect, it } from 'vitest'
import { Fr, frRandom, frOf } from './fr.js'
import { G1, G2, g1Mul, hexToBytes, pairingEqual } from './bls.js'
import { polyEval, polyDegree } from './poly.js'
import {
  KZG_COMMITMENT_BYTES,
  KZG_PROOF_BYTES,
  commit,
  deserializeProof,
  open,
  serializeProof,
  srsFromTau,
  verify,
} from './kzg.js'

const TAU = 0x2a3f5c91d7e4b60819af2c53d6e70b1449f8a2c6e3d15b7f0a9c4e2d6b8f1370n % Fr.ORDER
const SRS = srsFromTau(TAU, 16)
const P = [3n, 1n, 4n, 1n, 5n, 9n, 2n, 6n]

describe('KZG — commit / open / verify', () => {
  it('a commitment is one group element whatever the degree', () => {
    const short = commit(SRS, [7n])
    const long = commit(SRS, Array.from({ length: 17 }, () => frRandom()))
    expect(short.toBytes().length).toBe(KZG_COMMITMENT_BYTES)
    expect(long.toBytes().length).toBe(KZG_COMMITMENT_BYTES)
  })

  it('the commitment equals [p(tau)]1 — checked against the scalar directly', () => {
    // Independent re-derivation: the MSM in commit() vs one scalar multiply.
    expect(commit(SRS, P).equals(g1Mul(G1.BASE, polyEval(P, TAU)))).toBe(true)
  })

  it('an honest opening verifies at every point tried', () => {
    for (const z of [0n, 1n, 2n, 12345n, frRandom()]) {
      const y = polyEval(P, z)
      const proof = open(SRS, P, z)
      expect(proof.y).toBe(y)
      const result = verify(SRS, commit(SRS, P), z, y, proof)
      expect(result.ok).toBe(true)
    }
  })

  it('rejects a wrong value with PAIRING_FAIL, not a crash', () => {
    const z = 9n
    const y = polyEval(P, z)
    const proof = open(SRS, P, z)
    const bad = { ...proof, y: Fr.add(y, 1n) }
    const result = verify(SRS, commit(SRS, P), z, Fr.add(y, 1n), bad)
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.code).toBe('PAIRING_FAIL')
  })

  it('rejects a proof made for a different point with POINT_MISMATCH', () => {
    const proof = open(SRS, P, 9n)
    const result = verify(SRS, commit(SRS, P), 10n, polyEval(P, 10n), proof)
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.code).toBe('POINT_MISMATCH')
  })

  it('rejects a proof from another ceremony with SETUP_MISMATCH', () => {
    const other = srsFromTau(TAU + 1n, 16)
    const proof = open(other, P, 5n)
    const result = verify(SRS, commit(SRS, P), 5n, polyEval(P, 5n), proof)
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.code).toBe('SETUP_MISMATCH')
  })

  it('rejects a witness outside the prime-order subgroup with MALFORMED_PROOF', () => {
    const proof = open(SRS, P, 5n)
    const brokenWitness = {
      assertValidity() {
        throw new Error('not in subgroup')
      },
    }
    const result = verify(SRS, commit(SRS, P), 5n, polyEval(P, 5n), {
      ...proof,
      witness: brokenWitness as unknown as typeof proof.witness,
    })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.code).toBe('MALFORMED_PROOF')
  })

  it('accepts a zero-padded vector in both commit AND open', () => {
    // `commit` judges by DEGREE, so a vector padded past the SRS length is fine
    // as long as its real degree fits. `open` has to agree, or a caller that
    // pads gets a length-mismatch crash out of the multi-scalar multiplication
    // instead of a proof.
    const padded = [...P, ...new Array(20).fill(0n)]
    expect(padded.length).toBeGreaterThan(SRS.maxDegree + 1)
    const C = commit(SRS, padded)
    expect(C.equals(commit(SRS, P))).toBe(true)
    const proof = open(SRS, padded, 5n)
    expect(verify(SRS, C, 5n, polyEval(P, 5n), proof).ok).toBe(true)
  })

  it('rejects a claimed y that disagrees with the proof, before any pairing', () => {
    // The y-mismatch arm of POINT_MISMATCH: the proof is internally honest but
    // the verifier was asked about a different value than the one it witnesses.
    const proof = open(SRS, P, 5n)
    const result = verify(SRS, commit(SRS, P), 5n, Fr.add(proof.y, 1n), proof)
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.code).toBe('POINT_MISMATCH')
  })

  it('refuses to commit above the SRS degree', () => {
    expect(() => commit(SRS, Array.from({ length: 18 }, () => 1n))).toThrow(/exceeds this SRS/)
  })

  it('serialises to 112 bytes and parses back', () => {
    const proof = open(SRS, P, 7n)
    const bytes = serializeProof(proof)
    expect(bytes.length).toBe(KZG_PROOF_BYTES)
    expect(bytes.length).toBe(112)
    const parsed = deserializeProof(bytes, SRS.digest)
    expect(parsed.z).toBe(proof.z)
    expect(parsed.y).toBe(proof.y)
    expect(parsed.witness.equals(proof.witness)).toBe(true)
    expect(verify(SRS, commit(SRS, P), 7n, proof.y, parsed).ok).toBe(true)
  })

  it('refuses a proof of the wrong length', () => {
    expect(() => deserializeProof(new Uint8Array(111), SRS.digest)).toThrow(/112 bytes/)
  })

  it('refuses a non-canonical scalar in a serialised proof', () => {
    const proof = open(SRS, P, 7n)
    const bytes = serializeProof(proof)
    // Overwrite z with exactly r, which is one past the largest legal value.
    let v = Fr.ORDER
    for (let i = 31; i >= 0; i--) {
      bytes[i] = Number(v & 0xffn)
      v >>= 8n
    }
    expect(() => deserializeProof(bytes, SRS.digest)).toThrow(/canonical/)
  })
})

describe('KZG — the degree-bound check', () => {
  const BOUND = 7

  it('an honest low-degree prover can build the shifted commitment and passes', () => {
    const proof = open(SRS, P, 5n, { degreeBound: BOUND })
    expect(proof.shifted).toBeDefined()
    const result = verify(SRS, commit(SRS, P), 5n, polyEval(P, 5n), proof, { degreeBound: BOUND })
    expect(result.ok).toBe(true)
  })

  it('an over-degree prover CANNOT build the shifted commitment', () => {
    const over = Array.from({ length: 12 }, () => frRandom())
    expect(polyDegree(over)).toBeGreaterThan(BOUND)
    expect(() => open(SRS, over, 5n, { degreeBound: BOUND })).toThrow(/beyond the SRS/)
  })

  it('an over-degree prover omitting the shift is rejected with DEGREE_EXCEEDED', () => {
    const over = Array.from({ length: 12 }, () => frRandom())
    const proof = open(SRS, over, 5n) // no degreeBound: no shifted commitment
    const result = verify(SRS, commit(SRS, over), 5n, polyEval(over, 5n), proof, { degreeBound: BOUND })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.code).toBe('DEGREE_EXCEEDED')
  })

  it('a shifted commitment for the wrong bound is rejected', () => {
    const proof = open(SRS, P, 5n, { degreeBound: 8 })
    const result = verify(SRS, commit(SRS, P), 5n, polyEval(P, 5n), proof, { degreeBound: BOUND })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.code).toBe('DEGREE_EXCEEDED')
  })

  it('a forged shifted commitment fails the pairing form of the check', () => {
    const proof = open(SRS, P, 5n, { degreeBound: BOUND })
    const tampered = { ...proof, shifted: proof.shifted!.add(G1.BASE) }
    const result = verify(SRS, commit(SRS, P), 5n, polyEval(P, 5n), tampered, { degreeBound: BOUND })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.code).toBe('DEGREE_EXCEEDED')
  })

  it('the SAME over-degree proof passes when enforcement is off', () => {
    const over = Array.from({ length: 12 }, () => frRandom())
    const proof = open(SRS, over, 5n)
    expect(verify(SRS, commit(SRS, over), 5n, polyEval(over, 5n), proof).ok).toBe(true)
  })
})

describe('KZG — SRS structure', () => {
  it('the SRS really is a geometric series in tau', () => {
    for (let j = 1; j <= SRS.maxDegree; j++) {
      expect(pairingEqual(SRS.g1Powers[j], G2.BASE, SRS.g1Powers[j - 1], SRS.g2Powers[1])).toBe(true)
      expect(pairingEqual(SRS.g1Powers[j], G2.BASE, G1.BASE, SRS.g2Powers[j])).toBe(true)
    }
  })

  it('two different taus give different digests', () => {
    expect(srsFromTau(TAU, 4).digest).not.toBe(srsFromTau(TAU + 1n, 4).digest)
    expect(srsFromTau(TAU, 4).digest).toBe(srsFromTau(TAU, 4).digest)
  })
})

describe('a degenerate opening point does not break the equation', () => {
  it('opening at z = 0 recovers the constant term', () => {
    const proof = open(SRS, P, 0n)
    expect(proof.y).toBe(frOf(P[0]))
    expect(verify(SRS, commit(SRS, P), 0n, P[0], proof).ok).toBe(true)
  })

  it('a zero polynomial commits to the identity and still verifies', () => {
    const zero = [0n, 0n, 0n]
    const c = commit(SRS, zero)
    expect(c.is0()).toBe(true)
    const proof = open(SRS, zero, 4n)
    expect(proof.y).toBe(0n)
    expect(proof.witness.is0()).toBe(true)
    // Both sides of the equation are the identity of G_T, so it holds. The
    // upstream EIP-4844 vector `verify_kzg_proof_case_correct_proof_0_0` says
    // the same thing, and kat.test.ts runs it.
    expect(verify(SRS, c, 4n, 0n, proof).ok).toBe(true)
    // ...and the zero commitment does NOT open to a non-zero value.
    expect(verify(SRS, c, 4n, 1n, { ...proof, y: 1n }).ok).toBe(false)
  })

  it('hexToBytes refuses malformed hex', () => {
    expect(() => hexToBytes('abc')).toThrow(/odd length/)
    expect(() => hexToBytes('zz')).toThrow(/non-hex/)
  })
})
