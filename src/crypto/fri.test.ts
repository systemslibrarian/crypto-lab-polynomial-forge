import { describe, expect, it } from 'vitest'
import { Fr, frRandom, rootOfUnity } from './fr.js'
import {
  COSET_SHIFT,
  DEFAULT_FRI_PARAMS,
  FRI_COMMITMENT_BYTES,
  buildDomain,
  foldLayer,
  friCommit,
  friProofBytes,
  friProve,
  friSoundnessBits,
  friVerify,
  squareDomain,
} from './fri.js'
import { polyEval, polyEvalDomain } from './poly.js'

const P = [3n, 1n, 4n, 1n, 5n, 9n, 2n, 6n, 5n, 3n, 5n, 8n, 9n, 7n, 9n, 3n]
const PARAMS = DEFAULT_FRI_PARAMS

describe('the FRI evaluation domain', () => {
  it('is a coset of the right size, with distinct points', () => {
    const d = buildDomain(128)
    expect(d.size).toBe(128)
    expect(d.points[0]).toBe(COSET_SHIFT)
    expect(new Set(d.points.map(String)).size).toBe(128)
    expect(Fr.pow(d.generator, 128n)).toBe(1n)
    expect(Fr.pow(d.generator, 64n)).not.toBe(1n)
  })

  it('index i and i + half are x and -x', () => {
    const d = buildDomain(64)
    for (let i = 0; i < 32; i++) expect(d.points[i + 32]).toBe(Fr.neg(d.points[i]))
  })

  it('squaring the domain halves it and squares its points', () => {
    const d = buildDomain(64)
    const sq = squareDomain(d)
    expect(sq.size).toBe(32)
    for (let i = 0; i < 32; i++) expect(sq.points[i]).toBe(Fr.mul(d.points[i], d.points[i]))
  })

  it('never contains zero, so the DEEP quotient never divides by zero on it', () => {
    const d = buildDomain(128)
    expect(d.points.some((x) => x === 0n)).toBe(false)
  })

  it('refuses a non-power-of-two size', () => {
    expect(() => buildDomain(48)).toThrow(/power of two/)
  })

  it('uses the same roots of unity the field module derives', () => {
    expect(buildDomain(256).generator).toBe(rootOfUnity(8))
  })
})

describe('folding', () => {
  it('the folded evaluations are the evaluations of the folded polynomial', () => {
    // Independent re-derivation: split P into even and odd coefficient parts by
    // hand, form Pe + beta*Po, and evaluate that on the squared domain.
    const d = buildDomain(64)
    const values = polyEvalDomain(P, d.points)
    const beta = frRandom()
    const folded = foldLayer(values, d, beta)

    const even = P.filter((_, i) => i % 2 === 0)
    const odd = P.filter((_, i) => i % 2 === 1)
    const combined = even.map((c, i) => Fr.add(c, Fr.mul(beta, odd[i] ?? 0n)))
    const sq = squareDomain(d)
    const expected = polyEvalDomain(combined, sq.points)
    expect(folded).toEqual(expected)
  })

  it('halves the degree each round', () => {
    const d = buildDomain(64)
    let values = polyEvalDomain(P, d.points)
    let domain = d
    for (let k = 0; k < 3; k++) {
      values = foldLayer(values, domain, frRandom())
      domain = squareDomain(domain)
      expect(values.length).toBe(64 >> (k + 1))
    }
  })
})

describe('FRI as a polynomial commitment', () => {
  it('the commitment is one 32-byte hash whatever the degree', () => {
    expect(friCommit(P, PARAMS).root.length).toBe(FRI_COMMITMENT_BYTES)
    expect(friCommit([7n], PARAMS).root.length).toBe(FRI_COMMITMENT_BYTES)
  })

  it('an honest opening verifies at every point tried', () => {
    for (const z of [1n, 2n, 999n, frRandom()]) {
      const { commitment, proof } = friProve(P, z, PARAMS)
      expect(proof.y).toBe(polyEval(P, z))
      const result = friVerify(commitment.root, z, proof.y, proof)
      expect(result.ok).toBe(true)
    }
  })

  it('rejects a wrong claimed value', () => {
    const { commitment, proof } = friProve(P, 5n, PARAMS)
    const lie = Fr.add(proof.y, 1n)
    const result = friVerify(commitment.root, 5n, lie, { ...proof, y: lie })
    expect(result.ok).toBe(false)
    // Changing y changes the transcript, so the query positions no longer match.
    if (!result.ok) expect(['MALFORMED_PROOF', 'PAIRING_FAIL']).toContain(result.code)
  })

  it('rejects a proof for a different point with POINT_MISMATCH', () => {
    const { commitment, proof } = friProve(P, 5n, PARAMS)
    const result = friVerify(commitment.root, 6n, proof.y, proof)
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.code).toBe('POINT_MISMATCH')
  })

  it('rejects a proof against a different commitment root', () => {
    const { proof } = friProve(P, 5n, PARAMS)
    const other = friCommit(P.map((c, i) => (i === 0 ? Fr.add(c, 1n) : c)), PARAMS)
    const result = friVerify(other.root, 5n, proof.y, proof)
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.code).toBe('SETUP_MISMATCH')
  })

  it('rejects a tampered committed evaluation', () => {
    const { commitment, proof } = friProve(P, 5n, PARAMS)
    const queries = proof.queries.map((q, i) =>
      i === 0 ? { ...q, base: { ...q.base, lo: Fr.add(q.base.lo, 1n) } } : q,
    )
    const result = friVerify(commitment.root, 5n, proof.y, { ...proof, queries })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.code).toBe('MALFORMED_PROOF') // the Merkle path no longer closes
  })

  it('rejects a tampered folding layer value', () => {
    const { commitment, proof } = friProve(P, 5n, PARAMS)
    const queries = proof.queries.map((q, i) =>
      i === 2
        ? { ...q, layers: q.layers.map((l, k) => (k === 1 ? { ...l, lo: Fr.add(l.lo, 1n) } : l)) }
        : q,
    )
    const result = friVerify(commitment.root, 5n, proof.y, { ...proof, queries })
    expect(result.ok).toBe(false)
  })

  it('rejects a final layer that is not low degree', () => {
    const { commitment, proof } = friProve(P, 5n, PARAMS)
    const finalValues = proof.finalValues.map((v, i) => (i === 0 ? Fr.add(v, 1n) : v))
    const result = friVerify(commitment.root, 5n, proof.y, { ...proof, finalValues })
    expect(result.ok).toBe(false)
  })

  it('rejects a truncated query set', () => {
    const { commitment, proof } = friProve(P, 5n, PARAMS)
    const result = friVerify(commitment.root, 5n, proof.y, { ...proof, queries: proof.queries.slice(1) })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.code).toBe('MALFORMED_PROOF')
  })

  it('rejects queries moved off the transcript-chosen positions', () => {
    const { commitment, proof } = friProve(P, 5n, PARAMS)
    const queries = proof.queries.map((q, i) => (i === 0 ? { ...q, position: (q.position + 1) % 64 } : q))
    const result = friVerify(commitment.root, 5n, proof.y, { ...proof, queries })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.code).toBe('MALFORMED_PROOF')
  })

  it('the number of folding layers follows from the parameters', () => {
    const { proof } = friProve(P, 5n, PARAMS)
    const expectedLayers = Math.log2((PARAMS.n * PARAMS.blowup) / PARAMS.finalSize)
    expect(proof.layerRoots.length).toBe(expectedLayers)
    expect(proof.finalValues.length).toBe(PARAMS.finalSize)
    expect(proof.queries.length).toBe(PARAMS.queries)
  })

  it('reports a proof size that matches its own parts', () => {
    const { proof } = friProve(P, 5n, PARAMS)
    let expected = 32 + proof.layerRoots.length * 32 + proof.finalValues.length * 32 + 64
    for (const q of proof.queries) {
      expected += 4 + 64 + q.base.path.length * 32
      for (const l of q.layers) expected += 64 + l.path.length * 32
    }
    expect(friProofBytes(proof)).toBe(expected)
  })

  it('refuses a polynomial larger than the configured n', () => {
    expect(() => friCommit(new Array(PARAMS.n + 1).fill(1n), PARAMS)).toThrow(/configured for/)
  })

  it('states its soundness as a heuristic, not a claim', () => {
    const s = friSoundnessBits(PARAMS)
    expect(s.heuristicBits).toBe(Math.round(PARAMS.queries * Math.log2(PARAMS.blowup)))
    expect(s.caveat).toMatch(/Not a security claim/)
  })

  it('a short polynomial still opens correctly', () => {
    const short = [7n, 0n, 5n]
    const { commitment, proof } = friProve(short, 4n, PARAMS)
    expect(proof.y).toBe(polyEval(short, 4n))
    expect(friVerify(commitment.root, 4n, proof.y, proof).ok).toBe(true)
  })
})
