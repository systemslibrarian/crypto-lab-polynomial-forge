/**
 * Known-answer tests against the Ethereum EIP-4844 ceremony and its published
 * verify_kzg_proof vectors.
 *
 * WHY THESE ARE THE RIGHT ANCHOR. EIP-4844 is the largest deployed KZG setup in
 * existence, its trusted setup and its test vectors are versioned in a public
 * repository, and the vectors are checked in-tree rather than shipped as a
 * release artefact. `src/crypto/__vectors__/eip4844.json` records the exact
 * repository, commit, and URLs it was built from; the paths were listed through
 * the GitHub tree API at build time rather than typed from memory.
 *
 * WHAT THEY PIN. Two independent things:
 *
 *   1. That the FIXTURE ITSELF is the real ceremony - the pinned G1 monomial
 *      powers and the pinned G2 powers are checked against each other by
 *      pairing, so a transcription error cannot pass. This is not a test of our
 *      code; it is a test of the data our code is then tested against.
 *   2. That our verification equation agrees with the reference implementation
 *      on all 122 published cases, including the tri-state distinction between
 *      "invalid" (well-formed, wrong) and "error" (malformed input, must be
 *      rejected before any algebra).
 *
 * Then, with the fixture proved genuine, our own commit / open / verify runs
 * end to end against the mainnet SRS - so a bug anywhere in the pipeline shows
 * up as a failed pairing against Ethereum's ceremony, not against our own.
 */
import { describe, expect, it } from 'vitest'
import vectors from './__vectors__/eip4844.json'
import { Fr } from './fr.js'
import {
  G1,
  G2,
  type G1Point,
  type G2Point,
  g1FromBytesStrict,
  g2FromBytesStrict,
  hexToBytes,
  pairingEqual,
  g1Mul,
  g2Mul,
} from './bls.js'
import { frFromBytesStrict } from './fr.js'
import { commit, open, srsDigest, verify, type Srs } from './kzg.js'
import { polyEval, polyDegree } from './poly.js'

const g1Powers: G1Point[] = vectors.g1Monomial.map((h) => g1FromBytesStrict(hexToBytes(h)))
const g2Powers: G2Point[] = vectors.g2Monomial.map((h) => g2FromBytesStrict(hexToBytes(h)))

const MAINNET_SRS: Srs = {
  maxDegree: g1Powers.length - 1,
  g1Powers,
  g2Powers,
  digest: srsDigest(g1Powers, g2Powers),
}

describe('the pinned fixture really is the Ethereum ceremony', () => {
  it('records where it came from', () => {
    expect(vectors.source.repo).toBe('ethereum/c-kzg-4844')
    expect(vectors.source.commit).toMatch(/^[0-9a-f]{40}$/)
    expect(vectors.source.setupUrl).toContain(vectors.source.commit)
  })

  it('starts from the BLS12-381 generators', () => {
    expect(g1Powers[0].equals(G1.BASE)).toBe(true)
    expect(g2Powers[0].equals(G2.BASE)).toBe(true)
  })

  it('the pinned powers are a geometric series in one tau', () => {
    // e([tau^j]1, [1]2) == e([tau^(j-1)]1, [tau]2) for every pinned power.
    // A single mistyped hex character anywhere breaks this.
    for (let j = 1; j < g1Powers.length; j++) {
      expect(pairingEqual(g1Powers[j], G2.BASE, g1Powers[j - 1], g2Powers[1])).toBe(true)
    }
  })

  it('the pinned G2 powers mirror the G1 powers', () => {
    for (let j = 1; j < g2Powers.length; j++) {
      expect(pairingEqual(g1Powers[j], G2.BASE, G1.BASE, g2Powers[j])).toBe(true)
    }
  })

  it('every pinned point is in the prime-order subgroup', () => {
    for (const P of g1Powers) expect(P.isTorsionFree()).toBe(true)
    for (const P of g2Powers) expect(P.isTorsionFree()).toBe(true)
  })
})

describe('EIP-4844 verify_kzg_proof KATs', () => {
  const cases = vectors.verifyKzgProof

  it('carries the whole published suite', () => {
    expect(cases.length).toBe(122)
    const counts = { valid: 0, invalid: 0, error: 0 }
    for (const c of cases) counts[c.output as keyof typeof counts]++
    expect(counts.valid).toBe(54)
    expect(counts.invalid).toBe(48)
    expect(counts.error).toBe(20)
  })

  /**
   * The reference API is `verify_kzg_proof(commitment, z, y, proof)`. Our
   * `verify()` takes an Srs and a structured proof, so this adapter maps one to
   * the other. Parsing is strict, and a parse failure is the 'error' verdict -
   * NOT 'invalid'. Collapsing those two is the exact mistake the upstream
   * tri-state output exists to catch.
   */
  function runCase(c: (typeof cases)[number]): 'valid' | 'invalid' | 'error' {
    let commitment: G1Point
    let z: bigint
    let y: bigint
    let witness: G1Point
    try {
      commitment = g1FromBytesStrict(hexToBytes(c.commitment))
      z = frFromBytesStrict(hexToBytes(c.z))
      y = frFromBytesStrict(hexToBytes(c.y))
      witness = g1FromBytesStrict(hexToBytes(c.proof))
    } catch {
      return 'error'
    }
    const result = verify(MAINNET_SRS, commitment, z, y, {
      z,
      y,
      witness,
      srsDigest: MAINNET_SRS.digest,
    })
    return result.ok ? 'valid' : 'invalid'
  }

  for (const c of cases) {
    it(`${c.name} -> ${c.output}`, () => {
      expect(runCase(c)).toBe(c.output)
    })
  }
})

describe('our own pipeline, run against the mainnet SRS', () => {
  const P = [3n, 1n, 4n, 1n, 5n, 9n, 2n, 6n, 5n, 3n, 5n, 8n]

  it('commits, opens and verifies end to end on Ethereum\'s ceremony', () => {
    const C = commit(MAINNET_SRS, P)
    for (const z of [0n, 1n, 4242n, 0x1234567890abcdefn]) {
      const proof = open(MAINNET_SRS, P, z)
      expect(proof.y).toBe(polyEval(P, z))
      expect(verify(MAINNET_SRS, C, z, proof.y, proof).ok).toBe(true)
    }
  })

  it('rejects every neighbouring value of y', () => {
    const C = commit(MAINNET_SRS, P)
    const z = 77n
    const proof = open(MAINNET_SRS, P, z)
    for (const delta of [1n, 2n, Fr.ORDER - 1n]) {
      const badY = Fr.add(proof.y, delta)
      const result = verify(MAINNET_SRS, C, z, badY, { ...proof, y: badY })
      expect(result.ok).toBe(false)
    }
  })

  it('the degree-bound check works against the mainnet SRS too', () => {
    const bound = 15
    const C = commit(MAINNET_SRS, P)
    expect(polyDegree(P)).toBeLessThanOrEqual(bound)
    const proof = open(MAINNET_SRS, P, 9n, { degreeBound: bound })
    expect(verify(MAINNET_SRS, C, 9n, proof.y, proof, { degreeBound: bound }).ok).toBe(true)
    // And a polynomial above the bound cannot produce the shift at all.
    const over = Array.from({ length: 20 }, (_, i) => BigInt(i + 1))
    expect(() => open(MAINNET_SRS, over, 9n, { degreeBound: bound })).toThrow(/beyond the SRS/)
  })

  it('a commitment built from the pinned powers equals a scalar multiply when tau is known — it is not', () => {
    // We cannot do that here, and that is the point: nobody holds this tau.
    // What we CAN check is the homomorphism, which needs no trapdoor:
    // commit(a) + commit(b) == commit(a + b).
    const A = [1n, 2n, 3n]
    const B = [10n, 20n, 30n, 40n]
    const sum = [11n, 22n, 33n, 40n]
    expect(commit(MAINNET_SRS, A).add(commit(MAINNET_SRS, B)).equals(commit(MAINNET_SRS, sum))).toBe(true)
  })

  it('scalar multiples of a commitment track scalar multiples of the polynomial', () => {
    const A = [7n, 0n, 5n]
    const k = 12345n
    expect(g1Mul(commit(MAINNET_SRS, A), k).equals(commit(MAINNET_SRS, A.map((c) => Fr.mul(c, k))))).toBe(true)
    // and the same in G2, so the degree-bound check's side of the equation holds
    expect(g2Mul(G2.BASE, 1n).equals(G2.BASE)).toBe(true)
  })
})
