/** Two-opening instance of ePrint 2024/398, §4.1 equation (11).
 * Public-SRS attack only: this module never receives the setup secret.
 * This isolates KZG batching, not the paper's complete PLONK exploit.
 */
import { Fr, frOf } from './fr.js'
import { G1, g1Mul, pairingEqual, type G1Point } from './bls.js'
import { type KzgProof, type Srs } from './kzg.js'
import { Transcript } from './transcript.js'

export interface BatchOpening {
  readonly commitment: G1Point
  readonly proof: KzgProof
}
export type Pair = readonly [BatchOpening, BatchOpening]

export function batchChallenge(srs: Srs, entries: Pair, bindWitnesses: boolean): bigint {
  const t = new Transcript('two-opening-batch/v1')
    .absorb('srs', new TextEncoder().encode(srs.digest))
  entries.forEach(({ commitment, proof }, i) => {
    t.absorbPoint(`C${i}`, commitment).absorbScalar(`z${i}`, proof.z).absorbScalar(`y${i}`, proof.y)
  })
  if (bindWitnesses) entries.forEach(({ proof }, i) => t.absorbPoint(`W${i}`, proof.witness))
  return t.challenge('u')
}

/** Trust the locally audited SRS, but validate each submitted opening first. */
export function verifyBatch(srs: Srs, entries: Pair, bindWitnesses: boolean) {
  if (srs.maxDegree < 1) throw new Error('batch verification needs a degree-one SRS')
  for (const { commitment, proof } of entries) {
    if (proof.srsDigest !== srs.digest) throw new Error('SETUP_MISMATCH')
    if (frOf(proof.z) !== proof.z || frOf(proof.y) !== proof.y) throw new Error('non-canonical scalar')
    commitment.assertValidity()
    proof.witness.assertValidity()
  }
  const u = batchChallenge(srs, entries, bindWitnesses)
  const [a, b] = entries
  const F1 = a.commitment.subtract(g1Mul(G1.BASE, a.proof.y))
  const F2 = b.commitment.subtract(g1Mul(G1.BASE, b.proof.y))
  const weightedWitness = a.proof.witness.add(g1Mul(b.proof.witness, u))
  const weightedClaim = F1.add(g1Mul(F2, u))
    .add(g1Mul(a.proof.witness, a.proof.z))
    .add(g1Mul(b.proof.witness, Fr.mul(u, b.proof.z)))
  const ok = pairingEqual(weightedClaim, srs.g2Powers[0], weightedWitness, srs.g2Powers[1])
  return { ok, u, weightedWitness, weightedClaim }
}

/** Solve W1 + uW2 = A and F1 + uF2 + z1W1 + uz2W2 = B.
 * A = G1, B = [tau]G1 are PUBLIC points satisfying e(A,[tau]G2)=e(B,G2).
 * The attacker chooses W after seeing u. No discrete logarithm is computed.
 */
export function forgePrematureBatch(srs: Srs, claims: Pair): Pair {
  const [a, b] = claims
  const dz = Fr.sub(a.proof.z, b.proof.z)
  if (dz === 0n) throw new Error('the attack requires two distinct opening points')
  const u = batchChallenge(srs, claims, false)
  const A = G1.BASE
  const B = srs.g1Powers[1]
  const D = a.commitment.subtract(g1Mul(G1.BASE, a.proof.y))
    .add(g1Mul(b.commitment.subtract(g1Mul(G1.BASE, b.proof.y)), u))
  const W1 = g1Mul(B.subtract(D).subtract(g1Mul(A, b.proof.z)), Fr.inv(dz))
  const W2 = g1Mul(A.subtract(W1), Fr.inv(u))
  return [
    { commitment: a.commitment, proof: { ...a.proof, witness: W1 } },
    { commitment: b.commitment, proof: { ...b.proof, witness: W2 } },
  ]
}
