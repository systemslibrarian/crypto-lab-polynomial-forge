/**
 * IPA - a polynomial commitment from the inner-product argument.
 *
 * This is the Bulletproofs / Halo construction. crypto-lab-bulletproofs already
 * takes the inner-product argument apart in its own right (range proofs, the
 * folding, the aggregation); here it appears wearing a different hat, as the
 * commitment layer of a proof system. Same argument, different job.
 *
 * SETUP IS TRANSPARENT. The generators G_0..G_{n-1} and the extra base U are
 * produced by hash-to-curve from a fixed domain separation tag. There is no
 * secret anywhere in that derivation - which is the whole difference from KZG.
 * Nobody has to be trusted to forget anything, because nobody ever knew
 * anything. That is what "transparent setup" means, and it is bought with a
 * logarithmic proof instead of a constant one.
 *
 * COMMIT.  C = sum_i c_i * G_i
 *
 * OPEN AT z. Evaluating a polynomial IS an inner product:
 *
 *     p(z) = <c, b>   where b = (1, z, z^2, ..., z^{n-1})
 *
 * so proving p(z) = y is proving an inner product against a vector the verifier
 * can build itself. The argument folds both vectors in half each round:
 *
 *     L = <a_lo, G_hi> + <a_lo, b_hi> * U
 *     R = <a_hi, G_lo> + <a_hi, b_lo> * U
 *     a' = a_lo*x + a_hi*x^-1     b' = b_lo*x^-1 + b_hi*x     G' = G_lo*x^-1 + G_hi*x
 *
 * After log2(n) rounds the vectors are one element long and the prover sends
 * that single scalar. Proof size: 2*log2(n) group elements plus one scalar.
 *
 * VERIFY IS LINEAR. The verifier has to rebuild G* = <s, G>, and s has n
 * entries, so it does an n-sized multi-scalar multiplication. There is no way
 * around it: the generators are the only thing tying the proof to the original
 * commitment. That asymmetry - log-size proof, linear-time verify - is exactly
 * the row IPA occupies in the comparison table.
 *
 * NOT PRODUCTION, and specifically NOT HIDING. The commitment here is binding
 * only. A hiding variant adds a blinding term r*H and carries blinding through
 * the folding; it changes the sizes not at all and the reading a great deal, so
 * it is out of scope for this page and named as such.
 */
import { Fr, frOf, frInvertBatch } from './fr.js'
import { G1, G1_BYTES, type G1Point, g1Mul, g1Msm, hashToG1Generators } from './bls.js'
import { Transcript } from './transcript.js'
import { fail, pass, type VerifyResult } from './codes.js'

export const IPA_DST = 'CRYPTO-LAB-POLYNOMIAL-FORGE-IPA-V1_XMD:SHA-256_SSWU_RO_'

export interface IpaSetup {
  /** Power-of-two vector length. */
  readonly n: number
  readonly generators: readonly G1Point[]
  /** The base the claimed inner product is folded into. */
  readonly u: G1Point
  /** Human-readable statement of how these were derived. */
  readonly derivation: string
}

/**
 * Derive the generators. Deterministic, public, and reproducible by anyone from
 * the DST alone - re-run it and you get the same points.
 */
export function ipaSetup(n: number): IpaSetup {
  if (n < 1 || (n & (n - 1)) !== 0) throw new RangeError('IPA vector length must be a power of two')
  const generators = hashToG1Generators(IPA_DST, n, 'G')
  const u = hashToG1Generators(IPA_DST, 1, 'U')[0]
  return {
    n,
    generators,
    u,
    derivation: `hash_to_curve(BLS12-381 G1, DST="${IPA_DST}", msg="G:i") for i in 0..${n - 1}, plus msg="U:0"`,
  }
}

/** Pad coefficients up to the setup length. */
export function padToLength(coefficients: readonly bigint[], n: number): bigint[] {
  if (coefficients.length > n) throw new RangeError(`polynomial has ${coefficients.length} coefficients, setup holds ${n}`)
  const out = coefficients.map(frOf)
  while (out.length < n) out.push(0n)
  return out
}

/** C = sum_i c_i * G_i. */
export function ipaCommit(setup: IpaSetup, coefficients: readonly bigint[]): G1Point {
  return g1Msm(setup.generators, padToLength(coefficients, setup.n))
}

export interface IpaProof {
  readonly z: bigint
  readonly y: bigint
  readonly l: readonly G1Point[]
  readonly r: readonly G1Point[]
  /** The single surviving coefficient after all the folding. */
  readonly a: bigint
}

/** b = (1, z, z^2, ..., z^{n-1}) - the vector that turns evaluation into an inner product. */
export function powerVector(z: bigint, n: number): bigint[] {
  const out = new Array<bigint>(n)
  let acc = 1n
  for (let i = 0; i < n; i++) {
    out[i] = acc
    acc = Fr.mul(acc, frOf(z))
  }
  return out
}

function innerProduct(a: readonly bigint[], b: readonly bigint[]): bigint {
  let acc = 0n
  for (let i = 0; i < a.length; i++) acc = Fr.add(acc, Fr.mul(a[i], b[i]))
  return acc
}

function newTranscript(setup: IpaSetup, commitment: G1Point, z: bigint, y: bigint): Transcript {
  return new Transcript('ipa/v1')
    .absorb('n', new Uint8Array([(setup.n >>> 8) & 0xff, setup.n & 0xff]))
    .absorbPoint('C', commitment)
    .absorbScalar('z', z)
    .absorbScalar('y', y)
}

/** Prove p(z) = y for the committed p. */
export function ipaOpen(setup: IpaSetup, coefficients: readonly bigint[], z: bigint): IpaProof {
  const n = setup.n
  let a = padToLength(coefficients, n)
  let b = powerVector(z, n)
  let g = setup.generators.slice()
  const y = innerProduct(a, b)

  const commitment = g1Msm(setup.generators, a)
  const transcript = newTranscript(setup, commitment, z, y)
  // Bind the claimed inner product into a separate base so the folding cannot
  // trade group-element mass between the vector part and the product part.
  const uScalar = transcript.challenge('u')
  const u = g1Mul(setup.u, uScalar)

  const l: G1Point[] = []
  const r: G1Point[] = []

  while (a.length > 1) {
    const half = a.length / 2
    const aLo = a.slice(0, half)
    const aHi = a.slice(half)
    const bLo = b.slice(0, half)
    const bHi = b.slice(half)
    const gLo = g.slice(0, half)
    const gHi = g.slice(half)

    const L = g1Msm(gHi, aLo).add(g1Mul(u, innerProduct(aLo, bHi)))
    const R = g1Msm(gLo, aHi).add(g1Mul(u, innerProduct(aHi, bLo)))
    l.push(L)
    r.push(R)

    transcript.absorbPoint('L', L).absorbPoint('R', R)
    const x = transcript.challenge('x')
    const xInv = Fr.inv(x)

    const aNext = new Array<bigint>(half)
    const bNext = new Array<bigint>(half)
    const gNext = new Array<G1Point>(half)
    for (let i = 0; i < half; i++) {
      aNext[i] = Fr.add(Fr.mul(aLo[i], x), Fr.mul(aHi[i], xInv))
      bNext[i] = Fr.add(Fr.mul(bLo[i], xInv), Fr.mul(bHi[i], x))
      gNext[i] = g1Mul(gLo[i], xInv).add(g1Mul(gHi[i], x))
    }
    a = aNext
    b = bNext
    g = gNext
  }

  return { z: frOf(z), y, l, r, a: a[0] }
}

/**
 * The scalar vector s with G* = <s, G>.
 *
 * s_i is a product of one challenge per round - x_j if bit j of i is set,
 * x_j^-1 otherwise. Building it costs n multiplications, and the MSM against it
 * costs n more: this function is where IPA's linear verification lives.
 */
export function ipaScalarVector(challenges: readonly bigint[], n: number): bigint[] {
  const rounds = challenges.length
  const inv = frInvertBatch(challenges)
  const s = new Array<bigint>(n)
  for (let i = 0; i < n; i++) {
    let acc = 1n
    for (let j = 0; j < rounds; j++) {
      // Round j splits on the (rounds-1-j)-th bit: the first round separates the
      // low half from the high half of the whole vector.
      const bit = (i >> (rounds - 1 - j)) & 1
      acc = Fr.mul(acc, bit === 1 ? challenges[j] : inv[j])
    }
    s[i] = acc
  }
  return s
}

export function ipaVerify(
  setup: IpaSetup,
  commitment: G1Point,
  z: bigint,
  y: bigint,
  proof: IpaProof,
): VerifyResult {
  const n = setup.n
  const rounds = Math.log2(n)
  if (!Number.isInteger(rounds)) return fail('MALFORMED_PROOF', 'setup length is not a power of two')
  if (proof.l.length !== rounds || proof.r.length !== rounds) {
    return fail('MALFORMED_PROOF', `expected ${rounds} L/R pairs, got ${proof.l.length}/${proof.r.length}`)
  }
  if (frOf(proof.z) !== frOf(z)) {
    return fail('POINT_MISMATCH', `proof opens at z = ${frOf(proof.z)}, verifier is checking z = ${frOf(z)}`)
  }
  if (frOf(proof.y) !== frOf(y)) {
    return fail('POINT_MISMATCH', `proof claims y = ${frOf(proof.y)}, verifier is checking y = ${frOf(y)}`)
  }
  for (const P of [...proof.l, ...proof.r]) {
    try {
      P.assertValidity()
    } catch {
      return fail('MALFORMED_PROOF', 'an L or R point is outside the prime-order subgroup of G1')
    }
  }

  const transcript = newTranscript(setup, commitment, z, y)
  const uScalar = transcript.challenge('u')
  const u = g1Mul(setup.u, uScalar)

  // Replay the prover's challenges from the same transcript.
  const challenges: bigint[] = []
  for (let j = 0; j < rounds; j++) {
    transcript.absorbPoint('L', proof.l[j]).absorbPoint('R', proof.r[j])
    challenges.push(transcript.challenge('x'))
  }
  const chalSq = challenges.map((x) => Fr.mul(x, x))
  const chalSqInv = frInvertBatch(chalSq)

  // P = C + y*u, then folded: P' = P + sum_j (x_j^2 L_j + x_j^-2 R_j)
  let P = commitment.add(g1Mul(u, y))
  for (let j = 0; j < rounds; j++) {
    P = P.add(g1Mul(proof.l[j], chalSq[j])).add(g1Mul(proof.r[j], chalSqInv[j]))
  }

  // The linear part: rebuild the folded generator and the folded b.
  const s = ipaScalarVector(challenges, n)
  const gStar = g1Msm(setup.generators, s)
  const bStar = innerProduct(s, powerVector(z, n))

  const expected = g1Mul(gStar, proof.a).add(g1Mul(u, Fr.mul(proof.a, bStar)))
  if (!P.equals(expected)) {
    return fail('PAIRING_FAIL', 'the folded commitment does not match a*G* + (a*b*)*U')
  }
  return pass(`inner-product argument closes after ${rounds} folding rounds`)
}

/** Wire size: 2*log2(n) compressed G1 points, plus z, y and the final scalar. */
export function ipaProofBytes(n: number): number {
  return 2 * Math.log2(n) * G1_BYTES + 3 * 32
}

export const IPA_COMMITMENT_BYTES = G1_BYTES

export { G1 }
