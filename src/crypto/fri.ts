/**
 * FRI - a polynomial commitment from a low-degree test and a hash function.
 *
 * crypto-lab-stark-tower already runs FRI as the engine of a STARK. This page
 * surfaces it in the role the other two schemes are playing: as a standalone
 * polynomial commitment, committing to the same polynomial they do so the three
 * can be measured against each other.
 *
 * COMMIT. Evaluate p on a domain D that is BLOWUP times larger than it needs to
 * be, and Merkle-commit the evaluations. The redundancy is the point: a genuine
 * degree-(n-1) polynomial fills only a 1/BLOWUP fraction of the space of all
 * functions on D, so two different low-degree polynomials disagree almost
 * everywhere, and a few random spot checks catch a cheat.
 *
 * OPEN AT z (the DEEP trick). To prove p(z) = y, form
 *
 *     q(X) = (p(X) - y) / (X - z)
 *
 * and prove that q is low degree. This is the same division as the KZG opening,
 * and it works for the same reason: q is a polynomial exactly when y = p(z).
 * The opening point z is drawn from OUTSIDE D so the division never divides by
 * zero on the domain - that is what the "DEEP" in DEEP-FRI refers to.
 *
 * PROVE LOW DEGREE. Fold q in half, repeatedly. Split it into even and odd
 * parts, q(X) = q_e(X^2) + X*q_o(X^2), and take the random linear combination
 * q'(X^2) = q_e(X^2) + beta*q_o(X^2). Each fold halves the degree AND halves
 * the domain, and can be computed pointwise from a value and its negation:
 *
 *     q'(x^2) = (q(x) + q(-x))/2 + beta * (q(x) - q(-x))/(2x)
 *
 * After a few rounds what is left is small enough to send outright.
 *
 * VERIFY. Spot-check. Pick random positions, ask for the pair (q(x), q(-x)) at
 * every layer with Merkle proofs, and check that each layer really is the fold
 * of the one before it - plus, at the BASE layer where p itself was committed,
 * that q(x)*(x - z) = p(x) - y, so the low-degree object being tested is the
 * one tied to the commitment rather than some unrelated low-degree function.
 *
 * SOUNDNESS - READ THIS BEFORE BELIEVING A NUMBER. The parameters below are
 * chosen so the demo runs instantly in a browser, not to hit a security target.
 * With blowup B and Q queries the query phase contributes roughly
 * Q * log2(B) bits, under the conjectured proximity gaps that production STARKs
 * also assume, and ignoring the commit-phase error and any proof-of-work
 * grinding. `friSoundnessBits()` reports that heuristic and the page prints it
 * as a heuristic. Real deployments target 80-128 bits and add grinding; this
 * one does not.
 */
import { Fr, frFromBytesReduce, frInvertBatch, frOf, frToBytes, rootOfUnity } from './fr.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { polyEval, polyDegree, interpolate, type Poly } from './poly.js'
import { Transcript } from './transcript.js'
import {
  buildPairTree,
  openPair,
  verifyOpening,
  MERKLE_DIGEST_BYTES,
  type MerkleOpening,
  type MerkleTree,
} from './merkle.js'

import { bytesToHex } from './bls.js'
import { fail, pass, type VerifyResult } from './codes.js'

export interface FriParams {
  /** Number of coefficients of p, a power of two. */
  readonly n: number
  /** Domain size / n. Higher means fewer queries for the same soundness. */
  readonly blowup: number
  /** Number of spot checks. */
  readonly queries: number
  /** Fold until the layer has this many points, then send it whole. */
  readonly finalSize: number
}

export const DEFAULT_FRI_PARAMS: FriParams = { n: 16, blowup: 8, queries: 20, finalSize: 8 }

/**
 * Heuristic query-phase soundness in bits. Named `heuristic` in the return type
 * because it is one: the honest figure for a full FRI security claim needs the
 * commit-phase error and the proximity-gap conjecture spelled out, and neither
 * is folded in here.
 */
export function friSoundnessBits(params: FriParams): { readonly heuristicBits: number; readonly caveat: string } {
  return {
    heuristicBits: Math.round(params.queries * Math.log2(params.blowup)),
    caveat:
      'Query-phase only, under the same conjectured proximity gaps production STARKs assume, with no proof-of-work grinding and no commit-phase term. Not a security claim.',
  }
}

/**
 * The one input FRI refuses: an opening point that lands inside the evaluation
 * domain. It is not a soundness problem, it is a division by zero - the DEEP
 * quotient is undefined there - and the honest response is to say so rather
 * than to return a proof of something else.
 */
export class OpeningPointInDomainError extends Error {
  constructor(readonly z: bigint) {
    super(`opening point ${z} lies inside the FRI evaluation domain; DEEP requires a z outside it`)
    this.name = 'OpeningPointInDomainError'
  }
}

/** 1/2 in Fr, computed once. It appears in every fold, on both sides. */
const INV_TWO: bigint = Fr.inv(2n)

/** A coset of the multiplicative subgroup of order size: { shift * w^i }. */
export interface Domain {
  readonly size: number
  readonly shift: bigint
  readonly generator: bigint
  readonly points: readonly bigint[]
}

/**
 * The coset shift.
 *
 * FRI needs the opening point z to lie OUTSIDE the evaluation domain, because
 * the DEEP quotient divides by (x - z) at every domain point. Using the
 * subgroup itself would put 1 in the domain, and using a small integer as the
 * shift would put that integer in the domain - which is exactly the collision
 * a learner produces by typing the shift as their opening point.
 *
 * So the shift is a nothing-up-my-sleeve field element: the SHA-256 of a fixed
 * string, reduced into Fr. Nobody chose its value, it is reproducible by
 * anyone, and no small integer is anywhere near the resulting coset. That last
 * property is asserted in fri.test.ts rather than assumed.
 */
export const COSET_SHIFT_SEED = 'crypto-lab-polynomial-forge/fri/coset-shift/v1'

export const COSET_SHIFT: bigint = frFromBytesReduce(sha256(new TextEncoder().encode(COSET_SHIFT_SEED)))

export function buildDomain(size: number, shift: bigint = COSET_SHIFT): Domain {
  const k = Math.log2(size)
  if (!Number.isInteger(k)) throw new RangeError('FRI domain size must be a power of two')
  const w = rootOfUnity(k)
  const points: bigint[] = new Array(size)
  let acc = frOf(shift)
  for (let i = 0; i < size; i++) {
    points[i] = acc
    acc = Fr.mul(acc, w)
  }
  return { size, shift: frOf(shift), generator: w, points }
}

/** The domain of the next layer: every point squared, which halves the size. */
export function squareDomain(d: Domain): Domain {
  return buildDomain(d.size / 2, Fr.mul(d.shift, d.shift))
}

/**
 * One folding step, done pointwise.
 *
 * `values` are f over D; the result is f' over D squared. Index j of the output
 * pairs input indices j and j + half, which are x and -x because w^half = -1.
 */
export function foldLayer(values: readonly bigint[], domain: Domain, beta: bigint): bigint[] {
  const half = values.length / 2
  const out = new Array<bigint>(half)
  // One batched inversion for the whole layer instead of one per point. A field
  // inversion is ~200x a multiplication, so the naive form spends most of the
  // prover's time here - and the comparison act TIMES this code, so a needless
  // 200x is not a micro-optimisation, it is a wrong number on the page.
  const twoX = new Array<bigint>(half)
  for (let j = 0; j < half; j++) twoX[j] = Fr.mul(2n, domain.points[j])
  const invTwoX = frInvertBatch(twoX)
  const invTwo = Fr.inv(2n)
  for (let j = 0; j < half; j++) {
    const fx = values[j]
    const fnx = values[j + half]
    const even = Fr.mul(Fr.add(fx, fnx), invTwo)
    const odd = Fr.mul(Fr.sub(fx, fnx), invTwoX[j])
    out[j] = Fr.add(even, Fr.mul(beta, odd))
  }
  return out
}

interface Layer {
  readonly domain: Domain
  readonly values: readonly bigint[]
  readonly tree: MerkleTree
}

export interface FriQuery {
  /** Leaf index in layer 0's pair tree. */
  readonly position: number
  /** Opening of p at that position (both halves of the pair). */
  readonly base: MerkleOpening
  /** Opening of q at layer k, for every folded layer. */
  readonly layers: readonly MerkleOpening[]
}

export interface FriProof {
  readonly params: FriParams
  readonly z: bigint
  readonly y: bigint
  /** Merkle root of p's evaluations - this IS the commitment. */
  readonly baseRoot: Uint8Array
  /** Merkle roots of q's layers, layer 0 first. */
  readonly layerRoots: readonly Uint8Array[]
  /** The bottom layer, sent in full. */
  readonly finalValues: readonly bigint[]
  readonly queries: readonly FriQuery[]
}

/** The commitment: p evaluated on the blown-up domain, Merkle-rooted. */
export interface FriCommitment {
  readonly root: Uint8Array
  readonly domain: Domain
  readonly values: readonly bigint[]
  readonly tree: MerkleTree
  readonly params: FriParams
}

export function friCommit(coefficients: readonly bigint[], params: FriParams = DEFAULT_FRI_PARAMS): FriCommitment {
  if (coefficients.length > params.n) {
    throw new RangeError(`polynomial has ${coefficients.length} coefficients, FRI is configured for ${params.n}`)
  }
  const domain = buildDomain(params.n * params.blowup)
  const values = domain.points.map((x) => polyEval(coefficients, x))
  const tree = buildPairTree(values)
  return { root: tree.root, domain, values, tree, params }
}

function newTranscript(root: Uint8Array, params: FriParams, z: bigint, y: bigint): Transcript {
  return new Transcript('fri/v1')
    .absorb('root', root)
    .absorb('params', new Uint8Array([params.blowup, params.queries, params.finalSize]))
    .absorbScalar('z', z)
    .absorbScalar('y', y)
}

/** Evaluate q(x) = (p(x) - y)/(x - z) pointwise on the domain. */
function quotientValues(values: readonly bigint[], domain: Domain, z: bigint, y: bigint): bigint[] {
  return values.map((v, i) => {
    const denom = Fr.sub(domain.points[i], z)
    if (Fr.is0(denom)) throw new OpeningPointInDomainError(z)
    return Fr.div(Fr.sub(v, y), denom)
  })
}

export interface FriProveResult {
  readonly commitment: FriCommitment
  readonly proof: FriProof
}

export function friProve(
  coefficients: readonly bigint[],
  z: bigint,
  params: FriParams = DEFAULT_FRI_PARAMS,
  precomputed?: FriCommitment,
): FriProveResult {
  // The commitment can be passed in so the comparison act can time committing
  // and opening separately without counting the commitment twice.
  const commitment = precomputed ?? friCommit(coefficients, params)
  const zz = frOf(z)
  const y = polyEval(coefficients, zz)

  const transcript = newTranscript(commitment.root, params, zz, y)

  // Layer 0 of the low-degree test is q, not p.
  let domain = commitment.domain
  let values = quotientValues(commitment.values, domain, zz, y)
  const layers: Layer[] = []

  while (values.length > params.finalSize) {
    const tree = buildPairTree(values)
    layers.push({ domain, values, tree })
    transcript.absorb('layer', tree.root)
    const beta = transcript.challenge('beta')
    values = foldLayer(values, domain, beta)
    domain = squareDomain(domain)
  }
  const finalValues = values.slice()
  transcript.absorbScalars('final', finalValues)

  const queries: FriQuery[] = []
  const baseHalf = commitment.values.length / 2
  for (let qi = 0; qi < params.queries; qi++) {
    const position = transcript.challengeIndex(`query:${qi}`, baseHalf)
    const base = openPair(commitment.tree, commitment.values, position)
    const openings: MerkleOpening[] = []
    let p = position
    for (const layer of layers) {
      const half = layer.values.length / 2
      const idx = p % half
      openings.push(openPair(layer.tree, layer.values, idx))
      p = idx
    }
    queries.push({ position, base, layers: openings })
  }

  return {
    commitment,
    proof: {
      params,
      z: zz,
      y,
      baseRoot: commitment.root,
      layerRoots: layers.map((l) => l.tree.root),
      finalValues,
      queries,
    },
  }
}

/**
 * Verify a FRI opening.
 *
 * `expected` is the VERIFIER'S parameter set, and it is not optional in spirit:
 * blowup, query count and final-layer size are the entire soundness argument,
 * and a verifier that reads them out of the proof has let the prover choose its
 * own security level. A proof declaring one query would then verify in one
 * check and prove almost nothing. The default exists only so callers that
 * genuinely mean the shipped parameters do not have to repeat them.
 */
export function friVerify(
  root: Uint8Array,
  z: bigint,
  y: bigint,
  proof: FriProof,
  expected: FriParams = DEFAULT_FRI_PARAMS,
): VerifyResult {
  const params = expected
  if (
    proof.params.n !== expected.n ||
    proof.params.blowup !== expected.blowup ||
    proof.params.queries !== expected.queries ||
    proof.params.finalSize !== expected.finalSize
  ) {
    return fail(
      'SETUP_MISMATCH',
      `proof declares n=${proof.params.n} blowup=${proof.params.blowup} queries=${proof.params.queries} final=${proof.params.finalSize}, verifier requires n=${expected.n} blowup=${expected.blowup} queries=${expected.queries} final=${expected.finalSize}`,
    )
  }
  if (bytesToHex(root) !== bytesToHex(proof.baseRoot)) {
    return fail('SETUP_MISMATCH', 'the proof was built against a different commitment root')
  }
  if (frOf(proof.z) !== frOf(z)) {
    return fail('POINT_MISMATCH', `proof opens at z = ${frOf(proof.z)}, verifier is checking z = ${frOf(z)}`)
  }
  if (frOf(proof.y) !== frOf(y)) {
    return fail('POINT_MISMATCH', `proof claims y = ${frOf(proof.y)}, verifier is checking y = ${frOf(y)}`)
  }
  if (proof.queries.length !== params.queries) {
    return fail('MALFORMED_PROOF', `expected ${params.queries} queries, got ${proof.queries.length}`)
  }

  // Rebuild the domain chain and replay the transcript.
  const baseDomain = buildDomain(params.n * params.blowup)
  const domains: Domain[] = []
  let d = baseDomain
  while (d.size > params.finalSize) {
    domains.push(d)
    d = squareDomain(d)
  }
  const finalDomain = d
  if (domains.length === 0) {
    // Would mean the evaluation domain is already at the final size, so there is
    // nothing to fold and nothing to test. Refuse rather than index into an
    // empty layer list and throw.
    return fail('MALFORMED_PROOF', 'these parameters leave no folding layers; there is no low-degree test to run')
  }
  if (proof.layerRoots.length !== domains.length) {
    return fail('MALFORMED_PROOF', `expected ${domains.length} layer roots, got ${proof.layerRoots.length}`)
  }
  if (proof.finalValues.length !== params.finalSize) {
    return fail('MALFORMED_PROOF', `final layer must hold ${params.finalSize} values`)
  }

  const transcript = newTranscript(proof.baseRoot, params, proof.z, proof.y)
  const betas: bigint[] = []
  for (const r of proof.layerRoots) {
    transcript.absorb('layer', r)
    betas.push(transcript.challenge('beta'))
  }
  transcript.absorbScalars('final', proof.finalValues)

  // The bottom layer must itself be low degree, or the whole ladder proves
  // nothing. Interpolating finalSize points always succeeds; the claim is about
  // the DEGREE of the result.
  const finalPoly: Poly = interpolate(finalDomain.points, proof.finalValues)
  // The rate is constant down the ladder, so the bottom layer holds
  // finalSize/blowup coefficients - that is what "still low degree" means here.
  const maxFinalDegree = Math.max(0, Math.floor(params.finalSize / params.blowup) - 1)
  if (polyDegree(finalPoly) > maxFinalDegree) {
    return fail(
      'MALFORMED_PROOF',
      `the final layer interpolates to degree ${polyDegree(finalPoly)}, above the ${maxFinalDegree} the rate allows`,
    )
  }

  const baseHalf = baseDomain.size / 2
  for (let qi = 0; qi < params.queries; qi++) {
    const expectedPosition = transcript.challengeIndex(`query:${qi}`, baseHalf)
    const q = proof.queries[qi]
    if (q.position !== expectedPosition) {
      return fail('MALFORMED_PROOF', `query ${qi} is at position ${q.position}, the transcript says ${expectedPosition}`)
    }
    if (q.layers.length !== domains.length) {
      return fail('MALFORMED_PROOF', `query ${qi} opens ${q.layers.length} layers, expected ${domains.length}`)
    }
    if (!verifyOpening(proof.baseRoot, q.base, baseHalf)) {
      return fail('MALFORMED_PROOF', `query ${qi}: Merkle path for the committed evaluations does not reach the root`)
    }

    // DEEP link, on both halves of the base pair: q(x)*(x - z) == p(x) - y.
    for (const [slot, offset] of [
      ['lo', 0],
      ['hi', baseHalf],
    ] as const) {
      const x = baseDomain.points[q.position + offset]
      const px = slot === 'lo' ? q.base.lo : q.base.hi
      const qx = slot === 'lo' ? q.layers[0].lo : q.layers[0].hi
      const lhs = Fr.mul(qx, Fr.sub(x, proof.z))
      const rhs = Fr.sub(px, proof.y)
      if (lhs !== rhs) {
        return fail(
          'PAIRING_FAIL',
          `query ${qi}: the quotient does not match the committed polynomial at x = ${x} (${slot} half)`,
        )
      }
    }

    // Folding consistency, layer by layer.
    let position = q.position
    for (let k = 0; k < domains.length; k++) {
      const layerDomain = domains[k]
      const half = layerDomain.size / 2
      const idx = position % half
      const opening = q.layers[k]
      if (opening.index !== idx) {
        return fail('MALFORMED_PROOF', `query ${qi} layer ${k}: opened index ${opening.index}, expected ${idx}`)
      }
      if (!verifyOpening(proof.layerRoots[k], opening, half)) {
        return fail('MALFORMED_PROOF', `query ${qi} layer ${k}: Merkle path does not reach the layer root`)
      }
      const x = layerDomain.points[idx]
      // Two multiplications, not two inversions. `Fr.div` inverts its divisor
      // every call, and this runs once per layer per query - which made the
      // fold check the majority of friVerify's runtime, and Act 6 prints that
      // runtime as a measured comparison against KZG and IPA.
      const even = Fr.mul(Fr.add(opening.lo, opening.hi), INV_TWO)
      const odd = Fr.mul(Fr.sub(opening.lo, opening.hi), Fr.inv(Fr.mul(2n, x)))
      const folded = Fr.add(even, Fr.mul(betas[k], odd))

      const nextIsFinal = k === domains.length - 1
      const nextValue = nextIsFinal
        ? proof.finalValues[idx]
        : idx < domains[k + 1].size / 2
          ? q.layers[k + 1].lo
          : q.layers[k + 1].hi
      // For a non-final layer the next opening's index is idx mod nextHalf, so
      // `idx` selects which half of that pair the folded value must land in.
      if (!nextIsFinal) {
        const nextHalf = domains[k + 1].size / 2
        if (q.layers[k + 1].index !== idx % nextHalf) {
          return fail('MALFORMED_PROOF', `query ${qi} layer ${k + 1}: index does not follow from layer ${k}`)
        }
      }
      if (folded !== nextValue) {
        return fail('PAIRING_FAIL', `query ${qi} layer ${k}: the fold does not match the next layer`)
      }
      position = idx
    }
  }

  return pass(`all ${params.queries} spot checks agree with every folding layer and with the committed evaluations`)
}

/**
 * Serialise a FRI proof to the bytes it would actually travel as.
 *
 * This exists so the size the comparison act prints is MEASURED. A "size"
 * function that adds up what the author believes the parts to be will agree
 * with itself whatever the parts really are, and a test that re-derives the
 * same sum agrees with the mistake. `friProofBytes` is defined as this
 * function's output length, and `fri.test.ts` checks that it is.
 *
 * Layout: baseRoot || layerRoots || z || y || finalValues || per query
 * (position:u32 || lo || hi || path for the base, then the same per layer).
 * Nothing here is a wire format anyone else parses; it is an honest accounting.
 */
export function serializeFriProof(proof: FriProof): Uint8Array {
  const parts: Uint8Array[] = []
  parts.push(proof.baseRoot)
  for (const r of proof.layerRoots) parts.push(r)
  parts.push(frToBytes(proof.z))
  parts.push(frToBytes(proof.y))
  for (const v of proof.finalValues) parts.push(frToBytes(v))
  for (const q of proof.queries) {
    const pos = new Uint8Array(4)
    pos[0] = (q.position >>> 24) & 0xff
    pos[1] = (q.position >>> 16) & 0xff
    pos[2] = (q.position >>> 8) & 0xff
    pos[3] = q.position & 0xff
    parts.push(pos)
    for (const o of [q.base, ...q.layers]) {
      parts.push(frToBytes(o.lo))
      parts.push(frToBytes(o.hi))
      for (const node of o.path) parts.push(node)
    }
  }
  let total = 0
  for (const p of parts) total += p.length
  const out = new Uint8Array(total)
  let off = 0
  for (const p of parts) {
    out.set(p, off)
    off += p.length
  }
  return out
}

/** Size of a FRI proof, defined as the length of its serialisation. */
export function friProofBytes(proof: FriProof): number {
  return serializeFriProof(proof).length
}

export const FRI_COMMITMENT_BYTES = MERKLE_DIGEST_BYTES

export { frToBytes }
