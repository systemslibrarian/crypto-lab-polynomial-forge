/**
 * KZG (Kate-Zaverucha-Goldberg) polynomial commitments over BLS12-381.
 *
 * The scheme, in four lines:
 *
 *   SRS      [tau^0]1 .. [tau^D]1  and  [tau^0]2 .. [tau^D]2, for a tau nobody knows
 *   Commit   C  = [p(tau)]1   = sum_i c_i * [tau^i]1
 *   Open     q(X) = (p(X) - y)/(X - z),  pi = [q(tau)]1
 *   Verify   e(C - [y]1, [1]2) == e(pi, [tau]2 - [z]2)
 *
 * The verification equation is just the division identity
 *   p(X) - y = q(X) * (X - z)
 * evaluated at the unknown tau and moved into the exponent, where the pairing
 * is the only tool that can multiply two hidden values. That is the entire
 * trick: the pairing lets the verifier check a product of two things it can
 * only see in the exponent.
 *
 * NOT PRODUCTION. Real deployments (EIP-4844, PLONK) work in Lagrange basis,
 * batch openings across many polynomials, and use a fixed ceremony output. This
 * file is coefficient-basis, single-opening, and readable.
 */
import { Fr, frOf, frToBytes, frFromBytesStrict, FR_BYTES } from './fr.js'
import {
  G1,
  G2,
  G1_BYTES,
  type G1Point,
  type G2Point,
  g1Mul,
  g2Mul,
  g1Msm,
  pairingEqual,
  g1FromBytesStrict,
  bytesToHex,
} from './bls.js'
import {
  divideByLinear,
  polyDegree,
  polyEval,
  polyShift,
  polyTrim,
  type DivisionResult,
  type Poly,
} from './poly.js'
import { fail, pass, type VerifyResult } from './codes.js'
import { sha256 } from '@noble/hashes/sha2.js'

/**
 * A structured reference string. `g1Powers[i] = [tau^i]1`, `g2Powers[i] = [tau^i]2`.
 *
 * `digest` identifies WHICH ceremony produced this SRS. A verifier compares it
 * with the one recorded in a proof; that comparison is what SETUP_MISMATCH is.
 * It is a commitment to the SRS contents, not a secret.
 */
export interface Srs {
  /** Maximum polynomial degree this SRS can commit to. */
  readonly maxDegree: number
  readonly g1Powers: readonly G1Point[]
  readonly g2Powers: readonly G2Point[]
  readonly digest: string
}

/** A KZG evaluation proof. */
export interface KzgProof {
  /** The opening point the proof was made for. */
  readonly z: bigint
  /** The claimed value p(z). */
  readonly y: bigint
  /** pi = [q(tau)]1, the commitment to the quotient. */
  readonly witness: G1Point
  /** Digest of the SRS this proof was produced against. */
  readonly srsDigest: string
  /**
   * Optional shifted commitment [tau^(D-d) * p(tau)]1, supplied only when the
   * prover is answering a degree bound d. Its absence is what a verifier with
   * enforcement switched on rejects.
   */
  readonly shifted?: G1Point
  /** The degree bound d the shifted commitment was built for. */
  readonly shiftedBound?: number
}

/**
 * Build an SRS from a known tau. Used by tests and by the ceremony (which
 * builds it incrementally instead, from factors it may or may not destroy).
 *
 * A tau that anyone can see is the broken case, not the normal one - that is
 * precisely what Act 4 is about - so this function is not exported to the UI.
 */
export function srsFromTau(tau: bigint, maxDegree: number): Srs {
  if (!Number.isInteger(maxDegree) || maxDegree < 0) throw new RangeError('maxDegree must be >= 0')
  const t = frOf(tau)
  const g1Powers: G1Point[] = []
  const g2Powers: G2Point[] = []
  let power = 1n
  for (let i = 0; i <= maxDegree; i++) {
    g1Powers.push(g1Mul(G1.BASE, power))
    g2Powers.push(g2Mul(G2.BASE, power))
    power = Fr.mul(power, t)
  }
  return { maxDegree, g1Powers, g2Powers, digest: srsDigest(g1Powers, g2Powers) }
}

/**
 * A digest over every point in the SRS. Two SRSs agree on this only if they are
 * the same SRS, which is the property SETUP_MISMATCH needs.
 */
export function srsDigest(g1: readonly G1Point[], g2: readonly G2Point[]): string {
  const parts: Uint8Array[] = []
  for (const P of g1) parts.push(P.toBytes())
  for (const P of g2) parts.push(P.toBytes())
  return bytesToHex(sha256Concat(parts))
}

function sha256Concat(parts: readonly Uint8Array[]): Uint8Array {
  let total = 0
  for (const p of parts) total += p.length
  const buf = new Uint8Array(total)
  let off = 0
  for (const p of parts) {
    buf.set(p, off)
    off += p.length
  }
  return sha256(buf)
}

/**
 * C = [p(tau)]1 = sum_i c_i * [tau^i]1.
 *
 * One group element, 48 compressed bytes, for a polynomial of ANY degree the
 * SRS covers. That compression is the whole reason polynomial commitments are
 * the layer every modern proof system is built on.
 */
export function commit(srs: Srs, coefficients: readonly bigint[]): G1Point {
  const deg = polyDegree(coefficients)
  if (deg > srs.maxDegree) {
    throw new RangeError(
      `polynomial of degree ${deg} exceeds this SRS (max ${srs.maxDegree}); no honest commitment exists`,
    )
  }
  const used = coefficients.slice(0, srs.maxDegree + 1)
  return g1Msm(srs.g1Powers.slice(0, used.length), used)
}

/** The full division tableau for an opening, so the UI can step it. */
export function openingDivision(coefficients: readonly bigint[], z: bigint, y: bigint): DivisionResult {
  return divideByLinear(coefficients, z, y)
}

/**
 * Produce an honest opening proof for p at z.
 *
 * The honest prover cannot choose y: it computes p(z), because with any other
 * value the division leaves a remainder and the "quotient" is not a polynomial,
 * so there is nothing to commit to. This function refuses to pretend otherwise.
 */
export function open(
  srs: Srs,
  coefficients: readonly bigint[],
  z: bigint,
  options: { readonly degreeBound?: number } = {},
): KzgProof {
  const zz = frOf(z)
  const y = polyEval(coefficients, zz)
  // Trim trailing zeros first. `commit` accepts a zero-padded vector as long as
  // its DEGREE fits the SRS, so `open` has to agree: without this, a padded
  // array produces a quotient longer than the SRS and the multi-scalar
  // multiplication fails with a length mismatch rather than a useful error.
  const trimmed = polyTrim(coefficients)
  if (polyDegree(trimmed) > srs.maxDegree) {
    throw new RangeError(
      `polynomial of degree ${polyDegree(trimmed)} exceeds this SRS (max ${srs.maxDegree})`,
    )
  }
  const { quotient, remainder } = divideByLinear(trimmed, zz, y)
  if (!Fr.is0(remainder)) {
    // Unreachable with y = p(z); kept as a live assertion because the entire
    // scheme rests on it.
    throw new Error('internal: honest opening produced a non-zero remainder')
  }
  const witness = g1Msm(srs.g1Powers.slice(0, quotient.length), quotient)

  let shifted: G1Point | undefined
  let shiftedBound: number | undefined
  if (options.degreeBound !== undefined) {
    const d = options.degreeBound
    const shift = srs.maxDegree - d
    if (shift < 0) throw new RangeError('degree bound exceeds the SRS maximum degree')
    const deg = polyDegree(trimmed)
    if (deg + shift > srs.maxDegree) {
      // An over-degree polynomial would need [tau^k]1 for k > D, which the SRS
      // does not contain. That impossibility IS the degree-bound argument.
      throw new RangeError(
        `cannot build a shifted commitment for degree ${deg} at bound ${d}: it needs tau^${deg + shift}, beyond the SRS`,
      )
    }
    const shiftedCoeffs = polyShift(trimmed, shift)
    shifted = g1Msm(srs.g1Powers.slice(0, shiftedCoeffs.length), shiftedCoeffs)
    shiftedBound = d
  }

  return { z: zz, y, witness, srsDigest: srs.digest, shifted, shiftedBound }
}

/**
 * What a prover gets when it insists on a value that is not p(z).
 *
 * There is no honest opening for a wrong y, because (p(X) - y)/(X - z) is not a
 * polynomial. A prover that ploughs on anyway does exactly what `open` does -
 * runs the synthetic division and commits to the quotient row - and simply
 * discards the non-zero remainder. This function is that prover, written out so
 * the page can show what happens next rather than asserting it.
 *
 * The result is a well-formed proof object over a real group element. It is
 * rejected by `verify` with PAIRING_FAIL, because the identity
 * p(X) - y = q(X)(X - z) it is supposed to witness is off by exactly the
 * remainder, and the pairing sees that.
 */
export function attemptOpenAtClaimedValue(
  srs: Srs,
  coefficients: readonly bigint[],
  z: bigint,
  claimedY: bigint,
): { readonly proof: KzgProof; readonly remainder: bigint; readonly honest: boolean } {
  const zz = frOf(z)
  const y = frOf(claimedY)
  const { quotient, remainder } = divideByLinear(coefficients, zz, y)
  const witness = g1Msm(srs.g1Powers.slice(0, quotient.length), quotient)
  return {
    proof: { z: zz, y, witness, srsDigest: srs.digest },
    remainder,
    honest: Fr.is0(remainder),
  }
}

export interface VerifyOptions {
  /**
   * When set, the verifier enforces deg(p) <= degreeBound via the shifted
   * commitment check. When undefined, it does not - and the page says so with a
   * standing DEGREE_UNENFORCED banner rather than a failure.
   */
  readonly degreeBound?: number
}

/**
 * Verify a KZG opening.
 *
 * Order matters and is deliberate: structural checks first (they are cheap and
 * their failures are more informative), then the pairing, then the optional
 * degree bound. Each layer has its own code so the two attack acts can point at
 * exactly which one was and was not consulted.
 */
export function verify(
  srs: Srs,
  commitment: G1Point,
  z: bigint,
  y: bigint,
  proof: KzgProof,
  options: VerifyOptions = {},
): VerifyResult {
  if (proof.srsDigest !== srs.digest) {
    return fail(
      'SETUP_MISMATCH',
      `proof was made against SRS ${proof.srsDigest.slice(0, 16)}..., verifier holds ${srs.digest.slice(0, 16)}...`,
    )
  }
  if (frOf(proof.z) !== frOf(z)) {
    return fail('POINT_MISMATCH', `proof opens at z = ${frOf(proof.z)}, verifier is checking z = ${frOf(z)}`)
  }
  if (frOf(proof.y) !== frOf(y)) {
    return fail('POINT_MISMATCH', `proof claims y = ${frOf(proof.y)}, verifier is checking y = ${frOf(y)}`)
  }
  try {
    proof.witness.assertValidity()
  } catch {
    return fail('MALFORMED_PROOF', 'witness is not a valid point in the prime-order subgroup of G1')
  }

  // e(C - [y]1, [1]2) == e(pi, [tau]2 - [z]2)
  const lhsG1 = commitment.subtract(g1Mul(G1.BASE, y))
  const rhsG2 = srs.g2Powers[1].subtract(g2Mul(G2.BASE, z))
  const equationHolds = pairingEqual(lhsG1, srs.g2Powers[0], proof.witness, rhsG2)
  if (!equationHolds) {
    return fail('PAIRING_FAIL', 'e(C - [y]1, [1]2) and e(pi, [tau - z]2) are different G_T elements')
  }

  if (options.degreeBound !== undefined) {
    const d = options.degreeBound
    const shift = srs.maxDegree - d
    if (shift < 0) return fail('DEGREE_EXCEEDED', `bound ${d} exceeds the SRS maximum degree ${srs.maxDegree}`)
    if (!proof.shifted || proof.shiftedBound !== d) {
      return fail(
        'DEGREE_EXCEEDED',
        `no shifted commitment supplied for bound d = ${d}; the prover could not produce one`,
      )
    }
    try {
      proof.shifted.assertValidity()
    } catch {
      return fail('MALFORMED_PROOF', 'shifted commitment is not a valid point in the prime-order subgroup of G1')
    }
    // e(C_shift, [1]2) == e(C, [tau^(D-d)]2)
    const shiftOk = pairingEqual(proof.shifted, srs.g2Powers[0], commitment, srs.g2Powers[shift])
    if (!shiftOk) {
      return fail('DEGREE_EXCEEDED', `shifted commitment does not match [tau^${shift}] * C; degree exceeds ${d}`)
    }
    return pass(`pairing equation holds and deg(p) <= ${d} is proved`)
  }

  return pass('pairing equation holds')
}

/** Wire format: z (32) || y (32) || pi (48). 112 bytes. */
export function serializeProof(proof: KzgProof): Uint8Array {
  const out = new Uint8Array(FR_BYTES * 2 + G1_BYTES)
  out.set(frToBytes(proof.z), 0)
  out.set(frToBytes(proof.y), FR_BYTES)
  out.set(proof.witness.toBytes(), FR_BYTES * 2)
  return out
}

/**
 * Strict parse. Every rejection here is MALFORMED_PROOF, and the strictness is
 * load-bearing: a non-canonical scalar or an off-subgroup point that got as far
 * as the pairing would be checking a different statement than the one asked.
 */
export function deserializeProof(bytes: Uint8Array, srsDigestValue: string): KzgProof {
  if (bytes.length !== FR_BYTES * 2 + G1_BYTES) {
    throw new Error(`proof must be ${FR_BYTES * 2 + G1_BYTES} bytes, got ${bytes.length}`)
  }
  const z = frFromBytesStrict(bytes.subarray(0, FR_BYTES))
  const y = frFromBytesStrict(bytes.subarray(FR_BYTES, FR_BYTES * 2))
  const witness = g1FromBytesStrict(bytes.subarray(FR_BYTES * 2))
  return { z, y, witness, srsDigest: srsDigestValue }
}

/**
 * Parse and verify in one call, so a parse failure produces a real
 * `VerifyResult` with a real code rather than an exception a caller has to
 * translate into one by hand.
 *
 * This exists because the alternative is a UI that catches the parse error and
 * prints the string 'MALFORMED_PROOF' itself - at which point the page is
 * asserting a verdict rather than reporting one, and no test of the page can
 * tell the difference between a working strict parser and a hardcoded label.
 */
export function verifySerialized(
  srs: Srs,
  commitment: G1Point,
  z: bigint,
  y: bigint,
  bytes: Uint8Array,
  options: VerifyOptions = {},
): VerifyResult {
  let proof: KzgProof
  try {
    proof = deserializeProof(bytes, srs.digest)
  } catch (err) {
    return fail('MALFORMED_PROOF', err instanceof Error ? err.message : String(err))
  }
  return verify(srs, commitment, z, y, proof, options)
}

/** Size of a KZG proof on the wire, for the comparison act. */
export const KZG_PROOF_BYTES = FR_BYTES * 2 + G1_BYTES

/** Size of a KZG commitment on the wire. */
export const KZG_COMMITMENT_BYTES = G1_BYTES

export type { Poly }
