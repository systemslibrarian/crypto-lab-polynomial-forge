/**
 * Attack 1 - forging a KZG opening once the ceremony's trapdoor is known.
 *
 * This is not a break of KZG. KZG is exactly as sound as its assumption, and
 * the assumption is that nobody knows tau. Act 4's ceremony satisfies every
 * check a transcript can make and still ends with tau on the table, because
 * every participant kept their factor. What follows is what that costs.
 *
 * THE FORGERY. The honest opening is pi = [q(tau)]1 for q(X) = (p(X)-y)/(X-z),
 * and it only exists when y = p(z), because otherwise q is not a polynomial.
 * But the verifier never checks that pi is a commitment to a polynomial. It
 * checks one equation in G_T:
 *
 *     e(C - [y]1, [1]2) == e(pi, [tau - z]2)
 *
 * Anyone holding tau as a SCALAR can solve that equation directly, for any y
 * they like:
 *
 *     pi_forged = [ (p(tau) - y) / (tau - z) ]1
 *
 * The division is now an ordinary field division, not a polynomial division, so
 * a remainder is not an obstacle - there is no remainder, because there is no
 * polynomial. The result satisfies the pairing equation identically. The
 * verifier is not fooled by a subtle bug; it is answering the question it was
 * asked, and that question stopped meaning anything the moment tau was known.
 *
 * WHO CAN DO THIS. Someone who knows both tau and the committed polynomial -
 * in practice a prover who also compromised the ceremony. Knowing tau alone
 * does not let you forge against someone else's commitment, because recovering
 * p(tau) from C = [p(tau)]1 is a discrete log. Act 4 says so on the page.
 */
import { Fr, frOf } from './fr.js'
import { G1, type G1Point, g1Mul } from './bls.js'
import { polyEval } from './poly.js'
import type { KzgProof, Srs } from './kzg.js'

export interface ForgeryInput {
  readonly srs: Srs
  readonly coefficients: readonly bigint[]
  readonly tau: bigint
  readonly z: bigint
  /** The value the forger wants the verifier to accept. */
  readonly claimedY: bigint
}

export interface Forgery {
  readonly proof: KzgProof
  /** p(tau) as a scalar - the thing only a compromised prover can compute. */
  readonly pAtTau: bigint
  /** The true p(z), for contrast with claimedY. */
  readonly trueY: bigint
  /** The forged witness's discrete log: (p(tau) - y) / (tau - z). */
  readonly witnessScalar: bigint
}

/**
 * Build a forged opening. Throws only in the one degenerate case where the
 * opening point collides with the trapdoor (probability about 2^-255).
 */
export function forgeOpening(input: ForgeryInput): Forgery {
  const { srs, coefficients, z, claimedY } = input
  const tau = frOf(input.tau)
  const zz = frOf(z)
  const y = frOf(claimedY)

  const denom = Fr.sub(tau, zz)
  if (Fr.is0(denom)) {
    throw new Error('cannot forge at z = tau: the verification equation degenerates there')
  }

  const pAtTau = polyEval(coefficients, tau)
  const witnessScalar = Fr.mul(Fr.sub(pAtTau, y), Fr.inv(denom))
  const witness: G1Point = g1Mul(G1.BASE, witnessScalar)

  return {
    proof: { z: zz, y, witness, srsDigest: srs.digest },
    pAtTau,
    trueY: polyEval(coefficients, zz),
    witnessScalar,
  }
}

/**
 * The same forgery attempted without tau.
 *
 * Returned rather than thrown, because "the value is not in this page's memory"
 * is the honest outcome an erased ceremony produces, and the UI shows it as
 * such. There is no clever fallback: without tau the forger would have to
 * commit to a quotient that does not exist.
 */
export function forgeWithoutTau(): { readonly possible: false; readonly reason: string } {
  return {
    possible: false,
    reason:
      'No trapdoor is available. At least one participant erased their factor, so the product was never assembled and this page does not hold it. Forging would require committing to (p(X) - y)/(X - z), and with y != p(z) that is not a polynomial - there is nothing to commit to.',
  }
}
