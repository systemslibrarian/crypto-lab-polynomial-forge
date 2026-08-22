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
 * Anyone holding tau can solve that equation directly. Rearranged, it says the
 * discrete log of pi must be (tau - z)^-1 times the discrete log of C - [y]1 -
 * and multiplying a GROUP ELEMENT by a known scalar is just scalar
 * multiplication:
 *
 *     pi_forged = (tau - z)^-1 * (C - [y]1)
 *
 * The division is now an ordinary field inversion, not a polynomial division,
 * so a remainder is not an obstacle - there is no remainder, because there is
 * no polynomial. The result satisfies the pairing equation identically. The
 * verifier is not fooled by a subtle bug; it is answering the question it was
 * asked, and that question stopped meaning anything the moment tau was known.
 *
 * WHO CAN DO THIS - AND IT IS WORSE THAN IT LOOKS. Anyone who knows tau. That
 * is the whole requirement. Note what the formula above does NOT need: it never
 * extracts p(tau) from C, so it never solves a discrete log, so the forger
 * never has to know the committed polynomial. A commitment someone else made,
 * to data the forger has never seen, can be opened to any value at any point.
 *
 * An earlier revision of this file claimed the opposite - that knowing tau
 * alone was not enough, because recovering p(tau) from C would be a discrete
 * log. That was wrong, and wrong in the direction that understates the damage:
 * the scalar p(tau) is never needed, only the point C. `forge.test.ts` pins the
 * correction by forging against a commitment whose polynomial this module is
 * never given.
 */
import { Fr, frOf } from './fr.js'
import { G1, type G1Point, g1Mul } from './bls.js'
import type { KzgProof, Srs } from './kzg.js'

export interface ForgeryInput {
  readonly srs: Srs
  /** The commitment to open dishonestly. Its polynomial is NOT required. */
  readonly commitment: G1Point
  readonly tau: bigint
  readonly z: bigint
  /** The value the forger wants the verifier to accept. */
  readonly claimedY: bigint
}

export interface Forgery {
  readonly proof: KzgProof
  /** (tau - z)^-1, the only new value the forger had to compute. */
  readonly inverse: bigint
  /**
   * True when the forgery was produced without ever being given the committed
   * polynomial - which is every time, and is the point.
   */
  readonly neededThePolynomial: false
}

/**
 * Build a forged opening from the commitment alone.
 *
 * Throws only in the one degenerate case where the opening point collides with
 * the trapdoor (probability about 2^-255).
 */
export function forgeOpening(input: ForgeryInput): Forgery {
  const { srs, commitment, z, claimedY } = input
  const tau = frOf(input.tau)
  const zz = frOf(z)
  const y = frOf(claimedY)

  const denom = Fr.sub(tau, zz)
  if (Fr.is0(denom)) {
    throw new Error('cannot forge at z = tau: the verification equation degenerates there')
  }
  const inverse = Fr.inv(denom)

  // C - [y]1, scaled by (tau - z)^-1. Group arithmetic only: no discrete log,
  // no polynomial, no division with a remainder to worry about.
  const witness: G1Point = g1Mul(commitment.subtract(g1Mul(G1.BASE, y)), inverse)

  return {
    proof: { z: zz, y, witness, srsDigest: srs.digest },
    inverse,
    neededThePolynomial: false,
  }
}

/**
 * The same forgery attempted without tau.
 *
 * Returned rather than thrown, because "the value is not in this page's memory"
 * is the honest outcome an erased ceremony produces, and the UI shows it as
 * such. There is no clever fallback: without tau the forger would have to
 * commit to (p(X) - y)/(X - z), and with y != p(z) that is not a polynomial -
 * there is nothing to commit to.
 */
export function forgeWithoutTau(): { readonly possible: false; readonly reason: string } {
  return {
    possible: false,
    reason:
      'No trapdoor is available. At least one participant erased their factor, so the product was never assembled and this page does not hold it. Forging would require committing to (p(X) - y)/(X - z), and with y != p(z) that is not a polynomial - there is nothing to commit to.',
  }
}
