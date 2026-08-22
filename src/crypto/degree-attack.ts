/**
 * Attack 2 - the omitted degree bound.
 *
 * THE SETTING. An SRS supports degree up to D. The application needs a witness
 * of degree at most d, with d < D: a PLONK selector column, a Reed-Solomon
 * codeword, a vector of length d+1 encoded as a polynomial. The application
 * pins the witness down by opening it at k constraint points.
 *
 * THE OMISSION. Nothing in the KZG verification equation mentions degree. A
 * verifier that checks only openings is checking that the committed polynomial
 * passes through the constraint points - and every polynomial of the form
 *
 *     p'(X) = p(X) + Z(X) * h(X),   Z(X) = prod_i (X - z_i)
 *
 * passes through exactly the same points, for ANY h. Z vanishes on the
 * constraint set, so it is invisible to every constrained opening. Choose h to
 * push the degree up to D and every single KZG check still passes.
 *
 * WHAT IS ACTUALLY FALSE. The protocol's low-degree claim, one layer above the
 * commitment. Not evaluation binding.
 *
 * READ THAT AGAIN, BECAUSE THE TEMPTING LESSON IS WRONG. The missing check does
 * NOT let one commitment open to two different values at the same point. It
 * cannot: C' = [p'(tau)]1 is a different commitment from C = [p(tau)]1, and
 * each of them still opens to exactly one value at every point. Evaluation
 * binding is intact throughout this attack and was never the thing that broke.
 * What broke is that the verifier believed "this commitment holds a degree <= d
 * polynomial" when it had checked nothing of the kind.
 *
 * THE FIX. The standard shifted-commitment check. The prover also supplies
 * C_shift = [tau^(D-d) * p(tau)]1 and the verifier checks
 *
 *     e(C_shift, [1]2) == e(C, [tau^(D-d)]2)
 *
 * An honest prover can build C_shift from the SRS, because deg(p) + (D-d) <= D.
 * A prover whose polynomial has degree above d cannot: the shift would need
 * [tau^k]1 for some k > D, and the SRS simply stops. That impossibility is the
 * argument - which is why the check has to be RUN for it to mean anything.
 */
import { Fr, frOf, frRandom } from './fr.js'
import { interpolate, polyAdd, polyDegree, polyEval, polyMul, vanishingPoly, type Poly } from './poly.js'

export interface ConstraintSet {
  /** The points the application pins the witness down at. */
  readonly xs: readonly bigint[]
  readonly ys: readonly bigint[]
  /** The degree the application requires: at most d. */
  readonly bound: number
}

export interface OverDegreeWitness {
  /** The honest witness: the unique interpolant, degree <= k-1. */
  readonly honest: Poly
  /** The cheating witness: honest + Z*h, agreeing on every constraint point. */
  readonly cheating: Poly
  /** Z(X), the vanishing polynomial of the constraint set. */
  readonly vanishing: Poly
  /** h(X), the arbitrary multiplier. */
  readonly multiplier: Poly
  readonly honestDegree: number
  readonly cheatingDegree: number
}

/**
 * Build the honest witness and a cheating one that is indistinguishable at
 * every constraint point.
 *
 * `targetDegree` is where the cheat lands; it must exceed the bound (otherwise
 * there is no attack) and fit inside the SRS (otherwise the commitment itself
 * is impossible, which is a different and much less interesting failure).
 */
export function buildOverDegreeWitness(
  constraints: ConstraintSet,
  targetDegree: number,
  maxDegree: number,
  multiplierOverride?: readonly bigint[],
): OverDegreeWitness {
  const honest = interpolate(constraints.xs, constraints.ys)
  const honestDegree = polyDegree(honest)
  if (targetDegree <= constraints.bound) {
    throw new RangeError(`target degree ${targetDegree} does not exceed the bound ${constraints.bound}`)
  }
  if (targetDegree > maxDegree) {
    throw new RangeError(`target degree ${targetDegree} exceeds the SRS maximum ${maxDegree}`)
  }

  const vanishing = vanishingPoly(constraints.xs)
  const vanishDeg = polyDegree(vanishing)
  const hDeg = targetDegree - vanishDeg
  if (hDeg < 0) {
    throw new RangeError(
      `cannot reach degree ${targetDegree}: the vanishing polynomial alone has degree ${vanishDeg}`,
    )
  }

  let multiplier: Poly
  if (multiplierOverride) {
    multiplier = multiplierOverride.map(frOf)
  } else {
    multiplier = Array.from({ length: hDeg + 1 }, () => frRandom())
  }
  // The leading coefficient must be non-zero or the degree does not actually rise.
  if (Fr.is0(multiplier[hDeg] ?? 0n)) multiplier[hDeg] = 1n

  const cheating = polyAdd(honest, polyMul(vanishing, multiplier))

  return {
    honest,
    cheating,
    vanishing,
    multiplier,
    honestDegree,
    cheatingDegree: polyDegree(cheating),
  }
}

/** Evidence that the two witnesses are identical exactly where the protocol looks. */
export interface AgreementRow {
  readonly x: bigint
  readonly honestY: bigint
  readonly cheatingY: bigint
  readonly agrees: boolean
  readonly isConstraint: boolean
}

/**
 * Compare the two witnesses on the constraint points AND on points the protocol
 * never asks about.
 *
 * The shape of this table is the exhibit: identical on every constrained row,
 * different everywhere else. "Different everywhere else" is not a binding
 * failure - they are two different polynomials, and each opens to its own value
 * correctly. It is the reason the low-degree claim mattered in the first place.
 */
export function agreementTable(
  witness: OverDegreeWitness,
  constraints: ConstraintSet,
  extraPoints: readonly bigint[],
): AgreementRow[] {
  const rows: AgreementRow[] = []
  for (const x of constraints.xs) {
    rows.push({
      x: frOf(x),
      honestY: polyEval(witness.honest, x),
      cheatingY: polyEval(witness.cheating, x),
      agrees: polyEval(witness.honest, x) === polyEval(witness.cheating, x),
      isConstraint: true,
    })
  }
  for (const x of extraPoints) {
    const h = polyEval(witness.honest, x)
    const c = polyEval(witness.cheating, x)
    rows.push({ x: frOf(x), honestY: h, cheatingY: c, agrees: h === c, isConstraint: false })
  }
  return rows
}

/**
 * The statement the page must never blur.
 *
 * Exported as data rather than prose so `claims.spec.ts` can assert the page
 * actually says it, and so the wording lives next to the code it describes.
 */
export const BINDING_IS_INTACT = {
  claim: 'Evaluation binding is intact throughout this attack.',
  why: 'The cheating witness is a different polynomial, so it has a different commitment. Each commitment still opens to exactly one value at each point; neither opens to two.',
  whatBroke: "The protocol's low-degree claim, one layer above the commitment. The verifier believed the committed polynomial had degree at most d, and had checked nothing of the kind.",
} as const
