/**
 * The verifier's vocabulary.
 *
 * A verifier that can only say "no" teaches nothing. Every rejection on this
 * page names which check failed, and the codes are deliberately NOT
 * interchangeable - each one is a different thing going wrong at a different
 * layer, and telling them apart is most of the lesson in the two attack acts.
 */
export const FAILURE_CODES = [
  'PAIRING_FAIL',
  'POINT_MISMATCH',
  'SETUP_MISMATCH',
  'MALFORMED_PROOF',
  'DEGREE_EXCEEDED',
] as const

export type FailureCode = (typeof FAILURE_CODES)[number]

/**
 * DEGREE_UNENFORCED is NOT a failure code. It is a standing statement about the
 * verifier's configuration, shown as a persistent banner whenever the degree
 * bound is not being checked. That distinction is the whole point of Act 5: the
 * omission never produces a rejection, so if it were rendered as a failure the
 * exhibit would be lying about what a real verifier experiences.
 */
export const DEGREE_UNENFORCED = 'DEGREE_UNENFORCED' as const

export const FAILURE_EXPLANATIONS: Record<FailureCode, string> = {
  PAIRING_FAIL:
    'The pairing equation did not hold. The proof decoded cleanly and was checked against the right setup and the right point, and the two sides of e(C - [y]1, [1]2) = e(pi, [tau - z]2) still landed on different G_T elements.',
  POINT_MISMATCH:
    'The proof was produced for a different opening point than the one being verified. Caught before any pairing runs, because a proof about z = 4 is simply not evidence about z = 9.',
  SETUP_MISMATCH:
    'The proof was produced against a different structured reference string. The verifier compares the ceremony transcript digest the prover recorded with its own; two SRSs from different ceremonies are unrelated, so a pairing check against the wrong one is meaningless rather than merely false.',
  MALFORMED_PROOF:
    'The bytes did not decode as a valid proof: wrong length, a non-canonical scalar (a 32-byte value at or above r), a point off the curve, or a point on the curve but outside the prime-order subgroup. Rejected before it can reach any algebra.',
  DEGREE_EXCEEDED:
    'The degree-bound check failed: the committed polynomial has degree above the bound d that this application requires. Only reachable when degree enforcement is switched on - see the DEGREE_UNENFORCED banner for what happens when it is not.',
}

export const DEGREE_UNENFORCED_EXPLANATION =
  'This verifier is not checking the degree bound. Every cryptographic check below can pass while the committed polynomial has a degree the application never intended to allow. Nothing will fail; the absence of the check is the exhibit.'

/** A verification outcome. `ok: false` always names a code. */
export type VerifyResult =
  | { readonly ok: true; readonly detail: string }
  | { readonly ok: false; readonly code: FailureCode; readonly detail: string }

export function pass(detail: string): VerifyResult {
  return { ok: true, detail }
}

export function fail(code: FailureCode, detail: string): VerifyResult {
  return { ok: false, code, detail }
}
