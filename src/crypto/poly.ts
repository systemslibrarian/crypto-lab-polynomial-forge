/**
 * Univariate polynomials over Fr, in coefficient form.
 *
 * `Poly` is a plain array of coefficients, LOW DEGREE FIRST:
 *   [3n, 1n, 4n]  means  3 + X + 4X^2.
 *
 * Everything here is hand-rolled and deliberately unclever. The division step
 * in particular (`divideByLinear`) is the mechanism this whole lab exists to
 * show, so it is written as the schoolbook synthetic-division recurrence with
 * every intermediate row retained.
 */
import { Fr, frOf } from './fr.js'

export type Poly = bigint[]

/** Normalise coefficients into Fr and strip trailing zeros. */
export function polyTrim(c: readonly bigint[]): Poly {
  const out = c.map(frOf)
  while (out.length > 1 && Fr.is0(out[out.length - 1])) out.pop()
  return out
}

/** Degree of p. The zero polynomial is given degree -1. */
export function polyDegree(c: readonly bigint[]): number {
  for (let i = c.length - 1; i >= 0; i--) if (!Fr.is0(frOf(c[i]))) return i
  return -1
}

/** p(x) by Horner's rule. */
export function polyEval(c: readonly bigint[], x: bigint): bigint {
  let acc = 0n
  for (let i = c.length - 1; i >= 0; i--) acc = Fr.add(Fr.mul(acc, x), frOf(c[i]))
  return acc
}

/** a + b */
export function polyAdd(a: readonly bigint[], b: readonly bigint[]): Poly {
  const n = Math.max(a.length, b.length)
  const out: Poly = new Array(n)
  for (let i = 0; i < n; i++) out[i] = Fr.add(frOf(a[i] ?? 0n), frOf(b[i] ?? 0n))
  return out
}

/** a - b */
export function polySub(a: readonly bigint[], b: readonly bigint[]): Poly {
  const n = Math.max(a.length, b.length)
  const out: Poly = new Array(n)
  for (let i = 0; i < n; i++) out[i] = Fr.sub(frOf(a[i] ?? 0n), frOf(b[i] ?? 0n))
  return out
}

/** k * p */
export function polyScale(c: readonly bigint[], k: bigint): Poly {
  const s = frOf(k)
  return c.map((v) => Fr.mul(frOf(v), s))
}

/** a * b, schoolbook. Degrees here are tiny; there is no reason for anything else. */
export function polyMul(a: readonly bigint[], b: readonly bigint[]): Poly {
  if (a.length === 0 || b.length === 0) return [0n]
  const out: Poly = new Array(a.length + b.length - 1).fill(0n)
  for (let i = 0; i < a.length; i++) {
    const ai = frOf(a[i])
    if (Fr.is0(ai)) continue
    for (let j = 0; j < b.length; j++) out[i + j] = Fr.add(out[i + j], Fr.mul(ai, frOf(b[j])))
  }
  return out
}

/** X^k * p — the shift used by the KZG degree-bound check. */
export function polyShift(c: readonly bigint[], k: number): Poly {
  if (k < 0) throw new RangeError('shift must be non-negative')
  return [...new Array<bigint>(k).fill(0n), ...c.map(frOf)]
}

/** Z_S(X) = prod over s in S of (X - s). Vanishes exactly on S. */
export function vanishingPoly(points: readonly bigint[]): Poly {
  let z: Poly = [1n]
  for (const s of points) z = polyMul(z, [Fr.neg(frOf(s)), 1n])
  return z
}

/**
 * Lagrange interpolation through (x_i, y_i). Returns the unique polynomial of
 * degree <= n-1 hitting every point. Throws on a repeated x.
 */
export function interpolate(xs: readonly bigint[], ys: readonly bigint[]): Poly {
  if (xs.length !== ys.length) throw new Error('interpolate: length mismatch')
  const n = xs.length
  const seen = new Set<string>()
  for (const x of xs) {
    const k = frOf(x).toString(16)
    if (seen.has(k)) throw new Error('interpolate: duplicate x coordinate')
    seen.add(k)
  }
  let acc: Poly = [0n]
  for (let i = 0; i < n; i++) {
    let basis: Poly = [1n]
    let denom = 1n
    for (let j = 0; j < n; j++) {
      if (i === j) continue
      basis = polyMul(basis, [Fr.neg(frOf(xs[j])), 1n])
      denom = Fr.mul(denom, Fr.sub(frOf(xs[i]), frOf(xs[j])))
    }
    acc = polyAdd(acc, polyScale(basis, Fr.mul(frOf(ys[i]), Fr.inv(denom))))
  }
  return polyTrim(acc)
}

/** One row of the synthetic-division tableau, kept so the UI can step it. */
export interface DivisionStep {
  /** Index of the coefficient of the dividend being consumed, high to low. */
  readonly index: number
  /** The dividend's coefficient at `index` (this is a_i of p(X) - y). */
  readonly coefficient: bigint
  /** The value carried down from the previous step, before multiplying by z. */
  readonly carryIn: bigint
  /** carryIn * z — what gets added to `coefficient`. */
  readonly product: bigint
  /** coefficient + carryIn*z. For index >= 1 this is a quotient coefficient. */
  readonly carryOut: bigint
  /** True for the final row, whose carryOut IS the remainder. */
  readonly isRemainderRow: boolean
}

export interface DivisionResult {
  /** q(X) with (p(X) - y) = q(X)(X - z) + remainder. Low degree first. */
  readonly quotient: Poly
  /** The remainder. It is p(z) - y, so it is zero exactly when y = p(z). */
  readonly remainder: bigint
  /** Every row of the tableau, in the order the algorithm produces them. */
  readonly steps: readonly DivisionStep[]
}

/**
 * Divide (p(X) - y) by the linear factor (X - z) using synthetic division.
 *
 * This is the load-bearing fact of every KZG opening, and it is a fact about
 * polynomials, not about elliptic curves: the remainder of dividing p(X) - y
 * by (X - z) is exactly p(z) - y. So (X - z) divides p(X) - y with NO
 * remainder precisely when y = p(z), and in that case the quotient q(X) is a
 * genuine polynomial that can be committed to. If y is wrong there is no such
 * polynomial to commit to at all - the prover is not merely unable to convince
 * the verifier, there is nothing for them to hold.
 *
 * The recurrence, running from the top coefficient down:
 *   b_{n-1} = a_n
 *   b_{i-1} = a_i + z * b_i
 * with the last value being the remainder.
 */
export function divideByLinear(p: readonly bigint[], z: bigint, y: bigint): DivisionResult {
  const zz = frOf(z)
  const a = p.map(frOf)
  if (a.length === 0) a.push(0n)
  // The dividend is p(X) - y, which only changes the constant term.
  a[0] = Fr.sub(a[0], frOf(y))

  const n = a.length
  const quotient: Poly = new Array(Math.max(n - 1, 1)).fill(0n)
  const steps: DivisionStep[] = []

  let carry = 0n
  for (let i = n - 1; i >= 0; i--) {
    const product = Fr.mul(carry, zz)
    const carryOut = Fr.add(a[i], product)
    steps.push({
      index: i,
      coefficient: a[i],
      carryIn: carry,
      product,
      carryOut,
      isRemainderRow: i === 0,
    })
    if (i >= 1) quotient[i - 1] = carryOut
    carry = carryOut
  }

  return { quotient: quotient.length ? quotient : [0n], remainder: carry, steps }
}

/**
 * Evaluate p on every point of a domain. Naive O(n*m) Horner - the domains on
 * this page are at most a few hundred points, and a hand-written NTT would be
 * one more thing to get wrong for no visible benefit.
 */
export function polyEvalDomain(c: readonly bigint[], domain: readonly bigint[]): bigint[] {
  return domain.map((x) => polyEval(c, x))
}

/** Serialised size of a polynomial in coefficient form: 32 bytes per coefficient. */
export function polyByteLength(c: readonly bigint[]): number {
  return c.length * 32
}
