import { describe, expect, it } from 'vitest'
import { Fr, frRandom, frOf } from './fr.js'
import {
  divideByLinear,
  interpolate,
  polyAdd,
  polyByteLength,
  polyDegree,
  polyEval,
  polyEvalDomain,
  polyMul,
  polyScale,
  polyShift,
  polySub,
  polyTrim,
  vanishingPoly,
} from './poly.js'

const P = [3n, 1n, 4n, 1n, 5n, 9n, 2n, 6n] // 3 + X + 4X^2 + ... + 6X^7

describe('polynomials over Fr', () => {
  it('evaluates by Horner and by direct summation identically', () => {
    for (const x of [0n, 1n, 2n, 7n, frRandom()]) {
      // Independent re-derivation: sum c_i * x^i directly rather than Horner.
      let direct = 0n
      let power = 1n
      for (const c of P) {
        direct = Fr.add(direct, Fr.mul(c, power))
        power = Fr.mul(power, frOf(x))
      }
      expect(polyEval(P, x)).toBe(direct)
    }
  })

  it('reports degree, ignoring trailing zeros', () => {
    expect(polyDegree([1n, 2n, 3n])).toBe(2)
    expect(polyDegree([1n, 2n, 0n, 0n])).toBe(1)
    expect(polyDegree([0n])).toBe(-1)
    expect(polyTrim([1n, 0n, 0n])).toEqual([1n])
  })

  it('add / sub / scale / mul agree with evaluation at random points', () => {
    const A = [1n, 2n, 3n]
    const B = [5n, 0n, 0n, 7n]
    for (let i = 0; i < 8; i++) {
      const x = frRandom()
      expect(polyEval(polyAdd(A, B), x)).toBe(Fr.add(polyEval(A, x), polyEval(B, x)))
      expect(polyEval(polySub(A, B), x)).toBe(Fr.sub(polyEval(A, x), polyEval(B, x)))
      expect(polyEval(polyMul(A, B), x)).toBe(Fr.mul(polyEval(A, x), polyEval(B, x)))
      expect(polyEval(polyScale(A, 11n), x)).toBe(Fr.mul(11n, polyEval(A, x)))
    }
  })

  it('shifting by k multiplies by X^k', () => {
    const x = frRandom()
    expect(polyEval(polyShift(P, 5), x)).toBe(Fr.mul(polyEval(P, x), Fr.pow(x, 5n)))
    expect(polyDegree(polyShift(P, 5))).toBe(polyDegree(P) + 5)
  })

  it('the vanishing polynomial is zero exactly on its point set', () => {
    const pts = [2n, 5n, 11n, 13n]
    const z = vanishingPoly(pts)
    expect(polyDegree(z)).toBe(pts.length)
    for (const p of pts) expect(polyEval(z, p)).toBe(0n)
    for (const other of [3n, 7n, 1000n]) expect(polyEval(z, other)).not.toBe(0n)
  })

  it('interpolation recovers a known polynomial', () => {
    const xs = [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n]
    const ys = xs.map((x) => polyEval(P, x))
    const recovered = interpolate(xs, ys)
    expect(recovered.length).toBe(P.length)
    recovered.forEach((c, i) => expect(c).toBe(P[i]))
  })

  it('interpolation refuses a duplicated abscissa', () => {
    expect(() => interpolate([1n, 1n], [2n, 3n])).toThrow(/duplicate/)
  })
})

describe('divideByLinear — the mechanism the whole lab is about', () => {
  it('leaves no remainder exactly when y = p(z)', () => {
    for (const z of [0n, 1n, 2n, 9n, frRandom()]) {
      const y = polyEval(P, z)
      expect(divideByLinear(P, z, y).remainder).toBe(0n)
      expect(divideByLinear(P, z, Fr.add(y, 1n)).remainder).not.toBe(0n)
    }
  })

  it('the remainder is exactly p(z) - y, for every y', () => {
    const z = 13n
    const trueY = polyEval(P, z)
    for (const y of [0n, 1n, trueY, Fr.add(trueY, 42n), frRandom()]) {
      expect(divideByLinear(P, z, y).remainder).toBe(Fr.sub(trueY, y))
    }
  })

  it('quotient * (X - z) + remainder reconstructs p(X) - y', () => {
    const z = 6n
    const y = 99n
    const { quotient, remainder } = divideByLinear(P, z, y)
    const rebuilt = polyAdd(polyMul(quotient, [Fr.neg(z), 1n]), [remainder])
    const expected = polySub(P, [y])
    for (let i = 0; i < Math.max(rebuilt.length, expected.length); i++) {
      expect(frOf(rebuilt[i] ?? 0n)).toBe(frOf(expected[i] ?? 0n))
    }
  })

  it('the quotient has degree exactly one less than p', () => {
    const z = 4n
    const { quotient } = divideByLinear(P, z, polyEval(P, z))
    expect(polyDegree(quotient)).toBe(polyDegree(P) - 1)
  })

  it('every step of the tableau is internally consistent', () => {
    const z = 21n
    const y = polyEval(P, z)
    const { steps, quotient, remainder } = divideByLinear(P, z, y)
    expect(steps.length).toBe(P.length)
    let carry = 0n
    for (const s of steps) {
      expect(s.carryIn).toBe(carry)
      expect(s.product).toBe(Fr.mul(carry, z))
      expect(s.carryOut).toBe(Fr.add(s.coefficient, s.product))
      if (s.index >= 1) expect(quotient[s.index - 1]).toBe(s.carryOut)
      carry = s.carryOut
    }
    expect(steps[steps.length - 1].isRemainderRow).toBe(true)
    expect(steps[steps.length - 1].carryOut).toBe(remainder)
    // The tableau runs high coefficient to low, so the first row carries the
    // leading coefficient untouched and the last row is the constant term -
    // the only one subtracting y can reach.
    expect(steps[0].index).toBe(P.length - 1)
    expect(steps[0].coefficient).toBe(P[P.length - 1])
    expect(steps[steps.length - 1].index).toBe(0)
    expect(steps[steps.length - 1].coefficient).toBe(Fr.sub(P[0], y))
  })

  it('divides a constant polynomial without falling over', () => {
    const { quotient, remainder } = divideByLinear([7n], 3n, 7n)
    expect(remainder).toBe(0n)
    expect(polyDegree(quotient)).toBe(-1)
  })
})

describe('domain evaluation and sizes', () => {
  it('evaluates over a domain pointwise', () => {
    const domain = [1n, 2n, 3n]
    expect(polyEvalDomain(P, domain)).toEqual(domain.map((x) => polyEval(P, x)))
  })

  it('counts 32 bytes per coefficient', () => {
    expect(polyByteLength(P)).toBe(P.length * 32)
  })
})
