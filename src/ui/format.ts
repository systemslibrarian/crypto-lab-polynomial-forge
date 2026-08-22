/** Display formatting. Nothing here changes a value; it only shortens one. */

const NBSP = ' '

/** Full hex, with a thin space every 8 characters so long strings stay scannable. */
export function groupHex(hex: string, group = 8): string {
  const parts: string[] = []
  for (let i = 0; i < hex.length; i += group) parts.push(hex.slice(i, i + group))
  return parts.join(NBSP)
}

/** head...tail, for a value whose exact digits are not the point. */
export function ellipsize(hex: string, head = 10, tail = 8): string {
  if (hex.length <= head + tail + 3) return hex
  return `${hex.slice(0, head)}…${hex.slice(-tail)}`
}

export function bytes(n: number): string {
  if (n < 1024) return `${n} bytes`
  return `${(n / 1024).toFixed(1)} KiB (${n.toLocaleString('en-US')} bytes)`
}

export function ms(x: number): string {
  if (x >= 100) return `${x.toFixed(0)} ms`
  if (x >= 10) return `${x.toFixed(1)} ms`
  return `${x.toFixed(2)} ms`
}

/** A field element, short enough to read. Small values print as integers. */
export function scalar(x: bigint): string {
  if (x < 1_000_000_000n) return x.toString(10)
  return `0x${ellipsize(x.toString(16).padStart(64, '0'), 8, 6)}`
}

/** A field element in full, for the places where the exact value matters. */
export function scalarFull(x: bigint): string {
  return x.toString(10)
}

/** Render a coefficient vector as a polynomial. */
export function polyText(coefficients: readonly bigint[]): string {
  const terms: string[] = []
  for (let i = coefficients.length - 1; i >= 0; i--) {
    const c = coefficients[i]
    if (c === 0n) continue
    const coef = i === 0 || c !== 1n ? scalar(c) : ''
    const variable = i === 0 ? '' : i === 1 ? 'X' : `X^${i}`
    terms.push(`${coef}${coef && variable ? '·' : ''}${variable}`)
  }
  return terms.length ? terms.join(' + ') : '0'
}

export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`
}
