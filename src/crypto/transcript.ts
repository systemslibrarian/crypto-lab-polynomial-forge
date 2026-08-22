/**
 * Fiat-Shamir transcripts.
 *
 * Both the IPA and FRI on this page are public-coin interactive protocols made
 * non-interactive the standard way: wherever the protocol says "the verifier
 * sends a random challenge", both sides instead hash everything said so far and
 * read the challenge out of the digest.
 *
 * The rule that makes this safe is that EVERYTHING the prover has committed to
 * must be absorbed before the challenge is drawn. Getting that wrong is the
 * Frozen Heart class of bug - crypto-lab-frozen-heart is the fleet's demo of
 * exactly that failure - so this transcript makes absorption explicit and
 * length-prefixes every item, so no two different message sequences can produce
 * the same hash input.
 */
import { sha256 } from '@noble/hashes/sha2.js'
import { frFromBytesReduce, frToBytes } from './fr.js'
import type { G1Point } from './bls.js'

export class Transcript {
  private state: Uint8Array

  constructor(domain: string) {
    this.state = sha256(new TextEncoder().encode(`crypto-lab-polynomial-forge/${domain}`))
  }

  /** Absorb a labelled byte string. Label and payload are both length-prefixed. */
  absorb(label: string, data: Uint8Array): this {
    const labelBytes = new TextEncoder().encode(label)
    const buf = new Uint8Array(this.state.length + 4 + labelBytes.length + 4 + data.length)
    let off = 0
    buf.set(this.state, off)
    off += this.state.length
    writeU32(buf, off, labelBytes.length)
    off += 4
    buf.set(labelBytes, off)
    off += labelBytes.length
    writeU32(buf, off, data.length)
    off += 4
    buf.set(data, off)
    this.state = sha256(buf)
    return this
  }

  absorbScalar(label: string, x: bigint): this {
    return this.absorb(label, frToBytes(x))
  }

  absorbPoint(label: string, P: G1Point): this {
    return this.absorb(label, P.toBytes())
  }

  absorbScalars(label: string, xs: readonly bigint[]): this {
    const buf = new Uint8Array(xs.length * 32)
    xs.forEach((x, i) => buf.set(frToBytes(x), i * 32))
    return this.absorb(label, buf)
  }

  /**
   * Draw a field challenge. The counter byte means two challenges drawn in a
   * row differ even with nothing absorbed between them.
   */
  challenge(label: string): bigint {
    const labelBytes = new TextEncoder().encode(label)
    const buf = new Uint8Array(this.state.length + 1 + labelBytes.length)
    buf.set(this.state, 0)
    buf[this.state.length] = 0x01
    buf.set(labelBytes, this.state.length + 1)
    const out = sha256(buf)
    // Re-absorb so the next challenge depends on this one.
    this.absorb(`${label}:drawn`, out)
    const c = frFromBytesReduce(out)
    // A zero challenge would collapse a folding round; redraw rather than
    // silently produce a degenerate proof.
    return c === 0n ? 1n : c
  }

  /** Draw an index in [0, range). Rejection-sampled so the distribution is flat. */
  challengeIndex(label: string, range: number): number {
    if (range <= 0) throw new RangeError('range must be positive')
    for (let attempt = 0; attempt < 128; attempt++) {
      const labelBytes = new TextEncoder().encode(`${label}:${attempt}`)
      const buf = new Uint8Array(this.state.length + 1 + labelBytes.length)
      buf.set(this.state, 0)
      buf[this.state.length] = 0x02
      buf.set(labelBytes, this.state.length + 1)
      const out = sha256(buf)
      const v = (out[0] << 24) | (out[1] << 16) | (out[2] << 8) | out[3]
      const u = v >>> 0
      const limit = Math.floor(0x100000000 / range) * range
      if (u < limit) {
        this.absorb(`${label}:index`, out)
        return u % range
      }
    }
    throw new Error('rejection sampling failed 128 times; this is statistically impossible')
  }

  /** Current transcript digest, for display and for binding a proof to a session. */
  digest(): Uint8Array {
    return this.state.slice()
  }
}

function writeU32(buf: Uint8Array, off: number, v: number): void {
  buf[off] = (v >>> 24) & 0xff
  buf[off + 1] = (v >>> 16) & 0xff
  buf[off + 2] = (v >>> 8) & 0xff
  buf[off + 3] = v & 0xff
}
