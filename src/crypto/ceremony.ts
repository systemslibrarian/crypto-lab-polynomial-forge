/**
 * Powers of tau - a multi-party SRS ceremony, and the transcript that is
 * supposed to make it trustworthy.
 *
 * THE SHAPE. Start from a public, trivial SRS: [1]1, [1]1, [1]1, ... which is
 * the SRS for tau = 1 and secures nothing. Participant i draws a fresh random
 * factor r_i and RESCALES every power:
 *
 *     new[j] = r_i^j * old[j]
 *
 * After N participants the SRS is the one for tau = r_1 * r_2 * ... * r_N. No
 * participant ever saw tau, and none of them could have computed it - each one
 * knows exactly one factor of a product they only ever handled in the exponent.
 *
 * WHAT THE TRANSCRIPT PROVES. Two things, and both are real pairing checks that
 * run in this file:
 *
 *   1. Each contribution is WELL-FORMED - the participant really did multiply
 *      every power by the same single scalar, and they know that scalar. The
 *      proof of knowledge is the Bowe-Gabizon-Miers construction used by the
 *      real powers-of-tau ceremonies: publish s, s_x = [r]s in G1 and a
 *      challenge-derived pair h, h_x = [r]h in G2, then check
 *          e(s, h_x) == e(s_x, h)          (the same r on both sides)
 *          e(new_tau1, h) == e(old_tau1, h_x)   (that r is the update factor)
 *
 *   2. The final SRS is a genuine GEOMETRIC SERIES in some tau:
 *          e([tau^j]1, [1]2) == e([tau^(j-1)]1, [tau]2)   for every j >= 1
 *          e([tau^j]1, [1]2) == e([1]1, [tau^j]2)         G1 and G2 agree
 *
 * WHAT THE TRANSCRIPT DOES NOT PROVE. That anybody deleted anything. There is
 * no check here - and no check possible - that r_i was erased, because erasure
 * leaves no evidence. NEG-2 on this page is exactly that gap, and Act 4 walks a
 * ceremony where every check above passes and every participant kept their
 * factor.
 *
 * NOT PRODUCTION. Real ceremonies run over months with air-gapped machines,
 * published attestations, and randomness beacons. Here every participant is a
 * function call in one browser tab. What is faithful is the algebra and the
 * checks; what is not is any claim about who actually held what.
 */
import { Fr, frOf, frRandom, frToBytes } from './fr.js'
import {
  G1,
  G2,
  type G1Point,
  type G2Point,
  g1Mul,
  g2Mul,
  pairingEqual,
  bytesToHex,
} from './bls.js'
import { srsDigest, type Srs } from './kzg.js'
import { bls12_381 } from '@noble/curves/bls12-381.js'
import { sha256 } from '@noble/hashes/sha2.js'

/** Domain separation tag for the ceremony's challenge points in G2. */
export const CEREMONY_DST = 'CRYPTO-LAB-POLYNOMIAL-FORGE-POT-V1_XMD:SHA-256_SSWU_RO_'

/** The public record one participant leaves behind. */
export interface Contribution {
  /** 1-based position in the ceremony. */
  readonly index: number
  readonly name: string
  /** s in G1, a random point the participant chose. */
  readonly s: G1Point
  /** [r]s in G1. */
  readonly sx: G1Point
  /** h in G2, derived by hash-to-curve from the running transcript and (s, sx). */
  readonly h: G2Point
  /** [r]h in G2. */
  readonly hx: G2Point
  /** The running SRS after this contribution: g1Powers[1] is the new [tau]1. */
  readonly g1Powers: readonly G1Point[]
  readonly g2Powers: readonly G2Point[]
  /** Digest of the transcript up to and including this contribution. */
  readonly transcriptHash: string
}

/**
 * The secret half.
 *
 * `factor` is what the participant is supposed to destroy. In HONEST mode this
 * page destroys it for real - the field is overwritten with 0n and the original
 * value is never stored anywhere else, so the running application genuinely
 * cannot reconstruct tau afterwards. In TOXIC mode it is kept, which is the
 * only difference between the two worlds and, crucially, the only difference
 * the transcript cannot see.
 */
export interface RetainedFactor {
  readonly index: number
  readonly name: string
  /** 0n once erased. */
  factor: bigint
  erased: boolean
}

export interface Ceremony {
  readonly maxDegree: number
  readonly contributions: readonly Contribution[]
  /** One entry per participant; `erased` says whether this world kept the factor. */
  readonly retained: readonly RetainedFactor[]
  readonly srs: Srs
  /** True when every participant erased. */
  readonly allErased: boolean
}

/** A running SRS: matched G1 and G2 power vectors. */
export interface PowerPair {
  readonly g1Powers: readonly G1Point[]
  readonly g2Powers: readonly G2Point[]
}

/** The SRS everybody starts from: tau = 1, and therefore worth nothing on its own. */
export function initialPowers(maxDegree: number): PowerPair {
  const g1Powers: G1Point[] = []
  const g2Powers: G2Point[] = []
  for (let i = 0; i <= maxDegree; i++) {
    g1Powers.push(G1.BASE)
    g2Powers.push(G2.BASE)
  }
  return { g1Powers, g2Powers }
}

function hashPoints(prev: string, s: G1Point, sx: G1Point): Uint8Array {
  const enc = new TextEncoder()
  const parts = [enc.encode(prev), s.toBytes(), sx.toBytes()]
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
 * Run one participant's contribution.
 *
 * `mode` decides whether the factor is erased afterwards. It changes nothing
 * about the public record - which is the point.
 */
export function contribute(
  previous: PowerPair,
  index: number,
  name: string,
  previousTranscriptHash: string,
  mode: 'erase' | 'retain',
  factorOverride?: bigint,
): { contribution: Contribution; retained: RetainedFactor } {
  // A zero factor would collapse the SRS; a one factor would contribute nothing.
  let r = factorOverride === undefined ? frRandom() : frOf(factorOverride)
  while (Fr.is0(r) || r === 1n) r = frRandom()

  // Proof of knowledge, Bowe-Gabizon-Miers. s is a random G1 point (a random
  // multiple of the generator is enough: the verifier never needs its dlog).
  const s = g1Mul(G1.BASE, frRandom())
  const sx = g1Mul(s, r)
  const challenge = hashPoints(previousTranscriptHash, s, sx)
  const h = bls12_381.G2.hashToCurve(challenge, { DST: CEREMONY_DST }) as unknown as G2Point
  const hx = g2Mul(h, r)

  // Rescale every power: new[j] = r^j * old[j].
  const g1Powers: G1Point[] = []
  const g2Powers: G2Point[] = []
  let rj = 1n
  for (let j = 0; j < previous.g1Powers.length; j++) {
    g1Powers.push(g1Mul(previous.g1Powers[j], rj))
    g2Powers.push(g2Mul(previous.g2Powers[j], rj))
    rj = Fr.mul(rj, r)
  }

  const transcriptHash = bytesToHex(
    sha256(concatBytes([hashPoints(previousTranscriptHash, s, sx), g1Powers[1].toBytes(), g2Powers[1].toBytes()])),
  )

  const contribution: Contribution = { index, name, s, sx, h, hx, g1Powers, g2Powers, transcriptHash }

  const retained: RetainedFactor =
    mode === 'erase'
      ? { index, name, factor: 0n, erased: true }
      : { index, name, factor: r, erased: false }

  // In erase mode the local `r` goes out of scope here and is not referenced by
  // anything returned. That is as close to a real erasure as a garbage-collected
  // runtime allows, and it is enough that the running application cannot
  // reconstruct tau - which is what Act 4 demonstrates by trying.
  return { contribution, retained }
}

function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
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

export interface CeremonyOptions {
  readonly maxDegree: number
  readonly participants: readonly { readonly name: string; readonly mode: 'erase' | 'retain' }[]
}

/** Run a whole ceremony. */
export function runCeremony(options: CeremonyOptions): Ceremony {
  const { maxDegree, participants } = options
  if (maxDegree < 1) throw new RangeError('a ceremony needs at least [tau^0] and [tau^1]')
  if (participants.length === 0) throw new RangeError('a ceremony needs at least one participant')

  let current: PowerPair = initialPowers(maxDegree)
  let hash = 'crypto-lab-polynomial-forge/powers-of-tau/genesis'
  const contributions: Contribution[] = []
  const retained: RetainedFactor[] = []

  participants.forEach((p, i) => {
    const step = contribute(current, i + 1, p.name, hash, p.mode)
    contributions.push(step.contribution)
    retained.push(step.retained)
    current = { g1Powers: step.contribution.g1Powers, g2Powers: step.contribution.g2Powers }
    hash = step.contribution.transcriptHash
  })

  const srs: Srs = {
    maxDegree,
    g1Powers: current.g1Powers,
    g2Powers: current.g2Powers,
    digest: srsDigest(current.g1Powers, current.g2Powers),
  }

  return {
    maxDegree,
    contributions,
    retained,
    srs,
    allErased: retained.every((r) => r.erased),
  }
}

/** One line of the transcript audit. */
export interface CheckRow {
  readonly label: string
  readonly equation: string
  readonly ok: boolean
  readonly detail: string
}

export interface TranscriptAudit {
  readonly rows: readonly CheckRow[]
  readonly ok: boolean
  /**
   * Always true, whatever the outcome: the audit inspects public points only,
   * and there is no public evidence of erasure to inspect.
   */
  readonly erasureIsUnobservable: true
}

/**
 * Verify a ceremony transcript exactly as a real auditor would: from the public
 * record alone, with no access to any participant's factor.
 *
 * Run this on an honest ceremony and on a fully dishonest one and the output is
 * identical. That is not a bug in the audit; it is the theorem.
 */
export function auditTranscript(ceremony: Ceremony): TranscriptAudit {
  const rows: CheckRow[] = []
  const { contributions, maxDegree } = ceremony

  // A transcript with no contributions is not an honest ceremony with nothing
  // to check - it is the trivial SRS for tau = 1, where every "power" is the
  // generator and the trapdoor is public. Refuse it explicitly rather than
  // returning a vacuously green audit over an empty row list.
  if (contributions.length === 0) {
    return {
      rows: [
        {
          label: 'transcript: at least one contribution',
          equation: 'contributions.length >= 1',
          ok: false,
          detail:
            'an empty transcript is the SRS for tau = 1, whose trapdoor everybody knows; there is nothing here to audit',
        },
      ],
      ok: false,
      erasureIsUnobservable: true,
    }
  }

  let prev: PowerPair = initialPowers(maxDegree)
  let prevHash = 'crypto-lab-polynomial-forge/powers-of-tau/genesis'

  for (const c of contributions) {
    // 0. Every point in this contribution is a valid, prime-order, non-identity
    //    point. Skipping this is how an all-identity SRS passes: e(0, Q) is the
    //    identity of G_T, so a series check over identity points holds
    //    vacuously while the "SRS" secures nothing at all.
    let pointsOk = true
    let pointDetail = 'every published point is a valid, non-identity, prime-order point'
    try {
      for (const P of [c.s, c.sx, ...c.g1Powers]) {
        if (P.is0()) throw new Error('a G1 point is the identity')
        P.assertValidity()
      }
      for (const P of [c.h, c.hx, ...c.g2Powers]) {
        if (P.is0()) throw new Error('a G2 point is the identity')
        P.assertValidity()
      }
    } catch (err) {
      pointsOk = false
      pointDetail = err instanceof Error ? err.message : String(err)
    }
    rows.push({
      label: `#${c.index} ${c.name}: the points are real`,
      equation: 'on-curve, prime-order, and never the identity',
      ok: pointsOk,
      detail: pointDetail,
    })

    // 1. The challenge point really is derived from the transcript so far.
    const expectedChallenge = hashPoints(prevHash, c.s, c.sx)
    const expectedH = bls12_381.G2.hashToCurve(expectedChallenge, { DST: CEREMONY_DST }) as unknown as G2Point
    const hBinds = expectedH.equals(c.h)
    rows.push({
      label: `#${c.index} ${c.name}: challenge binds to the transcript`,
      equation: 'h = HashToG2(H(transcript || s || [r]s))',
      ok: hBinds,
      detail: hBinds
        ? 'the challenge point was derived from the record, so the proof below cannot have been prepared in advance'
        : 'the published challenge point does not match the transcript',
    })

    // 2. Proof of knowledge: the same r relates (s, sx) and (h, hx).
    const pokOk = pairingEqual(c.s, c.hx, c.sx, c.h)
    rows.push({
      label: `#${c.index} ${c.name}: knows the factor`,
      equation: 'e(s, [r]h) = e([r]s, h)',
      ok: pokOk,
      detail: pokOk
        ? 'one and the same scalar relates both published pairs'
        : 'the two published pairs are not related by a common scalar',
    })

    // 3. That same r is the factor actually applied to the SRS.
    const linkOk = pairingEqual(c.g1Powers[1], c.h, prev.g1Powers[1], c.hx)
    rows.push({
      label: `#${c.index} ${c.name}: applied that factor to the SRS`,
      equation: 'e([tau_new]1, h) = e([tau_old]1, [r]h)',
      ok: linkOk,
      detail: linkOk
        ? 'the new [tau]1 is the old one scaled by exactly the proved factor'
        : 'the SRS was not updated by the factor the participant proved knowledge of',
    })

    // 4. G1 and G2 were updated consistently.
    const crossOk = pairingEqual(c.g1Powers[1], G2.BASE, G1.BASE, c.g2Powers[1])
    rows.push({
      label: `#${c.index} ${c.name}: G1 and G2 agree on tau`,
      equation: 'e([tau]1, [1]2) = e([1]1, [tau]2)',
      ok: crossOk,
      detail: crossOk ? 'both groups carry the same tau' : 'the G1 and G2 halves disagree',
    })

    // 5. The declared transcript hash is RECOMPUTED rather than believed. The
    //    next contribution's challenge is derived from it, so a contributor who
    //    could declare an arbitrary hash could steer the challenge their
    //    successor is bound to.
    const expectedHash = bytesToHex(
      sha256(concatBytes([expectedChallenge, c.g1Powers[1].toBytes(), c.g2Powers[1].toBytes()])),
    )
    const hashOk = expectedHash === c.transcriptHash
    rows.push({
      label: `#${c.index} ${c.name}: the transcript hash is the one the record implies`,
      equation: 'H(challenge || [tau]1 || [tau]2)',
      ok: hashOk,
      detail: hashOk
        ? 'recomputed from the published points, not taken on trust'
        : 'the declared hash does not match the published points',
    })

    prev = { g1Powers: c.g1Powers, g2Powers: c.g2Powers }
    prevHash = c.transcriptHash
  }

  // 6. The SRS being audited IS the output of the last contribution. Without
  //    this every check above can pass over a contribution chain that has
  //    nothing to do with the reference string actually being used - which is
  //    the cheapest possible substitution attack on an audit.
  const last = contributions[contributions.length - 1]
  const srsMatchesChain =
    ceremony.srs.g1Powers.length === last.g1Powers.length &&
    ceremony.srs.g2Powers.length === last.g2Powers.length &&
    ceremony.srs.g1Powers.every((P, i) => P.equals(last.g1Powers[i])) &&
    ceremony.srs.g2Powers.every((P, i) => P.equals(last.g2Powers[i]))
  rows.push({
    label: 'final SRS: it is the output of the last contribution',
    equation: 'srs == contribution[n].powers, point for point',
    ok: srsMatchesChain,
    detail: srsMatchesChain
      ? 'the reference string in use is the one the chain above produced'
      : 'the reference string does not match the last contribution - the chain audits something else',
  })

  // 7. The series starts where it must: [tau^0] is the generator in both
  //    groups. An SRS whose zeroth power is anything else is not powers of tau.
  const basesOk =
    ceremony.srs.g1Powers[0].equals(G1.BASE) && ceremony.srs.g2Powers[0].equals(G2.BASE)
  rows.push({
    label: 'final SRS: the series starts at the generators',
    equation: '[tau^0]1 = g1 and [tau^0]2 = g2',
    ok: basesOk,
    detail: basesOk
      ? 'tau^0 = 1, so the zeroth power must be the generator itself'
      : 'the zeroth power is not the generator, so these are not powers of anything',
  })

  // 5. The finished SRS is a geometric series: consecutive powers line up.
  const { srs } = ceremony
  let seriesOk = true
  let firstBad = -1
  for (let j = 1; j <= maxDegree; j++) {
    if (!pairingEqual(srs.g1Powers[j], G2.BASE, srs.g1Powers[j - 1], srs.g2Powers[1])) {
      seriesOk = false
      firstBad = j
      break
    }
  }
  rows.push({
    label: 'final SRS: the powers are a geometric series',
    equation: 'e([tau^j]1, [1]2) = e([tau^(j-1)]1, [tau]2) for every j',
    ok: seriesOk,
    detail: seriesOk
      ? `all ${maxDegree} consecutive-power checks pass, so the SRS really is powers of one tau`
      : `power ${firstBad} does not follow from power ${firstBad - 1}`,
  })

  let mirrorOk = true
  let firstBadMirror = -1
  for (let j = 1; j <= maxDegree; j++) {
    if (!pairingEqual(srs.g1Powers[j], G2.BASE, G1.BASE, srs.g2Powers[j])) {
      mirrorOk = false
      firstBadMirror = j
      break
    }
  }
  rows.push({
    label: 'final SRS: the G2 powers mirror the G1 powers',
    equation: 'e([tau^j]1, [1]2) = e([1]1, [tau^j]2) for every j',
    ok: mirrorOk,
    detail: mirrorOk
      ? 'the G2 half is the same tau, which is what the degree-bound check will rely on'
      : `G2 power ${firstBadMirror} disagrees with the G1 half`,
  })

  return { rows, ok: rows.every((r) => r.ok), erasureIsUnobservable: true }
}

/**
 * Multiply the retained factors back together.
 *
 * Returns null when even one participant erased - not because the code declines
 * to, but because the value genuinely is not there. That asymmetry is the
 * security property: the ceremony survives as long as ONE contribution was
 * fresh and destroyed.
 */
export function recoverTau(ceremony: Ceremony): bigint | null {
  if (ceremony.retained.some((r) => r.erased)) return null
  let tau = 1n
  for (const r of ceremony.retained) tau = Fr.mul(tau, r.factor)
  return tau
}

/**
 * Confirm a recovered tau really is the ceremony's trapdoor, by rebuilding
 * [tau]1 from scratch and comparing with the SRS the transcript produced.
 */
export function tauMatchesSrs(ceremony: Ceremony, tau: bigint): boolean {
  return g1Mul(G1.BASE, tau).equals(ceremony.srs.g1Powers[1])
}

/** Byte length of the public transcript, for the honest-scoping copy. */
export function transcriptByteLength(ceremony: Ceremony): number {
  const perContribution = 48 * 2 + 96 * 2 + 32 // s, sx, h, hx, hash
  const srsBytes = (ceremony.maxDegree + 1) * (48 + 96)
  return ceremony.contributions.length * perContribution + srsBytes
}

export { frToBytes }
