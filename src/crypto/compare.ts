/**
 * The three-way comparison, measured rather than quoted.
 *
 * Every number in the comparison act is produced by running all three schemes
 * on the SAME polynomial at the SAME opening point in the visitor's own
 * browser. Nothing is a remembered figure from a paper, and the timings are
 * whatever this machine does today - which is the honest way to compare, and
 * also why the page says "on this machine, just now" next to them.
 *
 * WHAT THE TIMINGS ARE AND ARE NOT. They are wall-clock milliseconds for this
 * implementation. They are NOT a benchmark of the schemes: production KZG uses
 * batched openings and optimised multi-scalar multiplication, production FRI
 * uses an NTT and a hash tuned for the field, and none of that is here. What
 * survives that caveat is the SHAPE - constant vs logarithmic vs polylogarithmic
 * proof size, and constant vs linear vs polylogarithmic verification - because
 * that is a property of the mathematics rather than of the code.
 */
import { G1_BYTES } from './bls.js'
import { commit, open, verify, KZG_PROOF_BYTES, type Srs } from './kzg.js'
import { ipaCommit, ipaOpen, ipaProofBytes, ipaSetup, ipaVerify, type IpaSetup } from './ipa.js'
import {
  DEFAULT_FRI_PARAMS,
  friCommit,
  friProofBytes,
  friProve,
  friSoundnessBits,
  friVerify,
  type FriParams,
} from './fri.js'
import { MERKLE_DIGEST_BYTES } from './merkle.js'
import { polyEval } from './poly.js'

export type SchemeId = 'kzg' | 'ipa' | 'fri'

export interface SchemeRow {
  readonly id: SchemeId
  readonly name: string
  /** Which family of proof systems uses this commitment layer. */
  readonly usedBy: string
  readonly setup: 'trusted, universal' | 'transparent'
  readonly setupNote: string
  readonly commitmentBytes: number
  readonly proofBytes: number
  /** Asymptotic proof size in the polynomial's degree n. */
  readonly proofSizeOrder: string
  /** Asymptotic verifier cost in n. */
  readonly verifyCostOrder: string
  readonly postQuantum: boolean
  readonly pqNote: string
  readonly commitMs: number
  readonly openMs: number
  readonly verifyMs: number
  readonly verified: boolean
  readonly detail: string
}

export interface ComparisonInput {
  readonly srs: Srs
  readonly coefficients: readonly bigint[]
  readonly z: bigint
  readonly ipa?: IpaSetup
  readonly friParams?: FriParams
  /** How many times to repeat each measurement; the median is reported. */
  readonly repeats?: number
}

function median(xs: number[]): number {
  const s = [...xs].sort((a, b) => a - b)
  const mid = Math.floor(s.length / 2)
  return s.length % 2 === 1 ? s[mid] : (s[mid - 1] + s[mid]) / 2
}

/**
 * Run `fn` once untimed to warm the JIT, then `repeats` times with the clock,
 * and report the median. The median rather than the mean because a single
 * garbage-collection pause in a browser tab otherwise dominates the figure.
 */
function timed<T>(repeats: number, fn: () => T): { value: T; ms: number } {
  let value = fn()
  const samples: number[] = []
  for (let i = 0; i < repeats; i++) {
    const t0 = performance.now()
    value = fn()
    samples.push(performance.now() - t0)
  }
  return { value, ms: median(samples) }
}

/**
 * Run all three on the same polynomial. Returns one row per scheme plus the
 * shared inputs, so the UI can state exactly what was measured.
 */
export function runComparison(input: ComparisonInput): {
  readonly rows: readonly SchemeRow[]
  readonly degree: number
  readonly z: bigint
  readonly y: bigint
  readonly friHeuristicBits: number
  readonly friCaveat: string
} {
  const repeats = input.repeats ?? 3
  const { srs, coefficients, z } = input
  const friParams = input.friParams ?? DEFAULT_FRI_PARAMS
  const ipa = input.ipa ?? ipaSetup(friParams.n)
  const y = polyEval(coefficients, z)

  // --- KZG ---
  const kzgCommit = timed(repeats, () => commit(srs, coefficients))
  const kzgOpen = timed(repeats, () => open(srs, coefficients, z))
  const kzgVerify = timed(repeats, () => verify(srs, kzgCommit.value, z, y, kzgOpen.value))

  // --- IPA ---
  const ipaC = timed(repeats, () => ipaCommit(ipa, coefficients))
  const ipaP = timed(repeats, () => ipaOpen(ipa, coefficients, z))
  const ipaV = timed(repeats, () => ipaVerify(ipa, ipaC.value, z, y, ipaP.value))

  // --- FRI ---
  // Commit first and hand the result to the prover, so the three "commit"
  // columns all mean the same thing and the opening figure does not silently
  // include a second commitment.
  const friC = timed(repeats, () => friCommit(coefficients, friParams))
  const friP = timed(repeats, () => friProve(coefficients, z, friParams, friC.value))
  const friV = timed(repeats, () => friVerify(friC.value.root, z, y, friP.value.proof))

  const soundness = friSoundnessBits(friParams)

  const rows: SchemeRow[] = [
    {
      id: 'kzg',
      name: 'KZG',
      usedBy: 'PLONK-style systems',
      setup: 'trusted, universal',
      setupNote:
        'Needs a structured reference string with a trapdoor nobody may know. Universal: one ceremony serves every circuit up to its degree bound.',
      commitmentBytes: G1_BYTES,
      proofBytes: KZG_PROOF_BYTES,
      proofSizeOrder: 'constant',
      verifyCostOrder: 'constant (one pairing equation)',
      postQuantum: false,
      pqNote: 'Rests on a pairing, so Shor breaks it outright.',
      commitMs: kzgCommit.ms,
      openMs: kzgOpen.ms,
      verifyMs: kzgVerify.ms,
      verified: kzgVerify.value.ok,
      detail: kzgVerify.value.detail,
    },
    {
      id: 'ipa',
      name: 'IPA',
      usedBy: 'Bulletproofs / Halo-style systems',
      setup: 'transparent',
      setupNote:
        'Generators come from hash-to-curve on a public tag. Nothing secret exists, so nothing has to be destroyed.',
      commitmentBytes: G1_BYTES,
      proofBytes: ipaProofBytes(ipa.n),
      proofSizeOrder: 'logarithmic',
      verifyCostOrder: 'linear (an n-sized multi-scalar multiplication)',
      postQuantum: false,
      pqNote: 'Rests on discrete log in G1, so Shor breaks it outright.',
      commitMs: ipaC.ms,
      openMs: ipaP.ms,
      verifyMs: ipaV.ms,
      verified: ipaV.value.ok,
      detail: ipaV.value.detail,
    },
    {
      id: 'fri',
      name: 'FRI',
      usedBy: 'STARK-style systems',
      setup: 'transparent',
      setupNote: 'A hash function and a public evaluation domain. There is no setup to trust.',
      commitmentBytes: MERKLE_DIGEST_BYTES,
      proofBytes: friProofBytes(friP.value.proof),
      proofSizeOrder: 'polylogarithmic',
      verifyCostOrder: 'polylogarithmic',
      postQuantum: true,
      pqNote:
        'Rests only on a hash. Grover halves the effective security of a hash; it does not break the construction the way Shor breaks a discrete log.',
      commitMs: friC.ms,
      openMs: friP.ms,
      verifyMs: friV.ms,
      verified: friV.value.ok,
      detail: friV.value.detail,
    },
  ]

  return {
    rows,
    degree: coefficients.length - 1,
    z,
    y,
    friHeuristicBits: soundness.heuristicBits,
    friCaveat: soundness.caveat,
  }
}

/**
 * Why Groth16 is not a fourth row.
 *
 * Kept as data next to the comparison it belongs to, so the page and the tests
 * are reading the same sentences.
 */
export const GROTH16_CONTRAST = {
  heading: 'Why Groth16 is not on this list',
  claims: [
    {
      label: 'Groth16 has no swappable commitment scheme underneath',
      body: 'Its reference string is built for one specific circuit: the QAP is baked into the setup, and the proof is three group elements verified by one fixed pairing equation. There is no polynomial commitment layer you could take out and replace.',
    },
    {
      label: 'The three schemes here sit under a polynomial IOP',
      body: 'PLONK, Bulletproofs and STARKs are designed in two parts: an information-theoretic protocol about polynomials, and a commitment scheme that makes it non-interactive and succinct. Swap the commitment and you get a different system with the same logic - which is exactly what Halo (IPA) and the STARK family (FRI) do.',
    },
    {
      label: 'That is why Groth16 needs a new ceremony per circuit',
      body: 'A universal SRS like the one on this page is a property of the polynomial-commitment design, not of SNARKs in general. Change the circuit under Groth16 and the structured reference string is worthless; change the circuit over KZG and the same powers of tau still work.',
    },
    {
      label: 'Groth16 proofs are smaller, and that is the trade',
      body: 'Three group elements against PLONK-style transcripts of several hundred bytes. The monolithic design buys size and pays for it in flexibility and in one ceremony per circuit.',
    },
  ],
} as const
