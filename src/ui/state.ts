/**
 * The shared state every act reads from.
 *
 * Two things matter here beyond bookkeeping:
 *
 * RETIREMENT. A verdict on screen is only about the inputs it was computed
 * from. Change the polynomial, the opening point, or the ceremony, and every
 * verdict downstream stops being evidence - so the store bumps a generation
 * counter and each act retires its own verdict, saying so rather than leaving
 * a stale green box under changed inputs.
 *
 * NO-OP GUARD. Re-selecting the same value must NOT retire a fresh verdict.
 * Every setter compares first and returns without notifying when nothing
 * actually changed, so clicking the already-selected option is genuinely inert.
 */
import { Fr, frOf } from '../crypto/fr.js'
import { auditTranscript, runCeremony, type Ceremony, type TranscriptAudit } from '../crypto/ceremony.js'
import { ipaSetup, type IpaSetup } from '../crypto/ipa.js'
import { DEFAULT_FRI_PARAMS } from '../crypto/fri.js'

/** How many coefficients the visitor can edit directly. */
export const EDITABLE_COEFFICIENTS = 8

/** The vector length IPA and FRI are configured for. A power of two. */
export const SCHEME_LENGTH = DEFAULT_FRI_PARAMS.n

export type Mode = 'erase' | 'retain'

export interface Participant {
  readonly name: string
  readonly mode: Mode
}

export const PARTICIPANT_NAMES = ['Ada', 'Grace', 'Katherine', 'Dorothy', 'Annie', 'Evelyn'] as const

export interface AppState {
  /** The working polynomial: EDITABLE_COEFFICIENTS entries, low degree first. */
  coefficients: bigint[]
  /** The opening point. */
  z: bigint
  /** The value the visitor claims p(z) is. Starts equal to the true one. */
  claimedY: bigint
  participants: Participant[]
  srsDegree: number
  ceremony: Ceremony
  audit: TranscriptAudit
  ipa: IpaSetup
  /** Whether the Act 5 verifier enforces its degree bound. */
  enforceDegreeBound: boolean
  /** Bumped whenever anything a verdict depends on changes. */
  generation: number
}

export const DEFAULT_COEFFICIENTS: bigint[] = [3n, 1n, 4n, 1n, 5n, 9n, 2n, 6n]
export const DEFAULT_Z = 7n
export const DEFAULT_SRS_DEGREE = 24
export const SRS_DEGREE_CHOICES = [24, 64, 128] as const

type Listener = (state: AppState, reason: string) => void

const listeners: Listener[] = []

function buildCeremony(participants: readonly Participant[], srsDegree: number): {
  ceremony: Ceremony
  audit: TranscriptAudit
} {
  const ceremony = runCeremony({ maxDegree: srsDegree, participants: participants.map((p) => ({ ...p })) })
  return { ceremony, audit: auditTranscript(ceremony) }
}

const initialParticipants: Participant[] = [
  { name: PARTICIPANT_NAMES[0], mode: 'erase' },
  { name: PARTICIPANT_NAMES[1], mode: 'erase' },
  { name: PARTICIPANT_NAMES[2], mode: 'erase' },
  { name: PARTICIPANT_NAMES[3], mode: 'erase' },
]

const initial = buildCeremony(initialParticipants, DEFAULT_SRS_DEGREE)

export const state: AppState = {
  coefficients: [...DEFAULT_COEFFICIENTS],
  z: DEFAULT_Z,
  claimedY: evaluate(DEFAULT_COEFFICIENTS, DEFAULT_Z),
  participants: initialParticipants,
  srsDegree: DEFAULT_SRS_DEGREE,
  ceremony: initial.ceremony,
  audit: initial.audit,
  ipa: ipaSetup(SCHEME_LENGTH),
  enforceDegreeBound: false,
  generation: 0,
}

function evaluate(c: readonly bigint[], x: bigint): bigint {
  let acc = 0n
  for (let i = c.length - 1; i >= 0; i--) acc = Fr.add(Fr.mul(acc, x), frOf(c[i]))
  return acc
}

export function trueY(): bigint {
  return evaluate(state.coefficients, state.z)
}

export function subscribe(fn: Listener): void {
  listeners.push(fn)
}

function notify(reason: string): void {
  state.generation += 1
  for (const fn of listeners) fn(state, reason)
}

/** Returns true when the value actually changed. */
export function setCoefficient(index: number, value: bigint): boolean {
  const v = frOf(value)
  if (index < 0 || index >= state.coefficients.length) return false
  if (state.coefficients[index] === v) return false
  state.coefficients = state.coefficients.map((c, i) => (i === index ? v : c))
  state.claimedY = trueY()
  notify('the polynomial changed')
  return true
}

export function setZ(value: bigint): boolean {
  const v = frOf(value)
  if (state.z === v) return false
  state.z = v
  state.claimedY = trueY()
  notify('the opening point changed')
  return true
}

export function setClaimedY(value: bigint): boolean {
  const v = frOf(value)
  if (state.claimedY === v) return false
  state.claimedY = v
  notify('the claimed value changed')
  return true
}

export function setParticipantMode(index: number, mode: Mode): boolean {
  if (index < 0 || index >= state.participants.length) return false
  if (state.participants[index].mode === mode) return false
  state.participants = state.participants.map((p, i) => (i === index ? { ...p, mode } : p))
  rebuildCeremony('a participant changed what they did with their factor')
  return true
}

export function setAllModes(mode: Mode): boolean {
  if (state.participants.every((p) => p.mode === mode)) return false
  state.participants = state.participants.map((p) => ({ ...p, mode }))
  rebuildCeremony(
    mode === 'retain'
      ? 'every participant now retains their factor'
      : 'every participant now erases their factor',
  )
  return true
}

export function setParticipantCount(count: number): boolean {
  const n = Math.max(1, Math.min(PARTICIPANT_NAMES.length, Math.trunc(count)))
  if (n === state.participants.length) return false
  const next: Participant[] = []
  for (let i = 0; i < n; i++) {
    next.push(state.participants[i] ?? { name: PARTICIPANT_NAMES[i], mode: 'erase' })
  }
  state.participants = next
  rebuildCeremony('the number of participants changed')
  return true
}

export function setSrsDegree(degree: number): boolean {
  if (state.srsDegree === degree) return false
  state.srsDegree = degree
  rebuildCeremony('the ceremony was re-run at a different degree')
  return true
}

export function setEnforceDegreeBound(on: boolean): boolean {
  if (state.enforceDegreeBound === on) return false
  state.enforceDegreeBound = on
  notify(on ? 'degree-bound enforcement was switched on' : 'degree-bound enforcement was switched off')
  return true
}

function rebuildCeremony(reason: string): void {
  const built = buildCeremony(state.participants, state.srsDegree)
  state.ceremony = built.ceremony
  state.audit = built.audit
  notify(reason)
}

/** Re-run the ceremony with the current settings, drawing fresh randomness. */
export function rerunCeremony(): void {
  rebuildCeremony('the ceremony was re-run with fresh randomness')
}
