/**
 * A button handler that cannot fail silently.
 *
 * Every act on this page computes real cryptography when a control is pressed.
 * If that throws, the honest outcome is not an unchanged panel - it is a page
 * that says it broke. So the error is painted into the act's own verdict box as
 * an alarm AND written to the console, where the accessibility gate's error
 * watcher turns it into a failed run rather than a quietly stale screen.
 */
import type { VerdictView } from './verdict.js'

export function guarded(verdict: VerdictView, fn: () => void): () => void {
  return () => {
    try {
      fn()
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      verdict.set(
        'alarm',
        'THIS PAGE HIT AN ERROR',
        `${message} — that is a bug in this demo, not a result about the cryptography. Nothing below should be read as evidence.`,
      )
      // Deliberate: the gate watches console errors, so a broken act fails CI
      // instead of shipping as a panel that merely never updates.
      console.error('[polynomial-forge]', err)
    }
  }
}
