/**
 * The verdict box.
 *
 * Colour tracks SYSTEM INTEGRITY, not the verifier's raw return value. A
 * verifier that correctly rejects a false claim is the system working, and a
 * verifier that accepts a forgery is the system broken - so "accepted" is not
 * automatically green and "rejected" is not automatically red.
 *
 *   ok        the statement is true and the verifier accepted it
 *   rejected  the verifier refused, and refusing was right. Names the code.
 *   alarm     the verifier accepted something false, or a check that mattered
 *             was never run. This is the only red state on the page.
 *   idle      nothing has been computed yet, or a previous verdict was retired
 *             because its inputs changed
 *
 * Every state paints a glyph, a word and a colour together, so none of it is
 * carried by hue alone (WCAG 1.4.1). The glyph is aria-hidden; the word is the
 * accessible name of the state.
 */
import { el, appendRich } from './dom.js'

export type VerdictKind = 'ok' | 'rejected' | 'alarm' | 'idle'

const GLYPH: Record<VerdictKind, string> = {
  ok: '[+]',
  rejected: '[x]',
  alarm: '[!]',
  idle: '[ ]',
}

const CLASS: Record<VerdictKind, string> = {
  ok: 'is-ok',
  rejected: 'is-bad',
  alarm: 'is-alarm',
  idle: 'is-idle',
}

export interface VerdictView {
  readonly root: HTMLElement
  set(kind: VerdictKind, label: string, text: string): void
  retire(reason: string): void
}

/**
 * `role="status"` + `aria-live="polite"` so a screen-reader user hears the
 * outcome of a button they pressed without having to go looking for it.
 */
export function verdictBox(id: string, initial?: { kind: VerdictKind; label: string; text: string }): VerdictView {
  const icon = el('span', { class: 'verdict-icon', 'aria-hidden': 'true', text: GLYPH.idle })
  const label = el('span', { class: 'verdict-label', text: 'NOT RUN' })
  const text = el('p', { class: 'verdict-text' })
  const root = el(
    'div',
    { class: `verdict ${CLASS.idle}`, id, role: 'status', 'aria-live': 'polite' },
    [icon, el('div', { class: 'verdict-body' }, [label, text])],
  )

  const view: VerdictView = {
    root,
    set(kind, labelText, bodyText) {
      root.className = `verdict ${CLASS[kind]}`
      root.dataset.kind = kind
      icon.textContent = GLYPH[kind]
      label.textContent = labelText
      text.textContent = ''
      appendRich(text, bodyText)
    },
    retire(reason) {
      // Retirement is the REMOVAL of a result, not the arrival of one, and a
      // single keystroke can retire four verdicts at once. Announcing all of
      // them would bury the reader in polite interruptions about things that
      // just stopped being true. The live region is silenced for the swap and
      // restored afterwards, so the next real result still announces.
      root.setAttribute('aria-live', 'off')
      view.set('idle', 'RETIRED', reason)
      root.dataset.kind = 'idle'
      root.setAttribute('aria-live', 'polite')
    },
  }

  if (initial) view.set(initial.kind, initial.label, initial.text)
  else {
    root.dataset.kind = 'idle'
    text.textContent = 'Nothing has been computed yet.'
  }
  return view
}

/** The standing DEGREE_UNENFORCED notice. Not a failure - a statement of configuration. */
export function bannerBox(id: string, label: string, body: string): { root: HTMLElement; show(on: boolean): void } {
  const text = el('p')
  appendRich(text, body)
  const root = el('div', { class: 'banner', id, role: 'status', 'aria-live': 'polite' }, [
    el('span', { class: 'verdict-icon', 'aria-hidden': 'true', text: '[!]' }),
    el('div', { class: 'verdict-body' }, [el('span', { class: 'banner-label', text: label }), text]),
  ])
  return {
    root,
    show(on: boolean) {
      root.style.display = on ? 'flex' : 'none'
      root.dataset.shown = on ? 'true' : 'false'
    },
  }
}
