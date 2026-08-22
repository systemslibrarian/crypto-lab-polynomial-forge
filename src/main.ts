import './style.css'
import { failureCodeCard, heroSection, introCard, scopeCard, scriptureFooter } from './ui/intro.js'
import { actCommit } from './ui/act-commit.js'
import { actOpen } from './ui/act-open.js'
import { actCeremony, actToxic } from './ui/act-ceremony.js'
import { actDegree } from './ui/act-degree.js'
import { actCompare, actGroth16 } from './ui/act-compare.js'
import { el } from './ui/dom.js'

const found = document.querySelector<HTMLDivElement>('#app')
if (!found) throw new Error('App root #app was not found.')
const root: HTMLDivElement = found

/**
 * Everything is built synchronously and mounted in one go.
 *
 * The heavy work - the ceremony and its pairing audit - happens while the
 * modules above initialise, so by the time anything is in the document the page
 * is in its real, final, shipped state. Nothing is revealed later by an
 * animation, nothing is parked at opacity 0, and there is no window in which an
 * automated scan could read an empty container and call it a pass.
 *
 * `data-app-ready` on <html> is the signal the accessibility and claims suites
 * wait on, so they cannot race the first render.
 */
function mount(): void {
  const main = el('main', { id: 'main', 'aria-label': 'Polynomial Forge' }, [
    heroSection(),
    introCard(),
    scopeCard(),
    actCommit(),
    actOpen(),
    actCeremony(),
    actToxic(),
    actDegree(),
    actCompare(),
    actGroth16(),
    failureCodeCard(),
  ])
  root.appendChild(main)
  root.appendChild(scriptureFooter())
  document.documentElement.dataset.appReady = 'true'
}

try {
  mount()
} catch (err) {
  // A failure here means no cryptography ran at all, so say so loudly rather
  // than leaving an empty page that looks like a slow load.
  const message = err instanceof Error ? err.message : String(err)
  root.appendChild(
    el('div', { class: 'verdict is-alarm', role: 'alert' }, [
      el('span', { class: 'verdict-icon', 'aria-hidden': 'true', text: '[!]' }),
      el('div', { class: 'verdict-body' }, [
        el('span', { class: 'verdict-label', text: 'THIS PAGE FAILED TO START' }),
        el('p', { class: 'verdict-text', text: message }),
      ]),
    ]),
  )
  document.documentElement.dataset.appReady = 'failed'
  throw err
}
