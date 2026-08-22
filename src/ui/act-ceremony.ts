/**
 * Act 3 - The ceremony, and Act 4 - Toxic waste.
 *
 * These are one exhibit in two halves, because the second only means anything
 * if you watched the first pass. Act 3 runs a real multi-party powers-of-tau
 * ceremony and audits its transcript with real pairing checks. Act 4 flips
 * every participant to KEEPING their factor, re-runs the identical audit, and
 * shows it come out identical - then multiplies the factors together and forges
 * an opening the verifier from Act 2 accepts.
 *
 * NEG-2 is the point: well-formedness is verifiable; erasure is not.
 */
import { button, card, deep, el, panel, para, scrollRegion, table } from './dom.js'
import { bytes, ellipsize, ms, scalar, scalarFull } from './format.js'
import { verdictBox } from './verdict.js'
import { recoverTau, tauMatchesSrs, transcriptByteLength } from '../crypto/ceremony.js'
import { commit, verify } from '../crypto/kzg.js'
import { forgeOpening, forgeWithoutTau } from '../crypto/forge.js'
import { g1ToHex } from '../crypto/bls.js'
import { Fr, frOf } from '../crypto/fr.js'
import { polyEval } from '../crypto/poly.js'
import {
  PARTICIPANT_NAMES,
  SRS_DEGREE_CHOICES,
  rerunCeremony,
  setAllModes,
  setParticipantCount,
  setParticipantMode,
  setSrsDegree,
  state,
  subscribe,
  trueY,
} from './state.js'
import { guarded } from './guard.js'

export function actCeremony(): HTMLElement {
  const roster = el('div', { class: 'stack-tight' })
  const summary = el('div')
  const auditWrap = el('div')
  const auditStatus = verdictBox('audit-verdict')

  const countSelect = el('select', { id: 'participant-count' }) as HTMLSelectElement
  for (let n = 1; n <= PARTICIPANT_NAMES.length; n++) {
    countSelect.appendChild(el('option', { value: String(n), text: `${n}` }))
  }
  countSelect.value = String(state.participants.length)
  countSelect.addEventListener('change', () => setParticipantCount(Number(countSelect.value)))

  const degreeSelect = el('select', { id: 'srs-degree' }) as HTMLSelectElement
  for (const d of SRS_DEGREE_CHOICES) {
    degreeSelect.appendChild(el('option', { value: String(d), text: `degree ${d}` }))
  }
  degreeSelect.value = String(state.srsDegree)
  degreeSelect.addEventListener('change', () => setSrsDegree(Number(degreeSelect.value)))

  function renderRoster(): void {
    // Re-rendering destroys the button the user just pressed, which drops
    // keyboard focus to <body> and loses the reader's place entirely (WCAG
    // 3.2.2 / 2.4.3). Remember which control was focused and put focus back on
    // its replacement.
    const focusedId =
      document.activeElement instanceof HTMLElement && roster.contains(document.activeElement)
        ? document.activeElement.id
        : null
    roster.replaceChildren(
      ...state.participants.map((p, i) => {
        const eraseId = `mode-${i}-erase`
        const retainId = `mode-${i}-retain`
        const eraseBtn = button('Erases it', () => setParticipantMode(i, 'erase'), { id: eraseId })
        const retainBtn = button('Keeps it', () => setParticipantMode(i, 'retain'), { id: retainId })
        eraseBtn.setAttribute('aria-pressed', String(p.mode === 'erase'))
        retainBtn.setAttribute('aria-pressed', String(p.mode === 'retain'))
        eraseBtn.setAttribute('aria-label', `Participant ${i + 1} ${p.name} erases their factor`)
        retainBtn.setAttribute('aria-label', `Participant ${i + 1} ${p.name} keeps their factor`)
        return el('div', { class: 'switch-row' }, [
          el('span', { class: 'code-pill', text: `#${i + 1} ${p.name}` }),
          el('span', { class: 'seg' }, [eraseBtn, retainBtn]),
          el('span', {
            class: p.mode === 'erase' ? 'tag-ok' : 'tag-alarm',
            text: p.mode === 'erase' ? '[+] factor destroyed' : '[!] factor retained',
          }),
        ])
      }),
    )
    if (focusedId) {
      const restored = roster.querySelector<HTMLElement>(`#${CSS.escape(focusedId)}`)
      restored?.focus()
    }
  }

  function renderSummary(): void {
    const c = state.ceremony
    summary.replaceChildren(
      el('dl', { class: 'kv', id: 'ceremony-detail' }, [
        el('dt', { text: 'participants' }),
        el('dd', { text: String(c.contributions.length) }),
        el('dt', { text: 'SRS' }),
        el('dd', { text: `[tau^0]1 … [tau^${c.maxDegree}]1 and the matching G2 powers` }),
        el('dt', { text: 'transcript digest' }),
        el('dd', { text: ellipsize(c.contributions[c.contributions.length - 1].transcriptHash, 16, 10) }),
        el('dt', { text: 'SRS digest' }),
        el('dd', { text: ellipsize(c.srs.digest, 16, 10) }),
        el('dt', { text: 'public transcript size' }),
        el('dd', { text: bytes(transcriptByteLength(c)) }),
        el('dt', { text: '[tau]1' }),
        el('dd', { class: 'hex', text: ellipsize(g1ToHex(c.srs.g1Powers[1]), 24, 16) }),
      ]),
    )
  }

  // A polite live region that re-announces identical text on every unrelated
  // keystroke is worse than no live region: it trains a screen-reader user to
  // tune it out. The audit only speaks when the ceremony it describes has
  // actually changed.
  let lastAuditKey = ''

  function renderAudit(): void {
    const audit = state.audit
    auditWrap.replaceChildren(
      scrollRegion(
        'Ceremony transcript audit',
        table({
          caption:
            'Every row is a real pairing equation, computed now from the public transcript alone. No participant secret is consulted.',
          head: ['Check', 'Equation', 'Result'],
          rows: audit.rows.map((r) => ({
            cells: [
              r.label,
              r.equation,
              el('span', {
                class: r.ok ? 'tag-ok' : 'tag-alarm',
                text: r.ok ? '[+] PASS' : '[!] FAIL',
              }),
            ] as (string | Node)[],
          })),
        }),
      ),
    )
    const passing = audit.rows.filter((r) => r.ok).length
    const auditKey = `${state.ceremony.srs.digest}|${audit.ok}|${passing}/${audit.rows.length}`
    if (auditKey === lastAuditKey) return
    lastAuditKey = auditKey
    if (audit.ok) {
      auditStatus.set(
        'ok',
        'TRANSCRIPT VERIFIES',
        `All ${passing} checks pass. Every contribution is provably well-formed and the finished SRS really is the powers of a single tau. What no row above establishes - because no row CAN - is whether anybody destroyed anything.`,
      )
    } else {
      auditStatus.set(
        'rejected',
        'TRANSCRIPT REJECTED',
        `${audit.rows.length - passing} of ${audit.rows.length} checks failed. Something in the public record does not hold together.`,
      )
    }
  }

  subscribe(() => {
    if (countSelect.value !== String(state.participants.length)) {
      countSelect.value = String(state.participants.length)
    }
    if (degreeSelect.value !== String(state.srsDegree)) degreeSelect.value = String(state.srsDegree)
    renderRoster()
    renderSummary()
    renderAudit()
  })
  renderRoster()
  renderSummary()
  renderAudit()

  return card(
    el('span', { class: 'act-kicker', text: 'ACT 3' }),
    el('h2', { text: 'The ceremony — how a trapdoor gets built by people who must not keep it' }),
    para(
      'KZG needs powers of a secret tau, and needs nobody to know tau. Those two requirements look incompatible until you notice that tau can be a PRODUCT. Each participant draws a random factor, rescales every power in the exponent, publishes proof that they did it properly, and is supposed to destroy the factor. After n participants the trapdoor is r1·r2·…·rn — and no single participant ever held it.',
      'lede',
    ),
    para(
      'The security property is exactly this: the ceremony survives as long as at least ONE contribution was fresh and destroyed. Everyone else can be dishonest. That is a remarkably weak assumption, and it is why ceremonies are run with thousands of participants.',
    ),
    panel(
      'Run it',
      el('div', { class: 'row' }, [
        el('div', { class: 'field' }, [
          el('label', { for: 'participant-count', text: 'participants' }),
          countSelect,
        ]),
        el('div', { class: 'field' }, [
          el('label', { for: 'srs-degree', text: 'SRS size' }),
          degreeSelect,
        ]),
        button('Re-run with fresh randomness', () => rerunCeremony()),
      ]),
      el('p', {
        class: 'compare-note',
        text: 'A larger SRS is a real cost: one scalar multiplication per power per participant, and one pairing per power to audit. Degree 128 takes a few seconds, and that wait is the honest shape of the thing.',
      }),
    ),
    panel('Who did what with their factor', roster),
    panel('The finished reference string', summary),
    el('h3', { text: 'The transcript audit' }),
    para(
      'This is what a real auditor does, and all a real auditor can do: check the public record. Each contribution publishes a proof of knowledge of its factor, and the audit checks that the SAME factor is the one applied to the reference string. The finished SRS is then checked to be a genuine geometric series.',
    ),
    auditStatus.root,
    auditWrap,
    deep(
      'What each pairing check actually says',
      para(
        'The proof of knowledge is the Bowe-Gabizon-Miers construction the real powers-of-tau ceremonies use. The participant publishes s and [r]s in G1, then derives a challenge point h in G2 by hashing the transcript so far - so it cannot be chosen in advance - and publishes [r]h.',
      ),
      para(
        'e(s, [r]h) = e([r]s, h) says one and the same scalar relates both pairs, which is only possible if the participant knows it.',
      ),
      para(
        'e([tau_new]1, h) = e([tau_old]1, [r]h) says that same scalar is the one applied to the reference string - it ties the proof to the update rather than letting a participant prove knowledge of one value and apply another.',
      ),
      para(
        'e([tau^j]1, [1]2) = e([tau^(j-1)]1, [tau]2) for every j says the finished SRS is powers of ONE value, not an arbitrary list of points. Without it a malicious final contributor could publish points with no consistent tau at all, and every opening proof built on them would be meaningless.',
      ),
      para(
        'What is missing from that list is any check on erasure. There is no equation whose failure means "you kept it", because a destroyed secret and a retained one leave the same public record. Act 4 makes that concrete.',
      ),
    ),
  )
}

export function actToxic(): HTMLElement {
  const status = el('div')
  const tauPanel = el('div')
  const forgeVerdict = verdictBox('forge-verdict')
  const forgePanel = el('div')

  const yInput = el('input', {
    type: 'text',
    id: 'forge-y',
    value: '1',
    inputmode: 'numeric',
    'aria-describedby': 'forge-y-help',
  }) as HTMLInputElement

  const makeToxic = button(
    'Make every participant keep their factor',
    () => setAllModes('retain'),
    { class: 'danger', id: 'make-toxic' },
  )
  const makeHonest = button('Make every participant erase it', () => setAllModes('erase'), {
    id: 'make-honest',
  })

  const forgeBtn = button(
    'Forge an opening for that value',
    guarded(forgeVerdict, () => {
      const c = state.ceremony
      const tau = recoverTau(c)
      const z = state.z
      const raw = yInput.value.trim()
      if (!/^\d+$/.test(raw)) {
        yInput.setAttribute('aria-invalid', 'true')
        forgeVerdict.set('rejected', 'BAD INPUT', 'The claimed value must be a non-negative integer.')
        return
      }
      yInput.removeAttribute('aria-invalid')
      const lie = frOf(BigInt(raw))

      if (tau === null) {
        const why = forgeWithoutTau()
        forgeVerdict.set('ok', 'FORGERY IMPOSSIBLE', why.reason)
        forgePanel.replaceChildren()
        return
      }

      const C = commit(c.srs, state.coefficients)
      const t0 = performance.now()
      // Note what is NOT passed: the polynomial. The forgery is built from the
      // commitment alone, which is why it works against data the forger has
      // never seen.
      const forged = forgeOpening({ srs: c.srs, commitment: C, tau, z, claimedY: lie })
      const forgeMs = performance.now() - t0
      const result = verify(c.srs, C, z, lie, forged.proof)
      const truth = polyEval(state.coefficients, z)
      const isLie = lie !== truth

      forgePanel.replaceChildren(
        el('dl', { class: 'kv', id: 'forge-detail' }, [
          el('dt', { text: 'claimed y' }),
          el('dd', { text: scalarFull(lie) }),
          el('dt', { text: 'true p(z)' }),
          el('dd', { text: scalarFull(truth) }),
          el('dt', { text: 'forged pi' }),
          el('dd', { class: 'hex', text: ellipsize(g1ToHex(forged.proof.witness), 32, 20) }),
          el('dt', { text: 'how it was built' }),
          el('dd', { text: `pi = (tau − z)^-1 · (C − [y]1), from the commitment alone` }),
          el('dt', { text: 'needed the polynomial?' }),
          el('dd', { class: 'tag-alarm', text: '[!] no — only C and tau' }),
          el('dt', { text: 'time to forge' }),
          el('dd', { text: `${ms(forgeMs)} — one field inversion and one scalar multiplication` }),
        ]),
      )

      if (result.ok && isLie) {
        forgeVerdict.set(
          'alarm',
          'ACCEPTED — AND FALSE',
          `The verifier accepted y = ${scalar(lie)} at z = ${scalar(z)}. The true value is ${scalar(
            truth,
          )}. Nothing failed: the transcript above is still green, the proof is well-formed, the pairing equation genuinely holds. The verifier answered the question it was asked, and that question stopped meaning anything the moment tau was known.`,
        )
      } else if (result.ok) {
        forgeVerdict.set(
          'ok',
          'ACCEPTED — AND TRUE',
          `You asked for the true value, so the forged proof proves something true. Type any other number to see the difference.`,
        )
      } else {
        forgeVerdict.set('rejected', `REJECTED · ${result.code}`, result.detail)
      }
    }),
    { class: 'danger', id: 'forge-run' },
  )

  function render(): void {
    const c = state.ceremony
    const tau = recoverTau(c)
    const retained = c.retained.filter((r) => !r.erased).length
    const total = c.retained.length

    status.replaceChildren(
      el('dl', { class: 'kv', id: 'toxic-status' }, [
        el('dt', { text: 'transcript' }),
        el('dd', {
          class: state.audit.ok ? 'tag-ok' : 'tag-alarm',
          text: state.audit.ok
            ? `[+] all ${state.audit.rows.length} checks pass`
            : `[!] ${state.audit.rows.filter((r) => !r.ok).length} checks fail`,
        }),
        el('dt', { text: 'factors retained' }),
        el('dd', {
          class: retained === total ? 'tag-alarm' : retained > 0 ? 'tag-bad' : 'tag-ok',
          text: `${retained} of ${total}`,
        }),
        el('dt', { text: 'trapdoor' }),
        el('dd', {
          class: tau === null ? 'tag-ok' : 'tag-alarm',
          text:
            tau === null
              ? '[+] unrecoverable — at least one factor was destroyed'
              : '[!] recoverable — every factor was kept',
        }),
      ]),
    )

    if (tau === null) {
      tauPanel.replaceChildren(
        el('p', {
          text: `${total - retained} of ${total} participants destroyed their factor, so the product was never assembled and this page does not hold it. That is the security property: one honest contribution is enough.`,
        }),
      )
    } else {
      const matches = tauMatchesSrs(c, tau)
      tauPanel.replaceChildren(
        el('p', {
          text: 'Every factor was kept, so multiplying them together reconstructs the trapdoor. The check below rebuilds [tau]1 from the recovered scalar and compares it with the point the ceremony published — so this is the real tau, not a plausible-looking number.',
        }),
        el('dl', { class: 'kv', id: 'tau-detail' }, [
          // The factors are printed IN FULL, not elided. They are the toxic
          // waste - the exhibit is that these values still exist, and a reader
          // (or the claims suite) can multiply them together and land on the
          // trapdoor below. An elided digest would make that unverifiable,
          // which would make the exhibit an assertion.
          ...c.retained.flatMap((r) => [
            el('dt', { text: `${r.name} kept` }),
            el('dd', { class: 'hex', text: `0x${r.factor.toString(16).padStart(64, '0')}` }),
          ]),
          el('dt', { text: 'product = recovered tau' }),
          el('dd', { class: 'hex', text: `0x${tau.toString(16).padStart(64, '0')}` }),
          el('dt', { text: '[tau]1 rebuilt = published?' }),
          el('dd', {
            class: matches ? 'tag-alarm' : 'tag-bad',
            text: matches ? '[!] yes — this is the ceremony\'s real trapdoor' : '[x] no',
          }),
        ]),
      )
    }

    forgeBtn.disabled = false
  }

  subscribe((_s, reason) => {
    render()
    forgeVerdict.retire(`${reason}, so any forgery verdict here is no longer about this ceremony. Run it again.`)
    forgePanel.replaceChildren()
  })
  render()

  return card(
    el('span', { class: 'act-kicker', text: 'ACT 4 · ATTACK 1' }),
    el('h2', { text: 'Toxic waste — an all-green transcript over a completely dishonest ceremony' }),
    para(
      'Revision histories of this exhibit used to say "one participant retains tau", which is incoherent: no participant ever has tau. The interesting attack is about what the transcript can prove. Set every participant to KEEP their factor and re-read Act 3 — every pairing check still passes, every contribution is still provably well-formed, the audit is green end to end, and it is byte-for-byte the same audit an honest ceremony produces.',
      'lede',
    ),
    el('div', { class: 'stepper-controls' }, [makeToxic, makeHonest]),
    panel('Where this ceremony stands', status),
    panel('The trapdoor', tauPanel),
    el('h3', { text: 'Forge an opening' }),
    para(
      'With tau as a scalar, the verification equation stops being a test and becomes an equation you can solve. Pick any value you like — it does not have to be p(z), and it should not be, or there is nothing to see.',
    ),
    el('div', { class: 'row' }, [
      el('div', { class: 'field' }, [
        el('label', { for: 'forge-y', text: 'value to forge a proof for' }),
        yInput,
      ]),
      forgeBtn,
    ]),
    el('p', {
      id: 'forge-y-help',
      class: 'compare-note',
      text: 'The commitment and the opening point come from Acts 1 and 2, so the forgery runs against the same C you built there.',
    }),
    forgeVerdict.root,
    forgePanel,
    deep(
      'NEG-2 — why no transcript can close this',
      para(
        'KZG binding requires the final trapdoor to remain unknown, and a ceremony transcript cannot establish that it does. Well-formedness is verifiable; erasure is not.',
      ),
      para(
        'Every check in Act 3 is a statement about published points. Erasure is a statement about a value that is, by construction, not published — and about an event in the physical world. The two worlds this page switches between differ in exactly one respect, and it is the one respect no equation over the transcript can see.',
      ),
      para(
        'This is not a flaw in the audit. It is the theorem. Real ceremonies respond to it not by checking harder but by making the assumption cheaper: with 140,000 participants, "at least one of them was honest and careful" is about as weak as a cryptographic assumption gets. It is still an assumption about people rather than about mathematics, and it is the only one on this page.',
      ),
      para(
        'The same shape appears in crypto-lab-context-ward: every check green, the system owned anyway. Here it turns up in a setting nobody expects it — the ceremony that exists precisely to be auditable.',
      ),
    ),
    deep(
      'Who can actually do this — and it is worse than it looks',
      para(
        'Anyone who knows tau. That is the entire requirement, and it is worth being precise about why, because the intuitive answer is wrong.',
      ),
      para(
        'The forged witness is `pi = (tau − z)^-1 · (C − [y]1)`. Read the right-hand side carefully: `C` is a point the forger already has, `[y]1` is a point they can compute from the y they invented, and `(tau − z)^-1` is an ordinary field element. So the whole thing is one subtraction and one scalar multiplication — group operations on values already in hand.',
      ),
      para(
        'What it never does is extract `p(tau)` from `C`. That WOULD be a discrete log, and it is what makes people conclude a forger must also know the committed polynomial. They do not. The scalar `p(tau)` never appears in the computation at all, which means a commitment somebody else made, to data the forger has never seen, can be opened to any value at any point.',
      ),
      para(
        'An earlier revision of this page said the opposite. It was wrong, and wrong in the direction that understates the damage. The unit suite now pins the correction with a test that forges against a commitment whose polynomial is generated inside a closure and never handed to the forging code.',
      ),
    ),
  )
}

export { Fr, trueY }
