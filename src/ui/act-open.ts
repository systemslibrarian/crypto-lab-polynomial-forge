/**
 * Act 2 - Open and verify. THE headline mechanism.
 *
 * The one idea this page exists to teach is that an opening proof EXISTS only
 * when the claimed value is right, and the reason is a fact about polynomials
 * rather than about elliptic curves: dividing p(X) - y by (X - z) leaves a
 * remainder of exactly p(z) - y.
 *
 * So the act shows the division. Not the conclusion, not the hex - the actual
 * synthetic-division tableau, stepped row by row, with the remainder cell in
 * plain sight. Change y and the remainder stops being zero in front of you.
 * Then the real prover runs, the real pairing runs, and the verifier says what
 * it says.
 */
import { button, card, deep, el, panel, para, scrollRegion } from './dom.js'
import { ellipsize, groupHex, ms, scalar, scalarFull } from './format.js'
import { verdictBox } from './verdict.js'
import { FAILURE_EXPLANATIONS } from '../crypto/codes.js'
import { Fr, frOf } from '../crypto/fr.js'
import { divideByLinear, polyDegree, polyEval } from '../crypto/poly.js'
import {
  attemptOpenAtClaimedValue,
  commit,
  deserializeProof,
  open,
  serializeProof,
  verify,
} from '../crypto/kzg.js'
import { runCeremony } from '../crypto/ceremony.js'
import { g1ToHex } from '../crypto/bls.js'
import { setClaimedY, setZ, state, subscribe, trueY } from './state.js'
import { guarded } from './guard.js'

export function actOpen(): HTMLElement {
  // The tableau ARRIVES fully worked through, remainder in plain sight. A
  // stepper that starts empty makes the mechanism something you have to go
  // looking for; starting at the answer and letting the reader walk backwards
  // (or Reset and walk forwards) shows it immediately and still steps.
  let step = state.coefficients.length
  let lastGeneration = -1

  const zInput = el('input', {
    type: 'number',
    id: 'open-z',
    step: '1',
    min: '0',
    max: '999999',
    value: String(state.z),
    inputmode: 'numeric',
  }) as HTMLInputElement
  zInput.addEventListener('input', () => {
    const raw = zInput.value.trim()
    const n = raw === '' ? 0n : BigInt(Math.trunc(Number(raw)) || 0)
    setZ(frOf(n < 0n ? -n : n))
  })

  const yInput = el('input', {
    type: 'text',
    id: 'open-y',
    value: String(state.claimedY),
    inputmode: 'numeric',
    'aria-describedby': 'open-y-help',
  }) as HTMLInputElement
  yInput.addEventListener('input', () => {
    const raw = yInput.value.trim()
    if (!/^\d+$/.test(raw)) {
      yInput.setAttribute('aria-invalid', 'true')
      return
    }
    yInput.removeAttribute('aria-invalid')
    setClaimedY(frOf(BigInt(raw)))
  })

  const resetY = button('Use the true value p(z)', () => {
    setClaimedY(trueY())
  })

  const tableWrap = el('div')
  const stepStatus = el('p', { class: 'step-count', role: 'status', 'aria-live': 'polite' })
  const remainderLine = el('p')
  const verdict = verdictBox('open-verdict')
  const proofPanel = el('div')

  const stepBack = button('Back', () => {
    if (step > 0) {
      step -= 1
      renderTableau()
    }
  })
  const stepFwd = button('Step', () => {
    const total = state.coefficients.length
    if (step < total) {
      step += 1
      renderTableau()
    }
  })
  const runAll = button(
    'Run the whole division',
    () => {
      step = state.coefficients.length
      renderTableau()
    },
    { class: 'primary' },
  )
  const resetSteps = button('Reset', () => {
    step = 0
    renderTableau()
  })

  function renderTableau(): void {
    const z = state.z
    const y = state.claimedY
    const { steps, remainder, quotient } = divideByLinear(state.coefficients, z, y)
    const total = steps.length
    if (step > total) step = total

    const rows = steps.map((s, i) => {
      const revealed = i < step
      const rowClass = [
        s.isRemainderRow ? 'is-remainder' : '',
        revealed ? (i === step - 1 ? 'is-current' : '') : 'is-pending',
      ]
        .filter(Boolean)
        .join(' ')
      const hide = (v: bigint) => (revealed ? scalar(v) : '—')
      const carryCell = revealed
        ? el('span', {
            class: s.isRemainderRow
              ? `remainder-cell ${Fr.is0(s.carryOut) ? 'remainder-zero' : 'remainder-nonzero'}`
              : '',
            text: scalar(s.carryOut) + (s.isRemainderRow ? (Fr.is0(s.carryOut) ? '  (zero)' : '  (not zero)') : ''),
          })
        : el('span', { text: '—' })
      return {
        cells: [
          s.isRemainderRow ? 'constant term' : `X^${s.index}`,
          hide(s.coefficient),
          hide(s.carryIn),
          hide(s.product),
          carryCell,
          s.isRemainderRow ? 'this is the REMAINDER' : revealed ? `q${s.index - 1}` : '',
        ] as (string | Node)[],
        rowClass,
      }
    })

    const t = el('table', { class: 'tableau' })
    const cap = el('caption')
    cap.textContent = `Synthetic division of p(X) − ${scalar(y)} by (X − ${scalar(
      z,
    )}), top coefficient first. Each row carries down a_i + z·(previous carry).`
    t.appendChild(cap)
    const thead = el('thead')
    const hr = el('tr')
    for (const h of ['term', 'a_i', 'carry in', 'carry in × z', 'a_i + carry×z', 'is']) {
      hr.appendChild(el('th', { scope: 'col', text: h }))
    }
    thead.appendChild(hr)
    t.appendChild(thead)
    const tbody = el('tbody')
    for (const r of rows) {
      const tr = el('tr', r.rowClass ? { class: r.rowClass } : {})
      r.cells.forEach((c, i) => {
        const cell = el(i === 0 ? 'th' : 'td', i === 0 ? { scope: 'row' } : {})
        if (typeof c === 'string') cell.textContent = c
        else cell.appendChild(c)
        tr.appendChild(cell)
      })
      tbody.appendChild(tr)
    }
    t.appendChild(tbody)
    tableWrap.replaceChildren(
      scrollRegion('Synthetic division tableau', t),
      el('p', {
        class: 'compare-note',
        id: 'tableau-note',
        text: 'Every value here is an element of Fr, a prime field of about 2^255 elements, so arithmetic wraps. Subtracting a y larger than the constant term does not go negative — it lands near the top of the field, which is why that cell can turn into a 64-digit hex number.',
      }),
    )

    stepStatus.textContent =
      step === 0
        ? `Reset. ${total} rows to go — press Step.`
        : step < total
          ? `Row ${step} of ${total} worked through.`
          : `All ${total} rows worked through. Remainder = ${scalar(remainder)}.`

    stepBack.disabled = step === 0
    stepFwd.disabled = step >= total
    resetSteps.disabled = step === 0

    const done = step >= total
    remainderLine.textContent = ''
    if (!done) {
      remainderLine.textContent = 'Step through to the bottom row: that last carry-out is the remainder.'
    } else if (Fr.is0(remainder)) {
      remainderLine.replaceChildren(
        el('strong', { text: 'The remainder is zero. ' }),
        document.createTextNode(
          `So (X − ${scalar(z)}) divides p(X) − ${scalar(
            y,
          )} exactly, the carry-outs above ARE the coefficients of a real polynomial q of degree ${polyDegree(
            quotient,
          )}, and the prover has something to commit to.`,
        ),
      )
    } else {
      remainderLine.replaceChildren(
        el('strong', { text: 'The remainder is not zero. ' }),
        document.createTextNode(
          `It is exactly p(z) − y = ${scalar(polyEval(state.coefficients, z))} − ${scalar(y)} = ${scalar(
            remainder,
          )}. There is no polynomial q with p(X) − y = q(X)(X − z), so the honest prover has nothing to commit to. The button below runs the dishonest one instead.`,
        ),
      )
    }
  }

  const verifyBtn = button(
    'Build the proof and verify it',
    guarded(verdict, () => {
      const srs = state.ceremony.srs
      const z = state.z
      const y = state.claimedY
      const C = commit(srs, state.coefficients)
      const honest = y === trueY()

      const t0 = performance.now()
      const attempt = honest
        ? { proof: open(srs, state.coefficients, z), remainder: 0n, honest: true }
        : attemptOpenAtClaimedValue(srs, state.coefficients, z, y)
      const proveMs = performance.now() - t0

      const t1 = performance.now()
      const result = verify(srs, C, z, y, attempt.proof)
      const verifyMs = performance.now() - t1

      proofPanel.replaceChildren(
        el('dl', { class: 'kv', id: 'proof-detail' }, [
          el('dt', { text: 'pi = [q(tau)]1' }),
          el('dd', { class: 'hex', text: groupHex(g1ToHex(attempt.proof.witness)) }),
          el('dt', { text: 'claimed y' }),
          el('dd', { text: scalarFull(y) }),
          el('dt', { text: 'true p(z)' }),
          el('dd', { text: scalarFull(trueY()) }),
          el('dt', { text: 'division remainder' }),
          el('dd', { text: scalarFull(attempt.remainder) }),
          el('dt', { text: 'prove / verify' }),
          el('dd', { text: `${ms(proveMs)} / ${ms(verifyMs)} on this machine, just now` }),
        ]),
      )

      if (result.ok) {
        verdict.set(
          'ok',
          'ACCEPTED',
          `The pairing equation holds: e(C − [y]1, [1]2) = e(pi, [tau − z]2). The claimed value really is p(${scalar(
            z,
          )}), and the proof is ${48} bytes.`,
        )
      } else {
        verdict.set(
          'rejected',
          `REJECTED · ${result.code}`,
          `${result.detail}. The two sides of the equation differ by exactly the remainder above - which is why the honest prover could not build this proof in the first place.`,
        )
      }
    }),
    { class: 'primary', id: 'open-verify' },
  )

  // ── Tamper panel: every failure code, reachable ────────────────────────
  //
  // A verifier that can only say "no" teaches nothing, and a page that lists
  // five failure codes while only ever emitting one is not much better. Each
  // button below produces a REAL proof and then breaks it in a specific way,
  // so every code the reference table names has a route a reader can take.
  const tamperVerdict = verdictBox('tamper-verdict')
  const tamperPanel = el('div')

  function showTamper(code: string, detail: string, extra: [string, string][]): void {
    tamperVerdict.set('rejected', `REJECTED · ${code}`, detail)
    tamperPanel.replaceChildren(
      el(
        'dl',
        { class: 'kv', id: 'tamper-detail' },
        extra.flatMap(([k, v]) => [el('dt', { text: k }), el('dd', { text: v })]),
      ),
    )
  }

  const tamperValue = button(
    'Change the value',
    guarded(tamperVerdict, () => {
      const srs = state.ceremony.srs
      const C = commit(srs, state.coefficients)
      const z = state.z
      const y = trueY()
      const lie = Fr.add(y, 1n)
      const attempt = attemptOpenAtClaimedValue(srs, state.coefficients, z, lie)
      const result = verify(srs, C, z, lie, attempt.proof)
      if (result.ok) throw new Error('a wrong value was accepted; that should be impossible here')
      showTamper(result.code, result.detail, [
        ['what was broken', `the claimed value, ${scalar(y)} changed to ${scalar(lie)}`],
        ['division remainder', scalarFull(attempt.remainder)],
      ])
    }),
    { id: 'tamper-value' },
  )

  const tamperPoint = button(
    'Retarget the point',
    guarded(tamperVerdict, () => {
      const srs = state.ceremony.srs
      const C = commit(srs, state.coefficients)
      const proof = open(srs, state.coefficients, state.z)
      const other = Fr.add(state.z, 1n)
      const result = verify(srs, C, other, polyEval(state.coefficients, other), proof)
      if (result.ok) throw new Error('a proof for one point was accepted at another')
      showTamper(result.code, result.detail, [
        ['what was broken', `an honest proof about z = ${scalar(state.z)} offered as evidence about z = ${scalar(other)}`],
        ['caught', 'before any pairing runs — a proof about one point is simply not about another'],
      ])
    }),
    { id: 'tamper-point' },
  )

  const tamperSetup = button(
    'Swap the setup',
    guarded(tamperVerdict, () => {
      // A second, genuinely independent ceremony: different factors, different
      // tau, different SRS. Its proofs are not evidence about this one's.
      const other = runCeremony({
        maxDegree: state.srsDegree,
        participants: state.participants.map((p) => ({ name: p.name, mode: 'erase' as const })),
      })
      const proof = open(other.srs, state.coefficients, state.z)
      const C = commit(state.ceremony.srs, state.coefficients)
      const result = verify(state.ceremony.srs, C, state.z, polyEval(state.coefficients, state.z), proof)
      if (result.ok) throw new Error('a proof from another ceremony was accepted')
      showTamper(result.code, result.detail, [
        ['what was broken', 'the proof was built against a second ceremony run with different factors'],
        ['this SRS', ellipsize(state.ceremony.srs.digest, 12, 8)],
        ['that SRS', ellipsize(other.srs.digest, 12, 8)],
      ])
    }),
    { id: 'tamper-setup' },
  )

  const tamperBytes = button(
    'Corrupt the bytes',
    guarded(tamperVerdict, () => {
      const srs = state.ceremony.srs
      const proof = open(srs, state.coefficients, state.z)
      const bytes = serializeProof(proof)
      // Flip a bit inside the compressed G1 point. The result is almost never a
      // point on the curve at all, and when it is, almost never in the
      // prime-order subgroup - either way the strict parse refuses it.
      bytes[70] ^= 0x01
      let message = ''
      try {
        deserializeProof(bytes, srs.digest)
      } catch (err) {
        message = err instanceof Error ? err.message : String(err)
      }
      if (!message) throw new Error('a corrupted proof parsed cleanly; the parser is too permissive')
      showTamper('MALFORMED_PROOF', FAILURE_EXPLANATIONS.MALFORMED_PROOF, [
        ['what was broken', 'one bit flipped inside the 48-byte compressed witness point'],
        ['parser said', message],
        ['caught', 'at parse time, before any algebra could run on it'],
      ])
    }),
    { id: 'tamper-bytes' },
  )

  subscribe((s, reason) => {
    if (s.generation !== lastGeneration) {
      lastGeneration = s.generation
      step = s.coefficients.length
      verdict.retire(`${reason}, so the verdict below it is no longer about what is on screen. Run it again.`)
      proofPanel.replaceChildren()
      tamperVerdict.retire(`${reason}, so this rejection is no longer about what is on screen. Run it again.`)
      tamperPanel.replaceChildren()
    }
    if (zInput.value !== String(s.z) && document.activeElement !== zInput) zInput.value = String(s.z)
    if (yInput.value !== String(s.claimedY) && document.activeElement !== yInput) {
      yInput.value = String(s.claimedY)
      // The invalid flag belongs to what is IN the box. Replacing the contents
      // programmatically - which is what "Use the true value" does - has to
      // clear it, or the box keeps an alarm border over a perfectly good value.
      yInput.removeAttribute('aria-invalid')
    }
    renderTableau()
  })
  renderTableau()

  return card(
    el('span', { class: 'act-kicker', text: 'ACT 2 · THE MECHANISM' }),
    el('h2', { text: 'Open and verify — why the division has to come out exactly' }),
    para(
      'To prove p(z) = y, the prover divides p(X) − y by (X − z) and commits to the quotient. That is the whole opening. And it only works when y is right, for a reason you can watch happen: the remainder of that division is exactly p(z) − y.',
      'lede',
    ),
    para(
      'Step the division below. Then change the claimed value and step it again. When y is wrong the bottom cell stops being zero, the "quotient" stops being a polynomial, and there is nothing left for the prover to commit to. Press the verify button either way and watch the real pairing agree.',
    ),
    panel(
      'Inputs',
      el('div', { class: 'row' }, [
        el('div', { class: 'field' }, [el('label', { for: 'open-z', text: 'opening point z' }), zInput]),
        el('div', { class: 'field' }, [el('label', { for: 'open-y', text: 'claimed value y' }), yInput]),
        resetY,
      ]),
      el('p', {
        id: 'open-y-help',
        class: 'compare-note',
        text: 'y is a field element, so any non-negative integer is accepted and reduced mod r. Type anything other than p(z) to break it.',
      }),
    ),
    tableWrap,
    el('div', { class: 'stepper-controls' }, [stepFwd, stepBack, runAll, resetSteps, stepStatus]),
    remainderLine,
    el('div', { class: 'stepper-controls' }, [verifyBtn]),
    verdict.root,
    proofPanel,
    el('h3', { text: 'Break it four ways' }),
    para(
      'The verifier has five things it can say, and four of them are one button away. Each of these builds a real proof and then breaks it somewhere specific — the value, the point it is about, the setup it was built against, or the bytes themselves — so you can see which check catches what, and in what order.',
    ),
    el('div', { class: 'stepper-controls' }, [tamperValue, tamperPoint, tamperSetup, tamperBytes]),
    tamperVerdict.root,
    tamperPanel,
    deep(
      'The same division, moved into the exponent',
      para(
        'The identity the prover is proving is p(X) − y = q(X)·(X − z), an equation between polynomials. The verifier cannot check it as written, because it never sees p or q. What it has instead are their commitments, evaluated at the ceremony\'s unknown tau: C = [p(tau)]1 and pi = [q(tau)]1.',
      ),
      para(
        'Evaluate the identity at tau and it becomes p(tau) − y = q(tau)·(tau − z) - an equation between three hidden scalars, with a MULTIPLICATION on the right. Group arithmetic alone cannot multiply two hidden values. A pairing can, once:',
      ),
      para('e(C − [y]1, [1]2) = e(pi, [tau]2 − [z]2)'),
      para(
        'The left side is e(g1, g2)^(p(tau) − y); the right is e(g1, g2)^(q(tau)·(tau − z)). Equal exponents, so equal G_T elements. That is the entire verification: one identity, checked at one hidden point, with a pairing supplying the one multiplication that group arithmetic cannot.',
      ),
      para(
        'Note where the trust sits. The verifier never learns tau, and never needs to - it only needs [tau]2, which the ceremony published. But if anyone DOES know tau, the equation above becomes something they can solve directly for pi, for any y at all. That is Act 4.',
      ),
    ),
  )
}
