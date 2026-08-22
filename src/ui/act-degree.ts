/**
 * Act 5 - Attack 2: the omitted degree bound.
 *
 * The exhibit is a check that never runs, so there is nothing to watch fail.
 * What the page shows instead is the shape of the omission: two different
 * witnesses that are indistinguishable everywhere the protocol looks, every
 * KZG opening of both verifying, a standing DEGREE_UNENFORCED banner while the
 * check is off, and a DEGREE_EXCEEDED the moment it is switched on.
 *
 * NEG-1 lives here, and the exhibit is written to stop the tempting wrong
 * reading: the missing check does NOT let one commitment open two ways at the
 * same point. Evaluation binding is intact throughout.
 */
import { button, card, checkbox, deep, el, panel, para, scrollRegion, table } from './dom.js'
import { scalar } from './format.js'
import { bannerBox, verdictBox } from './verdict.js'
import { DEGREE_UNENFORCED, DEGREE_UNENFORCED_EXPLANATION } from '../crypto/codes.js'
import {
  BINDING_IS_INTACT,
  agreementTable,
  buildOverDegreeWitness,
  type ConstraintSet,
  type OverDegreeWitness,
} from '../crypto/degree-attack.js'
import { attemptOpenAtClaimedValue, commit, open, verify } from '../crypto/kzg.js'
import { polyDegree, polyEval } from '../crypto/poly.js'
import { Fr } from '../crypto/fr.js'
import { setEnforceDegreeBound, state, subscribe } from './state.js'
import { guarded } from './guard.js'

/** The application's constraints: a witness pinned at four points, degree <= 7. */
export const CONSTRAINTS: ConstraintSet = {
  xs: [2n, 3n, 5n, 7n],
  ys: [11n, 13n, 17n, 19n],
  bound: 7,
}

const CHEAT_DEGREE = 16
const UNCONSTRAINED_POINTS = [11n, 13n, 101n]

export function actDegree(): HTMLElement {
  let witness: OverDegreeWitness = buildOverDegreeWitness(CONSTRAINTS, CHEAT_DEGREE, state.srsDegree)

  const banner = bannerBox('degree-banner', DEGREE_UNENFORCED, DEGREE_UNENFORCED_EXPLANATION)
  const verdict = verdictBox('degree-verdict')
  const openingsWrap = el('div')
  const agreementWrap = el('div')
  const bindingWrap = el('div')

  const enforceToggle = checkbox(
    'enforce-degree',
    'Verifier enforces the degree bound (deg p <= 7)',
    state.enforceDegreeBound,
    (on) => setEnforceDegreeBound(on),
  )

  const runBtn = button(
    'Verify the over-degree witness',
    guarded(verdict, () => {
      const srs = state.ceremony.srs
      const bound = state.enforceDegreeBound ? CONSTRAINTS.bound : undefined
      const C = commit(srs, witness.cheating)

      // Every constrained opening, one row each.
      const rows = CONSTRAINTS.xs.map((x, i) => {
        const y = CONSTRAINTS.ys[i]
        let proofResult
        let note = ''
        try {
          const proof = open(srs, witness.cheating, x, bound === undefined ? {} : { degreeBound: bound })
          proofResult = verify(srs, C, x, y, proof, bound === undefined ? {} : { degreeBound: bound })
        } catch (err) {
          // With enforcement on, the cheating prover cannot even BUILD the
          // shifted commitment - the shift needs a power beyond the SRS. The
          // verifier then sees a proof with no shift and says DEGREE_EXCEEDED.
          note = err instanceof Error ? err.message : String(err)
          const fallback = attemptOpenAtClaimedValue(srs, witness.cheating, x, y)
          proofResult = verify(srs, C, x, y, fallback.proof, bound === undefined ? {} : { degreeBound: bound })
        }
        return {
          cells: [
            `z = ${scalar(x)}`,
            scalar(y),
            scalar(polyEval(witness.cheating, x)),
            el('span', {
              class: proofResult.ok ? 'tag-ok' : 'tag-bad',
              text: proofResult.ok ? '[+] ACCEPTED' : `[x] ${proofResult.ok ? '' : proofResult.code}`,
            }),
            note ? 'prover could not build the degree proof' : proofResult.detail,
          ] as (string | Node)[],
        }
      })

      openingsWrap.replaceChildren(
        scrollRegion(
          'Openings of the over-degree witness at every constraint point',
          table({
            caption: `Real KZG openings of the degree-${witness.cheatingDegree} witness, at each of the application's ${CONSTRAINTS.xs.length} constraint points.`,
            head: ['point', 'value the protocol expects', 'value the witness gives', 'verifier', 'why'],
            rows,
          }),
        ),
      )

      const allAccepted = rows.every((r) => {
        const cell = r.cells[3]
        return cell instanceof Element && cell.textContent?.includes('ACCEPTED')
      })

      if (!state.enforceDegreeBound && allAccepted) {
        verdict.set(
          'alarm',
          'EVERY CHECK PASSED — AND THE PROTOCOL IS WRONG',
          `All ${CONSTRAINTS.xs.length} openings verified. The committed polynomial has degree ${witness.cheatingDegree}, and the application requires at most ${CONSTRAINTS.bound}. No cryptographic check failed, because none of them is about degree. There is no failure code to report — that absence IS the exhibit.`,
        )
      } else if (state.enforceDegreeBound && !allAccepted) {
        verdict.set(
          'ok',
          'REJECTED · DEGREE_EXCEEDED',
          `With the bound enforced, the prover has to supply a shifted commitment [tau^(D−d)·p(tau)]1 as well. For a degree-${witness.cheatingDegree} polynomial that needs a power of tau beyond the end of the SRS, so it cannot be built — and the verifier says so.`,
        )
      } else if (state.enforceDegreeBound && allAccepted) {
        verdict.set(
          'alarm',
          'ENFORCEMENT DID NOT BITE',
          'The bound is switched on but the over-degree witness was still accepted. That should be impossible; treat it as a bug in this page rather than a result.',
        )
      } else {
        verdict.set('rejected', 'REJECTED', 'Some openings were refused with the bound switched off.')
      }

      // The honest witness, for contrast, under the same setting.
      const honestC = commit(srs, witness.honest)
      const honestProof = open(
        srs,
        witness.honest,
        CONSTRAINTS.xs[0],
        bound === undefined ? {} : { degreeBound: bound },
      )
      const honestResult = verify(
        srs,
        honestC,
        CONSTRAINTS.xs[0],
        CONSTRAINTS.ys[0],
        honestProof,
        bound === undefined ? {} : { degreeBound: bound },
      )

      // NEG-1, demonstrated rather than asserted: the two witnesses have
      // DIFFERENT commitments, and neither opens to two values at one point.
      const z0 = CONSTRAINTS.xs[0]
      const trueValue = polyEval(witness.cheating, z0)
      const lie = Fr.add(trueValue, 1n)
      // BOTH halves are real verifications. The honest opening used to be a
      // hardcoded '[+] ACCEPTED' in this table, which meant the row asserting
      // binding could not have reported a binding failure even if there were
      // one - the exact shape this act exists to warn about.
      const firstOpening = open(srs, witness.cheating, z0)
      const firstResult = verify(srs, C, z0, trueValue, firstOpening)
      const secondOpening = attemptOpenAtClaimedValue(srs, witness.cheating, z0, lie)
      const secondResult = verify(srs, C, z0, lie, secondOpening.proof)

      bindingWrap.replaceChildren(
        scrollRegion(
          'Evaluation binding checks',
          table({
          caption: 'Evaluation binding, checked rather than asserted.',
          head: ['Claim', 'Checked by', 'Result'],
          rows: [
            {
              cells: [
                'The two witnesses have different commitments',
                'comparing the two G1 points',
                el('span', {
                  class: honestC.equals(C) ? 'tag-alarm' : 'tag-ok',
                  text: honestC.equals(C) ? '[!] identical' : '[+] different points',
                }),
              ] as (string | Node)[],
            },
            {
              cells: [
                `The cheating commitment opens to ${scalar(trueValue)} at z = ${scalar(z0)}`,
                'a real KZG verification',
                el('span', {
                  class: firstResult.ok ? 'tag-ok' : 'tag-alarm',
                  text: firstResult.ok ? '[+] ACCEPTED' : `[!] ${firstResult.ok ? '' : firstResult.code}`,
                }),
              ] as (string | Node)[],
            },
            {
              cells: [
                `...and refuses ${scalar(lie)} at the SAME point`,
                'a real KZG verification',
                el('span', {
                  class: secondResult.ok ? 'tag-alarm' : 'tag-ok',
                  text: secondResult.ok ? '[!] ALSO ACCEPTED — binding broken' : '[+] REJECTED · PAIRING_FAIL',
                }),
              ] as (string | Node)[],
            },
            {
              cells: [
                'The honest witness still verifies under this setting',
                `degree bound ${state.enforceDegreeBound ? 'enforced' : 'not enforced'}`,
                el('span', {
                  class: honestResult.ok ? 'tag-ok' : 'tag-bad',
                  text: honestResult.ok ? '[+] ACCEPTED' : `[x] ${honestResult.ok ? '' : honestResult.code}`,
                }),
              ] as (string | Node)[],
            },
          ],
          }),
        ),
      )
    }),
    { class: 'primary', id: 'degree-run' },
  )

  function renderAgreement(): void {
    const rows = agreementTable(witness, CONSTRAINTS, UNCONSTRAINED_POINTS)
    agreementWrap.replaceChildren(
      scrollRegion(
        'Where the two witnesses agree',
        table({
          caption:
            'The honest interpolant and the over-degree witness, evaluated side by side. Identical on every row the protocol constrains; different on every row it does not.',
          head: ['point', 'constrained?', 'honest witness', 'over-degree witness', ''],
          rows: rows.map((r) => ({
            cells: [
              `z = ${scalar(r.x)}`,
              r.isConstraint ? 'yes' : 'no',
              scalar(r.honestY),
              scalar(r.cheatingY),
              el('span', {
                class: r.agrees ? 'tag-alarm' : 'tag-ok',
                text: r.agrees ? '[!] identical' : '[+] different',
              }),
            ] as (string | Node)[],
          })),
        }),
      ),
    )
  }

  subscribe((s, reason) => {
    witness = buildOverDegreeWitness(CONSTRAINTS, CHEAT_DEGREE, s.srsDegree, witness.multiplier)
    banner.show(!s.enforceDegreeBound)
    if (enforceToggle.input.checked !== s.enforceDegreeBound) {
      enforceToggle.input.checked = s.enforceDegreeBound
    }
    verdict.retire(`${reason}, so the verdict below is no longer about what is on screen. Run it again.`)
    openingsWrap.replaceChildren()
    bindingWrap.replaceChildren()
    renderAgreement()
  })
  banner.show(!state.enforceDegreeBound)
  renderAgreement()

  return card(
    el('span', { class: 'act-kicker', text: 'ACT 5 · ATTACK 2' }),
    el('h2', { text: 'The degree bound nobody checked' }),
    para(
      'The reference string supports degree up to D. This application needs a witness of degree at most 7, pinned by four constraint points. Nothing in the KZG verification equation mentions degree — so a verifier that checks only openings is checking that the committed polynomial passes through those four points, and nothing more.',
      'lede',
    ),
    para(
      `That is easy to exploit. Take the honest interpolant p, take Z(X) = (X−2)(X−3)(X−5)(X−7) which vanishes on every constraint point, and add Z(X)·h(X) for any h you like. The sum hits exactly the same four values, and its degree is whatever you want it to be — ${CHEAT_DEGREE} here. Every KZG opening still verifies.`,
    ),
    banner.root,
    panel(
      'The verifier\'s configuration',
      enforceToggle.wrap,
      el('p', {
        class: 'compare-note',
        text: 'Switching this on makes the prover supply a shifted commitment as well, and makes the verifier check it with a second pairing equation. Switching it off is the default because it is what protocols actually forget to do.',
      }),
      el('div', { class: 'stepper-controls' }, [runBtn]),
    ),
    verdict.root,
    openingsWrap,
    el('h3', { text: 'Why the openings agree' }),
    agreementWrap,
    el('h3', { text: 'What did NOT break' }),
    para(BINDING_IS_INTACT.claim + ' ' + BINDING_IS_INTACT.why, 'lede'),
    para(
      'The tempting wrong lesson is that a missing degree check lets one commitment open two ways at the same point. It does not, and the table below checks that rather than asserting it. What is false is the protocol\'s low-degree claim, one layer above the commitment.',
    ),
    bindingWrap,
    deep(
      'NEG-1 — a commitment binds a polynomial, not a statement about it',
      para(
        'A polynomial commitment does exactly one job: it binds the committer to a polynomial, and lets them open it honestly at any point. It says nothing about that polynomial\'s degree, nothing about where its coefficients came from, and nothing about whether it is the polynomial the protocol had in mind.',
      ),
      para(
        `Every cryptographic check in this act is green. The protocol-level claim — "the committed witness has degree at most ${CONSTRAINTS.bound}" — is false. And there is no failure code available, because nothing cryptographic failed. That is why this act prints a standing ${DEGREE_UNENFORCED} banner instead of a rejection: rendering the omission as a failure would misrepresent what a real verifier experiences, which is silence.`,
      ),
      para(
        'In a real system the consequence depends on what the low-degree claim was load-bearing for. In a PLONK-style protocol it bounds the number of constraints a witness can encode; in a Reed-Solomon setting it is the distance property the whole encoding rests on. Either way the protocol\'s soundness argument quietly assumed something the verifier never checked.',
      ),
    ),
    deep(
      'How the shifted-commitment check actually works',
      para(
        'The prover supplies C_shift = [tau^(D−d)·p(tau)]1 alongside the commitment, and the verifier checks e(C_shift, [1]2) = e(C, [tau^(D−d)]2).',
      ),
      para(
        'An honest prover can build C_shift straight from the SRS: multiplying by X^(D−d) shifts every coefficient up by D−d places, and since deg(p) <= d the highest power needed is tau^D, which the SRS has. A prover whose polynomial has degree above d needs tau^k for some k > D — and the SRS simply stops. The check works because the cheating prover cannot produce the input, not because the verifier catches a bad one.',
      ),
      para(
        'Which is exactly why it has to be RUN. An argument that rests on the prover being unable to supply something proves nothing at all if the verifier never asks for it.',
      ),
    ),
  )
}

export { polyDegree }
