/**
 * Act 1 - Commit.
 *
 * The exhibit is compression: pick coefficients, watch the polynomial's own
 * size grow, and watch the commitment sit at 48 bytes and refuse to move. It is
 * shown by measuring both, never asserted - and the commitment is a real
 * multi-scalar multiplication against the ceremony's structured reference
 * string, timed as it happens.
 */
import { card, deep, el, panel, para, scrollRegion, table } from './dom.js'
import { bytes, ellipsize, groupHex, ms, polyText, scalar } from './format.js'
import { commit, KZG_COMMITMENT_BYTES } from '../crypto/kzg.js'
import { g1ToHex } from '../crypto/bls.js'
import { polyByteLength, polyDegree } from '../crypto/poly.js'
import { EDITABLE_COEFFICIENTS, setCoefficient, state, subscribe } from './state.js'
import { frOf } from '../crypto/fr.js'

export function actCommit(): HTMLElement {
  const coefWrap = el('div', { class: 'coefs' })
  const inputs: HTMLInputElement[] = []

  for (let i = 0; i < EDITABLE_COEFFICIENTS; i++) {
    const id = `coef-${i}`
    const input = el('input', {
      type: 'number',
      id,
      step: '1',
      min: '0',
      max: '999999',
      value: String(state.coefficients[i]),
      inputmode: 'numeric',
    }) as HTMLInputElement
    input.addEventListener('input', () => {
      const raw = input.value.trim()
      const n = raw === '' ? 0n : BigInt(Math.trunc(Number(raw)) || 0)
      setCoefficient(i, frOf(n < 0n ? -n : n))
    })
    inputs.push(input)
    coefWrap.appendChild(
      el('div', { class: 'coef' }, [el('label', { for: id, text: `c${i} (X^${i})` }), input]),
    )
  }

  const polyOut = el('p', { class: 'poly-render' })
  const sizeTable = el('div')
  const commitOut = el('div')

  const growLabel = el('p', { class: 'compare-note' })

  function render(): void {
    polyOut.textContent = `p(X) = ${polyText(state.coefficients)}`

    const srs = state.ceremony.srs
    const t0 = performance.now()
    const C = commit(srs, state.coefficients)
    const commitMs = performance.now() - t0

    const polyBytes = polyByteLength(state.coefficients)
    const ratio = polyBytes / KZG_COMMITMENT_BYTES

    sizeTable.replaceChildren(
      table({
        caption: 'Measured on the values above, right now.',
        head: ['', 'What it is', 'Size'],
        rows: [
          {
            cells: [
              'The polynomial',
              `${EDITABLE_COEFFICIENTS} coefficients in Fr, 32 bytes each`,
              bytes(polyBytes),
            ],
            cellClasses: [undefined, undefined, 'num'],
          },
          {
            cells: [
              'The commitment',
              'one compressed point in BLS12-381 G1',
              bytes(KZG_COMMITMENT_BYTES),
            ],
            cellClasses: [undefined, undefined, 'num'],
          },
          {
            cells: ['Compression', 'polynomial bytes divided by commitment bytes', `${ratio.toFixed(1)}x`],
            cellClasses: [undefined, undefined, 'num'],
          },
        ],
      }),
    )

    const hex = g1ToHex(C)
    commitOut.replaceChildren(
      el('dl', { class: 'kv', id: 'commit-detail' }, [
        el('dt', { text: 'C = [p(tau)]1' }),
        el('dd', { class: 'hex', text: groupHex(hex) }),
        el('dt', { text: 'degree' }),
        el('dd', { text: String(polyDegree(state.coefficients)) }),
        el('dt', { text: 'SRS' }),
        el('dd', {
          text: `powers of tau up to X^${srs.maxDegree}, digest ${ellipsize(srs.digest, 12, 8)}`,
        }),
        el('dt', { text: 'time to commit' }),
        el('dd', { text: `${ms(commitMs)} on this machine, just now` }),
      ]),
    )

    growLabel.textContent = `This SRS runs to degree ${srs.maxDegree}, so a polynomial of up to ${
      srs.maxDegree + 1
    } coefficients (${bytes((srs.maxDegree + 1) * 32)}) still commits to those same 48 bytes. Act 3 lets you re-run the ceremony at a larger degree and watch the number stay put. Ethereum's ceremony runs to degree 4095 and its commitments are 48 bytes too.`
  }

  subscribe(() => {
    // Keep the inputs in step when something else changes the polynomial.
    inputs.forEach((input, i) => {
      const want = String(state.coefficients[i])
      if (input.value !== want && document.activeElement !== input) input.value = want
    })
    render()
  })
  render()

  return card(
    el('span', { class: 'act-kicker', text: 'ACT 1' }),
    el('h2', { text: 'Commit — one group element, whatever the degree' }),
    para(
      'Pick any coefficients you like. The commitment below is computed from them for real: it is the sum c0·[tau^0]1 + c1·[tau^1]1 + … over the ceremony\'s reference string, a multi-scalar multiplication in BLS12-381 G1. Change a coefficient and the point changes completely. Its SIZE never does.',
    ),
    panel('The polynomial', el('div', { class: 'row' }, [coefWrap]), polyOut),
    scrollRegion('Size comparison', sizeTable),
    panel('The commitment', commitOut),
    growLabel,
    deep(
      'Why the commitment is binding',
      para(
        'C = [p(tau)]1 hides p behind a discrete logarithm, so the commitment reveals nothing about the coefficients that is easy to extract. Binding is the other direction: to open C to a polynomial q with q != p you would need [p(tau)]1 = [q(tau)]1, that is (p - q)(tau) = 0, which means tau is a root of the non-zero polynomial p - q.',
      ),
      para(
        'A degree-d polynomial has at most d roots in a field of about 2^255 elements, so hitting one by chance is hopeless. But finding one deliberately is easy IF YOU KNOW TAU - and that is the whole of Act 4.',
      ),
      para(
        'Note also what the commitment is NOT: it is not hiding in the sense a Pedersen commitment is, because there is no blinding term. Two commits to the same polynomial produce the same point. Hiding variants add a blinding factor; this page does not, and says so rather than letting you assume it.',
      ),
    ),
  )
}

export { scalar }
