/**
 * Act 6 - the three-way comparison, and Act 7 - why Groth16 is not a fourth row.
 *
 * Every figure in the table is measured here, now, on the polynomial from Act 1
 * at the opening point from Act 2. Nothing is quoted from a paper.
 */
import { button, card, deep, el, panel, para, scrollRegion, table } from './dom.js'
import { bytes, ms, polyText, scalar } from './format.js'
import { verdictBox } from './verdict.js'
import { GROTH16_CONTRAST, runComparison, type SchemeRow } from '../crypto/compare.js'
import { DEFAULT_FRI_PARAMS } from '../crypto/fri.js'
import { state, subscribe } from './state.js'
import { guarded } from './guard.js'

export function actCompare(): HTMLElement {
  const tableWrap = el('div')
  const meta = el('div')
  const verdict = verdictBox('compare-verdict')

  const runBtn = button(
    'Measure all three, now',
    guarded(verdict, () => {
      const t0 = performance.now()
      const result = runComparison({
        srs: state.ceremony.srs,
        coefficients: state.coefficients,
        z: state.z,
        ipa: state.ipa,
        friParams: DEFAULT_FRI_PARAMS,
        repeats: 3,
      })
      const totalMs = performance.now() - t0

      const rows = result.rows.map((r: SchemeRow) => ({
        cells: [
          r.name,
          r.usedBy,
          r.setup,
          bytes(r.commitmentBytes),
          bytes(r.proofBytes),
          r.proofSizeOrder,
          r.verifyCostOrder,
          ms(r.verifyMs),
          el('span', {
            class: r.postQuantum ? 'tag-ok' : 'tag-bad',
            text: r.postQuantum ? '[+] yes' : '[x] no',
          }),
          el('span', {
            class: r.verified ? 'tag-ok' : 'tag-alarm',
            text: r.verified ? '[+] verified' : '[!] FAILED',
          }),
        ] as (string | Node)[],
        cellClasses: [undefined, undefined, undefined, 'num', 'num', undefined, undefined, 'num'],
      }))

      tableWrap.replaceChildren(
        scrollRegion(
          'Three-way comparison of commitment schemes',
          table({
            caption: `All three committing to p(X) = ${polyText(
              state.coefficients,
            )} and opening it at z = ${scalar(state.z)}. Timings are the median of 3 runs on this machine, just now.`,
            head: [
              'scheme',
              'used by',
              'setup',
              'commitment',
              'proof',
              'proof size',
              'verifier cost',
              'verify time',
              'post-quantum',
              'ran',
            ],
            rows,
          }),
        ),
      )

      const kzg = result.rows[0]
      const ipa = result.rows[1]
      const fri = result.rows[2]
      meta.replaceChildren(
        el('dl', { class: 'kv', id: 'compare-detail' }, [
          el('dt', { text: 'polynomial' }),
          el('dd', { text: `degree ${result.degree}, padded to ${DEFAULT_FRI_PARAMS.n} coefficients for IPA and FRI` }),
          el('dt', { text: 'opening' }),
          el('dd', { text: `p(${scalar(result.z)}) = ${scalar(result.y)}` }),
          el('dt', { text: 'FRI parameters' }),
          el('dd', {
            text: `blowup ${DEFAULT_FRI_PARAMS.blowup}, ${DEFAULT_FRI_PARAMS.queries} queries, folding down to ${DEFAULT_FRI_PARAMS.finalSize} points`,
          }),
          el('dt', { text: 'FRI soundness' }),
          el('dd', { text: `about ${result.friHeuristicBits} bits, HEURISTIC. ${result.friCaveat}` }),
          el('dt', { text: 'size ratio' }),
          el('dd', {
            text: `KZG ${kzg.proofBytes} B · IPA ${ipa.proofBytes} B (${(
              ipa.proofBytes / kzg.proofBytes
            ).toFixed(1)}x) · FRI ${fri.proofBytes} B (${(fri.proofBytes / kzg.proofBytes).toFixed(0)}x)`,
          }),
          el('dt', { text: 'whole measurement took' }),
          el('dd', { text: ms(totalMs) }),
        ]),
      )

      const allOk = result.rows.every((r) => r.verified)
      verdict.set(
        allOk ? 'ok' : 'alarm',
        allOk ? 'ALL THREE VERIFIED' : 'A SCHEME FAILED',
        allOk
          ? 'Three different commitment schemes, one polynomial, one opening point, three proofs that all check out. What differs is the price: what you have to trust, how many bytes travel, how much work the verifier does, and whether a quantum computer ends it.'
          : 'One of the three did not verify. Treat that as a bug in this page rather than a result about the scheme.',
      )
    }),
    { class: 'primary', id: 'compare-run' },
  )

  subscribe((_s, reason) => {
    verdict.retire(`${reason}, so the measurements below are stale. Measure again.`)
    tableWrap.replaceChildren()
    meta.replaceChildren()
  })

  return card(
    el('span', { class: 'act-kicker', text: 'ACT 6' }),
    el('h2', { text: 'Three schemes, one polynomial' }),
    para(
      'KZG, an inner-product argument, and FRI all do the same job: commit to a polynomial, then prove its value at a point. They disagree about almost everything else. Press the button and all three run here, on the polynomial from Act 1, at the opening point from Act 2.',
      'lede',
    ),
    el('div', { class: 'stepper-controls' }, [runBtn]),
    verdict.root,
    tableWrap,
    panel('What was measured', meta),
    el('p', {
      class: 'compare-note',
      text: 'The timings are this implementation on this machine, not a benchmark of the schemes: production KZG batches openings, production FRI uses an NTT and a field-tuned hash, and none of that is here. What survives that caveat is the SHAPE — constant against logarithmic against polylogarithmic — because that is a property of the mathematics rather than of the code.',
    }),
    deep(
      'IPA — how a logarithmic proof happens',
      para(
        'Evaluating a polynomial is an inner product: p(z) = <c, b> where b = (1, z, z^2, …). So proving an evaluation is proving an inner product against a vector the verifier can build itself.',
      ),
      para(
        'The argument folds both vectors in half each round, sending two group elements per round to keep the folded commitment honest. After log2(n) rounds one scalar is left and the prover sends it. That is 2·log2(n) points plus a scalar — logarithmic, with no trusted setup anywhere, because the generators come from hash-to-curve on a public tag.',
      ),
      para(
        'Verification is linear all the same. The verifier has to rebuild the folded generator, and that is an n-sized multi-scalar multiplication over the original generators. There is no way around it — the generators are the only thing tying the folded proof back to the original commitment.',
      ),
      para(
        'The same argument, doing its more famous job, is in crypto-lab-bulletproofs: range proofs rather than polynomial commitments, same folding.',
      ),
    ),
    deep(
      'FRI — how a hash function becomes a commitment scheme',
      para(
        'Evaluate p on a domain BLOWUP times larger than it needs to be and Merkle-commit the evaluations. The redundancy is the point: a genuine low-degree polynomial fills only a 1/BLOWUP fraction of the space of all functions on that domain, so two different low-degree polynomials disagree almost everywhere and a few random spot checks catch a cheat.',
      ),
      para(
        'To open at z, form q(X) = (p(X) − y)/(X − z) — the same division as Act 2, for the same reason — and prove q is low degree. That proof folds q in half repeatedly, each round replacing q with a random combination of its even and odd parts, until what is left is small enough to send outright. The verifier spot-checks that each layer really is the fold of the one before it.',
      ),
      para(
        'Nothing here rests on a discrete log or a pairing, only on a hash. That is why FRI is the only post-quantum row in the table. Grover halves the effective security of a hash; it does not break the construction the way Shor breaks a discrete log.',
      ),
      para('crypto-lab-stark-tower runs FRI in its usual setting, as the engine of a STARK.'),
    ),
  )
}

export function actGroth16(): HTMLElement {
  return card(
    el('span', { class: 'act-kicker', text: 'ACT 7' }),
    el('h2', { text: GROTH16_CONTRAST.heading }),
    para(
      'PLONK-style, Bulletproofs-style and STARK-style systems all appear in the table above because all three are built the same way: an information-theoretic protocol about polynomials, plus a commitment scheme that makes it succinct. Groth16 is a zk-SNARK with a trusted setup too, so it looks like it belongs. It does not, and the reason is worth an act rather than a footnote.',
      'lede',
    ),
    el(
      'div',
      { class: 'stack-tight' },
      GROTH16_CONTRAST.claims.map((c) =>
        el('div', { class: 'panel' }, [el('h3', { text: c.label }), el('p', { text: c.body })]),
      ),
    ),
    para(
      'The practical consequence is the one people meet first. A KZG ceremony is UNIVERSAL: run it once, and every circuit up to its degree bound can use it — which is why Ethereum ran one ceremony and not one per application. Groth16 needs a fresh ceremony for every circuit, and every one of them carries the whole of Act 4 with it.',
    ),
    deep(
      'What "polynomial IOP plus commitment" buys you',
      para(
        'Designing a proof system in two layers means the layers can be swapped. Halo took the PLONK-shaped protocol and put IPA underneath it, and the trusted setup disappeared. The STARK family put FRI underneath and got post-quantum security. Neither had to redesign the argument, because the argument was never entangled with the commitment.',
      ),
      para(
        'Groth16 has no such seam. Its structured reference string encodes the QAP — the arithmetisation of one specific circuit — directly, and its verification is a single fixed pairing equation over three group elements. There is nothing to swap.',
      ),
      para(
        'It is not that Groth16 is worse. Three group elements is smaller than anything in the table above, and for a circuit that never changes it is often the right answer. The point is that the ceremony question, and everything Act 4 shows about it, applies to Groth16 once per circuit rather than once ever — and that the commitment layer this page is about simply is not there to examine.',
      ),
    ),
  )
}
