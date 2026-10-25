import { Fr } from '../crypto/fr.js'
import { g1ToHex } from '../crypto/bls.js'
import { commit, open, verify } from '../crypto/kzg.js'
import { forgePrematureBatch, verifyBatch, type Pair } from '../crypto/batch.js'
import { polyEval } from '../crypto/poly.js'
import { button, card, deep, el, para, replace, scrollRegion, table } from './dom.js'
import { guarded } from './guard.js'
import { state, subscribe } from './state.js'
import { verdictBox } from './verdict.js'

export function actBatch(): HTMLElement {
  const early = verdictBox('batch-early')
  const bound = verdictBox('batch-bound')
  const results = el('div', { id: 'batch-results', hidden: true })
  const scenario = el('select', { id: 'batch-case' }, [
    el('option', { value: 'honest', text: 'Honest openings (control)' }),
    el('option', { value: 'attack', text: 'Construct false openings after the challenge' }),
  ])
  const point = el('select', { id: 'batch-point' }, [
    el('option', { value: '5', text: '5' }), el('option', { value: '7', text: '7' }),
  ])
  let previous = `${scenario.value}/${point.value}`
  function retire(reason: string) {
    early.retire(reason)
    bound.retire(reason)
    results.hidden = true
    replace(results)
  }
  for (const input of [scenario, point]) input.addEventListener('change', () => {
    const next = `${scenario.value}/${point.value}`
    if (next === previous) return
    previous = next
    retire('The batch inputs changed. Run the comparison again.')
  })
  // This exhibit shares only the ceremony, not the editable polynomial above.
  let digest = state.ceremony.srs.digest
  subscribe(() => {
    if (digest === state.ceremony.srs.digest) return
    digest = state.ceremony.srs.digest
    retire('The ceremony changed. Run the comparison against the new public setup.')
  })
  const run = button('Compare both batch verifiers', guarded(early, () => {
    results.hidden = true
    replace(results)
    bound.retire('Comparison is being recomputed.')
    const srs = state.ceremony.srs
    const polynomial = [3n, 2n, 1n]
    const C = commit(srs, polynomial)
    const points = [2n, BigInt(point.value)] as const
    const honest: Pair = [
      { commitment: C, proof: open(srs, polynomial, points[0]) },
      { commitment: C, proof: open(srs, polynomial, points[1]) },
    ]
    const attacking = scenario.value === 'attack'
    const claims: Pair = [
      { ...honest[0], proof: { ...honest[0].proof, y: Fr.add(honest[0].proof.y, 1n) } },
      { ...honest[1], proof: { ...honest[1].proof, y: Fr.add(honest[1].proof.y, 2n) } },
    ]
    const entries = attacking ? forgePrematureBatch(srs, claims) : honest
    const checks = entries.map(e => verify(srs, e.commitment, e.proof.z, e.proof.y, e.proof))
    const premature = verifyBatch(srs, entries, false)
    const complete = verifyBatch(srs, entries, true)
    const falseClaim = entries.some(e => e.proof.y !== polyEval(polynomial, e.proof.z))
    for (const [view, result] of [[early, premature], [bound, complete]] as const) {
      view.set(result.ok ? (falseClaim ? 'alarm' : 'ok') : 'rejected',
        result.ok ? (falseClaim ? 'ACCEPTED — AND FALSE' : 'ACCEPTED — TRUE') : 'REJECTED',
        result.ok ? 'The actual weighted pairing equation holds.' : 'The actual weighted pairing equation fails.')
    }
    replace(results,
      scrollRegion('Individual opening results', table({ caption: 'Check each opening before batching',
        head: ['Point z', 'True p(z)', 'Claimed y', 'Individual verifier'],
        rows: entries.map((e, i) => ({ cells: [String(e.proof.z), String(polyEval(polynomial, e.proof.z)),
          String(e.proof.y), checks[i].ok ? 'ACCEPTED' : 'REJECTED'] })),
      })),
      para(falseClaim
        ? 'The attack chooses two proof points after learning the premature challenge. Their errors cancel in that weighted check. Hashing both proof points changes the challenge and this constructed attack is rejected.'
        : 'Both claims are true and both batch verifiers check their real proofs. Acceptance here does not establish that a verifier resists malicious proofs.'),
      deep('Inspect the challenge order and group equations',
        para('Premature: hash(setup, commitments, points, values) → u → choose W1, W2. Bound: choose W1, W2 → hash(setup, commitments, points, values, W1, W2) → u.'),
        para('F1 = C1 − y1G, F2 = C2 − y2G. Each verifier checks e(F1 + uF2 + z1W1 + uz2W2, G2) = e(W1 + uW2, [τ]G2).'),
        para('For the attack, public A = G and B = [τ]G satisfy e(B,G2) = e(A,[τ]G2). Solve W1 = (B − F1 − uF2 − z2A)/(z1 − z2), W2 = (A − W1)/u. This uses public points, not the secret τ.'),
        el('pre', { id: 'batch-bytes', class: 'batch-bytes', text: [
          `Setup digest: ${srs.digest}`, `Premature u: ${premature.u}`, `Proof-bound u: ${complete.u}`,
          `Commitment: ${g1ToHex(C)}`, ...entries.map((e, i) => `W${i + 1}: ${g1ToHex(e.proof.witness)}`),
          `Premature weighted witness: ${g1ToHex(premature.weightedWitness)}`,
          `Premature weighted claim: ${g1ToHex(premature.weightedClaim)}`,
          `Bound weighted witness: ${g1ToHex(complete.weightedWitness)}`,
          `Bound weighted claim: ${g1ToHex(complete.weightedClaim)}`,
        ].join('\n') }),
      ),
    )
    results.hidden = false
  }), { id: 'batch-run' })
  const section = card(
    el('h2', { text: 'The last challenge: when two false openings cancel' }),
    para('Batch verification combines several checks into one using a challenge as a weight. Predict: if a prover learns that weight before choosing its proofs, can two wrong answers cancel?'),
    para('This separate example commits to p(X) = 3 + 2X + X² using the public setup from the ceremony above. The first opening point is 2. Honest mode starts with true values; attack mode adds 1 and 2 to those values, then constructs two proof points using only public information.'),
    el('div', { class: 'field' }, [el('label', { for: 'batch-case', text: 'Opening construction' }), scenario]),
    el('div', { class: 'field' }, [el('label', { for: 'batch-point', text: 'Second opening point' }), point]),
    run,
    el('h3', { text: 'Premature challenge — proof points omitted' }), early.root,
    el('h3', { text: 'Proof-bound challenge — both proof points included' }), bound.root,
    results,
    para('Scope: a two-opening KZG batch counterexample from the paper’s linear-system attack. This is not a complete PLONK exploit, a break of correctly implemented KZG, or a recovery of the ceremony secret. The repaired control demonstrates rejection of this attack; it is not a security proof for every protocol.'),
    el('p', {}, ['Source: ', el('a', { href: 'https://eprint.iacr.org/2024/398', text: 'The Last Challenge Attack on Fiat-Shamir in KZG-based SNARKs' }), ', §4.1, equation (11), PDF page 10.']),
  )
  section.id = 'batch-act'
  return section
}
