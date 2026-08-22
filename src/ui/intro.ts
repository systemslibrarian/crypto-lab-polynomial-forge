/**
 * The on-ramp: what a polynomial commitment is, in plain language, before any
 * hex or slider - and an honest statement of scope immediately after it.
 */
import { card, deep, el, panel, para, scrollRegion, table } from './dom.js'
import { DEGREE_UNENFORCED, DEGREE_UNENFORCED_EXPLANATION, FAILURE_CODES, FAILURE_EXPLANATIONS } from '../crypto/codes.js'

export function heroSection(): HTMLElement {
  const header = el('header', { class: 'cl-hero' }, [
    el('div', { class: 'cl-hero-main' }, [
      el('h1', { class: 'cl-hero-title', text: 'Polynomial Forge' }),
      el('p', { class: 'cl-hero-sub', text: 'KZG · IPA · FRI · BLS12-381' }),
      el('p', {
        class: 'cl-hero-desc',
        text: 'Commits one polynomial three ways, steps the division that makes an opening proof exist, then runs a powers-of-tau ceremony whose transcript verifies perfectly while every contributor keeps their toxic waste.',
      }),
    ]),
    el('aside', { class: 'cl-hero-why', 'aria-label': 'Why it matters' }, [
      el('span', { class: 'cl-hero-why-label', text: 'WHY IT MATTERS' }),
      el('p', {
        class: 'cl-hero-why-text',
        text: 'Every modern proof system - the ones securing rollups holding billions - rests on a polynomial commitment. The fastest of the three needs a ceremony nobody can audit for the one thing that matters, and the check that catches the other failure here is the one protocols forget to run.',
      }),
    ]),
  ])
  return header
}

export function introCard(): HTMLElement {
  const c = card(
    el('span', { class: 'act-kicker', text: 'START HERE' }),
    el('h2', { text: 'What is a polynomial commitment?' }),
    para(
      'Imagine you have a long list of numbers and you want to hand someone a short receipt for it - short enough to fit in a tweet - and then later answer questions about the list in a way they can check against that receipt. They should be able to catch you if you answer dishonestly, even though they never see the list.',
      'lede',
    ),
    para(
      'That is a polynomial commitment. The list becomes the coefficients of a polynomial. The receipt is one short value. And "what is the list\'s value at position z?" becomes "what is p(z)?" - a question you can answer with a small proof the holder of the receipt can check.',
    ),
    para(
      'This is the layer underneath almost every modern zero-knowledge proof system. A proof about a computation gets turned into a handful of claims about polynomials; the commitment scheme is what makes those claims short and checkable. Change the commitment scheme and you get a different proof system with the same logic - which is exactly what the three below are.',
    ),
    panel(
      'Notation, once',
      para(
        'Two pieces of shorthand run through the whole page. `[x]1` means "the number x hidden in the first group": the elliptic-curve point you get by adding the generator of G1 to itself x times. `[x]2` is the same thing in the second group, G2. Both are one-way - you can compute `[x]1` from x, and you cannot get x back out - which is exactly what makes them useful for hiding a value while still being able to check equations about it.',
      ),
      para(
        'So `C = [p(tau)]1` reads as "the commitment is the polynomial\'s value at the secret point tau, hidden in G1". Everything else is arithmetic on those hidden values.',
      ),
    ),
    deep(
      'Why polynomials, of all things?',
      para(
        'Because two different polynomials of degree at most d can agree in at most d places. Pick a random point out of a field with 2^255 elements and the chance they agree there is about d/2^255 - which is zero for any practical purpose. So checking a polynomial identity at ONE random point is as good as checking it everywhere.',
      ),
      para(
        'That single fact is what buys succinctness. A statement about a million-step computation becomes a polynomial identity; the verifier checks it at one point; the commitment scheme is what lets the prover answer at that point without handing over the polynomial.',
      ),
      para(
        'It is also why the field on this page is what it is. Every scheme here works over Fr, the scalar field of BLS12-381, a prime of about 2^255. FRI additionally needs a large power-of-two subgroup to fold over, and Fr obliges: r - 1 is divisible by 2^32.',
      ),
    ),
  )
  return c
}

export function scopeCard(): HTMLElement {
  return card(
    el('span', { class: 'act-kicker', text: 'SCOPE' }),
    el('h2', { text: 'What is real here, and what this does not prove' }),
    el('p', { class: 'lede' }, [
      document.createTextNode('This is '),
      el('strong', { text: 'not production cryptography' }),
      document.createTextNode(
        ' - it is a teaching demo. Everything cryptographic on this page is real and runs in your browser; nothing is mocked, stubbed or replayed from a recording.',
      ),
    ]),
    el('div', { class: 'grid-2' }, [
      el('div', {}, [
        el('h3', { text: 'Real' }),
        el('ul', {}, [
          el('li', {
            text: 'Real BLS12-381 group and pairing arithmetic from @noble/curves. The pairing is not the subject here - crypto-lab-pairing-gate takes it apart - so it comes from an audited library rather than being hand-rolled.',
          }),
          el('li', {
            text: 'Everything above the group operations is hand-rolled in this repo and meant to be read: the polynomial division, the commitment and verification algebra, the degree-bound check, the ceremony and its pairing checks, both attacks, the inner-product argument, and FRI.',
          }),
          el('li', {
            text: 'Real randomness from the browser CSPRNG for every ceremony factor.',
          }),
          el('li', {
            text: 'The verification code on this page is pinned against all 122 published EIP-4844 verify_kzg_proof vectors, and against the Ethereum mainnet ceremony output, in the test suite.',
          }),
        ]),
      ]),
      el('div', {}, [
        el('h3', { text: 'Not real, and not claimed to be' }),
        el('ul', {}, [
          el('li', {
            text: 'The ceremony runs in one browser tab, not across months and continents. What is faithful is the algebra and every check the transcript supports; what is not is any claim about who actually held what.',
          }),
          el('li', {
            text: 'All three commitments are in their BINDING, non-hiding form. A hiding variant adds blinding terms. Hiding is not what this page is about, and it changes none of the sizes compared below.',
          }),
          el('li', {
            text: 'FRI here uses teaching-grade parameters chosen so the page responds instantly. The soundness figure it prints is labelled a heuristic because that is what it is.',
          }),
          el('li', {
            text: 'One opening at a time, coefficient basis. Production KZG batches many openings across many polynomials and works in Lagrange basis.',
          }),
        ]),
      ]),
    ]),
    el('h3', { text: 'What this page does NOT prove' }),
    el('ul', {}, [
      el('li', {
        text: 'That KZG is broken. It is not. Act 4 breaks the ASSUMPTION KZG rests on - that nobody knows the trapdoor - and then shows what a verifier does when that assumption is false.',
      }),
      el('li', {
        text: 'That an unenforced degree bound breaks evaluation binding. It does not, and Act 5 is written specifically to stop you concluding that.',
      }),
      el('li', {
        text: 'Anything about the real Ethereum KZG ceremony, which had over 140,000 participants. This page cannot tell you whether any of them erased anything - and neither, as Act 4 shows, can its transcript.',
      }),
    ]),
  )
}

export function failureCodeCard(): HTMLElement {
  const rows = FAILURE_CODES.map((code) => ({
    cells: [code, FAILURE_EXPLANATIONS[code]] as (string | Node)[],
  }))
  return card(
    el('span', { class: 'act-kicker', text: 'REFERENCE' }),
    el('h2', { text: 'What the verifier can say' }),
    para(
      'A verifier that can only say "no" teaches nothing. Every rejection on this page names which check failed, and the codes are deliberately not interchangeable - telling them apart is most of the lesson in the two attack acts.',
    ),
    scrollRegion(
      'The five failure codes',
      table({
        caption: 'The five failure codes, and the one thing that is not a failure code.',
        head: ['Code', 'What it means'],
        rows,
      }),
    ),
    para(
      'One honesty note about that list. `PAIRING_FAIL` and `DEGREE_EXCEEDED` are the two that come from the cryptography itself: they are equations that did not hold. `MALFORMED_PROOF` is a parsing decision, and `POINT_MISMATCH` and `SETUP_MISMATCH` are this page\'s framing rather than anything in the KZG scheme — a production verifier such as Ethereum\'s `c-kzg` takes (commitment, z, y, proof) and returns a bare boolean, leaving it to the caller to have asked about the right point against the right setup. Naming those two here is a teaching choice, because "your proof is about something else" and "your proof is false" are different mistakes and a bare boolean cannot tell them apart.',
    ),
    el('div', { class: 'banner', role: 'note' }, [
      el('span', { class: 'verdict-icon', 'aria-hidden': 'true', text: '[!]' }),
      el('div', { class: 'verdict-body' }, [
        el('span', { class: 'banner-label', text: `${DEGREE_UNENFORCED} is not a failure code` }),
        el('p', { text: DEGREE_UNENFORCED_EXPLANATION }),
      ]),
    ]),
  )
}

export function scriptureFooter(): HTMLElement {
  return el('footer', { class: 'scripture-footer' }, [
    el('p', {
      text: 'So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31',
    }),
  ])
}
