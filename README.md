# Polynomial Forge

**KZG · IPA · FRI · Polynomial Commitment Schemes · BLS12-381**

A browser demo of the commitment layer underneath modern zero-knowledge proof systems. It commits
one polynomial three ways, steps the division that makes an opening proof exist at all, runs a real
multi-party powers-of-tau ceremony, and then shows two failures that leave every cryptographic check
green: a ceremony whose transcript verifies perfectly while every contributor keeps their toxic
waste, and a degree bound nobody enforced.

> **Not production cryptography — a teaching demo.**

**[Open the live demo →](https://systemslibrarian.github.io/crypto-lab-polynomial-forge/)**

---

## What It Is

Three polynomial commitment schemes, all committing to the same polynomial over `Fr`, the scalar
field of BLS12-381:

| Scheme | Powers | Setup | Proof | Verify | Post-quantum |
|---|---|---|---|---|---|
| **KZG** (Kate–Zaverucha–Goldberg, 2010) | PLONK-style systems | trusted, universal | constant | constant — one pairing equation | no |
| **IPA** (inner-product argument; Bootle et al. 2016, Bünz et al. 2018) | Bulletproofs / Halo-style systems | transparent | logarithmic | linear | no |
| **FRI** (Ben-Sasson et al. 2018) | STARK-style systems | transparent | polylogarithmic | polylogarithmic | yes |

**The problem.** A proof about a computation gets turned into a handful of claims about
polynomials. Somebody has to make those claims short and checkable without handing over the
polynomial. That is what a polynomial commitment does, and it is why changing the commitment scheme
gives you a different proof system with the same logic — which is exactly what Halo (IPA under a
PLONK-shaped protocol) and the STARK family (FRI) are.

**The exact primitives.**

- **KZG on BLS12-381.** Commit `C = [p(τ)]₁ = Σ cᵢ·[τⁱ]₁`. Open at `z` with the quotient
  `q(X) = (p(X) − y)/(X − z)` and `π = [q(τ)]₁`. Verify `e(C − [y]₁, [1]₂) = e(π, [τ − z]₂)`.
  Degree bounds are enforced — when you switch them on — by the standard shifted-commitment check
  `e(C_shift, [1]₂) = e(C, [τ^(D−d)]₂)`.
- **Powers of tau**, multi-party, with Bowe–Gabizon–Miers proofs of knowledge
  (`e(s, [r]h) = e([r]s, h)`) and full geometric-series consistency
  (`e([τʲ]₁, [1]₂) = e([τʲ⁻¹]₁, [τ]₂)` for every `j`).
- **IPA** in the Bulletproofs/Halo form: generators from hash-to-curve on a public tag, `log₂(n)`
  folding rounds, `2·log₂(n)` group elements plus one scalar.
- **FRI** with a DEEP quotient, a coset evaluation domain, SHA-256 Merkle commitments over
  value pairs, and Fiat-Shamir challenges.

**Security model.** All three are implemented in their **binding, non-hiding** form. Hiding
variants add blinding terms; hiding is not what this page is about and is named as out of scope
rather than left to be assumed. Randomness comes from the browser CSPRNG. Nothing is persisted and
there is no backend.

**Not production cryptography.** Real deployments batch openings across many polynomials, work in
Lagrange basis, use a fixed ceremony output, and run FRI with an NTT and a field-tuned hash. This
lab is coefficient-basis, single-opening, and written to be read. The FRI parameters are chosen so
the page responds instantly, and the soundness figure it prints is labelled a heuristic because
that is what it is.

**Where the crypto comes from.** BLS12-381 group and pairing arithmetic is `@noble/curves`
(audited, dependency-free, and what the rest of this fleet uses); SHA-256 is `@noble/hashes`. The
pairing is not the teaching subject here — [Pairing Gate](https://systemslibrarian.github.io/crypto-lab-pairing-gate/)
takes it apart — so it comes from a library rather than being hand-rolled. **Everything above the
group operations is hand-rolled in `src/crypto/` and meant to be inspected**: the polynomial
division, the commitment and verification algebra, the degree-bound check, the ceremony and its
pairing checks, both attacks, the inner-product argument, and FRI.

---

## Exhibits

1. **Commit.** Edit the coefficients and watch the polynomial's own size grow while the commitment
   stays at 48 bytes. Both sizes are measured, not asserted, and the commitment is a real
   multi-scalar multiplication against the ceremony's reference string.
2. **Open and verify — the mechanism.** The synthetic-division tableau for `(p(X) − y) ÷ (X − z)`,
   steppable row by row, with the remainder cell in plain sight. Change the claimed value and the
   remainder stops being zero in front of you; press verify and the real pairing agrees. Four
   tamper buttons then break a genuine proof four specific ways, one per failure code.
3. **The ceremony.** A real multi-party powers-of-tau run: each participant draws a factor,
   rescales every power in the exponent, and publishes a proof of knowledge. The transcript audit is
   a table of real pairing equations computed from the public record alone.
4. **Toxic waste (Attack 1).** Set every participant to keep their factor. The audit stays green,
   row for row, word for word. Then multiply the factors, recover τ, and forge an opening for any
   value you like — which the same verifier from Exhibit 2 accepts.
5. **The degree bound nobody checked (Attack 2).** An over-degree witness that hits every
   constraint point. Every KZG opening verifies, no failure code is available, and a standing
   `DEGREE_UNENFORCED` banner says so. Switch enforcement on and the same witness is refused with
   `DEGREE_EXCEEDED`.
6. **Three schemes, one polynomial.** All three measured in your browser on the same polynomial at
   the same opening point: setup type, commitment size, proof size, verifier cost, and
   post-quantum status.
7. **Why Groth16 is not on the list.** The contrast between a monolithic SNARK with a
   circuit-specific structured reference string and a polynomial-IOP-plus-commitment design.

---

## When to Use It

**Use a polynomial commitment when** you need to prove statements about large amounts of data
succinctly — rollup validity proofs, verifiable computation, data-availability sampling (this is
what EIP-4844 blob commitments are), vector commitments, and verifiable secret sharing.

**Choose KZG when** proof size and verifier cost dominate and a universal ceremony is acceptable —
one ceremony serves every circuit up to its degree bound. **Choose IPA when** you cannot accept a
trusted setup and can afford linear verification. **Choose FRI when** you need post-quantum
security or want no setup at all, and can afford proofs measured in tens of kilobytes.

**Do NOT use this code for anything.** It is a teaching implementation: single-opening,
coefficient-basis, non-hiding, with FRI parameters chosen for page responsiveness rather than for a
security target. For real work use `c-kzg-4844`, `arkworks`, `halo2`, or `winterfell`.

**Do NOT use KZG at all** if you cannot point at a specific ceremony and say who ran it and why you
believe at least one participant destroyed their contribution. Exhibit 4 exists because that
sentence is the entire security argument, and no transcript can supply it for you.

---

## Live Demo

**<https://systemslibrarian.github.io/crypto-lab-polynomial-forge/>**

You can: edit a polynomial and watch its commitment stay 48 bytes; step a synthetic division and
see why the remainder has to be zero; type a wrong value and have the real pairing reject it; break
a real proof four ways and see a different failure code for each; run a powers-of-tau ceremony with
one to six participants at three different degrees; make every participant dishonest and watch the
audit stay green; recover the trapdoor and forge an accepted proof of something false; run an
over-degree witness past a verifier that never checks degree; and measure all three schemes against
each other.

---

## What Can Go Wrong

This is the threat model, and most of it is on the page rather than in this file.

**A ceremony transcript cannot prove erasure (NEG-2).** Every check a powers-of-tau transcript
supports is a statement about published points: that a contribution is well-formed, that the
contributor knew their factor, that the finished SRS is powers of one τ. Erasure is a statement
about a value that is by construction not published, and about an event in the physical world.
Exhibit 4 runs the identical audit over an honest ceremony and a fully dishonest one and the output
is byte-for-byte the same. The mitigation is not a better check — it is more participants, so that
"at least one was honest and careful" becomes a cheap assumption. It is still an assumption about
people.

**Knowing τ destroys binding entirely.** With τ as a scalar the verification equation stops being a
test and becomes an equation you can solve: `π = [(p(τ) − y)/(τ − z)]₁` satisfies it for any `y`.
The forger has to be the prover (or know the polynomial), because recovering `p(τ)` from `C` is a
discrete log — but a prover who compromised the ceremony can open one commitment to any value at
any point.

**A commitment binds a polynomial, not a statement about it (NEG-1).** Nothing in the KZG
verification equation mentions degree. A verifier that checks only openings has checked that the
committed polynomial passes through the constrained points and nothing else, and
`p(X) + Z(X)·h(X)` passes through exactly the same points for any `h`. Exhibit 5 is that attack.
**It does not break evaluation binding** — the cheating witness is a different polynomial with a
different commitment, and neither commitment opens to two values at one point. What is false is the
protocol's low-degree claim, one layer above. The mitigation is the shifted-commitment check, and
the reason it works is that the cheating prover cannot produce the input — which is exactly why it
has to be run.

**Fiat-Shamir binds only what it absorbs.** Both the IPA and FRI on this page are public-coin
protocols made non-interactive by hashing the transcript. Absorbing too little is the Frozen Heart
class of bug — see [Frozen Heart](https://systemslibrarian.github.io/crypto-lab-frozen-heart/).
`src/crypto/transcript.ts` length-prefixes every item so no two message sequences can collide.

**Structural checks before algebra.** A non-canonical scalar (a 32-byte value at or above `r`) or a
point on the curve but outside the prime-order subgroup that reached a pairing would be checking a
different statement than the one asked. The parser refuses both, and reports `MALFORMED_PROOF`
rather than a false `PAIRING_FAIL`.

**Failure codes.** `PAIRING_FAIL` · `POINT_MISMATCH` · `SETUP_MISMATCH` · `MALFORMED_PROOF` ·
`DEGREE_EXCEEDED`. Every one is reachable from the page, and `e2e/claims.spec.ts` asserts that the
set the page documents is exactly the set it can emit. `DEGREE_UNENFORCED` is deliberately **not**
a failure code: it is a standing banner about the verifier's configuration, because rendering the
omission as a rejection would misrepresent what a real verifier experiences, which is silence.

---

## Real-World Usage

- **EIP-4844 (Ethereum, 2024).** Blob commitments are KZG on BLS12-381, over a setup produced by a
  ceremony with more than 140,000 participants. This lab's KZG verification is pinned against all
  122 published `verify_kzg_proof` vectors from that specification, and against the mainnet
  ceremony output itself.
- **PLONK and its descendants** (Halo2, Plonky, Aztec, zkSync, Scroll) use KZG or IPA as the
  commitment under a polynomial IOP. Swapping the commitment is how Halo removed the trusted setup.
- **STARKs** (StarkWare, Polygon Miden, RISC Zero, Winterfell) use FRI, which is why they are
  post-quantum and why their proofs are measured in tens or hundreds of kilobytes.
- **Verkle trees**, proposed for Ethereum state, are built from polynomial commitments rather than
  hashes precisely because the commitment is constant-size regardless of arity.

---

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-polynomial-forge.git
cd crypto-lab-polynomial-forge
npm install
npm run dev          # http://localhost:5173/crypto-lab-polynomial-forge/
```

```bash
npm test             # the unit and KAT suite
npm run build        # tsc --noEmit && vite build
npx playwright install chromium
npm run test:a11y    # the WCAG 2.1 AA gate, against the production build
npm run test:claims  # the claims suite: does the page tell the truth
```

---

## Related Demos

- **[Pairing Gate](https://systemslibrarian.github.io/crypto-lab-pairing-gate/)** — the BLS12-381
  pairing itself, taken apart. This lab uses it; that one explains it.
- **[Bulletproofs](https://systemslibrarian.github.io/crypto-lab-bulletproofs/)** — the
  inner-product argument in its more famous job, proving ranges.
- **[STARK Tower](https://systemslibrarian.github.io/crypto-lab-stark-tower/)** — FRI as the engine
  of a STARK rather than as a standalone commitment.
- **[SNARK Arena](https://systemslibrarian.github.io/crypto-lab-snark-arena/)** — Groth16 end to
  end, which is the system Exhibit 7 contrasts against.
- **[Frozen Heart](https://systemslibrarian.github.io/crypto-lab-frozen-heart/)** — what happens
  when a Fiat-Shamir transcript absorbs too little.
- **[Commit Gate](https://systemslibrarian.github.io/crypto-lab-commit-gate/)** — commitment
  schemes at their simplest, hiding and binding on a single value.
- **[Context Ward](https://systemslibrarian.github.io/crypto-lab-context-ward/)** — the same shape
  as Exhibit 4 in a different setting: every check green, the system owned anyway.

---

## Build & Verify

Vite + TypeScript, static, no backend. `npm test` runs **291 unit tests** across 11 files.

**Known-answer tests.** `src/crypto/__vectors__/eip4844.json` pins the Ethereum EIP-4844 trusted
setup prefix and all **122 published `verify_kzg_proof` vectors**, recorded with the repository,
commit SHA, and URLs they were fetched from. `src/crypto/kat.test.ts` runs them, and it pins two
independent things:

1. **That the fixture is genuine.** The pinned G1 monomial powers are checked against the pinned G2
   powers by pairing — `e([τʲ]₁, [1]₂) = e([τʲ⁻¹]₁, [τ]₂)` for every power — so a transcription
   error cannot pass. That is a test of the data, before any test of the code.
2. **That this lab's verifier agrees with the reference implementation** on all 122 cases,
   including the tri-state distinction between `invalid` (well-formed, wrong) and `error`
   (malformed input, which must be refused before any algebra).

Then the lab's own commit/open/verify runs end to end against the mainnet SRS, so a bug anywhere in
the pipeline shows up as a failed pairing against Ethereum's ceremony rather than against our own.

**The accessibility gate.** `npm run test:a11y` scans the *production build* served by
`vite preview` for zero WCAG 2.1 A/AA violations, across every state the lab teaches, at desktop
and 380px width. It asserts axe's `incomplete` bucket as well as `violations`, computes contrast
arithmetically over composited surfaces, measures non-text (1.4.11) contrast against a ratchet
baseline that is currently empty, and checks reflow (1.4.10), which axe has no rule for at all. The
GitHub Pages deploy is blocked if any of it fails.

**The claims suite.** `npm run test:claims` checks that the page tells the truth: the division
tableau re-derived cell by cell from the inputs on screen, `remainder + y = p(z)`, the recovered
trapdoor recomputed as the product of the factors the page listed, the two negative claims asserted
as fixtures, every failure code reached through its own path, verdict retirement, and a no-op guard
that a re-selection does not retire a fresh result.

---

## Performance

Measured in-browser and reported on the page rather than quoted here, because the numbers are
whatever your machine does. The shapes are stable: a KZG proof is 112 bytes and verifies with one
two-pairing check; an IPA proof over 16 coefficients is 480 bytes and verifies with an n-sized
multi-scalar multiplication; a FRI proof at blowup 8 with 20 queries is about 22 KB and verifies in
polylogarithmic time. The ceremony costs one scalar multiplication per power per participant and
one pairing per power to audit, which is why the degree-128 option takes a few seconds and says so.

---

*One of the browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
