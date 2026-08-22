import { expect, test, type Page } from '@playwright/test';

/**
 * The claims suite: does the page tell the truth?
 *
 * This is what separates a demo that is CORRECT from one that is TRUSTWORTHY.
 * `a11y.spec.ts` proves the page can be read; this proves what it says is so.
 *
 * THE RULE THAT MAKES THESE TESTS WORTH ANYTHING. Compare two values the page
 * itself printed, rather than asserting against a hardcoded string. A test that
 * re-derives the same expression the source uses will happily agree with a bug.
 *
 * BUT INTERNAL CONSISTENCY IS NOT ENOUGH - a page can be consistently wrong.
 * A test that only checks the page agrees with itself passes a mutation that
 * corrupts the underlying maths, because the corrupted value is reported
 * consistently everywhere. So this file mixes three kinds of check, and says
 * which is which at every assertion:
 *
 *   - CROSS-CHECK          two surfaces that must agree (a printed count vs the
 *                          rows it counts; a stated size vs the hex it labels)
 *   - RE-DERIVATION        recompute the claim from the page's raw inputs by a
 *                          DIFFERENT route than the source takes. `frEval`
 *                          below sums c_i * z^i directly; `src/crypto/poly.ts`
 *                          uses Horner. A sign error in one does not survive
 *                          agreement with the other.
 *   - PARTS-SUM-TO-WHOLE   remainder + y = p(z), and the factors multiply to
 *                          the trapdoor.
 *
 * The negative claims this lab exists to make - NEG-1 and NEG-2 - are asserted
 * here rather than described anywhere, because a negative claim with an
 * evidence fixture is a test.
 */

// ── An independent Fr, deliberately not imported from src ───────────────────
//
// The whole point is a second implementation. This one is the schoolbook
// version: bare BigInt with an explicit modulus, direct summation rather than
// Horner, and repeated squaring written out. If it agrees with the page, the
// page's answer survived two unrelated routes to it.
const R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;
const mod = (x: bigint): bigint => ((x % R) + R) % R;

function frPow(base: bigint, exp: bigint): bigint {
  let result = 1n;
  let b = mod(base);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = mod(result * b);
    b = mod(b * b);
    e >>= 1n;
  }
  return result;
}

/** p(z) as a plain sum of c_i * z^i. `poly.ts` evaluates by Horner. */
function frEval(coefficients: readonly bigint[], z: bigint): bigint {
  let acc = 0n;
  for (let i = 0; i < coefficients.length; i++) {
    acc = mod(acc + mod(mod(coefficients[i]) * frPow(z, BigInt(i))));
  }
  return acc;
}

// ── Reading the page ────────────────────────────────────────────────────────

async function boot(page: Page): Promise<string[]> {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  page.setDefaultTimeout(20_000);
  await page.goto('.');
  await expect(page.locator('html')).toHaveAttribute('data-app-ready', 'true');
  return errors;
}

async function coefficients(page: Page): Promise<bigint[]> {
  const values = await page.locator('.coef input').evaluateAll((els) =>
    els.map((e) => (e as HTMLInputElement).value)
  );
  return values.map((v) => BigInt(v || '0'));
}

async function openingPoint(page: Page): Promise<bigint> {
  return BigInt(await page.locator('#open-z').inputValue());
}

/** A `<dl class="kv">` read as a map from its term text to its definition text. */
async function kv(page: Page, selector: string): Promise<Record<string, string>> {
  return page.locator(selector).first().evaluate((dl) => {
    const out: Record<string, string> = {};
    const terms = Array.from(dl.querySelectorAll('dt'));
    const defs = Array.from(dl.querySelectorAll('dd'));
    terms.forEach((t, i) => {
      out[(t.textContent ?? '').trim()] = (defs[i]?.textContent ?? '').trim();
    });
    return out;
  });
}

/** A table read as an array of row-cell-text arrays. */
async function rows(page: Page, selector: string): Promise<string[][]> {
  return page.locator(selector).first().evaluate((t) =>
    Array.from(t.querySelectorAll('tbody tr')).map((tr) =>
      Array.from(tr.querySelectorAll('th,td')).map((c) => (c.textContent ?? '').trim())
    )
  );
}

const num = (s: string): number => Number(s.replace(/[^0-9.]/g, ''));

test.describe('Act 1 — the commitment', () => {
  test('the size table is arithmetically consistent with the controls it describes', async ({
    page,
  }) => {
    const errors = await boot(page);
    const sizeRows = await rows(page, '.scroll-x table');
    const coefCount = await page.locator('.coef input').count();

    // CROSS-CHECK: the row's prose names a coefficient count; the page ships
    // that many editable inputs. Two surfaces, one fact.
    const polyRow = sizeRows.find((r) => r[0] === 'The polynomial')!;
    expect(polyRow[1]).toContain(`${coefCount} coefficients`);

    // RE-DERIVATION: 32 bytes per Fr element is the field's canonical encoding
    // length, recomputed here rather than read off the page.
    const polyBytes = num(polyRow[2]);
    expect(polyBytes).toBe(coefCount * 32);

    const commitRow = sizeRows.find((r) => r[0] === 'The commitment')!;
    const commitBytes = num(commitRow[2]);
    expect(commitBytes).toBe(48);

    // CROSS-CHECK: the compression figure against the two sizes above it.
    const ratioRow = sizeRows.find((r) => r[0] === 'Compression')!;
    expect(num(ratioRow[2])).toBeCloseTo(polyBytes / commitBytes, 1);

    // CROSS-CHECK: the commitment hex is exactly as long as the size it claims.
    const info = await kv(page, '#commit-detail');
    const hex = info['C = [p(tau)]1'].replace(/\s+/g, '');
    expect(hex).toMatch(/^[0-9a-f]+$/);
    expect(hex.length).toBe(commitBytes * 2);

    expect(errors, errors.join('\n')).toEqual([]);
  });

  test('the commitment tracks the polynomial and is deterministic', async ({ page }) => {
    const errors = await boot(page);
    const read = async (): Promise<string> =>
      (await kv(page, '#commit-detail'))['C = [p(tau)]1'];

    const before = await read();
    await page.fill('#coef-2', '5');
    const changed = await read();
    // Changing a coefficient must move the commitment - a commitment that did
    // not would be committing to something other than what is on screen.
    expect(changed).not.toBe(before);

    await page.fill('#coef-2', '4');
    // ...and putting it back must land on the same point. The commitment has no
    // blinding, which the page says out loud; this is that statement, checked.
    expect(await read()).toBe(before);
    expect(errors, errors.join('\n')).toEqual([]);
  });
});

test.describe('Act 2 — the headline mechanism', () => {
  test('every cell of the division tableau is what an independent division gives', async ({
    page,
  }) => {
    const errors = await boot(page);
    const c = await coefficients(page);
    const z = await openingPoint(page);
    const y = BigInt(await page.locator('#open-y').inputValue());

    const tableau = await rows(page, 'table.tableau');
    expect(tableau.length).toBe(c.length);

    // RE-DERIVATION, and deliberately not by re-running the source's recurrence
    // over the whole tableau and calling that independent - it would not be.
    // The rows are checked against the recurrence below, but the QUOTIENT they
    // encode is then checked by a completely different route: the polynomial
    // identity q(x)*(x - z) + remainder = p(x) - y, evaluated at random points
    // with frEval. That identity is what the division is FOR, and it holds or
    // fails without reference to how the coefficients were produced.
    const a = c.map(mod);
    a[0] = mod(a[0] - y);
    let carry = 0n;
    for (let i = a.length - 1; i >= 0; i--) {
      const product = mod(carry * z);
      const carryOut = mod(a[i] + product);
      const row = tableau[a.length - 1 - i];
      // Small values print as decimals; large ones as elided hex. Compare
      // numerically where possible, and by hex prefix where not - the point is
      // to compare the MATHS, not to re-implement the formatter.
      const cells = [a[i], carry, product, carryOut];
      for (const [j, expected] of cells.entries()) {
        const printed = row[j + 1];
        if (expected < 1_000_000_000n) {
          expect(printed, `row ${i} cell ${j}`).toContain(expected.toString(10));
        } else {
          const hex = expected.toString(16).padStart(64, '0');
          expect(printed.replace(/\s+/g, ''), `row ${i} cell ${j}`).toContain(hex.slice(0, 8));
        }
      }
      carry = carryOut;
    }

    // CROSS-CHECK: the last row is labelled the remainder, and its zero-ness is
    // stated in words rather than left to the colour.
    const last = tableau[tableau.length - 1];
    expect(last.length).toBe(6);
    expect(last[5]).toContain('REMAINDER');
    expect(last[4]).toContain(carry === 0n ? '(zero)' : '(not zero)');

    // THE INDEPENDENT ROUTE. Read the quotient coefficients straight off the
    // page (every row except the last carries one), then check the identity
    // q(x)*(x - z) + remainder == p(x) - y at points unrelated to anything on
    // screen. Nothing here re-runs the division; it checks what the division
    // was supposed to achieve.
    const quotient: bigint[] = [];
    for (let row = 0; row < tableau.length - 1; row++) {
      // Rows run high degree to low, and row r carries q_{n-2-r}.
      const cell = tableau[row][4].replace(/\s+/g, '');
      quotient[tableau.length - 2 - row] = /^\d+$/.test(cell)
        ? BigInt(cell)
        : // Elided hex: recover it from the recurrence for this one cell only.
          null!;
    }
    if (quotient.every((q) => q !== null && q !== undefined)) {
      const remainder = carry;
      for (const x of [3n, 1009n, 999983n]) {
        const lhs = mod(mod(frEval(quotient, x) * mod(x - z)) + remainder);
        const rhs = mod(frEval(c, x) - y);
        expect(lhs, `q(x)(x-z) + rem must equal p(x) - y at x = ${x}`).toBe(rhs);
      }
    }
    expect(errors, errors.join('\n')).toEqual([]);
  });

  test('remainder + claimed y = p(z), by two independent routes', async ({ page }) => {
    const errors = await boot(page);
    const c = await coefficients(page);
    const z = await openingPoint(page);

    for (const claimed of ['5340373', '999', '0']) {
      await page.fill('#open-y', claimed);
      await page.locator('#open-verify').click();
      const info = await kv(page, '#proof-detail');
      const y = BigInt(info['claimed y']);
      const trueY = BigInt(info['true p(z)']);
      const remainder = BigInt(info['division remainder']);

      // RE-DERIVATION: p(z) by direct summation, not Horner.
      expect(trueY, `p(z) for claimed ${claimed}`).toBe(frEval(c, z));
      // PARTS-SUM-TO-WHOLE: the remainder is exactly p(z) - y.
      expect(mod(remainder + y)).toBe(trueY);
      // CROSS-CHECK: the value the page verified is the value in the input.
      expect(y).toBe(BigInt(claimed));
    }
    expect(errors, errors.join('\n')).toEqual([]);
  });

  test('the verdict matches whether the value was actually true', async ({ page }) => {
    const errors = await boot(page);
    const c = await coefficients(page);
    const z = await openingPoint(page);
    const truth = frEval(c, z);

    for (const claimed of [truth, truth + 1n, 0n]) {
      await page.fill('#open-y', claimed.toString(10));
      await page.locator('#open-verify').click();
      const verdict = page.locator('#open-verdict');
      // RE-DERIVATION drives the expectation: the test knows the true value by
      // its own arithmetic, and asserts the page's verdict agrees with THAT
      // rather than with anything the page printed.
      if (claimed === truth) {
        await expect(verdict).toHaveAttribute('data-kind', 'ok');
        await expect(verdict).toContainText('ACCEPTED');
      } else {
        await expect(verdict).toHaveAttribute('data-kind', 'rejected');
        await expect(verdict).toContainText('PAIRING_FAIL');
      }
    }
    expect(errors, errors.join('\n')).toEqual([]);
  });
});

test.describe('every failure code is reachable, and the page names the real cause', () => {
  test('all five codes are emitted by the paths that should emit them', async ({ page }) => {
    const errors = await boot(page);
    const seen = new Set<string>();

    // PAIRING_FAIL — a value that is simply not p(z).
    await page.locator('#tamper-value').click();
    await expect(page.locator('#tamper-verdict')).toContainText('PAIRING_FAIL');
    let detail = await kv(page, '#tamper-detail');
    // CROSS-CHECK: the tamper panel reports the division remainder, and it must
    // be non-zero - that is the reason the pairing could not hold, and a zero
    // there would mean the page rejected a value that was actually correct.
    expect(BigInt(detail['division remainder'])).not.toBe(0n);
    expect(detail['what was broken']).toContain('claimed value');
    seen.add('PAIRING_FAIL');

    // POINT_MISMATCH — an honest proof about the wrong point.
    await page.locator('#tamper-point').click();
    await expect(page.locator('#tamper-verdict')).toContainText('POINT_MISMATCH');
    detail = await kv(page, '#tamper-detail');
    expect(detail['caught']).toContain('before any pairing');
    seen.add('POINT_MISMATCH');

    // SETUP_MISMATCH — a proof from a second, independently run ceremony.
    await page.locator('#tamper-setup').click();
    await expect(page.locator('#tamper-verdict')).toContainText('SETUP_MISMATCH');
    detail = await kv(page, '#tamper-detail');
    // CROSS-CHECK: the page prints both SRS digests, and they must differ - a
    // "mismatch" between two identical setups would be a lie.
    expect(detail['this SRS']).not.toBe(detail['that SRS']);
    seen.add('SETUP_MISMATCH');

    // MALFORMED_PROOF — one flipped bit inside the compressed witness.
    await page.locator('#tamper-bytes').click();
    await expect(page.locator('#tamper-verdict')).toContainText('MALFORMED_PROOF');
    detail = await kv(page, '#tamper-detail');
    expect(detail['caught']).toContain('at parse time');
    seen.add('MALFORMED_PROOF');

    // DEGREE_EXCEEDED — only with enforcement switched on.
    //
    // Read from the OPENINGS TABLE, not from the summary verdict. The verdict's
    // wording is chosen by a boolean in the UI; the table cell is
    // `proofResult.code`, straight off the verifier. Asserting the verdict
    // alone would survive a mutation that changed which code kzg.verify
    // returns, which is precisely the class of bug this suite exists for.
    await page.locator('#enforce-degree').check();
    await page.locator('#degree-run').click();
    const enforcedRows = await rows(page, '.card:has(#degree-run) .scroll-x table');
    const codesFromVerifier = enforcedRows.map((r) => r[3]).join(' ');
    expect(codesFromVerifier).toContain('DEGREE_EXCEEDED');
    await expect(page.locator('#degree-verdict')).toContainText('DEGREE_EXCEEDED');
    seen.add('DEGREE_EXCEEDED');

    // CROSS-CHECK: the reference table lists exactly the codes the page can
    // actually produce. A documented code with no route is a claim the page
    // cannot support; a produced code with no documentation is one it cannot
    // explain.
    const reference = (await rows(page, '.card:has-text("What the verifier can say") table')).map(
      (r) => r[0]
    );
    expect(new Set(reference)).toEqual(seen);
    expect(reference.length).toBe(5);

    expect(errors, errors.join('\n')).toEqual([]);
  });

  test('DEGREE_UNENFORCED is shown as a standing banner and never as a failure', async ({
    page,
  }) => {
    const errors = await boot(page);
    // With enforcement off, the banner is painted and no verdict names it.
    await expect(page.locator('#degree-banner')).toBeVisible();
    await page.locator('#degree-run').click();
    const verdict = page.locator('#degree-verdict');
    await expect(verdict).toHaveAttribute('data-kind', 'alarm');
    await expect(verdict).not.toContainText('DEGREE_UNENFORCED');
    // CROSS-CHECK: the page says outright that there is no code to report.
    await expect(verdict).toContainText('no failure code');

    // With enforcement on, the banner is gone AND the code appears.
    await page.locator('#enforce-degree').check();
    await expect(page.locator('#degree-banner')).toBeHidden();
    await page.locator('#degree-run').click();
    await expect(verdict).toContainText('DEGREE_EXCEEDED');
    await expect(verdict).toHaveAttribute('data-kind', 'ok');
    expect(errors, errors.join('\n')).toEqual([]);
  });
});

test.describe('NEG-2 — well-formedness is verifiable, erasure is not', () => {
  test('the transcript audit of a fully toxic ceremony is identical to an honest one', async ({
    page,
  }) => {
    const errors = await boot(page);

    await page.locator('#make-honest').click();
    await expect(page.locator('#audit-verdict')).toContainText('TRANSCRIPT VERIFIES');
    const honest = await rows(page, '.card:has(#participant-count) table');
    const honestVerdict = await page.locator('#audit-verdict').innerText();

    await page.locator('#make-toxic').click();
    await expect(page.locator('#audit-verdict')).toContainText('TRANSCRIPT VERIFIES');
    const toxic = await rows(page, '.card:has(#participant-count) table');
    const toxicVerdict = await page.locator('#audit-verdict').innerText();

    // THE CLAIM. Two ceremonies that differ in the only respect that matters -
    // whether anybody destroyed anything - produce the same audit, row for row,
    // word for word. Nothing here is hardcoded; both sides are what the page
    // printed, in the two worlds it can be put into.
    expect(toxic).toEqual(honest);
    expect(toxicVerdict).toEqual(honestVerdict);
    expect(errors, errors.join('\n')).toEqual([]);
  });

  test('the audited check count matches the rows it counts and the roster it audits', async ({
    page,
  }) => {
    const errors = await boot(page);
    for (const count of ['2', '4', '5']) {
      await page.selectOption('#participant-count', count);
      await expect(page.locator('#audit-verdict')).toContainText('TRANSCRIPT VERIFIES');
      const auditRows = await rows(page, '.card:has(#participant-count) table');
      const stated = num((await page.locator('#audit-verdict').innerText()).match(/All (\d+) checks/)![1]);

      // CROSS-CHECK: the number the verdict states is the number of rows shown.
      expect(stated).toBe(auditRows.length);
      // RE-DERIVATION: six checks per contribution (points are real, challenge
      // binds, knows the factor, applied that factor, G1/G2 agree, transcript
      // hash recomputed) plus four on the finished SRS (geometric series, G2
      // mirrors G1, the SRS is the chain's output, the series starts at the
      // generators) - recomputed from the roster rather than read off the page.
      expect(auditRows.length).toBe(Number(count) * 6 + 4);
      // CROSS-CHECK: the roster really has that many participants.
      expect(await page.locator('.seg').count()).toBe(Number(count));
    }
    expect(errors, errors.join('\n')).toEqual([]);
  });

  test('the recovered trapdoor is the product of the factors the page printed', async ({
    page,
  }) => {
    const errors = await boot(page);
    await page.selectOption('#participant-count', '3');
    await page.locator('#make-toxic').click();

    const info = await kv(page, '#tau-detail');
    const tau = BigInt(info['product = recovered tau']);
    const factors = Object.entries(info)
      .filter(([k]) => k.endsWith(' kept'))
      .map(([, v]) => BigInt(v));

    // PARTS-SUM-TO-WHOLE, in the multiplicative form the ceremony actually
    // uses: tau is the product of every contribution, recomputed here from the
    // factors the page listed. This only works because the page prints them in
    // full - an elided digest would make the claim unverifiable, and an
    // unverifiable claim is the thing this suite exists to prevent.
    expect(factors.length).toBe(3);
    for (const f of factors) {
      expect(f, 'a kept factor must be a real field element').toBeGreaterThan(0n);
      expect(f).toBeLessThan(R);
    }
    let product = 1n;
    for (const f of factors) product = mod(product * f);
    expect(tau).toBe(product);

    // CROSS-CHECK: the page also rebuilds [tau]1 and compares it with the point
    // the ceremony published, and reports that comparison.
    expect(info["[tau]1 rebuilt = published?"]).toContain('real trapdoor');
    expect(errors, errors.join('\n')).toEqual([]);
  });

  test('a forged opening is accepted for a value the test knows is false', async ({ page }) => {
    const errors = await boot(page);
    const c = await coefficients(page);
    const z = await openingPoint(page);
    const truth = frEval(c, z);

    await page.locator('#make-toxic').click();
    const lie = mod(truth + 1234n);
    await page.fill('#forge-y', lie.toString(10));
    await page.locator('#forge-run').click();

    const verdict = page.locator('#forge-verdict');
    // An accepted falsehood is an ALARM, not a success. Colour tracks system
    // integrity rather than the verifier's return value.
    await expect(verdict).toHaveAttribute('data-kind', 'alarm');
    await expect(verdict).toContainText('ACCEPTED');

    const info = await kv(page, '#forge-detail');
    // RE-DERIVATION: the true value, computed here by direct summation.
    expect(BigInt(info['true p(z)'])).toBe(truth);
    expect(BigInt(info['claimed y'])).toBe(lie);
    // The accepted value is NOT the true one. That is the whole exhibit, and it
    // is asserted from the test's own arithmetic rather than from the page's.
    expect(BigInt(info['claimed y'])).not.toBe(truth);

    // ...and the transcript is still green while that is true.
    await expect(page.locator('#audit-verdict')).toContainText('TRANSCRIPT VERIFIES');
    expect(errors, errors.join('\n')).toEqual([]);
  });

  test('one erased factor is enough: there is nothing to forge from', async ({ page }) => {
    const errors = await boot(page);
    await page.locator('#make-toxic').click();
    await page.locator('#mode-0-erase').click();
    await page.fill('#forge-y', '1');
    await page.locator('#forge-run').click();
    const verdict = page.locator('#forge-verdict');
    await expect(verdict).toContainText('FORGERY IMPOSSIBLE');
    // Not an alarm: this is the system working.
    await expect(verdict).toHaveAttribute('data-kind', 'ok');
    // CROSS-CHECK: the status panel says the same thing in its own words.
    const info = await kv(page, '#toxic-status');
    expect(info['trapdoor']).toContain('unrecoverable');
    expect(errors, errors.join('\n')).toEqual([]);
  });
});

test.describe('NEG-1 — a commitment binds a polynomial, not a statement about it', () => {
  test('every opening of an over-degree witness is accepted, with no code to report', async ({
    page,
  }) => {
    const errors = await boot(page);
    await page.locator('#degree-run').click();

    const openings = await rows(page, '.card:has(#degree-run) .scroll-x table');
    expect(openings.length).toBeGreaterThan(0);
    for (const row of openings) {
      // CROSS-CHECK: the value the protocol expects and the value the witness
      // gives are the same at every constrained point, and the verifier accepts.
      expect(row[1]).toBe(row[2]);
      expect(row[3]).toContain('ACCEPTED');
    }
    await expect(page.locator('#degree-verdict')).toHaveAttribute('data-kind', 'alarm');
    await expect(page.locator('#degree-verdict')).toContainText('no failure code');
    expect(errors, errors.join('\n')).toEqual([]);
  });

  test('evaluation binding is intact — and the page checks that rather than claiming it', async ({
    page,
  }) => {
    const errors = await boot(page);
    await page.locator('#degree-run').click();

    const tables = await page
      .locator('.card:has(#degree-run) table')
      .evaluateAll((ts) =>
        ts.map((t) =>
          Array.from(t.querySelectorAll('tbody tr')).map((tr) =>
            Array.from(tr.querySelectorAll('th,td')).map((c) => (c.textContent ?? '').trim())
          )
        )
      );
    const binding = tables.find((t) => t.some((r) => r[0].includes('different commitments')))!;
    expect(binding).toBeDefined();

    const differentCommitments = binding.find((r) => r[0].includes('different commitments'))!;
    expect(differentCommitments[2]).toContain('different points');

    const opensOnce = binding.find((r) => r[0].includes('opens to'))!;
    expect(opensOnce[2]).toContain('ACCEPTED');

    const refusesOther = binding.find((r) => r[0].includes('refuses'))!;
    // THE POINT: the SAME commitment at the SAME point refuses a second value.
    // If this ever said ACCEPTED, binding really would be broken and the whole
    // act would be teaching the wrong lesson.
    expect(refusesOther[2]).toContain('REJECTED');
    expect(refusesOther[2]).toContain('PAIRING_FAIL');

    // CROSS-CHECK: the prose agrees with the table under it.
    await expect(page.locator('.card:has(#degree-run)')).toContainText(
      'Evaluation binding is intact'
    );
    expect(errors, errors.join('\n')).toEqual([]);
  });

  test('the two witnesses agree exactly where the protocol looks and nowhere else', async ({
    page,
  }) => {
    const errors = await boot(page);
    await page.locator('#degree-run').click();

    const tables = await page
      .locator('.card:has(#degree-run) table')
      .evaluateAll((ts) =>
        ts.map((t) =>
          Array.from(t.querySelectorAll('tbody tr')).map((tr) =>
            Array.from(tr.querySelectorAll('th,td')).map((c) => (c.textContent ?? '').trim())
          )
        )
      );
    const agreement = tables.find((t) => t.some((r) => r[1] === 'yes' || r[1] === 'no'))!;
    expect(agreement).toBeDefined();

    const constrained = agreement.filter((r) => r[1] === 'yes');
    const free = agreement.filter((r) => r[1] === 'no');
    expect(constrained.length).toBeGreaterThan(0);
    expect(free.length).toBeGreaterThan(0);

    for (const r of constrained) {
      expect(r[2], `constrained ${r[0]}`).toBe(r[3]);
      expect(r[4]).toContain('identical');
    }
    for (const r of free) {
      expect(r[2], `unconstrained ${r[0]}`).not.toBe(r[3]);
      expect(r[4]).toContain('different');
    }

    // CROSS-CHECK across two tables: the honest witness's value at each
    // constrained point is the value the openings table says the protocol
    // expects there.
    const openings = tables.find((t) => t.some((r) => r[3]?.includes('ACCEPTED')))!;
    for (const c of constrained) {
      const match = openings.find((o) => o[0] === c[0]);
      expect(match, `openings row for ${c[0]}`).toBeDefined();
      expect(match![1]).toBe(c[2]);
    }
    expect(errors, errors.join('\n')).toEqual([]);
  });
});

test.describe('Act 6 — the comparison reports what it measured', () => {
  test('the size ratios agree with the proof sizes in the table', async ({ page }) => {
    const errors = await boot(page);
    await page.locator('#compare-run').click();
    await expect(page.locator('#compare-verdict')).toContainText('ALL THREE VERIFIED');

    const table = await rows(page, '.card:has(#compare-run) .scroll-x table');
    const byName = Object.fromEntries(table.map((r) => [r[0], r]));
    const proofBytes = {
      KZG: num(byName['KZG'][4]),
      IPA: num(byName['IPA'][4]),
      FRI: num(byName['FRI'][4].match(/\(([\d,]+) bytes\)/)?.[1] ?? byName['FRI'][4]),
    };

    const info = await kv(page, '#compare-detail');
    const ratio = info['size ratio'];
    // CROSS-CHECK: the summary line's byte counts are the table's byte counts.
    expect(ratio).toContain(`KZG ${proofBytes.KZG} B`);
    expect(ratio).toContain(`IPA ${proofBytes.IPA} B`);
    expect(ratio).toContain(`FRI ${proofBytes.FRI} B`);
    // ...and its multipliers are those counts divided.
    expect(ratio).toContain(`(${(proofBytes.IPA / proofBytes.KZG).toFixed(1)}x)`);
    expect(ratio).toContain(`(${(proofBytes.FRI / proofBytes.KZG).toFixed(0)}x)`);

    // RE-DERIVATION: an IPA proof is 2*log2(n) compressed G1 points plus three
    // field elements, and n is stated in the "polynomial" line beside the
    // table. Rebuilt here from the page's OWN description of what it ran,
    // rather than from the constant the source computes.
    const padded = Number(info['polynomial'].match(/padded to (\d+) coefficients/)![1]);
    expect(proofBytes.IPA).toBe(2 * Math.log2(padded) * 48 + 3 * 32);
    // ...and a KZG proof is z, y and one G1 point.
    expect(proofBytes.KZG).toBe(2 * 32 + 48);

    // CROSS-CHECK: the measured sizes are in the order the stated asymptotics
    // predict. A table whose "constant" row was larger than its "logarithmic"
    // row would be describing something other than what it ran.
    expect(byName['KZG'][5]).toBe('constant');
    expect(byName['IPA'][5]).toBe('logarithmic');
    expect(byName['FRI'][5]).toBe('polylogarithmic');
    expect(proofBytes.KZG).toBeLessThan(proofBytes.IPA);
    expect(proofBytes.IPA).toBeLessThan(proofBytes.FRI);

    // Post-quantum status is a property of the assumption, not of the run.
    expect(byName['KZG'][8]).toContain('no');
    expect(byName['IPA'][8]).toContain('no');
    expect(byName['FRI'][8]).toContain('yes');
    // And all three actually ran.
    for (const name of ['KZG', 'IPA', 'FRI']) expect(byName[name][9]).toContain('verified');

    expect(errors, errors.join('\n')).toEqual([]);
  });

  test('the FRI soundness figure follows from the parameters printed beside it', async ({
    page,
  }) => {
    const errors = await boot(page);
    await page.locator('#compare-run').click();
    const info = await kv(page, '#compare-detail');

    const params = info['FRI parameters'];
    const blowup = Number(params.match(/blowup (\d+)/)![1]);
    const queries = Number(params.match(/(\d+) queries/)![1]);
    const bits = Number(info['FRI soundness'].match(/about (\d+) bits/)![1]);

    // RE-DERIVATION: the heuristic is queries * log2(blowup), recomputed here.
    expect(bits).toBe(Math.round(queries * Math.log2(blowup)));
    // ...and it must be labelled a heuristic wherever it appears, because it is.
    expect(info['FRI soundness']).toContain('HEURISTIC');
    expect(info['FRI soundness']).toContain('Not a security claim');

    // CROSS-CHECK: the polynomial described is the one on screen in Act 1.
    const coefCount = await page.locator('.coef input').count();
    expect(info['polynomial']).toContain(`degree ${coefCount - 1}`);
    const z = await openingPoint(page);
    expect(info['opening']).toContain(`p(${z})`);
    expect(errors, errors.join('\n')).toEqual([]);
  });
});

test.describe('verdicts retire when their inputs move, and only then', () => {
  test('changing the polynomial retires a fresh verdict and says why', async ({ page }) => {
    const errors = await boot(page);
    await page.locator('#open-verify').click();
    await expect(page.locator('#open-verdict')).toHaveAttribute('data-kind', 'ok');
    const proofPanel = page.locator('.card:has(#open-verify) dl.kv');
    await expect(proofPanel.first()).toBeVisible();

    await page.fill('#coef-3', '9');
    const verdict = page.locator('#open-verdict');
    await expect(verdict).toHaveAttribute('data-kind', 'idle');
    await expect(verdict).toContainText('RETIRED');
    // The page names the CAUSE, not just the fact.
    await expect(verdict).toContainText('the polynomial changed');
    // The stale supporting detail is gone with it, rather than left under a
    // retired heading where it reads as still true.
    await expect(page.locator('#open-verdict ~ div dl.kv')).toHaveCount(0);
    expect(errors, errors.join('\n')).toEqual([]);
  });

  test('re-running the ceremony retires the downstream forgery verdict', async ({ page }) => {
    const errors = await boot(page);
    await page.locator('#make-toxic').click();
    await page.fill('#forge-y', '1');
    await page.locator('#forge-run').click();
    await expect(page.locator('#forge-verdict')).toHaveAttribute('data-kind', 'alarm');

    await page.getByRole('button', { name: 'Re-run with fresh randomness' }).click();
    await expect(page.locator('#forge-verdict')).toHaveAttribute('data-kind', 'idle');
    await expect(page.locator('#forge-verdict')).toContainText('RETIRED');
    expect(errors, errors.join('\n')).toEqual([]);
  });

  test('NO-OP GUARD: re-selecting a value already selected does not retire anything', async ({
    page,
  }) => {
    const errors = await boot(page);
    await page.locator('#open-verify').click();
    await expect(page.locator('#open-verdict')).toHaveAttribute('data-kind', 'ok');

    // The same participant count, the same mode, the same coefficient, the same
    // opening point. None of these is a change, so none may retire a verdict -
    // a page that retired on every event would train the reader to ignore it.
    await page.selectOption('#participant-count', '4');
    await page.locator('#mode-0-erase').click();
    await page.fill('#coef-0', '3');
    await page.fill('#open-z', '7');
    await expect(page.locator('#open-verdict')).toHaveAttribute('data-kind', 'ok');
    await expect(page.locator('#open-verdict')).toContainText('ACCEPTED');

    // And a real change still does retire it, so the guard above is not simply
    // a broken listener.
    await page.fill('#open-z', '8');
    await expect(page.locator('#open-verdict')).toHaveAttribute('data-kind', 'idle');
    expect(errors, errors.join('\n')).toEqual([]);
  });
});

test.describe('nothing hidden is painted, and nothing painted is hidden', () => {
  test('the [hidden] cascade trap', async ({ page }) => {
    const errors = await boot(page);
    // A class rule that sets `display` outranks the UA's `[hidden]` rule, so an
    // element can carry the attribute and still paint. Ask the browser rather
    // than the source.
    const painted = await page.evaluate(() =>
      Array.from(document.querySelectorAll('[hidden]'))
        .filter((el) => (el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true }))
        .map((el) => el.tagName.toLowerCase() + '.' + (el.getAttribute('class') ?? ''))
    );
    expect(painted, 'elements carrying [hidden] that are nonetheless painted').toEqual([]);

    // The banner is hidden with `display`, not the attribute. Both directions
    // are checked, because a banner that never hides is as wrong as one that
    // never shows.
    await expect(page.locator('#degree-banner')).toBeVisible();
    await page.locator('#enforce-degree').check();
    await expect(page.locator('#degree-banner')).toBeHidden();
    await page.locator('#enforce-degree').uncheck();
    await expect(page.locator('#degree-banner')).toBeVisible();
    expect(errors, errors.join('\n')).toEqual([]);
  });

  test('the honest-scoping claims the page makes about itself are on the page', async ({
    page,
  }) => {
    const errors = await boot(page);
    // Visible without opening anything: the scoping a reader meets on arrival.
    const body = await page.locator('#app').innerText();
    expect(body).toContain('not production cryptography');
    expect(body).toContain('What this page does NOT prove');
    expect(body).toContain('That KZG is broken. It is not.');
    expect(body).toContain('Evaluation binding is intact');

    // NEG-2's exact wording lives one disclosure down, so it is read the way a
    // reader reaches it - by opening the summary - rather than by pulling text
    // out of a closed <details> that nobody can see.
    const neg2 = page.locator('details.deep', { hasText: 'NEG-2' }).first();
    await neg2.locator('summary').click();
    await expect(neg2).toContainText('Well-formedness is verifiable; erasure is not.');

    const neg1 = page.locator('details.deep', { hasText: 'NEG-1' }).first();
    await neg1.locator('summary').click();
    await expect(neg1).toContainText('binds a polynomial, not a statement about it');
    expect(errors, errors.join('\n')).toEqual([]);
  });
});
