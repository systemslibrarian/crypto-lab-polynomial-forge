import { expect, test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  reportCollected,
  resetScanCount,
  scansPerformed,
  watchPageErrors,
} from './gate';

/**
 * Every rendering `driveAllStates` walks. Asserted after each run, because a
 * green gate says nothing about how much of the page it looked at - and a
 * refactor that dropped half the drive would still be green, just faster.
 */
const EXPECTED_SCANS = 28;

/**
 * WCAG 2.1 A/AA regression gate.
 *
 * The lab is driven along everything it teaches, and every state is scanned:
 * the arrival state, where a four-participant honest ceremony has already been
 * run and audited, the synthetic-division tableau is fully worked through with
 * a zero remainder, the DEGREE_UNENFORCED banner is standing and every
 * button-driven verdict is idle; the shared skip link focused; an honest KZG
 * opening accepted by the real pairing; the tableau reset, stepped one row,
 * and run through; a wrong claimed value taking the PAIRING_FAIL branch with a
 * non-zero remainder on screen; a non-numeric claimed value behind an
 * `aria-invalid` boundary; a verdict RETIRED because a coefficient changed
 * under it; a progressive-disclosure panel opened through its summary; a
 * ceremony participant switched to keeping their factor and the participant
 * count changed, each re-running the audit; the all-toxic ceremony whose
 * transcript still verifies; a forged opening the real pairing accepts, which
 * is one of the page's two alarm-red states; the same forgery refused once one
 * factor is destroyed; the four tamper buttons, each breaking a real proof a
 * different way and producing a different failure code; an over-degree witness
 * whose every opening is accepted with no failure code available - the second
 * alarm state; the same witness refused with
 * DEGREE_EXCEEDED once enforcement is switched on; all three commitment
 * schemes measured into the comparison table; three hover states; and three
 * focus rings. Every one of those is scanned at desktop and phone width.
 *
 * See `gate.ts` for why nothing is injected into the page, why no disclosure is
 * opened from script, why the lab's shipped defaults are asserted rather than
 * assumed, and why `violations` is not the whole oracle.
 *
 * Dark is the only theme this lab ships, so it is the only one driven. There is
 * no toggle to exercise and `boot` asserts there is none.
 */
for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    resetScanCount();
    await boot(page, theme);
    await driveAllStates(page, theme);
    expect(scansPerformed, 'states scanned').toBe(EXPECTED_SCANS);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    resetScanCount();
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expect(scansPerformed, 'states scanned').toBe(EXPECTED_SCANS);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });
}
