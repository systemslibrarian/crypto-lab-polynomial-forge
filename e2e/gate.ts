import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Five rules govern everything here. Each one corrects a specific way the
 * retired template gate reported coverage it did not have, and each is written
 * out because the failure modes are subtle enough to be re-introduced by
 * anyone copying a gate from an arbitrary lab.
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The retired gate pushed
 *     `animation:none!important; transition:none!important` through
 *     `addStyleTag`. That BYPASSES a lab's own
 *     `@media (prefers-reduced-motion: reduce)` block instead of exercising it,
 *     so the rendering a reduced-motion reader actually gets is never the one
 *     scanned - and where a page parks content at `opacity: 0` and reveals it
 *     through an animation's `forwards` fill, the injection kills the reveal
 *     and the content is scanned INVISIBLE. This gate sets the preference
 *     through `emulateMedia`, asserts from inside the page that it took effect
 *     (`test.use({ reducedMotion })` and the config key are measured no-ops on
 *     Playwright 1.6x), and injects nothing.
 *
 *  2. IT FORCED HIDDEN CONTENT VISIBLE FROM SCRIPT. Stripping `[hidden]` and
 *     setting `<details>.open` by JS scans a state the page never renders, and
 *     destroys the ability to catch the `[hidden]` cascade trap - a class rule
 *     setting `display` outranks the UA `[hidden]` rule, so an element paints
 *     while the code believes it is hidden. This lab's depth lives behind nine
 *     `<details class="deep">` panels and its DEGREE_UNENFORCED banner is
 *     shown and hidden by a real `display` toggle; both are driven through
 *     their real controls, and the shut state is scanned before the open one.
 *
 *  3. IT DROVE BLIND AND THEN THREW THE STATES AWAY. Clicking every button
 *     whose label matches a regex, swallowing failures with `.catch(() => {})`
 *     and waiting a fixed 400ms scans one state at the end and calls it
 *     coverage - and a click that silently did nothing looks identical to one
 *     that worked. Worse, `waitForTimeout` IS the scan race: where a page
 *     builds asynchronously, axe scans an empty container and passes having
 *     checked nothing. This drive names every control it touches, waits on a
 *     real DOM completion signal after each, and scans after every step, at
 *     desktop and phone width.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. See `scan`. Every surface that
 *     carries this lab's meaning is a verdict box, a banner or a table tag, and
 *     axe's `incomplete` bucket is where every contrast decision it declined to
 *     make ends up - along with `aria-prohibited-attr`, which is where an
 *     `aria-label` on a role-less element hides. Both buckets are asserted, and
 *     contrast is computed arithmetically alongside them.
 *
 *  5. IT HAD NO REFLOW, NON-TEXT-CONTRAST OR GENERATED-CONTENT ORACLE. axe has
 *     no rule for WCAG 1.4.10 or 1.4.11 at all, and the arithmetic text walk
 *     cannot reach a control's boundary. This lab is mostly bordered panels,
 *     bordered inputs and eight scrollable tables, so the boundary oracle is
 *     the live one here: `nontext.ts` measures every control as painted at
 *     every driven state, and `expectNoHorizontalOverflow` adds the reflow
 *     check.
 *
 * Never chain `.withTags(...).withRules(...)` - both write `options.runOnly`,
 * so the second SILENTLY REPLACES the first and axe runs four best-practice
 * rules and zero WCAG rules while reading as a full A/AA pass. `scan` runs the
 * two sets as separate `analyze()` calls and merges them.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Two rAFs are not enough. A transition sampled mid-flight has a colour that
 * exists in no state of the page, and axe will happily report it: elsewhere in
 * this fleet that produced a phantom 2.00:1 failure on a button whose settled
 * ratio is 9:1. Transitions also drain in waves rather than in one batch, so a
 * poll for "nothing running right now" can exit through a gap between waves —
 * hence six consecutive quiet frames rather than one.
 *
 * Bounded three ways, because a gate that can hang is a gate nobody runs:
 * animations that never finish (`iterations: Infinity`) are excluded from the
 * quiescence test rather than waited on, a wall-clock budget inside the page
 * gives up and proceeds, and Playwright's own timeout is the backstop.
 *
 * Under the reduced motion this gate asserts, `style.css`'s reduced-motion
 * block cancels the one transition this lab declares - the 120ms background
 * fade on the division tableau's current row - so `getAnimations()` is
 * normally empty and this returns on the sixth frame. It stays because the
 * shared top bar's `.cl-btn` transitions are declared OUTSIDE the lab's
 * `@media` block and are not cancelled by it at all: hovering a top-bar button
 * really does start a 150ms transition that a scan can sample mid-flight.
 */
export async function settle(page: Page, budgetMs = 4000): Promise<void> {
  await page.waitForFunction(
    (budget: number) => {
      const w = window as unknown as { __quietFrames?: number; __settleStart?: number };
      if (w.__settleStart === undefined) w.__settleStart = performance.now();
      const done = (): boolean => {
        w.__quietFrames = 0;
        w.__settleStart = undefined;
        return true;
      };
      const running = document.getAnimations().filter((a) => {
        if (a.playState !== 'running') return false;
        const timing = a.effect?.getComputedTiming?.();
        // An infinite decorative animation never drains; waiting on it hangs.
        return timing?.iterations !== Infinity;
      });
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      if (w.__quietFrames >= 6) return done();
      if (performance.now() - (w.__settleStart ?? 0) > budget) return done();
      return false;
    },
    budgetMs,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state - the element then
 * renders at `opacity: 0` for every reader with the preference set. This lab
 * deliberately has no such shape: `style.css` declares no `@keyframes` at all,
 * nothing is parked at `opacity: 0`, and `main.ts` builds the entire page in
 * one synchronous pass rather than revealing it. The assertion runs anyway,
 * because "no reveal animations today" is a property of the current stylesheet
 * rather than of the page, and the day one is added this is what measures it.
 *
 * `aria-hidden` subtrees are excluded; what this lab hides is the decorative
 * `[+]` / `[x]` / `[!]` verdict glyphs, each sitting beside its own word - see
 * `contrast.ts`, which measures them anyway with the exemption lifted.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created. Every panel here renders synchronously at first activation, so a
 * renderer that throws leaves that tabpanel EMPTY — and an empty region is
 * exactly what a scan reports as perfectly accessible. Attach before `boot`,
 * assert after the drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * Exactly one banner landmark.
 *
 * The shared `.cl-topbar` carries an explicit `role="banner"`. This lab's hero
 * IS a `<header class="cl-hero">`, which implies a second banner - and the
 * shared bar's `dedupeBanner()` demotes it to `role="group"` at load. So this
 * assertion is live here rather than vacuous: it is measuring that the shared
 * script actually ran and actually reached the hero, which is exactly the
 * coupling that breaks when a lab moves its hero inside `<main>` or renders it
 * after `DOMContentLoaded`. Asserting the OUTCOME rather than the markup is
 * what catches either edit.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false; // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/**
 * List semantics survive their styling.
 *
 * This lab's lists are the plain `<ul>`s in the scope card - what is real, what
 * is not, and what the page does NOT prove - with their implicit roles intact.
 * None of them carries `list-style: none`, so nothing here needs the explicit
 * `role="list"` compensation Safari and VoiceOver require when that
 * declaration is present.
 *
 * The assertion is therefore about what must NOT appear: any explicit role on
 * a `ul`/`ol` must be `list` (any other value orphans every `<li>` under it),
 * and a `role="list"` must never sit on an empty element, because axe applies
 * `aria-required-children` to the explicit role and fails it the day that list
 * renders with no items. The `.plain-list` rule in `style.css` sets
 * `list-style: none` and is the one that would make the compensation
 * necessary, so this runs at every state rather than being read off the
 * source. Roles can be assigned as JS properties in an element-creation
 * helper, so ask the DOM rather than grepping.
 */
export async function assertListSemantics(page: Page): Promise<void> {
  const broken = await page.$$eval('ul[role], ol[role]', (els) =>
    els
      .filter((e) => e.getAttribute('role') !== 'list' || e.children.length === 0)
      .map(
        (e) =>
          `${e.tagName.toLowerCase()}[role=${e.getAttribute('role')}] with ${e.children.length} children`
      )
  );
  expect(
    broken,
    'an explicit non-list role on a list deletes its semantics; an empty role="list" fails aria-required-children'
  ).toEqual([]);
}

/**
 * Load the page with reduced motion actually in effect, and assert the content
 * every scan relies on is really on the page - including the lab's DEFAULTS,
 * which are never assumed.
 *
 * `test.use({ reducedMotion })` and the `reducedMotion` key in
 * `playwright.config.ts` are measured no-ops on Playwright 1.6x, so the
 * emulation is applied imperatively BEFORE the navigation and then ASSERTED
 * from inside the page. Nothing in this lab's JS branches on `matchMedia`, but
 * the CSS reduced-motion block is the only thing standing between a scan and
 * the tableau row's mid-flight background colour, so the assertion is the
 * difference between scanning the reduced-motion rendering and believing we
 * did.
 *
 * `data-app-ready` is the load-bearing wait. This page builds its whole DOM in
 * one synchronous pass in `main.ts` - the ceremony, its pairing audit and every
 * act - and sets that attribute afterwards. A navigation that merely resolves
 * proves nothing: if any of that threw, `#app` would hold a single alert box,
 * and a nearly-empty page is exactly what a scan reports as perfectly
 * accessible. Waiting on the attribute AND asserting the shipped defaults is
 * what makes an empty render impossible to pass.
 *
 * The theme is seeded through `localStorage` rather than by clicking anything,
 * which pins down a real coupling as a side effect: `index.html`'s anti-flash
 * script writes and reads `'theme'`. Dark is the only theme this lab ships.
 */
export async function boot(page: Page, theme: 'dark'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the
  // whole test timeout and reports nothing useful. 20s turns that silent hang
  // into a named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  // Everything below depends on the synchronous build having finished AND
  // succeeded. 'failed' is a real value main.ts can set.
  await expect(page.locator('html')).toHaveAttribute('data-app-ready', 'true');

  await assertSingleBanner(page);
  await assertListSemantics(page);

  // ── The page really rendered ────────────────────────────────────────────
  await expect(page.locator('main')).toHaveCount(1);
  await expect(page.locator('h1')).toHaveText('Polynomial Forge');
  // Intro, scope, seven acts, and the failure-code reference.
  await expect(page.locator('section.card')).toHaveCount(10);
  await expect(page.locator('.scripture-footer')).toHaveCount(1);

  // The shared skip link points at an id that exists. axe's skip-link rule is
  // best-practice, not WCAG-tagged, so `withTags` never runs it - a skip link
  // aimed at a missing element is exactly the kind of thing a green axe run
  // says nothing about.
  await expect(page.locator('a.cl-skip-link')).toHaveAttribute('href', '#app');
  await expect(page.locator('#app')).toHaveCount(1);

  // Dark is the only theme, so the page must carry no theme control at all -
  // not the shared bar's, which was removed, and not a lab-local one. The
  // shared CSS hides any lab toggle with `display:none !important`, which would
  // leave a dead-but-known element; asserting the count at zero catches the day
  // one is added without going through that list.
  await expect(
    page.locator('#theme-toggle, #themeToggle, .theme-toggle, .theme-toggle-btn, [data-theme-toggle]')
  ).toHaveCount(0);

  // ── Every shipped default, asserted rather than assumed ─────────────────
  // Act 1's polynomial is 3 + X + 4X^2 + X^3 + 5X^4 + 9X^5 + 2X^6 + 6X^7.
  for (const [i, v] of ['3', '1', '4', '1', '5', '9', '2', '6'].entries()) {
    await expect(page.locator(`#coef-${i}`)).toHaveValue(v);
  }
  await expect(page.locator('#open-z')).toHaveValue('7');
  // p(7) computed by the page at mount. Asserted as a literal here on purpose:
  // this is the one place the gate does NOT re-derive, because a default that
  // silently changes should break the drive rather than follow it.
  await expect(page.locator('#open-y')).toHaveValue('5340373');

  // Act 2 arrives with the division fully worked through and the remainder on
  // screen. A stepper that arrived empty would mean the headline mechanism was
  // never in the scanned rendering at all.
  await expect(page.locator('.tableau tr.is-remainder')).toHaveCount(1);
  await expect(page.locator('.tableau tr.is-remainder')).toContainText('(zero)');

  // Act 3 arrives with a four-participant honest ceremony already audited.
  await expect(page.locator('#participant-count')).toHaveValue('4');
  await expect(page.locator('#srs-degree')).toHaveValue('24');
  await expect(page.locator('#audit-verdict')).toContainText('TRANSCRIPT VERIFIES');
  await expect(page.locator('#audit-verdict')).toHaveAttribute('data-kind', 'ok');

  // Act 5 arrives with enforcement OFF, so the standing banner is visible.
  // That is the default because it is what protocols actually do.
  await expect(page.locator('#enforce-degree')).not.toBeChecked();
  await expect(page.locator('#degree-banner')).toBeVisible();
  await expect(page.locator('#degree-banner')).toContainText('DEGREE_UNENFORCED');

  // The verdicts that need a button press arrive idle, and say so.
  for (const id of ['#open-verdict', '#forge-verdict', '#degree-verdict', '#compare-verdict']) {
    await expect(page.locator(id)).toHaveAttribute('data-kind', 'idle');
    await expect(page.locator(id)).toContainText('NOT RUN');
  }

  // ── Disclosures ship shut ───────────────────────────────────────────────
  // The depth an expert wants is behind `<details>`, and a reader arrives at
  // the shut state. The gate this replaces opened every one from script before
  // its only scan, so the shut state was never scanned and the open one was
  // scanned in a rendering no reader can reach.
  await expect(page.locator('details.deep')).toHaveCount(11);
  await expect(page.locator('details.deep[open]')).toHaveCount(0);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this lab is
 * unusually exposed to it: it prints 96-character compressed G1 points and
 * 192-character G2 points, and it renders eight wide tables. The two defences
 * are different and both are load-bearing - the hex runs rely on
 * `overflow-wrap: anywhere` on `.hex` and `.kv dd`, while the tables live
 * inside `.scroll-x` regions that clip rather than widen the document. A table
 * that escapes its wrapper, or a new `<code>` run without the wrap rule, is
 * exactly what this catches at 380px.
 *
 * Elements clipped by a scrolling ancestor are identified as such rather than
 * blamed: a wide table inside `overflow-x: auto` has a huge bounding rect and
 * contributes nothing to the document's scroll width, so naming it would send
 * you off fixing the wrong element.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow: auto` wrapper has a huge bounding rect but
    // is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 *
 * This is the live oracle in this lab rather than a precaution. Every table
 * here is wide enough to scroll at some width - the comparison table has ten
 * columns - and each is wrapped by `scrollRegion()` in `ui/dom.ts`, which
 * supplies `tabindex="0"`, `role="region"` and an `aria-label` together. Drop
 * any one of those three and a keyboard reader can no longer scroll the table;
 * axe has no rule that would say so, and this fails on the Linux CI runner
 * even where it passes in a local Chromium.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY);
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * Nothing may be focusable while it paints nothing (WCAG 2.4.3 / 2.4.7).
 *
 * `opacity: 0` with `pointer-events: none` is NOT hiding: the element keeps
 * `tabIndex: 0`, so a keyboard reader tabs to a control that is not on screen
 * and the focus ring lands nowhere. `display: none` and `visibility: hidden`
 * DO remove an element from the tab order, so those are skipped rather than
 * flagged — the failure is specifically the invisible-but-tabbable pair. The
 * `hidden` tabpanels here take the `display: none` route, which is why five
 * panels' worth of buttons are legitimately absent from the tab order.
 *
 * Off-screen-but-focusable is the WCAG-sanctioned skip-link idiom and is
 * deliberately not flagged: the shared skip link parks at `top:-3rem` with
 * full opacity and slides in on focus. The drive scans it focused.
 *
 * The shape at risk here is the DEGREE_UNENFORCED banner, which is shown and
 * hidden with `display`. `display: none` removes an element from the tab order
 * outright, so it is skipped rather than flagged - but a future edit that
 * switched to `opacity: 0` would leave a hidden banner in the tab order, and
 * that is what this measures.
 */
export async function expectNoInvisibleFocusTargets(page: Page, label: string): Promise<void> {
  const bad = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll<HTMLElement>(FOCUSABLE))) {
      if (el.tabIndex < 0) continue;
      // display:none / visibility:hidden already remove it from the tab order.
      if (!el.checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      for (let n: Element | null = el; n; n = n.parentElement) {
        effective *= parseFloat(getComputedStyle(n).opacity);
      }
      const r = el.getBoundingClientRect();
      if (effective !== 0 && r.width > 0 && r.height > 0) continue;
      // Confirm it really is reachable rather than inferring it.
      const before = document.activeElement;
      el.focus();
      const took = document.activeElement === el;
      (before as HTMLElement | null)?.focus?.();
      if (took) {
        out.push(
          `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}.${(el.getAttribute('class') ?? '').trim()}` +
            ` (opacity ${effective}, ${Math.round(r.width)}x${Math.round(r.height)})`
        );
      }
    }
    return Array.from(new Set(out));
  });
  expect(bad, `focusable elements that paint nothing in state: ${label}`).toEqual([]);
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run.
 * It is a debugging aid only: `A11Y_COLLECT` is never set in CI, and a run
 * with it set prints every finding as it happens and then fails at the end, so
 * a green collection run cannot be mistaken for a green gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

async function soft(fn: () => Promise<void>): Promise<void> {
  if (!COLLECTING) return fn();
  try {
    await fn();
  } catch (e) {
    // Generous, not 900: a truncated oracle dump is how a second and third
    // finding in the same state get missed on a collection pass.
    record(String(e).slice(0, 6000));
  }
}

/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no
 * text node.
 *
 * IT IS CALLED FROM `scan()`, deliberately and not by accident. Fleet-wide
 * this oracle had been called from inside a soft wrapper AFTER its
 * `if (!COLLECTING) return` guard - so in a strict run, which is every run in
 * CI and every run anyone reads as a pass, the guard returned first and
 * `nontext.ts` never executed at all. Thirteen repos certified themselves
 * clean on an oracle that had never looked. Calling it here means it runs at
 * every driven state, including `:hover`, and this repo's baseline was
 * captured by that live path.
 *
 * A check that merely logs is not a gate, so it ratchets: anything NOT in the
 * baseline fails, anything in the baseline that got WORSE fails, and anything
 * in the baseline that has been FIXED fails until its entry is deleted. That
 * last rule is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(`WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`);
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the
 * point — or the drive stopped reaching the state that shows it, which is a
 * coverage regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Nine assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state — see `expectNotBlank`.
 *  - `violations` — the usual WCAG A/AA rule failures, plus four landmark
 *    best-practice rules `withTags` does not run on its own.
 *  - `incomplete` - axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically. Everything else in that bucket is a real result
 *    axe simply could not finish - including `aria-prohibited-attr`, which is
 *    where an `aria-label` on a role-less element hides. This page leans on
 *    getting that right: `scrollRegion()` pairs every `aria-label` with an
 *    explicit `role="region"`, and the ceremony roster's per-participant
 *    buttons carry `aria-label` on real `<button>` elements. Put a label on a
 *    role-less `<div>` and it is silently discarded, with nothing in
 *    `violations` to say so.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - the same walk over `aria-hidden` content with the exemption lifted —
 *    SC 1.4.3 is about what a reader SEES; see `contrast.ts` for what this
 *    lab hides and why it is measured anyway.
 *  - non-text contrast and generated content — SC 1.4.11, ratcheted; see
 *    `expectNoNewNonTextFailures`. This is the only oracle that judges a
 *    control's boundary against the surface OUTSIDE it.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - no focusable element that paints nothing — WCAG 2.4.3/2.4.7.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
/**
 * How many states this drive has scanned.
 *
 * Asserted by the spec at the end of each run. A gate's coverage is the number
 * of distinct renderings it looked at, and that number is otherwise invisible:
 * a refactor that quietly dropped half the drive would still report a green
 * run, and the only tell would be that it finished faster - which nobody
 * notices. Pinning the count turns "the drive got shorter" into a failure.
 */
export let scansPerformed = 0;

export function resetScanCount(): void {
  scansPerformed = 0;
}

export async function scan(page: Page, label: string): Promise<void> {
  scansPerformed += 1;
  const started = Date.now();
  await settle(page);
  await expectNotBlank(page, label);
  // TWO axe runs, deliberately, and this is not a style choice.
  //
  // `AxeBuilder.withTags()` and `AxeBuilder.withRules()` both write the same
  // `options.runOnly` field, so the second call SILENTLY REPLACES the first —
  // the axe-core/playwright source says so in as many words on `withRules`
  // ("Cannot be used with AxeBuilder#withTags"). Chained as
  // `.withTags(TAGS).withRules([...4 landmark rules])`, axe runs those FOUR
  // best-practice rules and NOT ONE WCAG RULE, while a green result reads
  // exactly like a full A/AA pass. For scale, `withTags(TAGS)` selects 69 of
  // axe-core 4.12's 105 rule definitions; the chained form executes 4.
  //
  // The landmark four are still wanted because they are best-practice rather
  // than WCAG-tagged, so `withTags` alone does not reach them - and this page
  // has exactly the shape they catch: a sticky `<header role="banner">` with
  // one `<nav>` inside it, then a `<div id="app">` holding one `<main>`, a
  // `<header class="cl-hero">` that the shared bar's script demotes to
  // `role="group"` so it does not become a second banner, an
  // `<aside class="cl-hero-why">` nested inside that hero, and a `<footer>`
  // that is a sibling of `<main>` rather than a child of it.
  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const landmarks = await new AxeBuilder({ page })
    .withRules([
      'landmark-no-duplicate-banner',
      'landmark-unique',
      'landmark-one-main',
      'landmark-complementary-is-top-level',
    ])
    .analyze();
  const results = {
    violations: [...wcag.violations, ...landmarks.violations],
    incomplete: [...wcag.incomplete, ...landmarks.incomplete],
  };

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  // The `incomplete` bucket is asserted, not skimmed. `aria-prohibited-attr`
  // and `aria-required-children` appear ONLY here — never in `violations` — so
  // a gate that ignores this bucket cannot see either. Only `color-contrast`
  // is allowed to remain, and only because the arithmetic walk below judges
  // those ratios for real; no other rule is filtered out.
  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  // The aria-hidden walk, exemption lifted — axe skips this text entirely and
  // the default walk honours the same boundary, so this second call is the
  // ONLY thing that ever measures it. See `contrast.ts` for the inventory.
  const hiddenContrast = Array.from(
    new Set(
      formatContrastFailures(
        await auditContrast(page, '[aria-hidden="true"], [aria-hidden="true"] *', true)
      )
    )
  );
  softExpect(hiddenContrast, `measured aria-hidden contrast failures in state: ${label}`, []);

  await soft(() => expectNoNewNonTextFailures(page, label));
  await soft(() => expectScrollersReachable(page, label));
  await soft(() => expectNoInvisibleFocusTargets(page, label));
  await soft(() => expectNoHorizontalOverflow(page, label));
  if (process.env.A11Y_TIMING) {
    console.log(`[scan ${scansPerformed}] ${Date.now() - started}ms — ${label}`);
  }
}

// ── The drive ───────────────────────────────────────────────────────────────

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Five things shape this drive:
 *
 *  - THE ARRIVAL STATE IS SCANNED FIRST, exactly as a reader gets it: the
 *    honest ceremony audited, the division tableau fully worked through with a
 *    zero remainder, the DEGREE_UNENFORCED banner standing, every `<details>`
 *    shut, and every button-driven verdict idle.
 *
 *  - EVERY VERDICT TONE IS REACHED THROUGH ITS REAL CONTROL. This lab has four
 *    - `ok`, `rejected`, `alarm` and `idle` - and they are the surfaces that
 *    carry its meaning, so all four are driven and scanned. The `alarm` tone in
 *    particular is only reachable by actually forging a proof or actually
 *    running the over-degree witness; it had no other route.
 *
 *  - EVERY FAILURE AND RETIREMENT STATE. A wrong claimed value taking the
 *    PAIRING_FAIL branch; a non-numeric claimed value painting `aria-invalid`;
 *    enforcement switched on so the same witness is refused with
 *    DEGREE_EXCEEDED; and the RETIRED state a verdict enters when its inputs
 *    change underneath it. None of those is reachable without deliberately
 *    breaking something, and none would otherwise be scanned.
 *
 *  - HOVER IS A STATE, AND IT PERSISTS AFTER A CLICK. `:hover` stays on the
 *    element under the pointer after `page.click()` resolves, so it is the
 *    state a reader occupies the instant after pressing a button - and
 *    `.primary:hover`, `.danger:hover` and `.cl-btn:hover` all repaint their
 *    fill. Each is scanned explicitly.
 *
 *  - NO FIXED TIMEOUTS. Every wait is on a real DOM completion signal: a
 *    verdict's `data-kind`, a step counter's wording, an `aria-pressed`, a
 *    banner's visibility.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  await scanAt('arrival: honest ceremony audited, division worked through, banner standing');

  // ── The shared skip link, focused ───────────────────────────────────────
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await scanAt('the shared skip link focused, slid in from top:-3rem');

  // ── Act 2: the honest opening ───────────────────────────────────────────
  await page.locator('#open-verify').click();
  await expect(page.locator('#open-verdict')).toHaveAttribute('data-kind', 'ok');
  await expect(page.locator('#open-verdict')).toContainText('ACCEPTED');
  await scanAt('Act 2: honest opening accepted by the real pairing - the ok tone');

  // ── Act 2: the stepper, back at the start and stepped forward ───────────
  await page.getByRole('button', { name: 'Reset' }).click();
  await expect(page.locator('p.step-count')).toContainText('Reset.');
  await expect(page.getByRole('button', { name: 'Back' })).toBeDisabled();
  await scanAt('Act 2: tableau reset to row 0, every value withheld, Back disabled');

  await page.getByRole('button', { name: 'Step', exact: true }).click();
  await expect(page.locator('p.step-count')).toContainText('Row 1 of 8');
  await expect(page.locator('.tableau tr.is-current')).toHaveCount(1);
  await scanAt('Act 2: one row stepped - the current-row highlight');

  await page.getByRole('button', { name: 'Run the whole division' }).click();
  await expect(page.locator('p.step-count')).toContainText('All 8 rows');
  await scanAt('Act 2: the whole division run, remainder zero and green');

  // ── Act 2: break it. A wrong y takes the PAIRING_FAIL branch. ───────────
  await page.fill('#open-y', '999');
  await expect(page.locator('.tableau tr.is-remainder')).toContainText('(not zero)');
  await page.locator('#open-verify').click();
  await expect(page.locator('#open-verdict')).toHaveAttribute('data-kind', 'rejected');
  await expect(page.locator('#open-verdict')).toContainText('PAIRING_FAIL');
  await scanAt('Act 2: a wrong claimed value - non-zero remainder and PAIRING_FAIL');

  // A non-numeric claimed value paints `aria-invalid` and recolours the input's
  // boundary. The 1.4.11 oracle judges controls as painted, so this state has
  // its own border colour and needs its own scan.
  await page.fill('#open-y', 'not-a-number');
  await expect(page.locator('#open-y')).toHaveAttribute('aria-invalid', 'true');
  await scanAt('Act 2: a malformed claimed value - the aria-invalid boundary');

  await page.getByRole('button', { name: 'Use the true value p(z)' }).click();
  await expect(page.locator('#open-y')).toHaveValue('5340373');
  await expect(page.locator('#open-y')).not.toHaveAttribute('aria-invalid', 'true');

  // ── The four tamper renderings, one per failure code ────────────────────
  // Each of these repaints the tamper verdict in the `rejected` tone with a
  // different code and a different detail list. None of them is reachable
  // without pressing the button, so none of them had ever been scanned.
  for (const [id, code] of [
    ['#tamper-value', 'PAIRING_FAIL'],
    ['#tamper-point', 'POINT_MISMATCH'],
    ['#tamper-setup', 'SETUP_MISMATCH'],
    ['#tamper-bytes', 'MALFORMED_PROOF'],
  ] as const) {
    await page.locator(id).click();
    await expect(page.locator('#tamper-verdict')).toContainText(code);
    await scanAt(`Act 2: a proof broken by ${id.replace('#tamper-', '')} — ${code}`);
  }

  // ── A retired verdict: the inputs moved under a fresh result ────────────
  await page.locator('#open-verify').click();
  await expect(page.locator('#open-verdict')).toHaveAttribute('data-kind', 'ok');
  await page.fill('#coef-0', '4');
  await expect(page.locator('#open-verdict')).toHaveAttribute('data-kind', 'idle');
  await expect(page.locator('#open-verdict')).toContainText('RETIRED');
  await scanAt('a verdict retired because its inputs changed underneath it');
  await page.fill('#coef-0', '3');

  // ── Act 1: a disclosure opened the way a reader opens one ───────────────
  await page.locator('details.deep > summary').first().click();
  await expect(page.locator('details.deep[open]')).toHaveCount(1);
  await scanAt('a progressive-disclosure panel opened through its summary');

  // ── Act 3: the ceremony roster and its audit ────────────────────────────
  await page.locator('#mode-0-retain').click();
  await expect(page.locator('#mode-0-retain')).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('#audit-verdict')).toContainText('TRANSCRIPT VERIFIES');
  await scanAt('Act 3: one participant keeps their factor - the audit is unchanged');

  await page.selectOption('#participant-count', '2');
  await expect(page.locator('#participant-count')).toHaveValue('2');
  await expect(page.locator('#audit-verdict')).toContainText('TRANSCRIPT VERIFIES');
  await scanAt('Act 3: the ceremony re-run with two participants');

  // ── Act 4: the whole point. All-toxic, still green, then a forgery. ─────
  await page.locator('#make-toxic').click();
  await expect(page.locator('#audit-verdict')).toContainText('TRANSCRIPT VERIFIES');
  await expect(page.locator('#forge-verdict')).toHaveAttribute('data-kind', 'idle');
  await scanAt('Act 4: every factor retained, the transcript audit still all-green');

  await page.fill('#forge-y', '1');
  await page.locator('#forge-run').click();
  await expect(page.locator('#forge-verdict')).toHaveAttribute('data-kind', 'alarm');
  await expect(page.locator('#forge-verdict')).toContainText('ACCEPTED — AND FALSE');
  await scanAt('Act 4: a forged opening the real pairing accepts - the alarm tone');

  await page.locator('#make-honest').click();
  await page.locator('#forge-run').click();
  await expect(page.locator('#forge-verdict')).toContainText('FORGERY IMPOSSIBLE');
  await scanAt('Act 4: with one factor destroyed there is no trapdoor to forge from');

  // ── Act 5: the omission, and then the check that closes it ──────────────
  await page.locator('#degree-run').click();
  await expect(page.locator('#degree-verdict')).toHaveAttribute('data-kind', 'alarm');
  await expect(page.locator('#degree-verdict')).toContainText('EVERY CHECK PASSED');
  await expect(page.locator('#degree-banner')).toBeVisible();
  await scanAt('Act 5: every opening of an over-degree witness accepted, banner standing');

  await page.locator('#enforce-degree').check();
  await expect(page.locator('#degree-banner')).toBeHidden();
  await page.locator('#degree-run').click();
  await expect(page.locator('#degree-verdict')).toContainText('DEGREE_EXCEEDED');
  await scanAt('Act 5: enforcement on - the same witness refused with DEGREE_EXCEEDED');

  await page.locator('#enforce-degree').uncheck();
  await expect(page.locator('#degree-banner')).toBeVisible();

  // ── Act 6: the measured comparison table ────────────────────────────────
  await page.locator('#compare-run').click();
  await expect(page.locator('#compare-verdict')).toHaveAttribute('data-kind', 'ok');
  await expect(page.locator('#compare-verdict')).toContainText('ALL THREE VERIFIED');
  await scanAt('Act 6: all three schemes measured, the comparison table rendered');

  // ── Hover, which persists after a click ─────────────────────────────────
  await page.locator('#compare-run').hover();
  await scanAt('a primary button hovered - its accent fill repainted');

  await page.locator('#make-toxic').hover();
  await scanAt('a danger button hovered');

  await page.locator('.cl-topbar .cl-btn').first().hover();
  await scanAt('a shared top bar control hovered');

  // ── Focus rings on the controls that take them ──────────────────────────
  await page.locator('#open-y').focus();
  await expect(page.locator('#open-y')).toBeFocused();
  await scanAt('a text input focused, showing its focus-visible outline');

  await page.locator('#srs-degree').focus();
  await expect(page.locator('#srs-degree')).toBeFocused();
  await scanAt('the styled select focused, showing its custom chevron and outline');

  await page.locator('#degree-run').focus();
  await scanAt('a primary button focused');
}
