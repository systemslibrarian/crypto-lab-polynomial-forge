import { defineConfig, devices } from '@playwright/test'

/**
 * Both browser suites run against the PRODUCTION BUILD served by `vite preview`,
 * so what passes here is what ships.
 *
 *   a11y.spec.ts    the axe + arithmetic-contrast + non-text WCAG A/AA gate
 *   claims.spec.ts  the claims suite: does the page tell the truth
 *
 * Port 4696 is unique to this lab across the fleet, in committed state, and is
 * never the Vite default 4173. With 190 labs side by side a shared port means
 * `reuseExistingServer` silently scans a different lab's preview - that has
 * really happened here.
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  timeout: 180_000,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: 'http://localhost:4696/crypto-lab-polynomial-forge/',
  },
  projects: [
    {
      name: 'a11y',
      testMatch: /a11y\.spec\.ts/,
      // Dark is the only theme this lab ships, so it is the only one scanned.
      use: { ...devices['Desktop Chrome'], colorScheme: 'dark' },
    },
    {
      name: 'claims',
      testMatch: /claims\.spec\.ts/,
      use: { ...devices['Desktop Chrome'], colorScheme: 'dark' },
    },
  ],
  webServer: {
    // Build before serving. `vite preview` serves whatever is already in dist/,
    // so without the build in front a run tests a stale bundle - and a build
    // that FAILS leaves the previous good bundle in place, so the whole suite
    // passes green against source that no longer compiles. That silently
    // invalidates mutation checking, which is the only way we prove a test has
    // teeth.
    command: 'npm run build && npm run preview -- --port 4696 --strictPort',
    url: 'http://localhost:4696/crypto-lab-polynomial-forge/',
    reuseExistingServer: !process.env.CI,
    timeout: 180_000,
  },
})
