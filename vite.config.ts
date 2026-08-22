import { defineConfig, configDefaults } from 'vitest/config'

// base must match the GitHub Pages project subpath:
// https://systemslibrarian.github.io/crypto-lab-polynomial-forge/
export default defineConfig({
  base: '/crypto-lab-polynomial-forge/',
  test: {
    // Colocated unit tests only; the Playwright specs in e2e/ are not Vitest specs.
    include: ['src/**/*.test.ts'],
    exclude: [...configDefaults.exclude, 'e2e/**'],
    // The BLS12-381 KAT suite runs 122 upstream vectors, each a pairing check.
    testTimeout: 120_000,
  },
})
