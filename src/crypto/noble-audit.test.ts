/* What "audited" covers for the Noble packages this lab ships.
 *
 * Four places called the libraries audited with no version: the README
 * ("@noble/curves (audited, dependency-free, ...)"), src/crypto/fr.ts
 * ("(audited, constant-time where it claims to be)"), src/crypto/bls.ts
 * ("@noble/curves is audited, has no dependencies") and the intro panel ("it
 * comes from an audited library"). The two libraries record different audits,
 * both behind the pins here:
 *
 *   @noble/curves ^2.4.0 — audited "at version 2.3.0, in Aug 2026, by [Trail of Bits]"
 *   @noble/hashes ^2.3.0 — audited "at version 1.0.0, in Jan 2022, independently, by [Cure53]"
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const read = (rel: string) => readFileSync(new URL(rel, import.meta.url), 'utf8');
const flat = (text: string) => text.replace(/\n\s*\*\s?/g, ' ').replace(/\s+/g, ' ');

const pkg = JSON.parse(read('../../package.json'));
const curvesReadme = read('../../node_modules/@noble/curves/README.md');
const hashesReadme = read('../../node_modules/@noble/hashes/README.md');

describe('the Noble audit claims', () => {
  it('pins versions later than either library has audited', () => {
    expect(pkg.dependencies['@noble/curves']).toBe('^2.4.0');
    expect(pkg.dependencies['@noble/hashes']).toBe('^2.3.0');
    expect(curvesReadme).toMatch(/at version 2\.3\.0, in Aug 2026, by \[Trail of Bits\]/);
    expect(hashesReadme).toMatch(/at version 1\.0\.0, in Jan 2022, independently, by \[Cure53\]/);
    expect(curvesReadme).not.toMatch(/at version 2\.4\.\d+, in [A-Z]/);
    expect(hashesReadme).not.toMatch(/at version 2\.\d+\.\d+, in [A-Z]/);
  });

  it('no place calls a shipped library simply "audited"', () => {
    for (const [name, text] of [
      ['README.md', flat(read('../../README.md'))],
      ['src/crypto/fr.ts', flat(read('./fr.ts'))],
      ['src/crypto/bls.ts', flat(read('./bls.ts'))],
      ['src/ui/intro.ts', flat(read('../ui/intro.ts'))],
    ] as const) {
      expect(text, name).not.toContain('(audited, dependency-free');
      expect(text, name).not.toContain('(audited, constant-time');
      expect(text, name).not.toContain('@noble/curves is audited');
      expect(text, name).not.toContain('from an audited library');
      expect(text, name).toMatch(/at version 2\.3\.0, in Aug 2026, by \[?Trail of Bits\]?/);
    }
  });
});
