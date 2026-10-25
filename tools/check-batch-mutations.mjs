import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';

// Local constrained environments can supply a browser config without changing
// the committed CI browser version or removing any assertion.
const config = process.env.POLYNOMIAL_PLAYWRIGHT_CONFIG;
const args = ['playwright', 'test', 'e2e/batch.claims.spec.ts', '--project=claims', '--workers=1', '--retries=0', ...(config ? ['--config', config] : [])];
const run = (cmd, argv) => spawnSync(cmd, argv, { encoding: 'utf8', env: { ...process.env, CI: '1' }, timeout: 180000 });
const build = () => {
  const r = run('npm', ['run', 'build']);
  if (r.status !== 0) throw new Error(`DOES NOT BUILD\n${r.stdout}\n${r.stderr}`);
  const hash = createHash('sha256');
  for (const f of readdirSync('dist/assets').filter(f => f.endsWith('.js')).sort()) hash.update(readFileSync(`dist/assets/${f}`));
  return hash.digest('hex');
};
const cases = [
  ['proof-bound challenge omits witnesses', 'src/crypto/batch.ts', 'if (bindWitnesses) entries.forEach', 'if (bindWitnesses && false) entries.forEach'],
  ['pairing verdict inverted', 'src/crypto/batch.ts', 'const ok = pairingEqual(', 'const ok = !pairingEqual('],
  ['negative scope claim removed', 'src/ui/act-batch.ts', 'This is not a complete PLONK exploit', 'This is a complete PLONK exploit'],
];
const baselineHash = build();
const baseline = run('npx', args);
if (baseline.status !== 0 || !/2 passed/.test(baseline.stdout)) throw new Error(`Baseline must pass both owning tests\n${baseline.stdout}\n${baseline.stderr}`);
console.log('Baseline: 2 owning tests passed');
for (const [name, path, from, to] of cases) {
  const original = readFileSync(path, 'utf8');
  if (original.split(from).length !== 2) throw new Error(`Non-unique mutation anchor: ${name}`);
  try {
    writeFileSync(path, original.replace(from, to));
    if (build() === baselineHash) throw new Error(`Bundle did not change: ${name}`);
    const r = run('npx', args);
    const log = `${r.stdout}\n${r.stderr}`;
    if (r.status !== 1 || !/[1-9]\d* failed/.test(log) || !/expect\(/.test(log) || /was not able to start|ERR_CONNECTION|Executable doesn't exist|browserType.launch/.test(log)) {
      throw new Error(`Not an assertion kill: ${name}\n${log}`);
    }
    console.log(`KILLED: ${name}`);
  } finally {
    writeFileSync(path, original);
    if (build() !== baselineHash) throw new Error(`Restored bundle differs: ${name}`);
  }
}
console.log('3/3 mutations killed; source and bundle restored');
