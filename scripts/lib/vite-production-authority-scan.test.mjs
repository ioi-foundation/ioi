import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { runProductionAuthorityScan } from './vite-production-authority-scan.mjs';

const forbidden = [
  { pattern: /\blocalStorage\b/u, label: 'browser operational persistence' },
  { pattern: /\bMath\.random\b/u, label: 'random authority material', sourceOnly: true },
];

async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ioi-vite-authority-scan-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await Promise.all([
    mkdir(path.join(root, 'src', 'nested'), { recursive: true }),
    mkdir(path.join(root, 'fixtures', 'legacy-ui'), { recursive: true }),
    mkdir(path.join(root, 'dist', '.vite'), { recursive: true }),
    mkdir(path.join(root, 'dist', 'assets'), { recursive: true }),
  ]);
  await Promise.all([
    writeFile(path.join(root, 'index.html'), '<script type="module" src="/src/main.js"></script>\n'),
    writeFile(path.join(root, 'src', 'main.js'), "import './nested/safe.js';\n"),
    writeFile(path.join(root, 'src', 'nested', 'safe.js'), "export const safe = true;\n"),
    writeFile(path.join(root, 'fixtures', 'legacy-ui', 'README.md'), '# Quarantined\n'),
    writeFile(path.join(root, 'fixtures', 'legacy-ui', 'danger.js'), 'localStorage.setItem("authority", Math.random());\n'),
    writeFile(path.join(root, 'dist', 'index.html'), '<script type="module" src="/assets/index.js"></script>\n'),
    writeFile(path.join(root, 'dist', 'assets', 'index.js'), 'const safe=true;\n'),
    writeFile(path.join(root, 'dist', '.vite', 'manifest.json'), `${JSON.stringify({ 'index.html': { file: 'assets/index.js', src: 'index.html', isEntry: true } })}\n`),
  ]);
  return root;
}

test('walks nested entry imports, hashes dist, and reports quarantined fixtures unreachable', async (t) => {
  const root = await fixture(t);
  await runProductionAuthorityScan({ appName: 'test.app', root, forbidden });
  const report = JSON.parse(await readFile(path.join(root, 'dist', 'production-authority-scan.json'), 'utf8'));
  assert.deepEqual(report.source_graph.files, ['index.html', 'src/main.js', 'src/nested/safe.js']);
  assert.equal(report.quarantined_fixtures[0].reachable, false);
  assert.match(report.dist.hashes['assets/index.js'], /^sha256:[0-9a-f]{64}$/u);
});

test('fails when a quarantined fixture enters the production import graph', async (t) => {
  const root = await fixture(t);
  await writeFile(path.join(root, 'src', 'main.js'), "import '../fixtures/legacy-ui/danger.js';\n");
  await assert.rejects(
    runProductionAuthorityScan({ appName: 'test.app', root, forbidden }),
    /quarantined fixture entered the production graph/u,
  );
});

test('fails when forbidden authority material survives in the built dist', async (t) => {
  const root = await fixture(t);
  await writeFile(path.join(root, 'dist', 'assets', 'index.js'), 'localStorage.setItem("authority", "forged");\n');
  await assert.rejects(
    runProductionAuthorityScan({ appName: 'test.app', root, forbidden }),
    /dist\/assets\/index\.js contains forbidden browser operational persistence/u,
  );
});
