import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runProductionAuthorityScan } from '../../../scripts/lib/vite-production-authority-scan.mjs';

await runProductionAuthorityScan({
  appName: 'aiagent.xyz',
  root: path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..'),
  forbidden: [
    { pattern: /\blocalStorage\b/u, label: 'browser operational persistence' },
    { pattern: /\bMath\.random\b/u, label: 'random receipt or authority material', sourceOnly: true },
    { pattern: /Audit Passed|Connected to IOI Network|Profit:/u, label: 'simulated terminal success' },
    { pattern: /window\.__IOI_SESSION__|x-ioi-principal|x-ioi-tenant/u, label: 'browser-controlled identity authority' },
  ],
});
