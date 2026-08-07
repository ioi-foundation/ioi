import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runProductionAuthorityScan } from '../../../scripts/lib/vite-production-authority-scan.mjs';

await runProductionAuthorityScan({
  appName: 'sas.xyz',
  root: path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..'),
  forbidden: [
    { pattern: /\blocalStorage\b/u, label: 'browser operational persistence' },
    { pattern: /\bMath\.random\b/u, label: 'random receipt or authority material', sourceOnly: true },
    { pattern: /chain forward-linked|signed .* now|settlement complete/iu, label: 'simulated authority claim' },
    { pattern: /window\.__IOI_SESSION__|x-ioi-principal|x-ioi-tenant/u, label: 'browser-controlled identity authority' },
  ],
});
