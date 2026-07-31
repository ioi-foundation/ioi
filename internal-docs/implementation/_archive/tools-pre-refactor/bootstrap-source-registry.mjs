#!/usr/bin/env node

// Permanent read-only facade for the completed one-time source-disposition
// migration. The replay-capable implementation is retained only as historical
// evidence under _archive/reconciliation-tools/. This live path must never
// discover, classify, approve, or write a private-estate path.

import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const mode = process.argv[2];
const archivedReplay = "_archive/reconciliation-tools/bootstrap-source-registry.replay-approved-transaction.mjs";

if (mode !== "--check" || process.argv.length !== 3) {
  process.stderr.write(
    `source registry write refused permanently: the approved one-time replay is sealed and archived at ${archivedReplay}; future changes require a reviewed append-only approval successor and a checker-pinned hash\n`,
  );
  process.exit(mode === "--finalize-approved-transaction" ? 1 : 2);
}

const checker = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "check-source-dispositions.mjs",
);
const result = spawnSync(process.execPath, [checker], {
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
});

if (result.stdout) process.stdout.write(result.stdout);
if (result.stderr) process.stderr.write(result.stderr);
if (result.error) {
  process.stderr.write(`source registry check failed to start: ${result.error.message}\n`);
  process.exit(1);
}
process.exit(result.status ?? 1);
