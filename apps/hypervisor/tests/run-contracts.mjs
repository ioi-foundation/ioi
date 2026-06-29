#!/usr/bin/env node
// Run all source-owned surface contract tests (*.contract.mjs).
// Requires the vite dev server on :1420. Run: npm run test:contract --workspace=@ioi/hypervisor-app
import { readdirSync } from "node:fs";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const dir = dirname(fileURLToPath(import.meta.url));
const tests = readdirSync(dir).filter((f) => f.endsWith(".contract.mjs")).sort();
let failed = 0;
for (const t of tests) {
  console.log(`\n=== ${t} ===`);
  try {
    execSync(`node ${join(dir, t)}`, { stdio: "inherit" });
  } catch {
    failed++;
  }
}
console.log(`\n${tests.length - failed}/${tests.length} contract suites passed.`);
process.exit(failed ? 1 : 0);
