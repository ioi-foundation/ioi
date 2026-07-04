#!/usr/bin/env node
// Harness adapter EXECUTION done-bar — the canonical single entry point for "the adapter
// drivers really execute, end to end, and the proof shows up everywhere it must".
//
// This composes the two assertion suites that together cover the full contract, without
// duplicating their checks:
//
//   1. verify-hypervisor-harness-adapter-drivers.mjs   (API truth)
//      Registry wiring + full-substrate runnability probes, admitted enable, isolated
//      session per harness with the binding admitted at create, wallet 403 challenge →
//      grant → execute, REAL workspace mutation (report ⇔ disk for every reported file),
//      normalized HarnessAdapterEvent records persisted, ImplementationResultPayload,
//      transcript state_root, execute receipt, Codex/Claude stay auth/provider-trust-gated
//      unwired slots, native-worker legacy lane unchanged, drivers restored to admitted-off.
//
//   2. verify-hypervisor-editor-harness-model-e2e.mjs  (UI projection truth)
//      New Session offers editor/harness/model axes → launch binds all three → OpenCode
//      driver executes into the environment workspace the editor serves → VS Code Browser
//      open lane serves that root → Work Ledger indexes the harness_execution entry with
//      receipt + state_root + Run Timeline link → transcript plane state_root matches →
//      Workbench renders the admitted harness binding.
//
// Both suites run REAL executions against the live Ollama route (qwen2.5:7b); nothing is
// faked and external CLI state is never treated as truth. Expect ~2–5 min total.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-harness-adapter-execution.mjs

import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SUITES = [
  ["API truth (drivers)", "verify-hypervisor-harness-adapter-drivers.mjs"],
  ["UI projection (editor+harness+model e2e)", "verify-hypervisor-editor-harness-model-e2e.mjs"],
];

let failed = 0;
for (const [label, file] of SUITES) {
  console.log(`\n━━ ${label} — ${file}`);
  // Paired budget ladder (hot-host doctrine): shim task 600s → daemon lane reap 660s →
  // per-suite ceiling must cover 2 sequential real driver runs + overhead. CPU-only local
  // model gates treat inference latency as stochastic, never deterministic.
  const r = spawnSync(process.execPath, [path.join(HERE, file)], { stdio: "inherit", timeout: 30 * 60 * 1000 });
  if (r.status !== 0) failed++;
}
console.log(`\nharness adapter execution readiness: ${failed ? "FAIL" : "OK"} (${SUITES.length - failed}/${SUITES.length} suites)`);
process.exit(failed ? 1 : 0);
