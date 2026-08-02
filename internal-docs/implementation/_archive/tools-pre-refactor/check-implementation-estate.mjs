#!/usr/bin/env node

// Read-only private acceptance bar. Writers are intentionally separate so a
// check can never refresh stale evidence or status as a side effect.

import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import { implementationRoot, repoRoot } from "./lib.mjs";

const checks = [
  ["source dispositions", "tools/check-source-dispositions.mjs", []],
  ["source manifest", "tools/freeze-source-manifest.mjs", ["--check"]],
  ["work-item migration finalization", "tools/check-work-item-migration-finalization.mjs", []],
  ["work-item code-anchor tests", "tools/check-work-items.mjs", ["--self-test-code-anchors"]],
  ["work items", "tools/check-work-items.mjs", []],
  ["single sequencer", "tools/check-single-sequencer.mjs", []],
  ["status truth", "tools/check-status-truth.mjs", []],
  ["approved sequencer diff", "tools/generate-approved-sequencer-diff.mjs", ["--check"]],
  ["private boundary status-parser tests", "tools/check-private-estate-boundary.mjs", ["--self-test-status-parser"]],
  ["private boundary", "tools/check-private-estate-boundary.mjs", []],
  ["module headers", "tools/check-module-headers.mjs", []],
  ["internal links", "tools/check-internal-links.mjs", []],
  ["Markdown structure tests", "tools/check-markdown-structure.mjs", ["--self-test"]],
  ["Markdown structure", "tools/check-markdown-structure.mjs", []],
  ["literal exits", "tools/check-literal-exits.mjs", []],
  ["program-state lifecycle tests", "tools/test-program-state-lifecycle.mjs", []],
  ["architecture review-ledger tests", "tools/test-architecture-coverage-review-ledger.mjs", []],
  ["architecture coverage", "tools/generate-architecture-coverage.mjs", ["--check"]],
  ["Hypervisor live read-only crawl evidence", "tools/capture-hypervisor-live-crawl.mjs", ["--check"]],
  ["Hypervisor visual-evidence tests", "tools/generate-hypervisor-surface-coverage.mjs", ["--self-test-visual-evidence"]],
  ["Hypervisor coverage generation", "tools/generate-hypervisor-surface-coverage.mjs", ["--check"]],
  ["Hypervisor coverage contract", "tools/check-hypervisor-surface-coverage.mjs", []],
  ["program state generation", "tools/generate-program-state.mjs", ["--check"]],
  ["program state compatibility", "check-program-state.mjs", []],
  ["generated projections", "tools/check-generated.mjs", []],
  ["checkout nonclaims", "tools/check-clean-checkout-nonclaims.mjs", []],
];

const failures = [];
const skips = [];
function skipSignals(output) {
  const signals = [];
  for (const line of output.split(/\r?\n/u)) {
    try {
      const value = JSON.parse(line);
      if (value?.result === "SKIP") signals.push(line);
    } catch {
      // Most checker output is ordinary text. Only standalone JSON notices are
      // interpreted structurally here.
    }
  }
  if (/\bvisual(?: result| evidence)?(?: remains)? SKIP\b/iu.test(output)) {
    signals.push("declared visual SKIP");
  }
  if (/\bM0 evidence SKIP\b/iu.test(output)) signals.push("declared M0 evidence SKIP");
  if (/\bclean checkout is SKIP\b/iu.test(output)) signals.push("declared clean-checkout SKIP");
  return [...new Set(signals)];
}

for (const [label, relative, args] of checks) {
  const command = path.join(implementationRoot, relative);
  const result = spawnSync(process.execPath, [command, ...args], {
    cwd: repoRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  const output = [result.stdout, result.stderr].filter(Boolean).join("").trim();
  if (result.status !== 0) {
    failures.push(`${label}: ${output || `exit ${result.status}`}`);
    continue;
  }
  const signals = skipSignals(output);
  if (signals.length > 0) {
    skips.push(`${label}: ${signals.join("; ")}`);
    process.stdout.write(`[SKIP] ${label}\n${output}\n`);
  } else {
    process.stdout.write(`[PASS] ${label}\n${output}\n`);
  }
}

if (failures.length > 0) {
  process.stderr.write(`implementation-estate check failed with ${failures.length} failing bar(s):\n${failures.map((failure) => `- ${failure}`).join("\n")}\n`);
  process.exit(1);
}

if (skips.length > 0) {
  process.stderr.write(`implementation-estate acceptance incomplete with ${skips.length} SKIP-bearing bar(s):\n${skips.map((skip) => `- ${skip}`).join("\n")}\nSKIP is not proof and the private estate is not fully accepted.\n`);
  process.exit(1);
}

process.stdout.write(`implementation-estate check passed: ${checks.length} private bars, zero failures, zero SKIPs\n`);
