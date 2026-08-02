#!/usr/bin/env node

// Current M4 OutcomeRoom done-bar. The predecessor runner mixed retired v1 mutation fixtures
// with current claims and could leave 41 assertions dark behind stale authority setup. This
// runner admits no skip or explanation lane: every child process must exit zero, emit its exact
// pinned number of positive assertions, and together produce exactly 143 current assertions.
//
//   98 — fresh bounded-System/runtime, Agentgres, CAS, refusal, recovery, and product projection
//   22 — field-for-field v3 room shapes and SystemScopedObjectBinding composition depth
//   23 — typed v1 retirement, zero-mutation, restart, and no compatibility-route behavior

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..", "..");
const childEnv = Object.fromEntries(
  Object.entries(process.env).filter(
    ([key]) =>
      !key.startsWith("IOI_TEST_") &&
      !key.startsWith("IOI_HYPERVISOR_WALLET_") &&
      !key.startsWith("IOI_WALLET_NETWORK_"),
  ),
);
const supportChecks = [
  {
    name: "architecture-contract-bar",
    command: "npm",
    args: ["run", "check:architecture-contract-bar"],
  },
  {
    name: "ported-surface-modules",
    command: process.execPath,
    args: ["apps/hypervisor/scripts/verify-hypervisor-surface-modules.mjs"],
  },
  {
    name: "isolated-listener-ownership",
    command: process.execPath,
    args: [
      "--test",
      "apps/hypervisor/scripts/lib/isolated-daemon.test.mjs",
    ],
  },
];
const planes = [
  {
    name: "bounded-System runtime plane",
    script: "apps/hypervisor/scripts/verify-m4-outcome-room-system-spine.mjs",
    expected: 98,
    countSentinel: "98/98 passed",
    successSentinel:
      "M4 outcome-room system spine: PASS (direct activation, real package/genesis/System, runtime-derived room result, reciprocal CAS, Agentgres replay/recovery, selected ported-shell projection)",
  },
  {
    name: "room composition contract-depth plane",
    script:
      "apps/hypervisor/scripts/verify-m4-room-composition-contract-depth.mjs",
    expected: 22,
    countSentinel: "22/22 passed",
    successSentinel: "M4 room composition contract depth: OK",
  },
  {
    name: "v1 retirement plane",
    script: "apps/hypervisor/scripts/verify-m4-outcome-room-v1-retirement.mjs",
    expected: 23,
    countSentinel: "23/23 passed",
    successSentinel: "M4 OutcomeRoom v1 retirement: OK",
  },
];

for (const support of supportChecks) {
  const result = spawnSync(support.command, support.args, {
    cwd: REPO,
    env: childEnv,
    encoding: "utf8",
    timeout: 45 * 60 * 1000,
    maxBuffer: 64 * 1024 * 1024,
  });
  const output = `${result.stdout || ""}\n${result.stderr || ""}`;
  const forbidden = output
    .split(/\r?\n/u)
    .filter((line) =>
      /^\s*(?:FAIL|SKIP|BLOCKED|VERIFIER CRASH|verifier crashed)(?:\s|:|$)/u.test(
        line,
      ),
    );
  if (result.error || result.status !== 0 || forbidden.length > 0) {
    if (result.stdout) process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
    console.error(
      `FAIL support check ${support.name}: ${result.error?.message || `exit ${result.status}`}${forbidden.length ? `; red/dark output: ${forbidden.join(" | ")}` : ""}`,
    );
    process.exit(1);
  }
  console.log(
    `M4_SUPPORT_CHECK=${support.name} EXIT=0 OUTPUT_SHA256=${createHash("sha256").update(output).digest("hex")}`,
  );
}

let total = 0;
for (const plane of planes) {
  const result = spawnSync(process.execPath, [plane.script], {
    cwd: REPO,
    env: childEnv,
    encoding: "utf8",
    timeout: 45 * 60 * 1000,
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  if (result.error) {
    console.error(`FAIL ${plane.name}: ${result.error.message}`);
    process.exit(1);
  }
  if (result.status !== 0) {
    console.error(`FAIL ${plane.name}: child exit ${result.status}`);
    process.exit(1);
  }
  const lines = String(result.stdout || "").split(/\r?\n/u);
  const diagnosticLines = `${result.stdout || ""}\n${result.stderr || ""}`.split(
    /\r?\n/u,
  );
  const forbidden = diagnosticLines.filter((line) =>
    /^\s*(?:FAIL|SKIP|BLOCKED|VERIFIER CRASH|verifier crashed)(?:\s|:|$)/u.test(line),
  );
  if (forbidden.length > 0) {
    console.error(
      `FAIL ${plane.name}: child emitted forbidden red/dark output: ${forbidden.join(" | ")}`,
    );
    process.exit(1);
  }
  const passLines = lines.filter((line) => /^\s*PASS(?:\s|$)/u.test(line));
  const passNames = passLines.map((line) =>
    line
      .trim()
      .replace(/^PASS\s+/u, "")
      .split(/\s+(?:—|\s\()/u, 1)[0]
      .trim(),
  );
  if (new Set(passNames).size !== passNames.length) {
    console.error(`FAIL ${plane.name}: duplicate PASS assertion names are not coverage`);
    process.exit(1);
  }
  if (!lines.includes(plane.countSentinel)) {
    console.error(`FAIL ${plane.name}: missing exact count sentinel '${plane.countSentinel}'`);
    process.exit(1);
  }
  if (!lines.includes(plane.successSentinel)) {
    console.error(`FAIL ${plane.name}: missing success sentinel '${plane.successSentinel}'`);
    process.exit(1);
  }
  const passes = passLines.length;
  if (passes !== plane.expected) {
    console.error(
      `FAIL ${plane.name}: emitted ${passes} PASS assertions, expected exactly ${plane.expected}`,
    );
    process.exit(1);
  }
  total += passes;
}

const expectedTotal = planes.reduce((sum, plane) => sum + plane.expected, 0);
if (total !== expectedTotal) {
  console.error(
    `FAIL current OutcomeRoom plane: ${total}/${expectedTotal} assertions`,
  );
  process.exit(1);
}
console.log(`${expectedTotal}/${expectedTotal} passed`);
console.log(
  "M4 OutcomeRoom plane: OK (current bounded-System runtime + contract depth + typed predecessor retirement; no skipped or dark assertions)",
);
