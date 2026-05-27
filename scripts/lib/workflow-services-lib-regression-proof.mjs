#!/usr/bin/env node
import assert from "node:assert/strict";
import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];

if (!outputPath) {
  throw new Error("usage: workflow-services-lib-regression-proof.mjs <output-path>");
}

const repairedRegressionTests = [
  "default_component_adapter_invokes_gated_authority_tooling_components",
  "browser_wait_timeout_honors_requested_duration_plus_grace",
  "semantic_impact_classifies_paths_from_runtime_receipts",
];

const startedAtMs = Date.now();
const commandArgs = ["test", "-p", "ioi-services", "--lib", "--", "--test-threads=1"];
const result = childProcess.spawnSync("cargo", commandArgs, {
  cwd: process.cwd(),
  encoding: "utf8",
  maxBuffer: 80 * 1024 * 1024,
});
const durationMs = Date.now() - startedAtMs;
const output = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;

assert.equal(result.status, 0, output.slice(-12000));
assert.equal(result.signal, null);
assert.match(output, /test result: ok\./);
assert.match(output, /2268 passed/);
assert.match(output, /0 failed/);
assert.match(output, /4 ignored/);
for (const testName of repairedRegressionTests) {
  assert.match(output, new RegExp(`${testName} \\.\\.\\. ok`), `missing repaired test: ${testName}`);
}

const proof = {
  schemaVersion: "ioi.autopilot.stage86.services-lib-regression-proof.v1",
  passed: true,
  generatedAt: new Date().toISOString(),
  checks: {
    cargoStatusOk: result.status === 0,
    noSignal: result.signal === null,
    testResultOk: /test result: ok\./.test(output),
    repairedRegressionTestsPassed: repairedRegressionTests.every((testName) =>
      new RegExp(`${testName} \\.\\.\\. ok`).test(output),
    ),
  },
  metrics: {
    durationMs,
    passed: 2268,
    failed: 0,
    ignored: 4,
  },
  stabilization: {
    mode: "single-rust-test-thread",
    reason:
      "A default-parallel proof attempt observed a post-test SIGABRT with `malloc(): unaligned fastbin chunk detected`; the services lib has process-env-dependent tests, so this proof keeps the broad logic regression deterministic while the env-mutation cleanup remains a follow-up.",
  },
  repairedRegressionTests,
  command: {
    command: `cargo ${commandArgs.join(" ")}`,
    status: result.status,
    signal: result.signal,
    stdoutTail: String(result.stdout ?? "").slice(-12000),
    stderrTail: String(result.stderr ?? "").slice(-4000),
  },
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
