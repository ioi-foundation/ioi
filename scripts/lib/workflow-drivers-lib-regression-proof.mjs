#!/usr/bin/env node
import assert from "node:assert/strict";
import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];

if (!outputPath) {
  throw new Error("usage: workflow-drivers-lib-regression-proof.mjs <output-path>");
}

const startedAtMs = Date.now();
const result = childProcess.spawnSync("cargo", ["test", "-p", "ioi-drivers", "--lib"], {
  cwd: process.cwd(),
  encoding: "utf8",
  maxBuffer: 20 * 1024 * 1024,
});
const durationMs = Date.now() - startedAtMs;
const output = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;

assert.equal(result.status, 0, output.slice(-8000));
assert.equal(result.signal, null);
assert.match(output, /test result: ok\./);
assert.match(output, /161 passed/);
assert.match(output, /0 failed/);
assert.match(output, /2 ignored/);
assert.match(output, /execute_strips_sensitive_inherited_environment \.\.\. ok/);

const proof = {
  schemaVersion: "ioi.autopilot.stage84.drivers-lib-regression-proof.v1",
  passed: true,
  generatedAt: new Date().toISOString(),
  checks: {
    cargoStatusOk: result.status === 0,
    noSignal: result.signal === null,
    testResultOk: /test result: ok\./.test(output),
    terminalEnvScrubTestPassed: /execute_strips_sensitive_inherited_environment \.\.\. ok/.test(output),
  },
  metrics: {
    durationMs,
    passed: 161,
    failed: 0,
    ignored: 2,
  },
  command: {
    command: "cargo test -p ioi-drivers --lib",
    status: result.status,
    signal: result.signal,
    stdoutTail: String(result.stdout ?? "").slice(-8000),
    stderrTail: String(result.stderr ?? "").slice(-4000),
  },
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
