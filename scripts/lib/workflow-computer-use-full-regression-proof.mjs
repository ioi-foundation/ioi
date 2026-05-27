#!/usr/bin/env node
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];

if (!outputPath) {
  throw new Error("usage: workflow-computer-use-full-regression-proof.mjs <output-path>");
}

const root = process.cwd();
const sdkDir = path.join(root, "packages/agent-sdk");

function runCommand(command, args, options = {}) {
  const startedAt = Date.now();
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? root,
    env: process.env,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  return {
    command: [command, ...args].join(" "),
    cwd: path.relative(root, options.cwd ?? root) || ".",
    status: result.status,
    signal: result.signal,
    durationMs: Date.now() - startedAt,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

const build = runCommand("npm", ["run", "build"], { cwd: sdkDir });
assert.equal(build.status, 0, build.stderr || build.stdout);

const test = runCommand("node", ["--test", "--test-concurrency=1", "test/computer-use.test.mjs"], {
  cwd: sdkDir,
});
assert.equal(test.status, 0, test.stderr || test.stdout);

const tap = `${test.stdout}\n${test.stderr}`;
const passCount = Number(tap.match(/# pass (\d+)/)?.[1] ?? 0);
const failCount = Number(tap.match(/# fail (\d+)/)?.[1] ?? -1);
assert.equal(passCount, 37, tap);
assert.equal(failCount, 0, tap);
for (const expectedSubtest of [
  "runtime daemon exposes computer-use provider registry through substrate client",
  "runtime daemon records coding-agent computer-use lease requests",
  "runtime daemon activates mounted sandboxed computer-use contracts instead of failing closed",
  "runtime daemon thread tool activates local fixture sandboxed computer-use lane",
  "runtime daemon fails closed when requested computer-use lane is unavailable",
]) {
  assert.match(tap, new RegExp(`# Subtest: ${expectedSubtest.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
}

const proof = {
  schemaVersion: "ioi.autopilot.stage98.computer-use-full-regression-proof.v1",
  passed: true,
  generatedAt: new Date().toISOString(),
  checks: {
    sdkBuildPassed: true,
    computerUseFullRegressionPassed: true,
    providerDiscoveryIncluded: true,
    leaseRequestProviderProjectionIncluded: true,
    sandboxedHostedAndFailClosedLanesIncluded: true,
  },
  metrics: {
    passCount,
    failCount,
    testDurationMs: test.durationMs,
  },
  commands: [
    {
      command: build.command,
      cwd: build.cwd,
      status: build.status,
      signal: build.signal,
      durationMs: build.durationMs,
    },
    {
      command: test.command,
      cwd: test.cwd,
      status: test.status,
      signal: test.signal,
      durationMs: test.durationMs,
    },
  ],
  evidence: {
    testPath: "packages/agent-sdk/test/computer-use.test.mjs",
  },
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
