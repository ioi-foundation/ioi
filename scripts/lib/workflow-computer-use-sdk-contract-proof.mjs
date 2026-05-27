#!/usr/bin/env node
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];

if (!outputPath) {
  throw new Error("usage: workflow-computer-use-sdk-contract-proof.mjs <output-path>");
}

const root = process.cwd();
const sdkDir = path.join(root, "packages/agent-sdk");
const sourcePath = path.join(sdkDir, "src/computer-use.ts");
const indexPath = path.join(sdkDir, "src/index.ts");
const testPath = path.join(sdkDir, "test/computer-use.test.mjs");

const requiredSourcePatterns = [
  /export interface ComputerUseLease/,
  /export interface ComputerControlAdapterContract/,
  /export interface ComputerUseObservationBundle/,
  /export interface EnvironmentSelectionReceipt/,
  /export interface CleanupReceipt/,
  /required_lanes:\s*\["native_browser",\s*"visual_gui",\s*"sandboxed_hosted"\]/,
  /forbids_shadow_runtime_truth:\s*true/,
];

const requiredIndexPatterns = [
  /defaultComputerUseHarnessContract/,
  /evaluateComputerUseTrajectory/,
  /ComputerUseLease/,
  /ComputerUseObservationBundle/,
  /CleanupReceipt/,
  /EnvironmentSelectionReceipt/,
];

const requiredTestNames = [
  "computer-use contract projection exposes three lanes and behavioral loop",
  "computer-use trajectory eval projects pass and fail-closed outcomes",
  "runtime daemon records coding-agent computer-use lease requests",
  "runtime daemon thread tool activates local fixture sandboxed computer-use lane",
  "runtime daemon fails closed when requested computer-use lane is unavailable",
];

function readText(filePath) {
  return fs.readFileSync(filePath, "utf8");
}

function runCommand(command, args, options = {}) {
  const startedAt = Date.now();
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? root,
    env: process.env,
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
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

const source = readText(sourcePath);
const index = readText(indexPath);
const testSource = readText(testPath);

for (const pattern of requiredSourcePatterns) {
  assert.match(source, pattern);
}

for (const pattern of requiredIndexPatterns) {
  assert.match(index, pattern);
}

for (const testName of requiredTestNames) {
  assert.ok(testSource.includes(`test("${testName}"`), `missing focused computer-use test: ${testName}`);
}

const build = runCommand("npm", ["run", "build"], { cwd: sdkDir });
assert.equal(build.status, 0, build.stderr || build.stdout);

const testNamePattern = requiredTestNames.map((name) => name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|");
const focusedTest = runCommand(
  "node",
  [
    "--test",
    "--test-concurrency=1",
    "--test-name-pattern",
    testNamePattern,
    "test/computer-use.test.mjs",
  ],
  { cwd: sdkDir },
);
assert.equal(focusedTest.status, 0, focusedTest.stderr || focusedTest.stdout);

const stdout = `${focusedTest.stdout}\n${focusedTest.stderr}`;
for (const testName of requiredTestNames) {
  assert.match(stdout, new RegExp(`# Subtest: ${testName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
}

const proof = {
  schemaVersion: "ioi.autopilot.stage92.computer-use-sdk-contract-proof.v1",
  passed: true,
  generatedAt: new Date().toISOString(),
  checks: {
    sdkExportsComputerUseContractSpine: true,
    defaultContractRequiresThreeLanes: true,
    defaultContractForbidsShadowRuntimeTruth: true,
    focusedComputerUseTestsPassed: true,
    localFixtureProviderIsExplicitlyFixtureOnly: true,
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
      command: focusedTest.command,
      cwd: focusedTest.cwd,
      status: focusedTest.status,
      signal: focusedTest.signal,
      durationMs: focusedTest.durationMs,
      requiredSubtests: requiredTestNames,
    },
  ],
  evidence: {
    sourcePath: path.relative(root, sourcePath),
    indexPath: path.relative(root, indexPath),
    testPath: path.relative(root, testPath),
  },
  parityPlusInterpretation: {
    sdkAndDaemonContract: "covered",
    productProviderRegistry: "open",
    concreteTaskScopedBrowserProvider: "open",
    localContainerProvider: "open",
    note:
      "The SDK/runtime computer-use contract and local fixture lane are regression guarded; the product-level provider registry and concrete isolated providers remain separate parity-plus implementation work.",
  },
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
