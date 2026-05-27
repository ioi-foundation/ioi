#!/usr/bin/env node
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];

if (!outputPath) {
  throw new Error("usage: workflow-computer-use-provider-discovery-api-proof.mjs <output-path>");
}

const root = process.cwd();
const daemonIndexPath = path.join(root, "packages/runtime-daemon/src/index.mjs");
const substrateClientPath = path.join(root, "packages/agent-sdk/src/substrate-client.ts");
const sdkIndexPath = path.join(root, "packages/agent-sdk/src/index.ts");
const sdkTestPath = path.join(root, "packages/agent-sdk/test/computer-use.test.mjs");

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

assert.match(readText(daemonIndexPath), /\/v1\/computer-use\/providers/);
assert.match(readText(daemonIndexPath), /computerUseProviderRegistryReport/);
assert.match(readText(substrateClientPath), /discoverComputerUseProviders/);
assert.match(readText(substrateClientPath), /RuntimeComputerUseProviderRegistryReport/);
assert.match(readText(sdkIndexPath), /RuntimeComputerUseProviderRegistryEntry/);
assert.match(readText(sdkTestPath), /runtime daemon exposes computer-use provider registry through substrate client/);

const daemonCheck = runCommand("node", ["--check", "packages/runtime-daemon/src/index.mjs"]);
assert.equal(daemonCheck.status, 0, daemonCheck.stderr || daemonCheck.stdout);

const sdkBuild = runCommand("npm", ["run", "build"], {
  cwd: path.join(root, "packages/agent-sdk"),
});
assert.equal(sdkBuild.status, 0, sdkBuild.stderr || sdkBuild.stdout);

const testName = "runtime daemon exposes computer-use provider registry through substrate client";
const apiTest = runCommand(
  "node",
  [
    "--test",
    "--test-concurrency=1",
    "--test-name-pattern",
    testName,
    "test/computer-use.test.mjs",
  ],
  { cwd: path.join(root, "packages/agent-sdk") },
);
assert.equal(apiTest.status, 0, apiTest.stderr || apiTest.stdout);
assert.match(`${apiTest.stdout}\n${apiTest.stderr}`, new RegExp(`# Subtest: ${testName}`));

const proof = {
  schemaVersion: "ioi.autopilot.stage96.computer-use-provider-discovery-api-proof.v1",
  passed: true,
  generatedAt: new Date().toISOString(),
  checks: {
    daemonEndpointExposesProviderRegistry: true,
    sdkClientExposesProviderDiscovery: true,
    sdkTypesExportProviderRegistry: true,
    liveDaemonBackedProviderDiscoveryTestPassed: true,
  },
  commands: [
    {
      command: daemonCheck.command,
      cwd: daemonCheck.cwd,
      status: daemonCheck.status,
      signal: daemonCheck.signal,
      durationMs: daemonCheck.durationMs,
    },
    {
      command: sdkBuild.command,
      cwd: sdkBuild.cwd,
      status: sdkBuild.status,
      signal: sdkBuild.signal,
      durationMs: sdkBuild.durationMs,
    },
    {
      command: apiTest.command,
      cwd: apiTest.cwd,
      status: apiTest.status,
      signal: apiTest.signal,
      durationMs: apiTest.durationMs,
    },
  ],
  evidence: {
    daemonIndexPath: path.relative(root, daemonIndexPath),
    substrateClientPath: path.relative(root, substrateClientPath),
    sdkIndexPath: path.relative(root, sdkIndexPath),
    sdkTestPath: path.relative(root, sdkTestPath),
  },
  parityPlusInterpretation: {
    publicProviderDiscovery: "added",
    localFixtureProvider: "discoverable_available_fixture",
    localContainerProvider: "discoverable_fail_closed_planned",
    remainingOpenWork:
      "Implement concrete task-scoped browser, Playwright context, local container execution, profile contamination guard, and GUI run-inspector provider rows.",
  },
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
