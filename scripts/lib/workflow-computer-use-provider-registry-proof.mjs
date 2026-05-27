#!/usr/bin/env node
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];

if (!outputPath) {
  throw new Error("usage: workflow-computer-use-provider-registry-proof.mjs <output-path>");
}

const root = process.cwd();
const registryPath = path.join(root, "packages/runtime-daemon/src/computer-use-provider-registry.mjs");
const registryTestPath = path.join(root, "packages/runtime-daemon/src/computer-use-provider-registry.test.mjs");
const codingToolsPath = path.join(root, "packages/runtime-daemon/src/coding-tools.mjs");
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

const registrySource = readText(registryPath);
const codingToolsSource = readText(codingToolsPath);
const sdkTestSource = readText(sdkTestPath);

for (const pattern of [
  /COMPUTER_USE_PROVIDER_REGISTRY_SCHEMA_VERSION/,
  /ioi\.computer_use\.sandboxed_hosted\.local_fixture/,
  /ioi\.computer_use\.sandboxed_hosted\.local_container/,
  /planned_fail_closed/,
  /fail_closed_when_unavailable:\s*true/,
]) {
  assert.match(registrySource, pattern);
}

for (const pattern of [/computerUseProviderForLane/, /providerRegistry/, /selected_provider_id/]) {
  assert.match(codingToolsSource, pattern);
}

assert.match(sdkTestSource, /providerRegistry\.selected_provider_id/);
assert.match(sdkTestSource, /unavailable_provider_ids\.includes\("ioi\.computer_use\.sandboxed_hosted\.local_container"\)/);

const registryTest = runCommand("node", ["--test", "packages/runtime-daemon/src/computer-use-provider-registry.test.mjs"]);
assert.equal(registryTest.status, 0, registryTest.stderr || registryTest.stdout);

const sdkBuild = runCommand("npm", ["run", "build"], {
  cwd: path.join(root, "packages/agent-sdk"),
});
assert.equal(sdkBuild.status, 0, sdkBuild.stderr || sdkBuild.stdout);

const leaseRequestTestName = "runtime daemon records coding-agent computer-use lease requests";
const leaseRequestTest = runCommand(
  "node",
  [
    "--test",
    "--test-concurrency=1",
    "--test-name-pattern",
    leaseRequestTestName,
    "test/computer-use.test.mjs",
  ],
  { cwd: path.join(root, "packages/agent-sdk") },
);
assert.equal(leaseRequestTest.status, 0, leaseRequestTest.stderr || leaseRequestTest.stdout);
assert.match(
  `${leaseRequestTest.stdout}\n${leaseRequestTest.stderr}`,
  /# Subtest: runtime daemon records coding-agent computer-use lease requests/,
);

const proof = {
  schemaVersion: "ioi.autopilot.stage94.computer-use-provider-registry-proof.v1",
  passed: true,
  generatedAt: new Date().toISOString(),
  checks: {
    registryReportsFixtureAndPlannedContainerSeparately: true,
    leaseRequestIncludesSelectedProvider: true,
    plannedContainerFailsClosed: true,
    providerRegistryHasReusableRuntimeModule: true,
  },
  commands: [
    {
      command: registryTest.command,
      cwd: registryTest.cwd,
      status: registryTest.status,
      signal: registryTest.signal,
      durationMs: registryTest.durationMs,
    },
    {
      command: sdkBuild.command,
      cwd: sdkBuild.cwd,
      status: sdkBuild.status,
      signal: sdkBuild.signal,
      durationMs: sdkBuild.durationMs,
    },
    {
      command: leaseRequestTest.command,
      cwd: leaseRequestTest.cwd,
      status: leaseRequestTest.status,
      signal: leaseRequestTest.signal,
      durationMs: leaseRequestTest.durationMs,
    },
  ],
  evidence: {
    registryPath: path.relative(root, registryPath),
    registryTestPath: path.relative(root, registryTestPath),
    codingToolsPath: path.relative(root, codingToolsPath),
    sdkTestPath: path.relative(root, sdkTestPath),
  },
  parityPlusInterpretation: {
    providerRegistrySpine: "added",
    daemonLeaseRequestProjection: "covered",
    localFixtureProvider: "available_fixture",
    localContainerProvider: "registered_fail_closed_planned",
    remainingOpenWork:
      "Expose provider discovery as a public daemon/API/SDK operation and implement concrete task-scoped browser, Playwright context, and local container providers.",
  },
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
