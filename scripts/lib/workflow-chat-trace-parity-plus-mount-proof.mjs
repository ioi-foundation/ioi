#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-chat-trace-parity-plus-mount-proof.mjs <output-path>");
}

const extensionPath = "apps/autopilot/openvscode-extension/ioi-workbench/extension.js";
const staticTestPath = "apps/autopilot/openvscode-extension/ioi-workbench/extension.static.test.mjs";
const extensionSource = fs.readFileSync(extensionPath, "utf8");
const staticTestSource = fs.readFileSync(staticTestPath, "utf8");

const mountPoints = [
  "studio-parity-plus-panels",
  "studio-engine-reconnect-banner",
  "studio-chat-responsibility-contract",
  "studio-engine-guard-security-scan",
  "studio-worker-contribution-trace",
];
const projectionArrays = [
  "engineReconnectBanners",
  "chatResponsibilityContracts",
  "securityScanPanels",
  "workerContributionTraces",
];

const checks = {
  rendererExists: /function studioParityPlusPanelRows/.test(extensionSource),
  cockpitMountExists: /data-testid="studio-parity-plus-panels"/.test(extensionSource),
  traceLinksIncluded: /studioTraceLink\(\{ \.\.\.item, kind: spec\.kind \}\)/.test(extensionSource),
  verifiedBadgesIncluded: /studioVerifiedBadge\(item\)/.test(extensionSource),
  mountPointsPresent: mountPoints.every((testId) => extensionSource.includes(testId)),
  projectionArraysPresent: projectionArrays.every((name) => extensionSource.includes(`${name}: []`)),
  staticTestsCoverMounts: mountPoints.every((testId) => staticTestSource.includes(testId)) &&
    projectionArrays.every((name) => staticTestSource.includes(`${name}: \\[\\]`) || staticTestSource.includes(`${name}: []`)),
};

for (const [name, value] of Object.entries(checks)) {
  assert.equal(value, true, name);
}

const proof = {
  schemaVersion: "ioi.autopilot.stage33.chat-trace-parity-plus-mount-proof.v1",
  passed: true,
  extensionPath,
  staticTestPath,
  mountPoints,
  projectionArrays,
  checks,
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
