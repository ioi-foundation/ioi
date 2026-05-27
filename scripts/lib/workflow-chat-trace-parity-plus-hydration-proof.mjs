#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-chat-trace-parity-plus-hydration-proof.mjs <output-path>");
}

const extensionPath = "apps/autopilot/openvscode-extension/ioi-workbench/extension.js";
const staticTestPath = "apps/autopilot/openvscode-extension/ioi-workbench/extension.static.test.mjs";
const extensionSource = fs.readFileSync(extensionPath, "utf8");
const staticTestSource = fs.readFileSync(staticTestPath, "utf8");

const hydrationCollections = [
  "engineReconnectBanners",
  "chatResponsibilityContracts",
  "securityScanPanels",
  "workerContributionTraces",
];

const checks = {
  eventPayloadHelperExists: /function studioRuntimeEventPayload/.test(extensionSource),
  parityHydratorExists: /function applyStudioParityPlusEvent/.test(extensionSource),
  agentTurnCallsHydrator: /applyStudioParityPlusEvent\(event, \{ kind, status, summary, receiptRefs \}\)/.test(extensionSource),
  reconnectSignatureMatched: /engine\[._-\]\?reconnect/.test(extensionSource),
  chatResponsibilitySignatureMatched: /chat\[._-\]\?responsibility/.test(extensionSource),
  securitySignatureMatched: /security\[._-\]\?scan/.test(extensionSource),
  workerContributionSignatureMatched: /worker\[._-\]\?contribution/.test(extensionSource),
  allCollectionsPushed: hydrationCollections.every((name) =>
    new RegExp(`studioRuntimeProjection\\.${name}\\.push`).test(extensionSource),
  ),
  allCollectionsTraceIndexed: hydrationCollections.every((name) =>
    new RegExp(`for \\(const item of firstArray\\(studioRuntimeProjection\\.${name}\\)\\)`).test(extensionSource),
  ),
  staticTestsCoverHydration: [
    "function applyStudioParityPlusEvent",
    "function studioRuntimeEventPayload",
    "applyStudioParityPlusEvent\\(event, \\{ kind, status, summary, receiptRefs \\}\\)",
    "studioRuntimeProjection\\.engineReconnectBanners\\.push",
    "studioRuntimeProjection\\.securityScanPanels\\.push",
  ].every((needle) => staticTestSource.includes(needle)),
};

for (const [name, value] of Object.entries(checks)) {
  assert.equal(value, true, name);
}

const proof = {
  schemaVersion: "ioi.autopilot.stage34.chat-trace-parity-plus-hydration-proof.v1",
  passed: true,
  extensionPath,
  staticTestPath,
  hydrationCollections,
  checks,
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
