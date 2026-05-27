#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-migration-assistant-plan-proof.mjs <output-path>");
}

const { buildWorkflowMigrationAssistantPlan } = await import(
  "../../packages/agent-ide/src/runtime/workflow-migration-assistant.ts"
);

const packageJsonPath = "apps/autopilot/openvscode-extension/ioi-workbench/package.json";
const extensionSourcePath = "apps/autopilot/openvscode-extension/ioi-workbench/extension.js";
const manifest = JSON.parse(fs.readFileSync(packageJsonPath, "utf8"));
const extensionSource = fs.readFileSync(extensionSourcePath, "utf8");

const plan = buildWorkflowMigrationAssistantPlan({
  sourceEditor: "cursor",
  settings: {
    "workbench.colorTheme": "Default Dark Modern",
    "files.exclude": {
      "**/.env": true,
      "**/dist": true,
    },
    "http.proxyStrictSSL": false,
    "security.workspace.trust.enabled": false,
    "terminal.integrated.env.linux": {
      API_TOKEN: "should-not-leak",
      PATH: "/usr/bin",
    },
  },
  keybindings: [
    {
      key: "ctrl+shift+i",
      command: "ioi.studio.open",
    },
  ],
  extensions: [
    "github.vscode-github-actions",
    "ms-vscode-remote.remote-ssh",
  ],
});

const commandIds = new Set(manifest.contributes.commands.map((entry) => entry.command));
const paletteIds = new Set(manifest.contributes.menus.commandPalette.map((entry) => entry.command));
const expectedCommands = [
  "ioi.migration.openAssistant",
  "ioi.migration.importVSCodeSettings",
  "ioi.migration.importCursorSettings",
  "ioi.migration.importWindsurfSettings",
  "ioi.migration.importVSCodeExtensions",
  "ioi.migration.importCursorExtensions",
  "ioi.migration.importWindsurfExtensions",
];

for (const commandId of expectedCommands) {
  assert.ok(commandIds.has(commandId), `${commandId} is contributed`);
  assert.ok(paletteIds.has(commandId), `${commandId} is visible in command palette`);
  assert.ok(plan.commandIds.includes(commandId), `${commandId} is represented in runtime plan`);
}

const blockedPolicyRefs = plan.items
  .filter((item) => item.status === "blocked")
  .map((item) => item.policyRef);
const manualReviewPolicyRefs = plan.items
  .filter((item) => item.status === "manual_review")
  .map((item) => item.policyRef);

assert.equal(plan.schemaVersion, "ioi.workflow.migration-assistant.v1");
assert.equal(plan.sourceEditor, "cursor");
assert.equal(plan.applyMode, "plan_only");
assert.equal(plan.status, "blocked");
assert.ok(plan.readyCount >= 2);
assert.ok(plan.manualReviewCount >= 2);
assert.ok(plan.blockedCount >= 2);
assert.ok(blockedPolicyRefs.includes("policy:migration.block.proxy_tls_disabled"));
assert.ok(blockedPolicyRefs.includes("policy:migration.block.workspace_trust_disabled"));
assert.ok(manualReviewPolicyRefs.includes("policy:migration.review.exclusions"));
assert.ok(manualReviewPolicyRefs.includes("policy:migration.review.terminal_env"));
assert.ok(manualReviewPolicyRefs.includes("policy:migration.extension.review"));
assert.equal(JSON.stringify(plan).includes("should-not-leak"), false);
assert.equal(JSON.stringify(plan).includes("[REDACTED]"), true);
assert.match(extensionSource, /writeBridgeRequest\("migration\.assistant\.open"/);
assert.match(extensionSource, /writeBridgeRequest\("migration\.import\.plan"/);
assert.match(extensionSource, /applyMode: "plan_only"/);
assert.match(extensionSource, /policyReviewRequired: true/);
assert.match(extensionSource, /sandboxBoundaryPreserved: true/);
assert.match(extensionSource, /autoApply: false/);

const proof = {
  schemaVersion: "ioi.autopilot.stage38.migration-assistant-plan-proof.v1",
  passed: true,
  generatedAt: new Date().toISOString(),
  checks: {
    commandsContributed: expectedCommands.every((commandId) => commandIds.has(commandId)),
    commandsVisible: expectedCommands.every((commandId) => paletteIds.has(commandId)),
    runtimePlanOnly: plan.applyMode === "plan_only",
    unsafeProxyBlocked: blockedPolicyRefs.includes("policy:migration.block.proxy_tls_disabled"),
    workspaceTrustDisableBlocked: blockedPolicyRefs.includes("policy:migration.block.workspace_trust_disabled"),
    exclusionsRequireReview: manualReviewPolicyRefs.includes("policy:migration.review.exclusions"),
    terminalEnvRequiresReview: manualReviewPolicyRefs.includes("policy:migration.review.terminal_env"),
    remoteExtensionRequiresReview: manualReviewPolicyRefs.includes("policy:migration.extension.review"),
    secretsRedacted: JSON.stringify(plan).includes("[REDACTED]") && !JSON.stringify(plan).includes("should-not-leak"),
    bridgeRequestsPlanOnly:
      /writeBridgeRequest\("migration\.assistant\.open"/.test(extensionSource) &&
      /writeBridgeRequest\("migration\.import\.plan"/.test(extensionSource) &&
      /autoApply: false/.test(extensionSource),
  },
  expectedCommands,
  plan,
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
