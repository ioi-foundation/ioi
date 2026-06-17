#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-safe-mode-tool-suppression-proof.mjs <output-path>");
}

const { buildWorkflowSafeModeToolSuppressionPanel } = await import(
  "../../packages/hypervisor-workbench/src/runtime/workflow-safe-mode-tool-suppression.ts"
);

const controls = [
  {
    id: "ask.compose",
    label: "Ask direct reply",
    surface: "ask",
    authority: "none",
    requiresRuntimeBridge: false,
  },
  {
    id: "agent.submit",
    label: "Agent harness turn",
    surface: "agent",
    authority: "execute",
    requiresRuntimeBridge: true,
    receiptRequired: true,
  },
  {
    id: "terminal.run",
    label: "Run terminal command",
    surface: "terminal",
    authority: "execute",
    requiresRuntimeBridge: true,
    receiptRequired: true,
  },
  {
    id: "browser.act",
    label: "Browser computer-use action",
    surface: "browser",
    authority: "network",
    requiresRuntimeBridge: true,
    receiptRequired: true,
  },
  {
    id: "trace.open",
    label: "Open Trace",
    surface: "trace",
    authority: "read",
    requiresRuntimeBridge: false,
  },
  {
    id: "migration.plan",
    label: "Review import plan",
    surface: "migration",
    authority: "read",
    requiresRuntimeBridge: false,
  },
];

const safeModePanel = buildWorkflowSafeModeToolSuppressionPanel({
  safeMode: {
    enabled: true,
    trigger: "bridge_timeout",
    reason: "Runtime bridge command timed out while submitting an Agent turn.",
    allowAskWithoutTools: true,
    exitRequires: "daemon_reconnect",
  },
  controls,
});

const normalPanel = buildWorkflowSafeModeToolSuppressionPanel({
  safeMode: {
    enabled: false,
  },
  controls,
});

const safeRows = new Map(safeModePanel.controls.map((row) => [row.id, row]));

assert.equal(safeModePanel.schemaVersion, "ioi.workflow.safe-mode-tool-suppression.v1");
assert.equal(safeModePanel.status, "safe_mode");
assert.equal(safeModePanel.trigger, "bridge_timeout");
assert.equal(safeModePanel.responsibilityBoundary.askDirectTextAllowed, true);
assert.equal(safeModePanel.responsibilityBoundary.agentHarnessAllowed, false);
assert.equal(safeModePanel.responsibilityBoundary.toolsSuppressed, true);
assert.equal(safeRows.get("ask.compose")?.state, "enabled");
assert.ok(safeRows.get("ask.compose")?.policyRefs.includes("policy:safe_mode.ask_direct_no_tools"));
assert.equal(safeRows.get("agent.submit")?.state, "disabled");
assert.ok(safeRows.get("agent.submit")?.policyRefs.includes("policy:safe_mode.suppress_tools"));
assert.ok(safeRows.get("agent.submit")?.policyRefs.includes("policy:safe_mode.receipt_required_before_resume"));
assert.equal(safeRows.get("terminal.run")?.state, "disabled");
assert.equal(safeRows.get("browser.act")?.state, "disabled");
assert.equal(safeRows.get("trace.open")?.state, "read_only");
assert.equal(safeRows.get("migration.plan")?.state, "read_only");
assert.equal(safeModePanel.disabledCount, 3);
assert.equal(safeModePanel.readOnlyCount, 2);
assert.equal(safeModePanel.enabledCount, 1);
assert.equal(normalPanel.status, "normal");
assert.equal(normalPanel.disabledCount, 0);
assert.equal(normalPanel.enabledCount, controls.length);

const proof = {
  schemaVersion: "ioi.autopilot.stage41.safe-mode-tool-suppression-proof.v1",
  passed: true,
  generatedAt: new Date().toISOString(),
  checks: {
    directAskPreserved: safeRows.get("ask.compose")?.state === "enabled",
    agentHarnessSuppressed: safeRows.get("agent.submit")?.state === "disabled",
    terminalExecutionSuppressed: safeRows.get("terminal.run")?.state === "disabled",
    browserNetworkSuppressed: safeRows.get("browser.act")?.state === "disabled",
    traceReadOnlyPreserved: safeRows.get("trace.open")?.state === "read_only",
    migrationReviewReadOnlyPreserved: safeRows.get("migration.plan")?.state === "read_only",
    receiptRequiredBeforeResume:
      safeRows.get("agent.submit")?.policyRefs.includes("policy:safe_mode.receipt_required_before_resume") === true,
    normalModeRestoresControls: normalPanel.enabledCount === controls.length && normalPanel.disabledCount === 0,
  },
  safeModePanel,
  normalPanel,
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
