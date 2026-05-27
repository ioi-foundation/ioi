#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-imported-executor-config-proof.mjs <output-path>");
}

const { buildWorkflowImportedExecutorConfigPanel } = await import(
  "../../packages/agent-ide/src/runtime/workflow-imported-executor-config.ts"
);

const panel = buildWorkflowImportedExecutorConfigPanel({
  sourceTable: "executor_metadata",
  sourceRowId: 1,
  trajectoryId: "trajectory-stage51",
  allowedCommands: ["echo", "date", "cat", "curl", "python"],
  blockedCommands: ["rm", "ssh"],
  ideChecks: {
    diagnostics: true,
    tests: true,
    lint: false,
  },
  memoryLimitMb: 2048,
  networkDefault: "allow",
  receiptRefs: ["receipt:ioi:executor-config"],
});

const rows = new Map(panel.rows.map((row) => [row.id, row]));

assert.equal(panel.schemaVersion, "ioi.workflow.imported-executor-config.v1");
assert.equal(panel.status, "blocked");
assert.equal(panel.importedAuthority, "advisory_only");
assert.equal(panel.sourceTable, "executor_metadata");
assert.equal(panel.sourceRowId, "1");
assert.ok(panel.readyCount >= 6);
assert.ok(panel.manualReviewCount >= 2);
assert.ok(panel.blockedCount >= 2);
assert.equal(rows.get("allow:echo")?.status, "ready");
assert.equal(rows.get("allow:curl")?.status, "blocked");
assert.ok(rows.get("allow:curl")?.policyRefs.includes("policy:executor_config.block.imported_network_allow"));
assert.equal(rows.get("allow:python")?.status, "manual_review");
assert.equal(rows.get("block:ssh")?.status, "ready");
assert.equal(rows.get("ide-check:lint")?.status, "manual_review");
assert.equal(rows.get("resource:memory")?.status, "ready");
assert.equal(rows.get("network:default")?.status, "blocked");
assert.ok(rows.get("network:default")?.policyRefs.includes("policy:executor_config.block.network_default_allow"));

const proof = {
  schemaVersion: "ioi.autopilot.stage51.imported-executor-config-proof.v1",
  passed: true,
  generatedAt: new Date().toISOString(),
  checks: {
    executorMetadataMapped: panel.sourceTable === "executor_metadata" && panel.sourceRowId === "1",
    importedAuthorityAdvisoryOnly: panel.importedAuthority === "advisory_only",
    safeBaseCommandsReady: ["allow:echo", "allow:date", "allow:cat"].every((id) => rows.get(id)?.status === "ready"),
    importedNetworkAllowBlocked: rows.get("allow:curl")?.status === "blocked",
    nonBaseCommandNeedsReview: rows.get("allow:python")?.status === "manual_review",
    blockedCommandsPreservedAsDenyHints: rows.get("block:ssh")?.policyRefs.includes("policy:executor_config.imported_deny_hint") === true,
    disabledIdeCheckNeedsReview: rows.get("ide-check:lint")?.status === "manual_review",
    networkDefaultAllowBlocked: rows.get("network:default")?.status === "blocked",
  },
  panel,
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
