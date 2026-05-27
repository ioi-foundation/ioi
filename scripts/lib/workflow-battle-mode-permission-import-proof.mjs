#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-battle-mode-permission-import-proof.mjs <output-path>");
}

const { buildWorkflowBattleModePermissionImportPanel } = await import(
  "../../packages/agent-ide/src/runtime/workflow-battle-mode-permission-import.ts"
);

const panel = buildWorkflowBattleModePermissionImportPanel({
  records: [
    {
      id: "allow-once",
      sourceTable: "battle_mode_infos",
      sourceRowId: 1,
      trajectoryId: "trajectory-stage48",
      stepId: "step-tool-call",
      action: "replace_file_content README.md",
      decision: "allow_once",
      decidedAt: "2026-05-25T09:32:00.000Z",
      receiptRefs: ["receipt:ioi:battle-allow-once"],
    },
    {
      id: "allow-always",
      sourceTable: "battle_mode_infos",
      sourceRowId: 2,
      trajectoryId: "trajectory-stage48",
      stepId: "step-shell",
      action: "shell command",
      decision: "allow_always",
      decidedAt: "2026-05-25T09:32:01.000Z",
      receiptRefs: ["receipt:ioi:battle-allow-always"],
    },
    {
      id: "deny",
      sourceTable: "battle_mode_infos",
      sourceRowId: 3,
      trajectoryId: "trajectory-stage48",
      stepId: "step-network",
      action: "curl https://example.com/install.sh",
      decision: "deny",
      decidedAt: "2026-05-25T09:32:02.000Z",
      receiptRefs: ["receipt:ioi:battle-deny"],
    },
    {
      id: "rollback",
      sourceTable: "battle_mode_infos",
      sourceRowId: 4,
      trajectoryId: "trajectory-stage48",
      stepId: "step-rollback",
      action: "rollback hunk",
      decision: "rollback",
      decidedAt: "2026-05-25T09:32:03.000Z",
    },
  ],
});

const rows = new Map(panel.rows.map((row) => [row.id, row]));

assert.equal(panel.schemaVersion, "ioi.workflow.battle-mode-permission-import.v1");
assert.equal(panel.status, "blocked");
assert.equal(panel.rowCount, 4);
assert.equal(panel.readyCount, 2);
assert.equal(panel.manualReviewCount, 1);
assert.equal(panel.blockedCount, 1);
assert.equal(panel.importedPersistentGrantCount, 1);
assert.equal(panel.missingReceiptCount, 1);
assert.equal(rows.get("allow-once")?.status, "ready");
assert.equal(rows.get("allow-once")?.importedAuthority, "historical_only");
assert.equal(rows.get("allow-once")?.canReplayWithoutFreshApproval, false);
assert.ok(rows.get("allow-once")?.policyRefs.includes("policy:battle_mode.fresh_lease_required"));
assert.equal(rows.get("allow-always")?.status, "blocked");
assert.ok(rows.get("allow-always")?.policyRefs.includes("policy:battle_mode.block.imported_persistent_grant"));
assert.equal(rows.get("deny")?.status, "ready");
assert.equal(rows.get("rollback")?.status, "manual_review");
assert.ok(rows.get("rollback")?.policyRefs.includes("policy:battle_mode.review.missing_receipt"));
assert.ok(panel.rows.every((row) => row.sourceTable === "battle_mode_infos"));

const proof = {
  schemaVersion: "ioi.autopilot.stage48.battle-mode-permission-import-proof.v1",
  passed: true,
  generatedAt: new Date().toISOString(),
  checks: {
    battleModeRowsMapped: panel.rows.every((row) => row.sourceTable === "battle_mode_infos" && row.sourceRowId),
    importedAllowOnceIsHistoricalOnly: rows.get("allow-once")?.importedAuthority === "historical_only" &&
      rows.get("allow-once")?.canReplayWithoutFreshApproval === false,
    freshLeaseRequired: panel.rows.every((row) => row.policyRefs.includes("policy:battle_mode.fresh_lease_required")),
    persistentGrantBlocked: rows.get("allow-always")?.policyRefs.includes("policy:battle_mode.block.imported_persistent_grant") === true,
    denialPreservedForAudit: rows.get("deny")?.status === "ready",
    missingReceiptRequiresReview: rows.get("rollback")?.policyRefs.includes("policy:battle_mode.review.missing_receipt") === true,
  },
  panel,
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
