#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-parent-trajectory-linkage-proof.mjs <output-path>");
}

const { buildWorkflowParentTrajectoryLinkagePanel } = await import(
  "../../packages/hypervisor-workbench/src/runtime/workflow-parent-trajectory-linkage.ts"
);

const panel = buildWorkflowParentTrajectoryLinkagePanel({
  currentTrajectoryId: "trajectory-parent",
  links: [
    {
      id: "ready-child",
      parentTrajectoryId: "trajectory-parent",
      childTrajectoryId: "trajectory-child-a",
      sourceTable: "parent_references",
      sourceRowId: 1,
      childDbPath: "/home/heathledger/.gemini/antigravity-ide/conversations/trajectory-child-a.db",
      childExists: true,
      childStatus: "completed",
      mergePolicy: "manual_review",
      receiptRefs: ["receipt:ioi:parent-child-a"],
    },
    {
      id: "missing-child",
      parentTrajectoryId: "trajectory-parent",
      childTrajectoryId: "trajectory-child-b",
      sourceTable: "parent_references",
      sourceRowId: 2,
      childDbPath: "/home/heathledger/.gemini/antigravity-ide/conversations/trajectory-child-b.db",
      childExists: false,
      childStatus: "unknown",
      mergePolicy: "read_only",
    },
    {
      id: "auto-merge",
      parentTrajectoryId: "trajectory-parent",
      childTrajectoryId: "trajectory-child-c",
      sourceTable: "parent_references",
      sourceRowId: 3,
      childExists: true,
      childStatus: "completed",
      mergePolicy: "auto_merge",
      receiptRefs: ["receipt:ioi:parent-child-c"],
    },
    {
      id: "cycle",
      parentTrajectoryId: "trajectory-parent",
      childTrajectoryId: "trajectory-parent",
      sourceTable: "parent_references",
      sourceRowId: 4,
      childExists: true,
      childStatus: "completed",
      mergePolicy: "manual_review",
      receiptRefs: ["receipt:ioi:parent-cycle"],
    },
  ],
});

const rows = new Map(panel.rows.map((row) => [row.id, row]));

assert.equal(panel.schemaVersion, "ioi.workflow.parent-trajectory-linkage.v1");
assert.equal(panel.status, "blocked");
assert.equal(panel.linkCount, 4);
assert.equal(panel.readyCount, 1);
assert.equal(panel.manualReviewCount, 1);
assert.equal(panel.blockedCount, 2);
assert.equal(panel.missingChildCount, 1);
assert.equal(panel.missingReceiptCount, 1);
assert.equal(rows.get("ready-child")?.status, "ready");
assert.equal(rows.get("missing-child")?.status, "manual_review");
assert.ok(rows.get("missing-child")?.policyRefs.includes("policy:parent_trajectory.review.missing_child_db"));
assert.ok(rows.get("missing-child")?.policyRefs.includes("policy:parent_trajectory.review.missing_receipt"));
assert.equal(rows.get("auto-merge")?.status, "blocked");
assert.ok(rows.get("auto-merge")?.policyRefs.includes("policy:parent_trajectory.block.auto_merge"));
assert.equal(rows.get("cycle")?.status, "blocked");
assert.ok(rows.get("cycle")?.policyRefs.includes("policy:parent_trajectory.block.cycle"));
assert.ok(panel.rows.every((row) => row.sourceTable === "parent_references"));

const proof = {
  schemaVersion: "ioi.autopilot.stage47.parent-trajectory-linkage-proof.v1",
  passed: true,
  generatedAt: new Date().toISOString(),
  checks: {
    parentReferenceRowsMapped: panel.rows.every((row) => row.sourceTable === "parent_references" && row.sourceRowId),
    receiptBackedChildReady: rows.get("ready-child")?.status === "ready",
    missingChildRequiresReview: rows.get("missing-child")?.policyRefs.includes("policy:parent_trajectory.review.missing_child_db") === true,
    missingReceiptRequiresReview: rows.get("missing-child")?.policyRefs.includes("policy:parent_trajectory.review.missing_receipt") === true,
    autoMergeBlocked: rows.get("auto-merge")?.policyRefs.includes("policy:parent_trajectory.block.auto_merge") === true,
    cycleBlocked: rows.get("cycle")?.policyRefs.includes("policy:parent_trajectory.block.cycle") === true,
    manualWritebackGateAlwaysPresent: panel.rows.every((row) =>
      row.policyRefs.includes("policy:parent_trajectory.manual_writeback_gate")
    ),
  },
  panel,
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
