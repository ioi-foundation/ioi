#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-imported-stop-hook-gates-proof.mjs <output-path>");
}

const { buildWorkflowImportedStopHookGatePanel } = await import(
  "../../packages/hypervisor-workbench/src/runtime/workflow-imported-stop-hook-gates.ts"
);

const panel = buildWorkflowImportedStopHookGatePanel({
  records: [
    {
      id: "tests-pass",
      sourceTable: "steps",
      sourceRowId: 10,
      trajectoryId: "trajectory-stage49",
      stepId: "step-stop-hook-pass",
      stepType: 6,
      importedStatus: "completed",
      gateKind: "tests",
      receiptRefs: ["receipt:ioi:stop-hook-pass"],
    },
    {
      id: "diagnostics-block",
      sourceTable: "steps",
      sourceRowId: 11,
      trajectoryId: "trajectory-stage49",
      stepId: "step-stop-hook-diagnostics",
      stepType: 6,
      importedStatus: "rejected",
      gateKind: "diagnostics",
      diagnosticCount: 2,
      receiptRefs: ["receipt:ioi:stop-hook-diagnostics"],
    },
    {
      id: "unknown-no-receipt",
      sourceTable: "steps",
      sourceRowId: 12,
      trajectoryId: "trajectory-stage49",
      stepId: "step-stop-hook-unknown",
      stepType: 6,
      importedStatus: "unknown",
      gateKind: "unknown",
    },
  ],
});

const rows = new Map(panel.rows.map((row) => [row.id, row]));

assert.equal(panel.schemaVersion, "ioi.workflow.imported-stop-hook-gates.v1");
assert.equal(panel.status, "blocked");
assert.equal(panel.rowCount, 3);
assert.equal(panel.passedCount, 1);
assert.equal(panel.blockedCount, 1);
assert.equal(panel.manualReviewCount, 1);
assert.equal(panel.liveVerificationRequiredCount, 3);
assert.equal(panel.missingReceiptCount, 1);
assert.equal(rows.get("tests-pass")?.status, "passed");
assert.equal(rows.get("tests-pass")?.liveVerificationRequired, true);
assert.ok(rows.get("tests-pass")?.policyRefs.includes("policy:imported_stop_hook.live_verification_required"));
assert.equal(rows.get("diagnostics-block")?.status, "blocked");
assert.ok(rows.get("diagnostics-block")?.policyRefs.includes("policy:imported_stop_hook.block.imported_gate_failed"));
assert.equal(rows.get("unknown-no-receipt")?.status, "manual_review");
assert.ok(rows.get("unknown-no-receipt")?.policyRefs.includes("policy:imported_stop_hook.review.missing_receipt"));
assert.ok(rows.get("unknown-no-receipt")?.policyRefs.includes("policy:imported_stop_hook.review.unknown_gate"));

const proof = {
  schemaVersion: "ioi.autopilot.stage49.imported-stop-hook-gates-proof.v1",
  passed: true,
  generatedAt: new Date().toISOString(),
  checks: {
    stopHookRowsMapped: panel.rows.every((row) => row.sourceTable === "steps" && row.stepType === "6"),
    historicalPassStillRequiresLiveVerification: rows.get("tests-pass")?.liveVerificationRequired === true,
    rejectedDiagnosticsBlocks: rows.get("diagnostics-block")?.policyRefs.includes("policy:imported_stop_hook.block.imported_gate_failed") === true,
    unknownMissingReceiptRequiresReview: rows.get("unknown-no-receipt")?.status === "manual_review",
    allRowsHistoricalOnly: panel.rows.every((row) => row.historicalOnly === true),
  },
  panel,
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
