#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-imported-browser-action-evidence-proof.mjs <output-path>");
}

const { buildWorkflowImportedBrowserActionEvidencePanel } = await import(
  "../../packages/agent-ide/src/runtime/workflow-imported-browser-action-evidence.ts"
);

const panel = buildWorkflowImportedBrowserActionEvidencePanel({
  records: [
    {
      id: "ready-click",
      sourceTable: "steps",
      sourceRowId: 20,
      trajectoryId: "trajectory-stage50",
      stepId: "step-browser-click",
      action: "click",
      url: "https://example.local/app",
      target: { x: 320, y: 240 },
      viewport: { width: 1280, height: 720 },
      screenshotRef: "artifact:browser:screenshot-before",
      domSnapshotRef: "artifact:browser:dom-before",
      accessibilityRef: "artifact:browser:ax-before",
      postconditionRef: "artifact:browser:screenshot-after",
      cleanupRef: "receipt:browser:cleanup",
      receiptRefs: ["receipt:ioi:browser-click"],
    },
    {
      id: "missing-observation",
      sourceTable: "steps",
      sourceRowId: 21,
      trajectoryId: "trajectory-stage50",
      stepId: "step-browser-type",
      action: "type",
      target: { x: 400, y: 320 },
      viewport: { width: 1280, height: 720 },
      postconditionRef: "artifact:browser:postcondition",
      receiptRefs: ["receipt:ioi:browser-type"],
    },
    {
      id: "bad-target",
      sourceTable: "steps",
      sourceRowId: 22,
      trajectoryId: "trajectory-stage50",
      stepId: "step-browser-click-bad",
      action: "click",
      target: { x: 1400, y: 20 },
      viewport: { width: 1280, height: 720 },
      screenshotRef: "artifact:browser:screenshot-before",
      domSnapshotRef: "artifact:browser:dom-before",
      postconditionRef: "artifact:browser:screenshot-after",
      cleanupRef: "receipt:browser:cleanup",
      receiptRefs: ["receipt:ioi:browser-bad-target"],
    },
  ],
});

const rows = new Map(panel.rows.map((row) => [row.id, row]));

assert.equal(panel.schemaVersion, "ioi.workflow.imported-browser-action-evidence.v1");
assert.equal(panel.status, "blocked");
assert.equal(panel.rowCount, 3);
assert.equal(panel.readyCount, 1);
assert.equal(panel.manualReviewCount, 1);
assert.equal(panel.blockedCount, 1);
assert.equal(panel.missingObservationCount, 1);
assert.equal(panel.missingPostconditionCount, 0);
assert.equal(panel.missingCleanupCount, 1);
assert.equal(rows.get("ready-click")?.status, "ready");
assert.ok(rows.get("ready-click")?.policyRefs.includes("policy:imported_browser.replay_requires_fresh_observation"));
assert.equal(rows.get("missing-observation")?.status, "manual_review");
assert.ok(rows.get("missing-observation")?.policyRefs.includes("policy:imported_browser.review.missing_observation"));
assert.equal(rows.get("bad-target")?.status, "blocked");
assert.ok(rows.get("bad-target")?.policyRefs.includes("policy:imported_browser.block.target_out_of_viewport"));

const proof = {
  schemaVersion: "ioi.autopilot.stage50.imported-browser-action-evidence-proof.v1",
  passed: true,
  generatedAt: new Date().toISOString(),
  checks: {
    browserRowsMapped: panel.rows.every((row) => row.sourceTable === "steps" && row.sourceRowId),
    readyRowHasObservationVerificationCleanupAndReceipt:
      rows.get("ready-click")?.status === "ready" &&
      Object.values(rows.get("ready-click")?.evidenceRefs || {}).filter(Boolean).length >= 4,
    replayRequiresFreshObservation: panel.rows.every((row) =>
      row.policyRefs.includes("policy:imported_browser.replay_requires_fresh_observation")
    ),
    missingObservationRequiresReview: rows.get("missing-observation")?.status === "manual_review",
    targetOutOfViewportBlocked: rows.get("bad-target")?.status === "blocked",
  },
  panel,
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
