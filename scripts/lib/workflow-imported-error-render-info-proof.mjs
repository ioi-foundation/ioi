#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-imported-error-render-info-proof.mjs <output-path>");
}

const { buildWorkflowImportedErrorRenderInfoPanel } = await import(
  "../../packages/agent-ide/src/runtime/workflow-imported-error-render-info.ts"
);

const panel = buildWorkflowImportedErrorRenderInfoPanel({
  sourceTable: "steps",
  trajectoryId: "trajectory-stage54",
  workspaceRoot: "/workspace/project",
  rows: [
    {
      sourceRowId: 10,
      stepIndex: 4,
      column: "error_details",
      code: "TS2304",
      severity: "error",
      message: "Cannot find name Widget token=stage54-message-secret.",
      stack: "STACK_CANARY_STAGE54\nAuthorization: Bearer ya29.stage54stacksecret",
      diagnosticPath: "src/widget.ts",
      receiptRefs: ["receipt:ioi:error-render:error"],
    },
    {
      sourceRowId: 11,
      stepIndex: 5,
      column: "render_info",
      renderKind: "screenshot",
      artifactRef: "artifact:browser:screenshot-stage54",
      targetUri: "file:///workspace/project/.autopilot/replay.png",
      receiptRefs: ["receipt:ioi:error-render:render"],
    },
    {
      sourceRowId: 12,
      stepIndex: 6,
      column: "error_details",
      code: "PATH_ESCAPE",
      message: "Path escaped workspace",
      diagnosticPath: "/etc/passwd",
      receiptRefs: ["receipt:ioi:error-render:path"],
    },
    {
      sourceRowId: 13,
      stepIndex: 7,
      column: "render_info",
      renderKind: "markdown",
      artifactRef: "artifact:render:markdown-stage54",
      targetUri: "https://example.invalid/render/payload",
      receiptRefs: ["receipt:ioi:error-render:external"],
    },
    {
      sourceRowId: 14,
      stepIndex: 8,
      column: "task_details",
      code: "TASK_NOTE",
      message: "Imported task detail without an IOI receipt.",
      diagnosticPath: "./docs/task.md",
      receiptRefs: [],
    },
  ],
});

const rows = new Map(panel.rows.map((row) => [row.id, row]));
const errorRow = rows.get("step:4:error_details:10");
const renderRow = rows.get("step:5:render_info:11");
const pathEscapeRow = rows.get("step:6:error_details:12");
const externalRenderRow = rows.get("step:7:render_info:13");
const missingReceiptRow = rows.get("step:8:task_details:14");

assert.equal(panel.schemaVersion, "ioi.workflow.imported-error-render-info.v1");
assert.equal(panel.status, "blocked");
assert.equal(panel.importedAuthority, "historical_only");
assert.equal(panel.applyMode, "audit_only");
assert.equal(panel.rawStackRetention, "never");
assert.equal(panel.externalRenderRetention, "never");
assert.equal(panel.rowCount, 5);
assert.ok(panel.readyCount >= 2);
assert.ok(panel.needsReviewCount >= 1);
assert.ok(panel.blockedCount >= 2);

assert.ok(errorRow);
assert.equal(errorRow.status, "ready");
assert.equal(errorRow.retention, "summary_only");
assert.equal(errorRow.diagnosticPath, "src/widget.ts");
assert.match(errorRow.stackHash ?? "", /^stable-fnv1a32:[a-f0-9]{8}$/);
assert.ok(errorRow.redactedMessage.includes("[REDACTED]"));

assert.ok(renderRow);
assert.equal(renderRow.status, "ready");
assert.equal(renderRow.retention, "artifact_ref_only");
assert.equal(renderRow.artifactRef, "artifact:browser:screenshot-stage54");

assert.ok(pathEscapeRow);
assert.equal(pathEscapeRow.status, "blocked");
assert.equal(pathEscapeRow.diagnosticPath, null);
assert.ok(pathEscapeRow.policyRefs.includes("policy:error_render.block.workspace_path_escape"));

assert.ok(externalRenderRow);
assert.equal(externalRenderRow.status, "blocked");
assert.ok(externalRenderRow.policyRefs.includes("policy:error_render.block.external_render_uri"));

assert.ok(missingReceiptRow);
assert.equal(missingReceiptRow.status, "needs_review");
assert.ok(missingReceiptRow.policyRefs.includes("policy:error_render.review.missing_receipt"));
assert.equal(missingReceiptRow.diagnosticPath, "docs/task.md");

const serialized = JSON.stringify(panel);
for (const canary of [
  "STACK_CANARY_STAGE54",
  "ya29.stage54stacksecret",
  "stage54-message-secret",
]) {
  assert.ok(!serialized.includes(canary), `panel leaked ${canary}`);
}

const proof = {
  schemaVersion: "ioi.autopilot.stage54.imported-error-render-info-proof.v1",
  passed: true,
  generatedAt: new Date().toISOString(),
  checks: {
    historicalOnly: panel.importedAuthority === "historical_only",
    auditOnly: panel.applyMode === "audit_only",
    rawStackNeverRetained: panel.rawStackRetention === "never",
    artifactRefOnlyRender: renderRow?.retention === "artifact_ref_only",
    workspacePathEscapeBlocked: pathEscapeRow?.status === "blocked",
    externalRenderUriBlocked: externalRenderRow?.status === "blocked",
    missingReceiptNeedsReview: missingReceiptRow?.status === "needs_review",
    canariesAbsent: true,
  },
  panel,
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
