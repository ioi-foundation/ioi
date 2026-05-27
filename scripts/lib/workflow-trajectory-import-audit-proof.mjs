#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-trajectory-import-audit-proof.mjs <output-path>");
}

const { buildWorkflowTrajectoryImportAudit } = await import(
  "../../packages/agent-ide/src/runtime/workflow-trajectory-import-audit.ts"
);

const workspaceRoot = process.cwd();
const workspaceUri = `file://${workspaceRoot}/packages/agent-ide/src/index.ts`;

const panel = buildWorkflowTrajectoryImportAudit({
  currentWorkspaceRoot: workspaceRoot,
  records: [
    {
      sourceTable: "steps",
      fieldPath: "steps.step_payload",
      sequence: 2,
      stepId: "step-message",
      decodedType: "TrajectoryStepMessage",
      payload: {
        role: "assistant",
        content: "Imported decoded message from Antigravity trajectory.",
        receiptRefs: ["receipt:ioi:chat-reply-1"],
      },
    },
    {
      sourceTable: "steps",
      fieldPath: "steps.step_payload",
      sequence: 3,
      stepId: "step-tool",
      decodedType: "TrajectoryStepToolCall",
      payload: {
        toolName: "edit_file",
        input: "patch README.md",
      },
    },
    {
      sourceTable: "executor_metadata",
      fieldPath: "executor_metadata.data",
      sequence: 4,
      stepId: "step-executor",
      decodedType: "ExecutorMetadata",
      payload: {
        command: "npm test -- --runInBand",
        status: "ok",
        receiptRefs: ["receipt:ioi:terminal-1"],
      },
    },
    {
      sourceTable: "trajectory_metadata_blob",
      fieldPath: "trajectory_metadata_blob.data",
      sequence: 1,
      stepId: "trajectory-root",
      decodedType: "TrajectoryMetadata",
      workspaceUri,
      payload: {
        workspaceUri,
        trajectoryId: "ag-stage40-fixture",
      },
    },
    {
      sourceTable: "steps",
      fieldPath: "steps.metadata",
      sequence: 5,
      stepId: "step-secret",
      decodedType: "TrajectoryStepMessage",
      payload: {
        role: "user",
        content: "Do not leak this imported payload.",
        api_key: "sk-stage40-secret-value",
      },
    },
    {
      sourceTable: "trajectory_metadata_blob",
      fieldPath: "trajectory_metadata_blob.data",
      sequence: 6,
      stepId: "trajectory-escape",
      decodedType: "TrajectoryMetadata",
      workspaceUri: "file:///etc/passwd",
      payload: {
        workspaceUri: "file:///etc/passwd",
      },
    },
  ],
});

const rowsByStep = new Map(panel.rows.map((row) => [row.stepId, row]));
const messageRow = rowsByStep.get("step-message");
const toolRow = rowsByStep.get("step-tool");
const secretRow = rowsByStep.get("step-secret");
const escapeRow = rowsByStep.get("trajectory-escape");
const serialized = JSON.stringify(panel);

assert.equal(panel.schemaVersion, "ioi.workflow.trajectory-import-audit.v1");
assert.equal(panel.applyMode, "plan_only");
assert.equal(panel.sourceFormat, "decoded_sqlite_rows");
assert.equal(panel.status, "blocked");
assert.equal(panel.rowCount, 6);
assert.equal(panel.messageCount, 2);
assert.equal(panel.toolCallCount, 1);
assert.ok(panel.workspaceUriCount >= 2);
assert.equal(panel.secretFindingCount, 1);
assert.ok(panel.missingReceiptCount >= 2);
assert.ok(messageRow);
assert.ok(toolRow);
assert.ok(secretRow);
assert.ok(escapeRow);
assert.equal(messageRow.status, "ready");
assert.equal(toolRow.status, "manual_review");
assert.ok(toolRow.policyRefs.includes("policy:trajectory_import.review.missing_ioi_receipt"));
assert.equal(secretRow.status, "blocked");
assert.ok(secretRow.policyRefs.includes("policy:trajectory_import.block.secret_material"));
assert.equal(serialized.includes("sk-stage40-secret-value"), false);
assert.equal(serialized.includes("[REDACTED]"), true);
assert.equal(escapeRow.status, "blocked");
assert.ok(escapeRow.policyRefs.includes("policy:trajectory_import.block.workspace_escape"));
assert.deepEqual(panel.rows.map((row) => row.seq), [1, 2, 3, 4, 5, 6]);
assert.equal(panel.rows[0].sourceTable, "trajectory_metadata_blob");
assert.equal(panel.rows[0].fieldPath, "trajectory_metadata_blob.data");

const proof = {
  schemaVersion: "ioi.autopilot.stage40.trajectory-import-audit-proof.v1",
  passed: true,
  generatedAt: new Date().toISOString(),
  checks: {
    importsDecodedSqliteRows: panel.sourceFormat === "decoded_sqlite_rows",
    planOnly: panel.applyMode === "plan_only",
    sequenceSorted: panel.rows.map((row) => row.seq).join(",") === "1,2,3,4,5,6",
    tableAndFieldMappingVisible: panel.rows.every((row) => row.sourceTable && row.fieldPath),
    receiptBackedMessageReady: messageRow.status === "ready" &&
      messageRow.receiptRefs.includes("receipt:ioi:chat-reply-1"),
    unsignedToolCallRequiresReview: toolRow.status === "manual_review" &&
      toolRow.policyRefs.includes("policy:trajectory_import.review.missing_ioi_receipt"),
    secretsRedactedAndBlocked: secretRow.status === "blocked" &&
      !serialized.includes("sk-stage40-secret-value") &&
      serialized.includes("[REDACTED]"),
    workspaceEscapeBlocked: escapeRow.status === "blocked" &&
      escapeRow.policyRefs.includes("policy:trajectory_import.block.workspace_escape"),
  },
  panel,
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
