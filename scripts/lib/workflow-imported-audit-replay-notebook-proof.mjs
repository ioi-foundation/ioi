#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-imported-audit-replay-notebook-proof.mjs <output-path>");
}

const { buildWorkflowSignedReplayNotebook } = await import(
  "../../packages/agent-ide/src/runtime/workflow-signed-replay-notebook.ts"
);
const {
  isWorkspaceNotebookPath,
  parseWorkspaceNotebookDocument,
  updateWorkspaceNotebookCellSource,
} = await import("../../packages/workspace-substrate/src/notebook.ts");
const { buildWorkflowImportedGenerationMetadataPanel } = await import(
  "../../packages/agent-ide/src/runtime/workflow-imported-generation-metadata.ts"
);
const { buildWorkflowImportedErrorRenderInfoPanel } = await import(
  "../../packages/agent-ide/src/runtime/workflow-imported-error-render-info.ts"
);
const { buildWorkflowImportedExecutorConfigPanel } = await import(
  "../../packages/agent-ide/src/runtime/workflow-imported-executor-config.ts"
);
const { buildWorkflowImportedPolicyDraft } = await import(
  "../../packages/agent-ide/src/runtime/workflow-imported-policy-draft.ts"
);

const outputDir = path.dirname(outputPath);
fs.mkdirSync(outputDir, { recursive: true });

const threadId = "thread.stage57.imported-audit-replay";
const workflowGraphId = "workflow.imported-audit-replay";
const snapshotId = "snapshot.stage57.imported-audit";
const auditPath = ".autopilot/imported/trajectory-stage57.audit.json";

const generationPanel = buildWorkflowImportedGenerationMetadataPanel({
  trajectoryId: "trajectory-stage57",
  rows: [
    {
      sourceRowId: 1,
      kind: "prompt_context",
      text: "Prompt text PRIVATE_STAGE57_PROMPT sk-stage57promptsecret",
      modelId: "qwen/qwen3.5",
      tokenCounts: { input: 2048, output: 0, reasoning: 0 },
      receiptRefs: ["receipt:stage57:generation"],
    },
  ],
});
const errorRenderPanel = buildWorkflowImportedErrorRenderInfoPanel({
  trajectoryId: "trajectory-stage57",
  workspaceRoot: "/workspace/project",
  rows: [
    {
      sourceRowId: 2,
      stepIndex: 2,
      column: "error_details",
      code: "TS2304",
      message: "Cannot find imported symbol token=stage57-message-secret",
      stack: "STACK_STAGE57_CANARY\nBearer ya29.stage57stacksecret",
      diagnosticPath: "src/imported.ts",
      receiptRefs: ["receipt:stage57:error-render"],
    },
  ],
});
const executorPanel = buildWorkflowImportedExecutorConfigPanel({
  sourceTable: "executor_metadata",
  sourceRowId: 57,
  trajectoryId: "trajectory-stage57",
  allowedCommands: ["echo", "curl"],
  blockedCommands: ["ssh"],
  ideChecks: { diagnostics: true, tests: true, lint: false },
  memoryLimitMb: 2048,
  networkDefault: "allow",
  receiptRefs: ["receipt:stage57:executor"],
});
const policyDraft = buildWorkflowImportedPolicyDraft({ sourcePanel: executorPanel });

const importedPanels = [
  generationPanel,
  errorRenderPanel,
  executorPanel,
  policyDraft,
];
const events = importedPanels.map((panel, index) => ({
  event_id: `evt-stage57-import-${index + 1}`,
  seq: index + 1,
  eventKind: "tool.completed",
  componentKind: "imported_audit",
  status: panel.status,
  threadId,
  workflowGraphId,
  workflowNodeId: "workflow.imported-audit.project",
  toolName: "trajectory.import.audit",
  toolCallId: `tool-call-stage57-import-${index + 1}`,
  payload: {
    summary: `Imported audit panel ${panel.schemaVersion} projected as read-only evidence.`,
    changedFiles: [{ path: auditPath }],
  },
  receipt_refs: panel.receiptRefs ?? [`receipt:stage57:panel:${index + 1}`],
  artifact_refs: [`artifact:stage57:panel:${index + 1}`],
  policy_decision_refs: ["policy:stage57:historical_only"],
}));
const notebook = buildWorkflowSignedReplayNotebook({
  events: [
    ...events,
    {
      event_id: "evt-stage57-snapshot",
      seq: events.length + 1,
      eventKind: "workspace.snapshot.created",
      componentKind: "workspace_snapshot",
      status: "completed",
      threadId,
      workflowGraphId,
      workflowNodeId: "workflow.imported-audit.snapshot",
      payload: {
        snapshotId,
        summary: "Snapshot before imported audit replay export.",
        changedFiles: [{ path: auditPath }],
        fileCount: 1,
      },
      receipt_refs: ["receipt:stage57:snapshot"],
      artifact_refs: ["artifact:stage57:snapshot"],
      rollback_refs: [snapshotId],
    },
  ],
  snapshots: [
    {
      snapshot_id: snapshotId,
      thread_id: threadId,
      eventId: "evt-stage57-snapshot-list",
      status: "completed",
      summary: "Imported audit replay snapshot list item.",
      changedFiles: [{ path: auditPath }],
      file_count: 1,
      receipt_refs: ["receipt:stage57:snapshot-list"],
      artifact_refs: ["artifact:stage57:snapshot-list"],
    },
  ],
  restoreResults: [
    {
      schema_version: "ioi.workflow.workspace-restore-preview.v1",
      snapshot_id: snapshotId,
      thread_id: threadId,
      preview_status: "ready",
      summary: "Previewed imported audit replay restore without mutating workspace.",
      operations: [{ path: auditPath, diff: "+ imported audit replay document\n" }],
      receipt_refs: ["receipt:stage57:restore-preview"],
      artifact_refs: ["artifact:stage57:restore-preview"],
      rollback_refs: [snapshotId],
      policy_decision_refs: ["policy:stage57:restore-preview"],
    },
    {
      schema_version: "ioi.workflow.workspace-restore-apply.v1",
      snapshot_id: snapshotId,
      thread_id: threadId,
      apply_status: "blocked",
      summary: "Blocked imported audit replay restore apply until operator approval.",
      approval_required: true,
      approval_satisfied: false,
      operations: [{ path: auditPath, apply_reason: "imported_audit_restore_requires_approval" }],
      receipt_refs: ["receipt:stage57:restore-apply-blocked"],
      rollback_refs: [snapshotId],
      policy_decision_refs: ["policy:stage57:restore-apply-blocked"],
    },
  ],
});

const autopilotPath = "stage57-imported-audit-replay.autopilot";
const serializedAutopilot = `${JSON.stringify(notebook, null, 2)}\n`;
const autopilotDocument = parseWorkspaceNotebookDocument(autopilotPath, serializedAutopilot);
assert.equal(isWorkspaceNotebookPath(autopilotPath), true);
assert.ok(autopilotDocument);
assert.equal(autopilotDocument.documentKind, "autopilot_replay");
assert.equal(autopilotDocument.readOnlyReplayMode, true);
assert.ok(autopilotDocument.cellCount >= 6);
assert.ok(autopilotDocument.receiptBackedCellCount >= 6);
assert.ok(autopilotDocument.cells.every((cell) => cell.readOnly === true));
assert.equal(
  updateWorkspaceNotebookCellSource(serializedAutopilot, autopilotDocument.cells[0].id, "tamper"),
  null,
);

const joined = autopilotDocument.cells.map((cell) => cell.source).join("\n");
assert.match(joined, /trajectory\.import\.audit/);
assert.match(joined, /ioi\.workflow\.imported-generation-metadata\.v1/);
assert.match(joined, /ioi\.workflow\.imported-policy-draft\.v1/);
assert.match(joined, /Restore apply/);
assert.match(joined, /Status: blocked/);

const serializedPanelsAndNotebook = JSON.stringify({ importedPanels, notebook, autopilotDocument });
for (const canary of [
  "PRIVATE_STAGE57_PROMPT",
  "sk-stage57promptsecret",
  "STACK_STAGE57_CANARY",
  "stage57-message-secret",
  "ya29.stage57stacksecret",
]) {
  assert.ok(!serializedPanelsAndNotebook.includes(canary), `replay export leaked ${canary}`);
}

const proof = {
  schemaVersion: "ioi.autopilot.stage57.imported-audit-replay-notebook-proof.v1",
  passed: true,
  generatedAt: new Date().toISOString(),
  checks: {
    signedReplayBuilderUsed: notebook.schema_version === "ioi.workflow.signed-replay-notebook.v1",
    autopilotDocumentParsed: autopilotDocument.documentKind === "autopilot_replay",
    readOnlyReplayMode: autopilotDocument.readOnlyReplayMode === true,
    allCellsReadOnly: autopilotDocument.cells.every((cell) => cell.readOnly === true),
    receiptBackedCellsVisible: autopilotDocument.receiptBackedCellCount >= 6,
    restoreApplyBlocked: notebook.restore_apply_blocked_count === 1,
    tamperUpdateDenied:
      updateWorkspaceNotebookCellSource(serializedAutopilot, autopilotDocument.cells[0].id, "tamper") === null,
    canariesAbsent: true,
  },
  notebook,
  autopilotDocument: {
    path: autopilotDocument.path,
    documentKind: autopilotDocument.documentKind,
    cellCount: autopilotDocument.cellCount,
    receiptBackedCellCount: autopilotDocument.receiptBackedCellCount,
    readOnlyReplayMode: autopilotDocument.readOnlyReplayMode,
    cells: autopilotDocument.cells,
  },
};

fs.writeFileSync(path.join(outputDir, autopilotPath), serializedAutopilot);
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
