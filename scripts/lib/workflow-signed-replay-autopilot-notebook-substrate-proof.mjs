#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error(
    "usage: workflow-signed-replay-autopilot-notebook-substrate-proof.mjs <output-path>",
  );
}

const { buildWorkflowSignedReplayNotebook } = await import(
  "../../packages/agent-ide/src/runtime/workflow-signed-replay-notebook.ts"
);
const {
  isWorkspaceNotebookPath,
  parseWorkspaceNotebookDocument,
  updateWorkspaceNotebookCellSource,
} = await import("../../packages/workspace-substrate/src/notebook.ts");

const threadId = "thread.autopilot.stage36.signed-replay-substrate";
const workflowGraphId = "workflow.react-flow.autopilot-replay-notebook-substrate";
const snapshotId = "snapshot.stage36.signed-replay";
const changedPath = "src/runtime/agent-loop.ts";

const notebook = buildWorkflowSignedReplayNotebook({
  events: [
    {
      event_id: "evt-stage36-tool",
      seq: 1,
      eventKind: "tool.completed",
      componentKind: "tool",
      status: "completed",
      threadId,
      workflowGraphId,
      workflowNodeId: "workflow.stage36.file.apply_patch",
      toolName: "file.apply_patch",
      toolCallId: "tool-call-stage36-patch",
      payload: {
        summary: "Applied a workflow harness parity patch.",
        changedFiles: [{ path: changedPath }],
      },
      receiptRefs: ["receipt:stage36:tool"],
      artifactRefs: ["artifact:stage36:patch"],
    },
    {
      event_id: "evt-stage36-snapshot",
      seq: 2,
      eventKind: "workspace.snapshot.created",
      componentKind: "workspace_snapshot",
      status: "completed",
      threadId,
      workflowGraphId,
      workflowNodeId: "workflow.stage36.workspace.snapshot",
      payload: {
        snapshotId,
        summary: "Created a receipt-backed snapshot before replay.",
        changedFiles: [{ path: changedPath }],
        fileCount: 1,
      },
      receiptRefs: ["receipt:stage36:snapshot"],
      artifactRefs: ["artifact:stage36:snapshot"],
      rollbackRefs: [snapshotId],
    },
  ],
  snapshots: [
    {
      snapshotId,
      threadId,
      eventId: "evt-stage36-snapshot-list",
      status: "completed",
      summary: "Snapshot list item remains shareable in the replay notebook.",
      changedFiles: [{ path: changedPath }],
      fileCount: 1,
      receiptRefs: ["receipt:stage36:snapshot-list"],
      artifactRefs: ["artifact:stage36:snapshot-list"],
      policyDecisionRefs: ["policy:stage36:snapshot"],
    },
  ],
  restoreResults: [
    {
      schemaVersion: "ioi.workflow.workspace-restore-preview.v1",
      snapshotId,
      threadId,
      previewStatus: "ready",
      summary: "Previewed restore operations without mutating the workspace.",
      operations: [
        {
          path: changedPath,
          diff: "- harness = partial\n+ harness = parity\n",
        },
      ],
      receiptRefs: ["receipt:stage36:restore-preview"],
      artifactRefs: ["artifact:stage36:restore-preview"],
      rollbackRefs: [snapshotId],
      policyDecisionRefs: ["policy:stage36:restore-preview"],
    },
    {
      schemaVersion: "ioi.workflow.workspace-restore-apply.v1",
      snapshotId,
      threadId,
      applyStatus: "blocked",
      summary: "Blocked restore apply until explicit operator approval.",
      approvalRequired: true,
      approvalSatisfied: false,
      operations: [
        {
          path: changedPath,
          apply_reason: "workspace_restore_apply_requires_approval",
        },
      ],
      receiptRefs: ["receipt:stage36:restore-apply-blocked"],
      rollbackRefs: [snapshotId],
      policyDecisionRefs: ["policy:stage36:restore-apply-blocked"],
    },
  ],
});

const autopilotPath = "stage36-signed-replay.autopilot";
const serializedAutopilot = `${JSON.stringify(notebook, null, 2)}\n`;
const autopilotDocument = parseWorkspaceNotebookDocument(
  autopilotPath,
  serializedAutopilot,
);

assert.equal(isWorkspaceNotebookPath(autopilotPath), true);
assert.ok(autopilotDocument);
assert.equal(autopilotDocument.documentKind, "autopilot_replay");
assert.equal(autopilotDocument.language, "autopilot-replay");
assert.equal(autopilotDocument.kernelDisplayName, "Autopilot Signed Replay");
assert.equal(autopilotDocument.readOnlyReplayMode, true);
assert.equal(autopilotDocument.cellCount, notebook.cellCount);
assert.equal(
  autopilotDocument.receiptBackedCellCount,
  notebook.receiptBackedCellCount,
);
assert.ok(autopilotDocument.receiptBackedCellCount > 0);
assert.ok(autopilotDocument.cells.length >= 4);
assert.ok(autopilotDocument.cells.every((cell) => cell.readOnly === true));

const joinedReplaySource = autopilotDocument.cells
  .map((cell) => cell.source)
  .join("\n---\n");
assert.match(joinedReplaySource, /Read-only restore preview/);
assert.match(joinedReplaySource, /Restore apply/);
assert.match(joinedReplaySource, /Status: blocked/);
assert.match(joinedReplaySource, /Receipts: receipt:stage36:/);
assert.match(joinedReplaySource, /Rollback refs: snapshot\.stage36\.signed-replay/);
assert.match(joinedReplaySource, /Restore preview: \/v1\/threads\//);
assert.match(joinedReplaySource, /Restore apply: \/v1\/threads\//);

const autopilotTamperAttempt = updateWorkspaceNotebookCellSource(
  serializedAutopilot,
  autopilotDocument.cells[0].id,
  "tampered replay cell",
);
assert.equal(autopilotTamperAttempt, null);

const ipynb = {
  nbformat: 4,
  nbformat_minor: 5,
  metadata: {
    language_info: { name: "typescript" },
    kernelspec: { display_name: "TypeScript" },
  },
  cells: [
    {
      id: "editable-cell",
      cell_type: "code",
      source: ["const answer = 41;\n"],
      execution_count: null,
      outputs: [],
      metadata: {},
    },
  ],
};
const serializedIpynb = `${JSON.stringify(ipynb, null, 2)}\n`;
const ipynbDocument = parseWorkspaceNotebookDocument(
  "stage36-editable.ipynb",
  serializedIpynb,
);
const updatedIpynb = updateWorkspaceNotebookCellSource(
  serializedIpynb,
  "editable-cell",
  "const answer = 42;\n",
);
assert.equal(isWorkspaceNotebookPath("stage36-editable.ipynb"), true);
assert.ok(ipynbDocument);
assert.equal(ipynbDocument.documentKind, "jupyter");
assert.ok(updatedIpynb);
assert.match(updatedIpynb, /const answer = 42;/);

const proof = {
  schemaVersion:
    "ioi.autopilot.stage36.signed-replay-autopilot-notebook-substrate-proof.v1",
  passed: true,
  generatedAt: new Date().toISOString(),
  checks: {
    autopilotExtensionRecognized: isWorkspaceNotebookPath(autopilotPath),
    autopilotDocumentParsed:
      autopilotDocument.documentKind === "autopilot_replay",
    signedReplayBuilderUsed:
      notebook.schemaVersion === "ioi.workflow.signed-replay-notebook.v1",
    readOnlyReplayMode: autopilotDocument.readOnlyReplayMode === true,
    allAutopilotCellsReadOnly: autopilotDocument.cells.every(
      (cell) => cell.readOnly === true,
    ),
    tamperUpdateDenied: autopilotTamperAttempt === null,
    receiptBackedCellsVisible:
      autopilotDocument.receiptBackedCellCount ===
      notebook.receiptBackedCellCount,
    restoreEndpointsVisible:
      joinedReplaySource.includes("/restore-preview") &&
      joinedReplaySource.includes("/restore-apply"),
    rollbackRefsVisible: joinedReplaySource.includes(snapshotId),
    ipynbStillEditable: Boolean(updatedIpynb?.includes("const answer = 42;")),
  },
  autopilotDocument: {
    path: autopilotDocument.path,
    documentKind: autopilotDocument.documentKind,
    language: autopilotDocument.language,
    kernelDisplayName: autopilotDocument.kernelDisplayName,
    readOnlyReplayMode: autopilotDocument.readOnlyReplayMode,
    receiptBackedCellCount: autopilotDocument.receiptBackedCellCount,
    cellCount: autopilotDocument.cellCount,
    cells: autopilotDocument.cells.map((cell) => ({
      id: cell.id,
      cellType: cell.cellType,
      readOnly: cell.readOnly,
      outputPreview: cell.outputPreview,
      sourceExcerpt: cell.source.slice(0, 420),
    })),
  },
  ipynbDocument: {
    documentKind: ipynbDocument.documentKind,
    language: ipynbDocument.language,
    kernelDisplayName: ipynbDocument.kernelDisplayName,
    updatedSourceContainsAnswer42: updatedIpynb.includes("const answer = 42;"),
  },
  notebook,
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
