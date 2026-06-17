import assert from "node:assert/strict";
import test from "node:test";

import type { WorkflowRuntimeThreadEventLike } from "./workflow-runtime-event-projection";
import { buildWorkflowHunkDecisionReceiptPanel } from "./workflow-hunk-decision-receipt-panel";

const proposalEvent = (
  overrides: Partial<WorkflowRuntimeThreadEventLike> & Record<string, unknown>,
): WorkflowRuntimeThreadEventLike =>
  ({
    id: "event-workflow-edit-proposed",
    cursor: "cursor-1",
    seq: 1,
    threadId: "thread-hunk-decision",
    thread_id: "thread-hunk-decision",
    turnId: "turn-hunk-decision",
    turn_id: "turn-hunk-decision",
    type: "workflow_edit_proposed",
    eventKind: "workflow.edit_proposed",
    event_kind: "workflow.edit_proposed",
    sourceEventKind: "Workflow.EditProposed",
    status: "completed",
    componentKind: "workflow_compositor",
    workflowNodeId: "workflow-edit-node",
    workflow_node_id: "workflow-edit-node",
    workflowGraphId: "workflow.hunk-decision",
    workflow_graph_id: "workflow.hunk-decision",
    payloadSchemaVersion: "ioi.workflow.edit-proposed.v1",
    receiptRefs: [],
    artifactRefs: [],
    policyDecisionRefs: [],
    rollbackRefs: [],
    payload: {
      proposal_id: "proposal-hunk-decision",
      approval_id: "approval-hunk-decision",
      workflow_relative_path: "src/example.ts",
      code_diff: [
        "diff --git a/src/example.ts b/src/example.ts",
        "--- a/src/example.ts",
        "+++ b/src/example.ts",
        "@@ -1 +1 @@",
        "-old",
        "+new",
      ].join("\n"),
    },
    ...overrides,
  }) as WorkflowRuntimeThreadEventLike;

test("hunk decision receipt panel uses canonical evidence refs", () => {
  const panel = buildWorkflowHunkDecisionReceiptPanel({
    events: [
      proposalEvent({
        receipt_refs: ["receipt-canonical-proposal"],
        policy_decision_refs: ["policy-canonical-proposal"],
      }),
    ],
  });

  assert.deepEqual(panel.rows[0]?.proposalReceiptRefs, [
    "receipt-canonical-proposal",
  ]);
  assert.deepEqual(panel.rows[0]?.policyDecisionRefs, [
    "policy-canonical-proposal",
  ]);
  assert.deepEqual(panel.evidenceRefs, ["receipt-canonical-proposal"]);
});

test("hunk decision receipt panel uses canonical proposal and bridge metadata", () => {
  const panel = buildWorkflowHunkDecisionReceiptPanel({
    events: [
      proposalEvent({
        approval_id: "approval-canonical",
        thread_id: "thread-canonical",
        turn_id: "turn-canonical",
        workflow_graph_id: "graph-canonical",
        workflow_node_id: "node-canonical",
        payload: {
          proposal_id: "proposal-canonical",
          approval_id: "approval-canonical",
          workflow_relative_path: "src/canonical.ts",
          patch_hash: "patch-canonical",
          target_workflow_node_ids: ["target-canonical"],
          code_diff: [
            "diff --git a/src/canonical.ts b/src/canonical.ts",
            "--- a/src/canonical.ts",
            "+++ b/src/canonical.ts",
            "@@ -1 +1 @@",
            "-old",
            "+new",
          ].join("\n"),
        },
      }),
    ],
    hunkDecisions: [
      {
        request_type: "chat.hunkDecision",
        payload: {
          proposal_id: "proposal-canonical",
          approval_id: "approval-canonical",
          hunk_file: "src/canonical.ts",
          hunk_index: 0,
          owns_runtime_state: true,
          decision: "approve",
        },
        receipt_refs: ["receipt-canonical-bridge"],
      },
    ],
  });

  const row = panel.rows[0];
  assert.equal(row?.proposalId, "proposal-canonical");
  assert.equal(row?.approvalId, "approval-canonical");
  assert.equal(row?.threadId, "thread-canonical");
  assert.equal(row?.turnId, "turn-canonical");
  assert.equal(row?.workflowGraphId, "graph-canonical");
  assert.equal(row?.workflowNodeId, "node-canonical");
  assert.deepEqual(row?.targetWorkflowNodeIds, ["target-canonical"]);
  assert.equal(row?.filePath, "src/canonical.ts");
  assert.equal(row?.patchHash, "patch-canonical");
  assert.equal(row?.bridgeRequestType, "chat.hunkDecision");
  assert.equal(row?.bridgeOwnsRuntimeState, true);
  assert.deepEqual(row?.decisionReceiptRefs, ["receipt-canonical-bridge"]);
});

test("hunk decision receipt panel ignores retired evidence aliases", () => {
  const panel = buildWorkflowHunkDecisionReceiptPanel({
    events: [
      proposalEvent({
        receiptRefs: ["receipt-retired-proposal"],
        policyDecisionRefs: ["policy-retired-proposal"],
      }),
    ],
    hunkDecisions: [
      {
        request_type: "chat.hunkDecision",
        payload: {
          approval_id: "approval-hunk-decision",
          decision: "approve",
        },
        receiptRefs: ["receipt-retired-bridge-decision"],
      },
    ],
    applyResults: [
      {
        proposal_id: "proposal-hunk-decision",
        status: "blocked",
        receiptRefs: ["receipt-retired-blocked-apply"],
        policyDecisionRefs: ["policy-retired-blocked-apply"],
      },
    ],
  });

  assert.deepEqual(panel.rows[0]?.proposalReceiptRefs, []);
  assert.deepEqual(panel.rows[0]?.decisionReceiptRefs, []);
  assert.deepEqual(panel.rows[0]?.applyReceiptRefs, []);
  assert.deepEqual(panel.rows[0]?.receiptRefs, []);
  assert.deepEqual(panel.rows[0]?.policyDecisionRefs, []);
  assert.deepEqual(panel.evidenceRefs, []);
});

test("hunk decision receipt panel ignores retired proposal and bridge aliases", () => {
  const panel = buildWorkflowHunkDecisionReceiptPanel({
    events: [
      proposalEvent({
        thread_id: undefined,
        turn_id: undefined,
        workflow_graph_id: undefined,
        workflow_node_id: undefined,
        approvalId: "approval-retired",
        threadId: "thread-retired",
        turnId: "turn-retired",
        workflowGraphId: "graph-retired",
        workflowNodeId: "node-retired",
        payload: {
          proposalId: "proposal-retired",
          approvalId: "approval-retired",
          workflowRelativePath: "src/retired.ts",
          workflowPath: "src/retired-path.ts",
          patchHash: "patch-retired",
          codeDiff: [
            "diff --git a/src/retired.ts b/src/retired.ts",
            "--- a/src/retired.ts",
            "+++ b/src/retired.ts",
            "@@ -1 +1 @@",
            "-old",
            "+new",
          ].join("\n"),
          targetWorkflowNodeIds: ["target-retired"],
          boundedTargets: ["bounded-retired"],
        },
      }),
    ],
    hunkDecisions: [
      {
        requestType: "chat.hunkDecision",
        approvalId: "approval-retired",
        proposalId: "proposal-retired",
        hunkFile: "src/retired.ts",
        hunkIndex: 0,
        payload: {
          approvalId: "approval-retired",
          proposalId: "proposal-retired",
          filePath: "src/retired.ts",
          hunkIndex: 0,
          ownsRuntimeState: true,
          decision: "approve",
        },
        receipt_refs: ["receipt-retired-bridge-should-not-match"],
      },
    ],
    applyResults: [
      {
        proposalId: "proposal-retired",
        approvalId: "approval-retired",
        status: "blocked",
        receipt_refs: ["receipt-retired-apply-should-not-match"],
      },
    ],
  });

  assert.equal(panel.hunkCount, 0);
  assert.equal(panel.rows[0], undefined);
  assert.deepEqual(panel.evidenceRefs, []);
});
