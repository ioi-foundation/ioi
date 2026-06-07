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
    turnId: "turn-hunk-decision",
    type: "workflow_edit_proposed",
    eventKind: "workflow.edit_proposed",
    sourceEventKind: "Workflow.EditProposed",
    status: "completed",
    componentKind: "workflow_compositor",
    workflowNodeId: "workflow-edit-node",
    workflowGraphId: "workflow.hunk-decision",
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
