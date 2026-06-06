import assert from "node:assert/strict";
import test from "node:test";

import {
  computerUseProjectionForRun,
} from "./computer-use-projection.mjs";

test("computer-use projection accepts canonical computer_use_target_ref", () => {
  const projection = projectionFor({
    runId: "projection_canonical_target",
    metadata: {
      computer_use: true,
      computer_use_action_kind: "click",
      computer_use_target_ref: "target_requested",
    },
  });

  assert.equal(projection.actionProposal.target_ref, "target_requested");
  assert.equal(projection.affordanceGraph.affordances[0].target_ref, "target_requested");
  assert.equal(projection.events.find((event) => event.type === "computer_use_action_proposed")
    .data.computer_use_target_ref, "target_requested");
});

test("computer-use projection ignores retired targetRef request alias", () => {
  const projection = projectionFor({
    runId: "projection_retired_target",
    metadata: {
      computer_use: true,
      computer_use_action_kind: "click",
      targetRef: "target_retired",
    },
  });

  assert.equal(projection.actionProposal.target_ref, "target_projection_retired_target_document");
  assert.equal(projection.affordanceGraph.affordances[0].target_ref, "target_projection_retired_target_document");
  assert.equal(projection.events.find((event) => event.type === "computer_use_action_proposed")
    .data.computer_use_target_ref, "target_projection_retired_target_document");
});

test("computer-use projection accepts canonical action and approval refs", () => {
  const projection = projectionFor({
    runId: "projection_canonical_action",
    metadata: {
      computer_use: true,
      computer_use_action_kind: "click",
      computer_use_approval_ref: "approval_computer_use",
      computer_use_target_ref: "target_requested",
    },
  });

  assert.equal(projection.actionProposal.target_ref, "target_requested");
  assert.equal(projection.actionProposal.normalized_action_candidate, "click target_requested");
  assert.equal(projection.action, null);
  assert.equal(projection.actionReceipt, null);
  assert.equal(projection.policyDecision.action_kind, "click");
  assert.equal(projection.policyDecision.approval_ref, "approval_computer_use");
  assert.equal(projection.policyDecision.outcome, "blocked_executor_unavailable");
});

test("computer-use projection ignores retired actionKind and approvalRef aliases", () => {
  const projection = projectionFor({
    runId: "projection_retired_action",
    prompt: "inspect the requested computer-use target",
    metadata: {
      computer_use: true,
      actionKind: "click",
      approvalRef: "approval_retired",
    },
  });

  assert.equal(projection.actionProposal.target_ref, "target_projection_retired_action_document");
  assert.equal(projection.actionProposal.normalized_action_candidate, "inspect current page and summarize actionable targets");
  assert.equal(projection.action.action_kind, "inspect");
  assert.equal(projection.actionReceipt.status, "completed");
  assert.equal(projection.policyDecision.action_kind, "inspect");
  assert.equal(projection.policyDecision.approval_ref, null);
  assert.equal(projection.policyDecision.outcome, "approved_for_read_only_probe");
});

function projectionFor({ runId, metadata, prompt = "click the requested computer-use target" }) {
  return computerUseProjectionForRun({
    agent: { cwd: "/tmp/ioi-projection-test" },
    runId,
    prompt,
    mode: "dry_run",
    selectedModel: "model_test",
    request: { metadata },
  });
}
