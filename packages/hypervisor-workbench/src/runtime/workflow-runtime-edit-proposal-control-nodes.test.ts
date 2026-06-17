import assert from "node:assert/strict";
import test from "node:test";

import {
  createRuntimeWorkflowEditProposalApplyControlRequest,
  createRuntimeWorkflowEditProposalControlRequest,
  createRuntimeWorkflowEditProposalControlRequestFromWorkflowNode,
} from "./workflow-runtime-edit-proposal-control-nodes";

test("builds React Flow workflow edit proposal controls for daemon dispatch", () => {
  const request = createRuntimeWorkflowEditProposalControlRequest({
    threadId: "thread-a",
    proposalId: "proposal-a",
    workflowGraphId: "workflow-a",
    workflowNodeId: "runtime.workflow-edit-proposal.proposal-a",
    title: "Review node change",
    summary: "Bounded workflow edit.",
    targetWorkflowNodeIds: ["node-a", "node-a", "node-b"],
    workflowPath: "flows/demo.workflow.json",
    workflowPatch: { version: "1", nodes: [] },
    codeDiff: "metadata only",
  });

  assert.equal(request.endpoint, "/v1/threads/thread-a/workflow-edit-proposals");
  assert.equal(request.method, "POST");
  assert.equal(request.body.proposal_only, true);
  assert.equal(request.body.mutation_allowed, false);
  assert.equal(request.body.mutation_executed, false);
  assert.equal(request.body.approval_mode, "human_required");
  assert.deepEqual(request.body.target_workflow_node_ids, ["node-a", "node-b"]);
  assert.deepEqual(request.body.workflow_patch, { version: "1", nodes: [] });
  assert.equal(Object.prototype.hasOwnProperty.call(request.body, "workflowGraphId"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(request.body, "proposalId"), false);
  assert.equal(
    Object.prototype.hasOwnProperty.call(request.body, "targetWorkflowNodeIds"),
    false,
  );
  assert.equal(Object.prototype.hasOwnProperty.call(request.body, "boundedTargets"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(request.body, "workflowPath"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(request.body, "workflowPatch"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(request.body, "codeDiff"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(request.body, "mutationExecuted"), false);

  const apply = createRuntimeWorkflowEditProposalApplyControlRequest({
    threadId: "thread-a",
    proposalId: "proposal-a",
    approvalId: "approval-a",
    workflowGraphId: "workflow-a",
  });
  assert.equal(
    apply.endpoint,
    "/v1/threads/thread-a/workflow-edit-proposals/proposal-a/apply",
  );
  assert.equal(apply.body.approval_id, "approval-a");
  assert.equal(Object.prototype.hasOwnProperty.call(apply.body, "proposalId"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(apply.body, "approvalId"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(apply.body, "workflowGraphId"), false);
});

test("builds workflow edit proposal controls from proposal nodes", () => {
  const request = createRuntimeWorkflowEditProposalControlRequestFromWorkflowNode(
    {
      id: "proposal-node",
      type: "proposal",
      config: {
        logic: {
          proposalAction: {
            actionKind: "create",
            boundedTargets: ["model-node"],
            requiresApproval: true,
          },
          title: "Review model node",
          workflowPath: "flows/demo.workflow.json",
          workflowPatch: { metadata: { id: "workflow-a" } },
        } as any,
        law: {},
      },
    },
    { threadId: "thread-a" },
    { workflowGraphId: "workflow-a", actor: "workflow-author" },
  );

  assert.equal(request.nodeType, "proposal");
  assert.equal(request.body.workflow_graph_id, "workflow-a");
  assert.equal(
    request.body.workflow_node_id,
    "runtime.workflow-edit-proposal.proposal-node",
  );
  assert.deepEqual(request.body.bounded_targets, ["model-node"]);
  assert.equal(request.body.actor, "workflow-author");
});

test("workflow edit proposal controls ignore retired raw input aliases", () => {
  const request = createRuntimeWorkflowEditProposalControlRequest({
    input: {
      thread_id: "thread-canonical",
      threadId: "thread-retired",
      proposalId: "proposal-retired",
      targetWorkflowNodeIds: ["target-retired"],
      boundedTargets: ["bound-retired"],
      workflowPath: "flows/retired.workflow.json",
      workflowPatch: { retired: true },
      codeDiff: "diff-retired",
    },
  });

  assert.equal(request.threadId, "thread-canonical");
  assert.equal(request.body.proposal_id, null);
  assert.deepEqual(request.body.target_workflow_node_ids, []);
  assert.equal(request.body.workflow_path, null);
  assert.equal(request.body.workflow_patch, null);
  assert.equal(request.body.code_diff, null);

  const canonical = createRuntimeWorkflowEditProposalControlRequest({
    input: {
      thread_id: "thread-canonical",
      proposal_id: "proposal-canonical",
      target_workflow_node_ids: ["target-canonical"],
      bounded_targets: ["bound-canonical"],
      workflow_path: "flows/canonical.workflow.json",
      workflow_patch: { canonical: true },
      code_diff: "diff-canonical",
    },
  });

  assert.equal(canonical.body.proposal_id, "proposal-canonical");
  assert.deepEqual(canonical.body.target_workflow_node_ids, ["target-canonical"]);
  assert.equal(canonical.body.workflow_path, "flows/canonical.workflow.json");
  assert.deepEqual(canonical.body.workflow_patch, { canonical: true });
  assert.equal(canonical.body.code_diff, "diff-canonical");

  assert.throws(
    () =>
      createRuntimeWorkflowEditProposalApplyControlRequest({
        input: {
          threadId: "thread-retired",
          proposalId: "proposal-retired",
          approvalId: "approval-retired",
        },
      }),
    /threadId input/,
  );

  const apply = createRuntimeWorkflowEditProposalApplyControlRequest({
    input: {
      thread_id: "thread-canonical",
      proposal_id: "proposal-canonical",
      approval_id: "approval-canonical",
    },
  });

  assert.equal(apply.threadId, "thread-canonical");
  assert.equal(apply.proposalId, "proposal-canonical");
  assert.equal(apply.body.approval_id, "approval-canonical");
});
