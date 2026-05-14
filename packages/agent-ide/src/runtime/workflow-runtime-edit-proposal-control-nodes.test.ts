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
  assert.equal(request.body.workflowGraphId, "workflow-a");
  assert.equal(
    request.body.workflowNodeId,
    "runtime.workflow-edit-proposal.proposal-node",
  );
  assert.deepEqual(request.body.boundedTargets, ["model-node"]);
  assert.equal(request.body.actor, "workflow-author");
});
