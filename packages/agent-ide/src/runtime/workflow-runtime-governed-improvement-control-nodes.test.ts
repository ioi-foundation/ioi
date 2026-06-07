import assert from "node:assert/strict";
import test from "node:test";

import {
  RUNTIME_GOVERNED_IMPROVEMENT_PROPOSAL_SCHEMA_VERSION,
  createRuntimeGovernedImprovementControlRequest,
  createRuntimeGovernedImprovementControlRequestFromWorkflowNode,
  type RuntimeGovernedImprovementProposal,
} from "./workflow-runtime-governed-improvement-control-nodes";

function proposal(): RuntimeGovernedImprovementProposal {
  return {
    schema_version: RUNTIME_GOVERNED_IMPROVEMENT_PROPOSAL_SCHEMA_VERSION,
    proposal_id: "proposal://runtime-improvement/ide",
    target_ref: "skill://runtime-auditor/current",
    candidate_ref: "skill-candidate://runtime-auditor/from-trace",
    surface: "skill",
    source_trace_ref: "trace://runtime-improvement/high-fitness",
    eval_receipt_refs: ["receipt://eval/ide-holdout-pass"],
    verifier_receipt_refs: ["receipt://verifier/ide-regression-pass"],
    approval_ref: "approval://wallet/runtime-improvement/ide",
    rollback_ref: "rollback://skill/runtime-auditor/current",
  };
}

const retiredGovernedImprovementRequestAliases = [
  "eventKind",
  "componentKind",
  "payloadSchemaVersion",
  "workflowGraphId",
  "workflowNodeId",
  "proposalId",
  "targetRef",
  "candidateRef",
  "sourceTraceRef",
  "evalReceiptRefs",
  "verifierReceiptRefs",
  "approvalRef",
  "rollbackRef",
  "agentgresOperationRef",
  "expectedHeads",
  "stateRootBefore",
  "stateRootAfter",
  "resultingHead",
  "approvalMode",
  "proposalOnly",
  "mutationAllowed",
  "mutationExecuted",
  "proposal_payload",
  "proposalPayload",
];

const retiredGovernedImprovementProposalInputFields = [
  "proposal_payload",
  "proposalPayload",
];

const retiredGovernedImprovementProposalPayloadAliases = [
  "schemaVersion",
  "proposalId",
  "targetRef",
  "candidateRef",
  "sourceTraceRef",
  "evalReceiptRefs",
  "verifierReceiptRefs",
  "approvalRef",
  "rollbackRef",
  "agentgresOperationRef",
  "expectedHeads",
  "stateRootBefore",
  "stateRootAfter",
  "resultingHead",
];

const retiredGovernedImprovementProposalTruthFields = [
  "agentgres_operation_ref",
  "expected_heads",
  "state_root_before",
  "state_root_after",
  "resulting_head",
];

const retiredGovernedImprovementWorkflowLogicAliases = [
  "governedImprovement",
  "runtimeImprovementProposal",
  "workflowNodeId",
];

test("builds governed improvement proposal controls for daemon admission", () => {
  const request = createRuntimeGovernedImprovementControlRequest({
    threadId: "thread-ide",
    workflowGraphId: "workflow-governed-improvement",
    workflowNodeId: "runtime.governed-improvement-proposal.ide",
    proposal: {
      ...proposal(),
      eval_receipt_refs: [
        "receipt://eval/ide-holdout-pass",
        "receipt://eval/ide-holdout-pass",
      ],
    },
  });

  assert.equal(request.endpoint, "/v1/threads/thread-ide/governed-improvement-proposals");
  assert.equal(request.method, "POST");
  assert.equal(request.nodeType, "governed_improvement_proposal");
  assert.equal(request.body.source, "react_flow");
  assert.equal(request.body.payload_schema_version, RUNTIME_GOVERNED_IMPROVEMENT_PROPOSAL_SCHEMA_VERSION);
  assert.equal(request.body.proposal_id, "proposal://runtime-improvement/ide");
  assert.equal(request.body.target_ref, "skill://runtime-auditor/current");
  assert.equal(request.body.candidate_ref, "skill-candidate://runtime-auditor/from-trace");
  assert.equal(request.body.approval_mode, "human_required");
  assert.equal(request.body.proposal_only, true);
  assert.equal(request.body.mutation_allowed, false);
  assert.equal(request.body.mutation_executed, false);
  assert.deepEqual(request.body.eval_receipt_refs, ["receipt://eval/ide-holdout-pass"]);
  assert.deepEqual(request.body.verifier_receipt_refs, ["receipt://verifier/ide-regression-pass"]);
  assert.equal(request.body.proposal.proposal_id, "proposal://runtime-improvement/ide");
  assert.equal(request.body.proposal.approval_ref, "approval://wallet/runtime-improvement/ide");
  for (const key of retiredGovernedImprovementProposalTruthFields) {
    assert.equal(Object.prototype.hasOwnProperty.call(request.body, key), false, `${key} must not be emitted`);
    assert.equal(Object.prototype.hasOwnProperty.call(request.body.proposal, key), false, `${key} must not be emitted`);
  }
  for (const key of retiredGovernedImprovementRequestAliases) {
    assert.equal(Object.prototype.hasOwnProperty.call(request.body, key), false, `${key} must not be emitted`);
  }
  for (const key of retiredGovernedImprovementProposalPayloadAliases) {
    assert.equal(Object.prototype.hasOwnProperty.call(request.body.proposal, key), false, `${key} must not be emitted`);
  }
});

test("builds governed improvement controls from canonical input proposal", () => {
  const request = createRuntimeGovernedImprovementControlRequest({
    threadId: "thread-ide",
    input: {
      proposal: proposal(),
    },
  });

  assert.equal(request.body.proposal.proposal_id, "proposal://runtime-improvement/ide");
  assert.equal(request.body.proposal_id, "proposal://runtime-improvement/ide");
});

test("governed improvement controls reject retired proposal input field aliases", () => {
  for (const proposalField of retiredGovernedImprovementProposalInputFields) {
    assert.throws(
      () =>
        createRuntimeGovernedImprovementControlRequest({
          threadId: "thread-ide",
          input: {
            [proposalField]: proposal(),
          },
          proposalField,
        }),
      /retired proposal input field aliases/,
    );
  }
});

test("governed improvement controls reject retired proposal payload aliases", () => {
  for (const key of retiredGovernedImprovementProposalPayloadAliases) {
    assert.throws(
      () =>
        createRuntimeGovernedImprovementControlRequest({
          threadId: "thread-ide",
          proposal: {
            ...proposal(),
            [key]: "retired",
          },
        }),
      /retired proposal payload aliases/,
    );
  }
});

test("governed improvement controls reject retired proposal truth fields", () => {
  for (const key of retiredGovernedImprovementProposalTruthFields) {
    assert.throws(
      () =>
        createRuntimeGovernedImprovementControlRequest({
          threadId: "thread-ide",
          proposal: {
            ...proposal(),
            [key]: key === "expected_heads" ? ["agentgres://head/client"] : "client-supplied-truth",
          },
        }),
      /retired proposal payload aliases/,
    );
  }
});

test("governed improvement controls reject raw input proposal payload aliases", () => {
  assert.throws(
    () =>
      createRuntimeGovernedImprovementControlRequest({
        threadId: "thread-ide",
        input: {
          ...proposal(),
          proposalId: "proposal://runtime-improvement/retired",
        },
      }),
    /retired proposal payload aliases/,
  );
});

test("builds governed improvement controls from workflow proposal nodes", () => {
  const request = createRuntimeGovernedImprovementControlRequestFromWorkflowNode(
    {
      id: "governed-improvement-node",
      type: "proposal",
      config: {
        logic: {
          proposal: proposal(),
        } as any,
        law: {},
      },
    },
    { threadId: "thread-from-node" },
    { workflowGraphId: "workflow-from-node", actor: "runtime-reviewer" },
  );

  assert.equal(request.threadId, "thread-from-node");
  assert.equal(request.proposalId, "proposal://runtime-improvement/ide");
  assert.equal(
    request.body.workflow_node_id,
    "runtime.governed-improvement-proposal.governed-improvement-node",
  );
  assert.equal(request.body.workflow_graph_id, "workflow-from-node");
  assert.equal(request.body.actor, "runtime-reviewer");
});

test("governed improvement controls reject retired workflow logic aliases", () => {
  for (const key of retiredGovernedImprovementWorkflowLogicAliases) {
    assert.throws(
      () =>
        createRuntimeGovernedImprovementControlRequestFromWorkflowNode(
          {
            id: "governed-improvement-node",
            type: "proposal",
            config: {
              logic: {
                proposal: proposal(),
                [key]: key === "workflowNodeId" ? "runtime.retired-node-id" : proposal(),
              } as any,
              law: {},
            },
          },
          { threadId: "thread-from-node" },
        ),
      /retired logic aliases/,
    );
  }
});

test("governed improvement controls fail closed without evaluation receipts", () => {
  assert.throws(
    () =>
      createRuntimeGovernedImprovementControlRequest({
        threadId: "thread-ide",
        proposal: {
          ...proposal(),
          eval_receipt_refs: [],
        },
      }),
    /eval_receipt_refs/,
  );
});
