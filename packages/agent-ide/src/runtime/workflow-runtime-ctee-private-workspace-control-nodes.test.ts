import assert from "node:assert/strict";
import test from "node:test";

import {
  WORKFLOW_RUNTIME_CTEE_PRIVATE_WORKSPACE_CONTROL_SCHEMA_VERSION,
  createRuntimeCteePrivateWorkspaceControlRequest,
  createRuntimeCteePrivateWorkspaceControlRequestFromWorkflowNode,
} from "./workflow-runtime-ctee-private-workspace-control-nodes";

function cteeAction() {
  return {
    invocation: {
      schema_version: "ioi.step_module_invocation.v1",
      invocation_id: "invocation://ctee/ide",
      module_ref: {
        kind: "private_workspace_ctee_action",
        id: "private_workspace.mount",
        manifest_ref: "module://ctee/private-workspace@1",
      },
      custody: {
        privacy_profile: "private_workspace_ctee",
        plaintext_policy: {
          node_plaintext_allowed: false,
          declassification_required: true,
        },
        custody_proof_ref: "artifact://custody-proof",
        leakage_profile_ref: "artifact://leakage-profile",
      },
      execution: {
        backend: "ctee_operator",
      },
    },
    node_trust: {
      runtime_node_ref: "node://rented-untrusted",
      trusted_for_plaintext: false,
      attestation_ref: null,
    },
  };
}

const retiredCteePrivateWorkspaceRequestAliases = [
  "eventKind",
  "componentKind",
  "workflowGraphId",
  "workflowNodeId",
  "invocationId",
  "runtimeNodeRef",
  "trustedForPlaintext",
  "expectedHeads",
  "admissionOnly",
  "directTruthWriteAllowed",
  "plaintextCustodyCheckedByRust",
  "ctee_action",
  "cteeAction",
];

const retiredCteePrivateWorkspaceControlInputAliases = [
  "workflowGraphId",
  "workflowNodeId",
];

test("builds cTEE private workspace controls for daemon admission", () => {
  const request = createRuntimeCteePrivateWorkspaceControlRequest({
    nodeId: "node-ctee-private-workspace",
    threadId: "thread-ide",
    action: cteeAction(),
    workflow_graph_id: "workflow.ctee",
    actor: "workflow-author",
  });

  assert.equal(request.schemaVersion, WORKFLOW_RUNTIME_CTEE_PRIVATE_WORKSPACE_CONTROL_SCHEMA_VERSION);
  assert.equal(request.endpoint, "/v1/threads/thread-ide/ctee-private-workspace-actions");
  assert.equal(request.method, "POST");
  assert.equal(request.nodeType, "ctee_private_workspace_action");
  assert.equal(request.invocationId, "invocation://ctee/ide");
  assert.equal(request.body.source, "react_flow");
  assert.equal(request.body.runtime_node_ref, "node://rented-untrusted");
  assert.equal(request.body.trusted_for_plaintext, false);
  assert.equal(request.body.action.invocation.invocation_id, "invocation://ctee/ide");
  assert.equal(Object.prototype.hasOwnProperty.call(request.body, "expected_heads"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(request.body.action, "expected_heads"), false);
  assert.equal(request.body.admission_only, true);
  assert.equal(request.body.direct_truth_write_allowed, false);
  assert.equal(request.body.plaintext_custody_checked_by_rust, true);
  for (const key of retiredCteePrivateWorkspaceRequestAliases) {
    assert.equal(Object.prototype.hasOwnProperty.call(request.body, key), false, `${key} must not be emitted`);
  }
  assert.equal(request.endpoint.includes("/apply"), false);
});

test("builds cTEE private workspace controls from workflow nodes", () => {
  const request = createRuntimeCteePrivateWorkspaceControlRequestFromWorkflowNode(
    {
      id: "ctee-node",
      type: "runtime.control.ctee_private_workspace",
      config: {
        logic: {
          cteePrivateWorkspace: cteeAction(),
        },
      } as any,
    },
    { threadId: "thread-node" },
    { workflow_graph_id: "workflow.ctee-node", actor: "runtime-composer" },
  );

  assert.equal(request.nodeId, "ctee-node");
  assert.equal(request.threadId, "thread-node");
  assert.equal(request.body.actor, "runtime-composer");
  assert.equal(request.body.workflow_graph_id, "workflow.ctee-node");
  assert.equal(request.body.workflow_node_id, "runtime.ctee-private-workspace-action.ctee-node");
  assert.equal(request.body.action.node_trust.runtime_node_ref, "node://rented-untrusted");
});

test("cTEE private workspace controls reject retired control input aliases", () => {
  for (const key of retiredCteePrivateWorkspaceControlInputAliases) {
    assert.throws(
      () =>
        createRuntimeCteePrivateWorkspaceControlRequest({
          threadId: "thread-ide",
          action: cteeAction(),
          [key]: "retired",
        } as any),
      /retired control input aliases/,
    );
  }
});

test("cTEE private workspace workflow node options reject retired workflow graph input alias", () => {
  assert.throws(
    () =>
      createRuntimeCteePrivateWorkspaceControlRequestFromWorkflowNode(
        {
          id: "ctee-node",
          type: "runtime.control.ctee_private_workspace",
          config: {
            logic: {
              action: cteeAction(),
            },
          } as any,
        },
        { threadId: "thread-node" },
        { workflowGraphId: "workflow.ctee-node" } as any,
      ),
    /retired control input aliases/,
  );
});

test("cTEE private workspace controls reject retired Agentgres truth fields", () => {
  const invalid: Record<string, unknown> = cteeAction();
  invalid.expected_heads = ["agentgres://ctee/private-workspace/head/client"];

  assert.throws(
    () =>
      createRuntimeCteePrivateWorkspaceControlRequest({
        threadId: "thread-ide",
        action: invalid,
      }),
    /expected heads are Rust-derived/,
  );
});
