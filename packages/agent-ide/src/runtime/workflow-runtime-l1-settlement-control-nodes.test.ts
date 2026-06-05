import assert from "node:assert/strict";
import test from "node:test";

import {
  WORKFLOW_RUNTIME_L1_SETTLEMENT_CONTROL_SCHEMA_VERSION,
  createRuntimeL1SettlementControlRequest,
  createRuntimeL1SettlementControlRequestFromWorkflowNode,
} from "./workflow-runtime-l1-settlement-control-nodes";

function settlementAttempt() {
  return {
    schema_version: "ioi.l1_settlement_admission.v1",
    settlement_ref: "l1://settlement/marketplace-payment",
    domain_ref: "domain://marketplace/services",
    state_root_ref: "state-root://agentgres/marketplace/after",
    trigger_refs: ["l1-trigger://service-contract/payment"],
    receipt_refs: ["receipt://local-settlement/payment"],
  };
}

test("builds L1 settlement controls for daemon admission", () => {
  const request = createRuntimeL1SettlementControlRequest({
    nodeId: "node-l1-settlement",
    threadId: "thread-ide",
    attempt: settlementAttempt(),
    workflowGraphId: "workflow.l1-settlement",
    actor: "workflow-author",
  });

  assert.equal(request.schemaVersion, WORKFLOW_RUNTIME_L1_SETTLEMENT_CONTROL_SCHEMA_VERSION);
  assert.equal(request.endpoint, "/v1/threads/thread-ide/l1-settlement-attempts");
  assert.equal(request.method, "POST");
  assert.equal(request.nodeType, "l1_settlement_attempt");
  assert.equal(request.settlementRef, "l1://settlement/marketplace-payment");
  assert.equal(request.body.source, "react_flow");
  assert.equal(request.body.settlement_ref, "l1://settlement/marketplace-payment");
  assert.equal(request.body.domain_ref, "domain://marketplace/services");
  assert.equal(request.body.state_root_ref, "state-root://agentgres/marketplace/after");
  assert.deepEqual(request.body.trigger_refs, ["l1-trigger://service-contract/payment"]);
  assert.deepEqual(request.body.receipt_refs, ["receipt://local-settlement/payment"]);
  assert.equal(request.body.admission_only, true);
  assert.equal(request.body.direct_truth_write_allowed, false);
  assert.equal(request.body.default_runtime_settlement_allowed, false);
  assert.equal(request.body.settlement_trigger_checked_by_rust, true);
  assert.equal(request.endpoint.includes("/apply"), false);
});

test("builds L1 settlement controls from workflow nodes", () => {
  const request = createRuntimeL1SettlementControlRequestFromWorkflowNode(
    {
      id: "l1-settlement-node",
      type: "runtime.control.l1_settlement",
      config: {
        logic: {
          l1Settlement: settlementAttempt(),
        },
      } as any,
    },
    { threadId: "thread-node" },
    { workflowGraphId: "workflow.l1-node", actor: "runtime-composer" },
  );

  assert.equal(request.nodeId, "l1-settlement-node");
  assert.equal(request.threadId, "thread-node");
  assert.equal(request.body.actor, "runtime-composer");
  assert.equal(request.body.workflow_graph_id, "workflow.l1-node");
  assert.equal(request.body.workflow_node_id, "runtime.l1-settlement-attempt.l1-settlement-node");
  assert.equal(request.body.settlementAttempt.settlement_ref, "l1://settlement/marketplace-payment");
});

test("L1 settlement controls fail closed without trigger refs", () => {
  const invalid = settlementAttempt();
  invalid.trigger_refs = [];

  assert.throws(
    () =>
      createRuntimeL1SettlementControlRequest({
        threadId: "thread-ide",
        attempt: invalid,
      }),
    /trigger_refs/,
  );
});
