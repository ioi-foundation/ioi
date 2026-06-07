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

const retiredL1SettlementRequestAliases = [
  "eventKind",
  "componentKind",
  "payloadSchemaVersion",
  "workflowGraphId",
  "workflowNodeId",
  "settlementRef",
  "domainRef",
  "stateRootRef",
  "triggerRefs",
  "receiptRefs",
  "admissionOnly",
  "directTruthWriteAllowed",
  "mutationAllowed",
  "defaultRuntimeSettlementAllowed",
  "settlementTriggerCheckedByRust",
  "settlement_attempt",
  "settlementAttempt",
];

const retiredL1SettlementControlInputAliases = [
  "workflowGraphId",
  "workflowNodeId",
];

test("builds L1 settlement controls for daemon admission", () => {
  const request = createRuntimeL1SettlementControlRequest({
    nodeId: "node-l1-settlement",
    threadId: "thread-ide",
    attempt: settlementAttempt(),
    workflow_graph_id: "workflow.l1-settlement",
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
  for (const key of retiredL1SettlementRequestAliases) {
    assert.equal(Object.prototype.hasOwnProperty.call(request.body, key), false, `${key} must not be emitted`);
  }
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
    { thread_id: "thread-node" },
    { workflow_graph_id: "workflow.l1-node", actor: "runtime-composer" },
  );

  assert.equal(request.nodeId, "l1-settlement-node");
  assert.equal(request.threadId, "thread-node");
  assert.equal(request.body.actor, "runtime-composer");
  assert.equal(request.body.workflow_graph_id, "workflow.l1-node");
  assert.equal(request.body.workflow_node_id, "runtime.l1-settlement-attempt.l1-settlement-node");
  assert.equal(request.body.attempt.settlement_ref, "l1://settlement/marketplace-payment");
});

test("L1 settlement workflow nodes read canonical settlement attempt logic", () => {
  const request = createRuntimeL1SettlementControlRequestFromWorkflowNode(
    {
      id: "l1-settlement-node",
      type: "runtime.control.l1_settlement",
      config: {
        logic: {
          settlement_attempt: settlementAttempt(),
        },
      } as any,
    },
    { thread_id: "thread-node" },
    { workflow_graph_id: "workflow.l1-node", actor: "runtime-composer" },
  );

  assert.equal(request.body.settlement_ref, "l1://settlement/marketplace-payment");
  assert.equal(request.body.domain_ref, "domain://marketplace/services");
});

test("L1 settlement workflow nodes ignore retired settlement attempt logic alias", () => {
  assert.throws(
    () =>
      createRuntimeL1SettlementControlRequestFromWorkflowNode(
        {
          id: "l1-settlement-node",
          type: "runtime.control.l1_settlement",
          config: {
            logic: {
              settlementAttempt: settlementAttempt(),
            },
          } as any,
        },
        { thread_id: "thread-node" },
        { workflow_graph_id: "workflow.l1-node", actor: "runtime-composer" },
      ),
    /settlement_ref/,
  );
});

test("L1 settlement controls reject retired control input aliases", () => {
  for (const key of retiredL1SettlementControlInputAliases) {
    assert.throws(
      () =>
        createRuntimeL1SettlementControlRequest({
          threadId: "thread-ide",
          attempt: settlementAttempt(),
          [key]: "retired",
        } as any),
      /retired control input aliases/,
    );
  }
});

test("L1 settlement workflow node options reject retired workflow graph input alias", () => {
  assert.throws(
    () =>
      createRuntimeL1SettlementControlRequestFromWorkflowNode(
        {
          id: "l1-settlement-node",
          type: "runtime.control.l1_settlement",
          config: {
            logic: {
              attempt: settlementAttempt(),
            },
          } as any,
        },
        { threadId: "thread-node" },
        { workflowGraphId: "workflow.l1-node" } as any,
      ),
    /retired control input aliases/,
  );
});

test("L1 settlement controls ignore retired attempt aliases", () => {
  const aliasOnlyAttempt = {
    schemaVersion: "ioi.l1_settlement_admission.v1",
    settlementRef: "l1://settlement/retired",
    domainRef: "domain://retired",
    stateRootRef: "state-root://retired",
    triggerRefs: ["l1-trigger://retired"],
    receiptRefs: ["receipt://retired"],
  };

  assert.throws(
    () =>
      createRuntimeL1SettlementControlRequest({
        threadId: "thread-ide",
        attempt: aliasOnlyAttempt as any,
      }),
    /settlement_ref/,
  );

  assert.throws(
    () =>
      createRuntimeL1SettlementControlRequest({
        input: {
          thread_id: "thread-ide",
          settlementAttempt: settlementAttempt(),
        },
      }),
    /settlement_ref/,
  );
});

test("L1 settlement controls read canonical raw input fields", () => {
  const request = createRuntimeL1SettlementControlRequest({
    input: {
      thread_id: "thread-canonical-input",
      settlement_attempt: settlementAttempt(),
    },
  });

  assert.equal(request.threadId, "thread-canonical-input");
  assert.equal(request.body.settlement_ref, "l1://settlement/marketplace-payment");
  assert.deepEqual(request.body.trigger_refs, ["l1-trigger://service-contract/payment"]);
  assert.deepEqual(request.body.receipt_refs, ["receipt://local-settlement/payment"]);
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
