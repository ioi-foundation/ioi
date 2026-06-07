import assert from "node:assert/strict";
import test from "node:test";

import {
  codingToolContracts,
  codingToolStepModuleProjection,
} from "./coding-tools.mjs";
import {
  STEP_MODULE_INVOCATION_SCHEMA_VERSION,
  STEP_MODULE_RESULT_SCHEMA_VERSION,
  createModelMountStepModuleProjection,
  createStepModuleInvocationForCodingTool,
  validateStepModuleInvocationShape,
  validateStepModuleResultShape,
} from "./step-module-abi.mjs";

test("every coding tool contract can project into the Step/Module ABI", () => {
  for (const contract of codingToolContracts()) {
    assert.equal(Object.hasOwn(contract, "stableToolId"), false);
    assert.equal(Object.hasOwn(contract, "primitiveCapabilities"), false);
    assert.equal(Object.hasOwn(contract, "authorityScopeRequirements"), false);
    const { invocation, result } = codingToolStepModuleProjection(
      contract.stable_tool_id,
      {},
      {},
      {
        run_id: "run:test",
        task_id: "task:test",
        thread_id: "thread:test",
        workflow_graph_id: "workflow:test",
        workflow_node_id: `node:test:${contract.stable_tool_id}`,
        state_root_before: "sha256:before",
        projection_watermark: "domain_seq:1",
      },
    );

    assert.equal(invocation.schema_version, STEP_MODULE_INVOCATION_SCHEMA_VERSION);
    assert.equal(result.schema_version, STEP_MODULE_RESULT_SCHEMA_VERSION);
    assert.equal(invocation.module_ref.kind, "workload_job");
    assert.equal(invocation.module_ref.id, contract.stable_tool_id);
    assert.equal(invocation.execution.backend, "workload_grpc");
    assert.deepEqual(
      invocation.authority.primitive_capabilities,
      contract.primitive_capabilities,
    );
    assert.deepEqual(
      invocation.authority.authority_scopes,
      contract.authority_scope_requirements,
    );
    assert.equal(result.invocation_id, invocation.invocation_id);
    assert.equal(result.workflow_projection.workflow_node_id, invocation.workflow_node_id);
    assert.equal(result.workflow_projection.status, "projected");
    assert.ok(result.receipt_refs.length > 0);
    assert.doesNotThrow(() => validateStepModuleInvocationShape(invocation));
    assert.doesNotThrow(() => validateStepModuleResultShape(result));
  }
});

test("cTEE private workspace projection refuses node plaintext custody", () => {
  const contract = codingToolContracts()[0];
  const invocation = createStepModuleInvocationForCodingTool({
    contract,
    toolId: contract.stable_tool_id,
  });
  invocation.module_ref.kind = "private_workspace_ctee_action";
  invocation.execution.backend = "ctee_operator";
  invocation.custody.privacy_profile = "private_workspace_ctee";
  invocation.custody.plaintext_policy.node_plaintext_allowed = true;

  assert.throws(
    () => validateStepModuleInvocationShape(invocation),
    /cannot allow node plaintext custody/,
  );
});

test("coding tool StepModule projection ignores retired camelCase context aliases", () => {
  const contract = codingToolContracts()[0];
  const { invocation, result } = codingToolStepModuleProjection(
    contract.stable_tool_id,
    {},
    {},
    {
      run_id: "run:canonical",
      task_id: "task:canonical",
      thread_id: "thread:canonical",
      workflow_graph_id: "workflow:canonical",
      workflow_node_id: "node:canonical",
      context_chamber_ref: "context://canonical",
      action_proposal_ref: "proposal://canonical",
      gate_result_ref: "gate://canonical",
      actor_id: "actor:canonical",
      runtime_node_ref: "runtime://canonical",
      policy_hash: "sha256:policy-canonical",
      authority_grant_refs: ["grant://canonical"],
      approval_ref: "approval://canonical",
      state_root_before: "sha256:before-canonical",
      projection_watermark: "domain_seq:canonical",
      idempotency_key: "idem:canonical",
      deadline_ms: 1234,
      workflow_projection_status: "projected",
      execution_result_ref: "result://canonical",
      normalized_observation_ref: "observation://canonical",
      receipt_refs: ["receipt://canonical"],
      artifact_refs: ["artifact://canonical"],
      payload_refs: ["payload://canonical"],
      agentgres_operation_refs: ["agentgres://canonical"],
      state_root_after: "sha256:after-canonical",
      resulting_head: "head:canonical",
      evidence_refs: ["evidence://canonical"],
      model_reentry_required: true,
      verifier_required: true,
      runId: "run:retired",
      taskId: "task:retired",
      threadId: "thread:retired",
      workflowGraphId: "workflow:retired",
      workflowNodeId: "node:retired",
      contextChamberRef: "context://retired",
      actionProposalRef: "proposal://retired",
      gateResultRef: "gate://retired",
      actorId: "actor:retired",
      runtimeNodeRef: "runtime://retired",
      policyHash: "sha256:policy-retired",
      authorityGrantRefs: ["grant://retired"],
      approvalRef: "approval://retired",
      stateRootBefore: "sha256:before-retired",
      projectionWatermark: "domain_seq:retired",
      idempotencyKey: "idem:retired",
      deadlineMs: 9999,
      workflowProjectionStatus: "failed",
      executionResultRef: "result://retired",
      normalizedObservationRef: "observation://retired",
      receiptRefs: ["receipt://retired"],
      artifactRefs: ["artifact://retired"],
      payloadRefs: ["payload://retired"],
      agentgresOperationRefs: ["agentgres://retired"],
      stateRootAfter: "sha256:after-retired",
      resultingHead: "head:retired",
      evidenceRefs: ["evidence://retired"],
      modelReentryRequired: false,
      verifierRequired: false,
    },
  );

  assert.equal(invocation.run_id, "run:canonical");
  assert.equal(invocation.task_id, "task:canonical");
  assert.equal(invocation.thread_id, "thread:canonical");
  assert.equal(invocation.workflow_graph_id, "workflow:canonical");
  assert.equal(invocation.workflow_node_id, "node:canonical");
  assert.equal(invocation.context_chamber_ref, "context://canonical");
  assert.equal(invocation.action_proposal_ref, "proposal://canonical");
  assert.equal(invocation.gate_result_ref, "gate://canonical");
  assert.equal(invocation.actor.actor_id, "actor:canonical");
  assert.equal(invocation.actor.runtime_node_ref, "runtime://canonical");
  assert.equal(invocation.authority.policy_hash, "sha256:policy-canonical");
  assert.deepEqual(invocation.authority.authority_grant_refs, ["grant://canonical"]);
  assert.equal(invocation.authority.approval_ref, "approval://canonical");
  assert.equal(invocation.input.state_root_before, "sha256:before-canonical");
  assert.equal(invocation.input.projection_watermark, "domain_seq:canonical");
  assert.equal(invocation.execution.idempotency_key, "idem:canonical");
  assert.equal(invocation.execution.deadline_ms, 1234);
  assert.equal(result.workflow_projection.status, "projected");
  assert.equal(result.execution_result_ref, "result://canonical");
  assert.equal(result.normalized_observation_ref, "observation://canonical");
  assert.deepEqual(result.receipt_refs, ["receipt://canonical"]);
  assert.deepEqual(result.artifact_refs, ["artifact://canonical"]);
  assert.deepEqual(result.payload_refs, ["payload://canonical"]);
  assert.deepEqual(result.agentgres_operation_refs, ["agentgres://canonical"]);
  assert.equal(result.state_root_after, "sha256:after-canonical");
  assert.equal(result.resulting_head, "head:canonical");
  assert.deepEqual(result.workflow_projection.evidence_refs, ["evidence://canonical"]);
  assert.equal(result.next.model_reentry_required, true);
  assert.equal(result.next.verifier_required, true);
});

test("StepModule ABI rejects retired daemon_js execution backend", () => {
  const contract = codingToolContracts()[0];
  const invocation = createStepModuleInvocationForCodingTool({
    contract,
    toolId: contract.stable_tool_id,
  });
  invocation.module_ref.kind = "daemon_native_tool";
  invocation.execution.backend = "daemon_js";

  assert.throws(
    () => validateStepModuleInvocationShape(invocation),
    /execution backend daemon_js is not allowed for module kind daemon_native_tool/,
  );
});

test("model mount receipts project into the Step/Module ABI", () => {
  const { invocation, result } = createModelMountStepModuleProjection({
    invocationRef: "model-invocation://receipt.1.model_invocation",
    routeRef: "route.local-first",
    providerRef: "provider.local",
    endpointRef: "endpoint.local",
    modelRef: "model.local",
    capability: "responses",
    invocationKind: "responses",
    inputHash: "sha256:input",
    outputHash: "sha256:output",
    policyHash: "sha256:policy",
    routeDecisionRef: "model_mount://route_decision/test",
    routeReceiptRef: "receipt://receipt.route",
    receiptRef: "receipt://receipt.1.model_invocation",
    authorityGrantRefs: ["grant://wallet/model-chat"],
    workflowGraphId: "workflow.graph",
    workflowNodeId: "workflow.node",
    privacyProfile: "local_private",
  });

  assert.equal(invocation.schema_version, STEP_MODULE_INVOCATION_SCHEMA_VERSION);
  assert.equal(invocation.module_ref.kind, "model_mount");
  assert.equal(invocation.execution.backend, "model_mount");
  assert.equal(invocation.custody.privacy_profile, "internal");
  assert.deepEqual(invocation.authority.authority_grant_refs, ["grant://wallet/model-chat"]);
  assert.ok(invocation.input.context_refs.includes("model_mount://route_decision/test"));
  assert.equal(result.schema_version, STEP_MODULE_RESULT_SCHEMA_VERSION);
  assert.equal(result.invocation_id, invocation.invocation_id);
  assert.equal(result.workflow_projection.component_kind, "ModelInvocationNode");
  assert.equal(result.workflow_projection.status, "live");
  assert.deepEqual(result.receipt_refs, ["receipt://receipt.1.model_invocation"]);
  assert.doesNotThrow(() => validateStepModuleInvocationShape(invocation));
  assert.doesNotThrow(() => validateStepModuleResultShape(result));
});

test("model mount StepModule projection refuses cTEE plaintext custody", () => {
  assert.throws(
    () =>
      createModelMountStepModuleProjection({
        invocationRef: "model-invocation://receipt.private",
        routeRef: "route.private",
        providerRef: "provider.private",
        endpointRef: "endpoint.private",
        modelRef: "model.private",
        inputHash: "sha256:input",
        outputHash: "sha256:output",
        receiptRef: "receipt://receipt.private",
        privacyProfile: "private_workspace_ctee",
        nodePlaintextAllowed: true,
      }),
    /cannot allow node plaintext custody/,
  );
});

test("Agentgres operation refs require result state-root binding", () => {
  const contract = codingToolContracts()[0];
  assert.throws(
    () =>
      codingToolStepModuleProjection(contract.stable_tool_id, {}, {}, {
        agentgres_operation_refs: ["agentgres://operation/test"],
      }),
    /state_root_after and resulting_head/,
  );
});
