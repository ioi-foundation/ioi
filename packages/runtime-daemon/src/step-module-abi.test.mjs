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
    const { invocation, result } = codingToolStepModuleProjection(
      contract.stableToolId,
      {},
      {},
      {
        runId: "run:test",
        taskId: "task:test",
        threadId: "thread:test",
        workflowGraphId: "workflow:test",
        workflowNodeId: `node:test:${contract.stableToolId}`,
        stateRootBefore: "sha256:before",
        projectionWatermark: "domain_seq:1",
      },
    );

    assert.equal(invocation.schema_version, STEP_MODULE_INVOCATION_SCHEMA_VERSION);
    assert.equal(result.schema_version, STEP_MODULE_RESULT_SCHEMA_VERSION);
    assert.equal(invocation.module_ref.kind, "daemon_native_tool");
    assert.equal(invocation.module_ref.id, contract.stableToolId);
    assert.equal(invocation.execution.backend, "daemon_js");
    assert.deepEqual(
      invocation.authority.primitive_capabilities,
      contract.primitiveCapabilities,
    );
    assert.deepEqual(
      invocation.authority.authority_scopes,
      contract.authorityScopeRequirements,
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
    toolId: contract.stableToolId,
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
      codingToolStepModuleProjection(contract.stableToolId, {}, {}, {
        agentgresOperationRefs: ["agentgres://operation/test"],
      }),
    /state_root_after and resulting_head/,
  );
});
