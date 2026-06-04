import assert from "node:assert/strict";
import test from "node:test";

import {
  codingToolContracts,
  codingToolStepModuleProjection,
} from "./coding-tools.mjs";
import {
  STEP_MODULE_INVOCATION_SCHEMA_VERSION,
  STEP_MODULE_RESULT_SCHEMA_VERSION,
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
