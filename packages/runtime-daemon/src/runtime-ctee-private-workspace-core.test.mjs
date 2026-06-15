import assert from "node:assert/strict";
import test from "node:test";

import {
  RUNTIME_CTEE_PRIVATE_WORKSPACE_BACKEND,
  RuntimeCteePrivateWorkspaceCore,
  RuntimeCteePrivateWorkspaceCoreError,
  createRuntimeCteePrivateWorkspaceCore,
} from "./runtime-ctee-private-workspace-core.mjs";

function cteeRequest() {
  return {
    invocation: {
      schema_version: "ioi.step_module_invocation.v1",
      invocation_id: "invocation://ctee/daemon-core",
      run_id: "run:ctee",
      task_id: "task:ctee",
      thread_id: "thread:ctee",
      workflow_graph_id: "workflow.ctee",
      workflow_node_id: "node.ctee.private-workspace",
      action_proposal_ref: "action:ctee:private-workspace",
      gate_result_ref: "gate:ctee:private-workspace",
      module_ref: {
        kind: "private_workspace_ctee_action",
        id: "private_workspace.mount",
        version: "1",
        manifest_ref: "module://ctee/private-workspace@1",
      },
      actor: {
        actor_id: "runtime:hypervisor-daemon",
        runtime_node_ref: "node://private-workspace",
      },
      authority: {
        authority_grant_refs: ["grant://ctee/private-workspace"],
        policy_hash: "sha256:ctee-policy",
        primitive_capabilities: ["prim:private_workspace.mount"],
        authority_scopes: ["scope:ctee.private_workspace"],
        approval_ref: "approval://declassify",
      },
      input: {
        input_hash: "sha256:ctee-input",
        state_root_before: "sha256:ctee-before",
        projection_watermark: "agentgres:ctee:0",
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
        idempotency_key: "idem:ctee.daemon-core",
        deadline_ms: 300000,
        resource_lease_ref: "lease://ctee",
      },
    },
    node_trust: {
      runtime_node_ref: "node://rented-untrusted",
      trusted_for_plaintext: false,
      attestation_ref: null,
    },
  };
}

function admittedResult(request, context) {
  return {
    schema_version: "ioi.runtime.ctee_private_workspace_admission.v1",
    object: "ioi.runtime_ctee_private_workspace_admission",
    status: "admitted",
    action_executed: true,
    source: "rust_ctee_private_workspace_protocol",
    backend: RUNTIME_CTEE_PRIVATE_WORKSPACE_BACKEND,
    thread_id: context.thread_id,
    agent_id: context.agent_id,
    invocation_id: request.invocation.invocation_id,
    receipt_ref: "receipt://ctee/private-workspace/daemon-core",
    record: {
      receipt: {
        receipt_ref: "receipt://ctee/private-workspace/daemon-core",
        custody_proof_ref: "artifact://custody-proof",
      },
      result: {
        status: "success",
        receipt_refs: ["receipt://ctee/private-workspace/daemon-core"],
      },
      receipt_binding: {
        binding_hash: "sha256:ctee-binding",
      },
      agentgres_admission: {
        operation_ref: "agentgres://ctee/private-workspace/operations/daemon-core",
      },
      projection: {
        evidence_refs: ["receipt://ctee/private-workspace/daemon-core"],
      },
    },
    receipt: {
      receipt_ref: "receipt://ctee/private-workspace/daemon-core",
      custody_proof_ref: "artifact://custody-proof",
    },
    result: {
      status: "success",
      receipt_refs: ["receipt://ctee/private-workspace/daemon-core"],
    },
    receipt_binding: {
      binding_hash: "sha256:ctee-binding",
    },
    accepted_receipt_append: {
      issuer: "rust_receipt_core",
    },
    agentgres_admission: {
      operation_ref: "agentgres://ctee/private-workspace/operations/daemon-core",
    },
    projection_record: {
      evidence_refs: ["receipt://ctee/private-workspace/daemon-core"],
    },
    receipt_refs: ["receipt://ctee/private-workspace/daemon-core"],
    evidence_refs: ["receipt://ctee/private-workspace/daemon-core"],
  };
}

test("cTEE private workspace core calls typed Rust daemon-core custody API", () => {
  const calls = [];
  const core = createRuntimeCteePrivateWorkspaceCore({
    daemonCoreCteeApi: {
      executePrivateWorkspaceCteeAction(request, context) {
        calls.push({ request, context });
        return admittedResult(request, context);
      },
    },
  });

  const result = core.executeAction(cteeRequest(), {
    thread_id: "thread:ctee-core",
    agent_id: "agent:ctee-core",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.invocation.invocation_id, "invocation://ctee/daemon-core");
  assert.equal(calls[0].request.node_trust.trusted_for_plaintext, false);
  assert.equal(Object.hasOwn(calls[0].request, "expected_heads"), false);
  assert.deepEqual(calls[0].context, {
    thread_id: "thread:ctee-core",
    agent_id: "agent:ctee-core",
  });
  assert.equal(Object.hasOwn(calls[0], "operation"), false);
  assert.equal(Object.hasOwn(calls[0], "schema_version"), false);
  assert.equal(result.schema_version, "ioi.runtime.ctee_private_workspace_admission.v1");
  assert.equal(result.object, "ioi.runtime_ctee_private_workspace_admission");
  assert.equal(result.status, "admitted");
  assert.equal(result.action_executed, true);
  assert.equal(result.thread_id, "thread:ctee-core");
  assert.equal(result.agent_id, "agent:ctee-core");
  assert.equal(result.invocation_id, "invocation://ctee/daemon-core");
  assert.equal(result.receipt_ref, "receipt://ctee/private-workspace/daemon-core");
  assert.equal(result.source, "rust_ctee_private_workspace_protocol");
  assert.equal(result.backend, RUNTIME_CTEE_PRIVATE_WORKSPACE_BACKEND);
  assert.equal(result.receipt.custody_proof_ref, "artifact://custody-proof");
  assert.equal(result.receipt_binding.binding_hash, "sha256:ctee-binding");
  assert.equal(result.accepted_receipt_append.issuer, "rust_receipt_core");
  assert.deepEqual(result.receipt_refs, ["receipt://ctee/private-workspace/daemon-core"]);
});

test("cTEE private workspace core returns the Rust envelope without JS normalization", () => {
  const rustEnvelope = {
    schema_version: "ioi.runtime.ctee_private_workspace_admission.v1",
    record: {
      result: {},
      projection: {},
    },
  };
  const core = createRuntimeCteePrivateWorkspaceCore({
    daemonCoreCteeApi: {
      executePrivateWorkspaceCteeAction() {
        return rustEnvelope;
      },
    },
  });

  const result = core.executeAction(cteeRequest());

  assert.equal(result, rustEnvelope);
  assert.equal(Object.hasOwn(result, "receipt_refs"), false);
  assert.equal(Object.hasOwn(result, "evidence_refs"), false);
  assert.equal(Object.hasOwn(result, "source"), false);
  assert.equal(Object.hasOwn(result, "backend"), false);
});

test("cTEE private workspace core rejects retired compatibility options", () => {
  assert.throws(
    () => new RuntimeCteePrivateWorkspaceCore({ command: "ioi-runtime-daemon-core" }),
    (error) =>
      error instanceof RuntimeCteePrivateWorkspaceCoreError &&
      error.code === "ctee_private_workspace_core_compatibility_option_retired",
  );
  assert.throws(
    () => new RuntimeCteePrivateWorkspaceCore({ args: ["--ctee"] }),
    (error) =>
      error instanceof RuntimeCteePrivateWorkspaceCoreError &&
      error.code === "ctee_private_workspace_core_compatibility_option_retired",
  );
  assert.throws(
    () => new RuntimeCteePrivateWorkspaceCore({ daemonCoreInvoker() {} }),
    (error) =>
      error instanceof RuntimeCteePrivateWorkspaceCoreError &&
      error.code === "ctee_private_workspace_core_compatibility_option_retired" &&
      error.details.retired_option === "daemonCoreInvoker",
  );
  assert.throws(
    () =>
      new RuntimeCteePrivateWorkspaceCore({
        daemonCoreApi: {
          executePrivateWorkspaceCteeAction() {},
        },
      }),
    (error) =>
      error instanceof RuntimeCteePrivateWorkspaceCoreError &&
      error.code === "ctee_private_workspace_core_compatibility_option_retired" &&
      error.details.retired_option === "daemonCoreApi",
  );
});

test("cTEE private workspace core rejects retired bridge request aliases before Rust invocation", () => {
  const calls = [];
  const core = createRuntimeCteePrivateWorkspaceCore({
    daemonCoreCteeApi: {
      executePrivateWorkspaceCteeAction() {
        calls.push("invoked");
        return {};
      },
    },
  });
  const request = cteeRequest();

  assert.throws(
    () =>
      core.executeAction({
        ...request,
        nodeTrust: request.node_trust,
        expectedHeads: ["agentgres://ctee/private-workspace/head/client"],
        expected_heads: ["agentgres://ctee/private-workspace/head/client"],
      }),
    (error) =>
      error.code === "ctee_private_workspace_core_request_aliases_retired" &&
      error.details.status === 400 &&
      error.details.retired_aliases.includes("nodeTrust") &&
      error.details.retired_aliases.includes("expectedHeads") &&
      error.details.retired_aliases.includes("expected_heads") &&
      Object.hasOwn(error.details, "nodeTrust") === false &&
      Object.hasOwn(error.details, "expectedHeads") === false,
  );
  assert.deepEqual(calls, []);
});

test("cTEE private workspace core fails closed without typed daemon-core cTEE API", () => {
  const core = createRuntimeCteePrivateWorkspaceCore({});

  assert.throws(
    () => core.executeAction(cteeRequest()),
    (error) => error.code === "ctee_private_workspace_core_direct_ctee_api_unconfigured",
  );
});

test("cTEE private workspace core surfaces Rust execution rejection", () => {
  const core = createRuntimeCteePrivateWorkspaceCore({
    daemonCoreCteeApi: {
      executePrivateWorkspaceCteeAction() {
        return {
          ok: false,
          error: {
            code: "ctee_execution_invalid",
            message: "untrusted node plaintext mount fails",
          },
        };
      },
    },
  });

  assert.throws(
    () => core.executeAction(cteeRequest()),
    (error) =>
      error.code === "ctee_execution_invalid" &&
      /untrusted node plaintext mount fails/.test(error.message),
  );
});
