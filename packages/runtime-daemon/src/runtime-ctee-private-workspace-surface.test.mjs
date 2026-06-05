import assert from "node:assert/strict";
import test from "node:test";

import {
  CTEE_PRIVATE_WORKSPACE_ADMISSION_RESPONSE_SCHEMA_VERSION,
  createRuntimeCteePrivateWorkspaceSurface,
} from "./runtime-ctee-private-workspace-surface.mjs";

function cteeAction() {
  return {
    invocation: {
      schema_version: "ioi.step_module_invocation.v1",
      invocation_id: "invocation://ctee/surface",
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
    expected_heads: ["agentgres://ctee/private-workspace/head/before"],
  };
}

function store() {
  const calls = [];
  return {
    calls,
    agentForThread(threadId) {
      calls.push({ name: "agentForThread", threadId });
      return { id: "agent_surface" };
    },
    cteePrivateWorkspaceRunner: {
      executeAction(input) {
        calls.push({ name: "executeAction", input });
        return {
          source: "rust_ctee_private_workspace_command",
          backend: "ctee_operator",
          record: {
            receipt: {
              receipt_ref: "receipt://ctee/private-workspace/surface",
              custody_proof_ref: "artifact://custody-proof",
            },
            result: {
              invocation_id: "invocation://ctee/surface",
              status: "success",
              receipt_refs: ["receipt://ctee/private-workspace/surface"],
            },
            receipt_binding: {
              binding_hash: "sha256:ctee-binding",
            },
            agentgres_admission: {
              operation_ref: "agentgres://ctee/private-workspace/operations/surface",
            },
            projection: {
              projection_ref: "projection://ctee/private-workspace/surface",
              evidence_refs: ["receipt://ctee/private-workspace/surface"],
            },
          },
          receipt: {
            receipt_ref: "receipt://ctee/private-workspace/surface",
            custody_proof_ref: "artifact://custody-proof",
          },
          result: {
            invocation_id: "invocation://ctee/surface",
            status: "success",
            receipt_refs: ["receipt://ctee/private-workspace/surface"],
          },
          receipt_binding: {
            binding_hash: "sha256:ctee-binding",
          },
          accepted_receipt_append: {
            issuer: "rust_receipt_core",
          },
          agentgres_admission: {
            operation_ref: "agentgres://ctee/private-workspace/operations/surface",
          },
          projection_record: {
            projection_ref: "projection://ctee/private-workspace/surface",
            evidence_refs: ["receipt://ctee/private-workspace/surface"],
          },
          receipt_refs: ["receipt://ctee/private-workspace/surface"],
          evidence_refs: ["receipt://ctee/private-workspace/surface"],
        };
      },
    },
  };
}

test("cTEE private workspace surface executes nested action through Rust runner", () => {
  const runtimeStore = store();
  const surface = createRuntimeCteePrivateWorkspaceSurface();

  const result = surface.executeCteePrivateWorkspaceAction(runtimeStore, "thread_surface", {
    action: cteeAction(),
  });

  assert.equal(result.schema_version, CTEE_PRIVATE_WORKSPACE_ADMISSION_RESPONSE_SCHEMA_VERSION);
  assert.equal(result.status, "admitted");
  assert.equal(result.action_executed, true);
  assert.equal(result.thread_id, "thread_surface");
  assert.equal(result.agent_id, "agent_surface");
  assert.equal(result.invocation_id, "invocation://ctee/surface");
  assert.equal(result.receipt_ref, "receipt://ctee/private-workspace/surface");
  assert.equal(result.receipt.custody_proof_ref, "artifact://custody-proof");
  assert.equal(result.receipt_binding.binding_hash, "sha256:ctee-binding");
  assert.equal(result.accepted_receipt_append.issuer, "rust_receipt_core");
  assert.equal(
    result.agentgres_admission.operation_ref,
    "agentgres://ctee/private-workspace/operations/surface",
  );
  assert.equal(result.projection_record.projection_ref, "projection://ctee/private-workspace/surface");
  assert.deepEqual(result.receipt_refs, ["receipt://ctee/private-workspace/surface"]);
  assert.deepEqual(result.evidence_refs, ["receipt://ctee/private-workspace/surface"]);
  assert.deepEqual(runtimeStore.calls.map((call) => call.name), ["agentForThread", "executeAction"]);
});

test("cTEE private workspace surface fails closed without action payload", () => {
  const surface = createRuntimeCteePrivateWorkspaceSurface();

  assert.throws(
    () => surface.executeCteePrivateWorkspaceAction(store(), "thread_surface", {}),
    (error) => error.code === "ctee_private_workspace_action_required",
  );
});
