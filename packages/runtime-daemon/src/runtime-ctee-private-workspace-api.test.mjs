import assert from "node:assert/strict";
import test from "node:test";

import {
  createRuntimeCteePrivateWorkspaceSurface,
} from "./runtime-ctee-private-workspace-surface.mjs";

const CTEE_PRIVATE_WORKSPACE_ADMISSION_RESPONSE_SCHEMA_VERSION =
  "ioi.runtime.ctee_private_workspace_admission.v1";

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
    cteePrivateWorkspaceCore: {
      executeAction(input, context) {
        calls.push({ name: "executeAction", input, context });
        return {
          schema_version: CTEE_PRIVATE_WORKSPACE_ADMISSION_RESPONSE_SCHEMA_VERSION,
          object: "ioi.runtime_ctee_private_workspace_admission",
          status: "admitted",
          action_executed: true,
          source: "rust_ctee_private_workspace_protocol",
          backend: "ctee_operator",
          thread_id: context.thread_id,
          agent_id: context.agent_id,
          invocation_id: "invocation://ctee/surface",
          receipt_ref: "receipt://ctee/private-workspace/surface",
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

const CTEE_PRIVATE_WORKSPACE_ADMISSION_CAMEL_ALIASES = [
  "schemaVersion",
  "actionExecuted",
  "threadId",
  "agentId",
  "invocationId",
  "receiptRef",
  "receiptBinding",
  "acceptedReceiptAppend",
  "agentgresAdmission",
  "projectionRecord",
  "receiptRefs",
  "evidenceRefs",
];

test("cTEE private workspace surface executes nested action through Rust core", () => {
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
  assert.deepEqual(runtimeStore.calls.at(-1).context, {
    thread_id: "thread_surface",
    agent_id: "agent_surface",
  });
});

test("cTEE private workspace surface rejects retired request aliases before agent lookup or Rust core", () => {
  const runtimeStore = store();
  const surface = createRuntimeCteePrivateWorkspaceSurface();

  assert.throws(
    () =>
      surface.executeCteePrivateWorkspaceAction(runtimeStore, "thread_surface", {
        ctee_action: cteeAction(),
        cteeAction: cteeAction(),
      }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "ctee_private_workspace_action_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, ["cteeAction", "ctee_action"]);
      assert.deepEqual(error.details.canonical_fields, ["action"]);
      return true;
    },
  );
  assert.deepEqual(runtimeStore.calls, []);
});

test("cTEE private workspace surface rejects client supplied Agentgres truth before Rust core", () => {
  const runtimeStore = store();
  const surface = createRuntimeCteePrivateWorkspaceSurface();

  assert.throws(
    () =>
      surface.executeCteePrivateWorkspaceAction(runtimeStore, "thread_surface", {
        action: {
          ...cteeAction(),
          expected_heads: ["agentgres://ctee/private-workspace/head/client"],
          expectedHeads: ["agentgres://ctee/private-workspace/head/client"],
        },
      }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "ctee_private_workspace_agentgres_truth_fields_retired");
      assert.deepEqual(error.details.retired_fields, ["expected_heads", "expectedHeads"]);
      return true;
    },
  );
  assert.deepEqual(runtimeStore.calls, []);
});

test("cTEE private workspace surface ignores retired nested invocation identity alias", () => {
  const runtimeStore = store();
  runtimeStore.cteePrivateWorkspaceCore.executeAction = (input) => {
    runtimeStore.calls.push({ name: "executeAction", input });
    return {
      schema_version: CTEE_PRIVATE_WORKSPACE_ADMISSION_RESPONSE_SCHEMA_VERSION,
      object: "ioi.runtime_ctee_private_workspace_admission",
      status: "admitted",
      action_executed: true,
      invocation_id: undefined,
      receipt_ref: null,
      record: {
        result: {
          status: "success",
          receipt_refs: [],
        },
      },
      result: {
        status: "success",
        receipt_refs: [],
      },
      receipt_refs: [],
      evidence_refs: [],
    };
  };
  const surface = createRuntimeCteePrivateWorkspaceSurface();
  const action = cteeAction();
  action.invocation = {
    ...action.invocation,
    invocation_id: undefined,
    invocationId: "invocation://ctee/retired",
  };

  const result = surface.executeCteePrivateWorkspaceAction(runtimeStore, "thread_surface", {
    action,
  });

  assert.equal(result.invocation_id, undefined);
  assert.equal(runtimeStore.calls.at(-1).input.invocation.invocationId, "invocation://ctee/retired");
});

test("cTEE private workspace surface exposes only canonical snake_case admission fields", () => {
  const result = createRuntimeCteePrivateWorkspaceSurface().executeCteePrivateWorkspaceAction(
    store(),
    "thread_surface",
    { action: cteeAction() },
  );

  for (const key of CTEE_PRIVATE_WORKSPACE_ADMISSION_CAMEL_ALIASES) {
    assert.equal(Object.hasOwn(result, key), false, `${key} must not be emitted`);
  }
});

test("cTEE private workspace surface fails closed without action payload", () => {
  const surface = createRuntimeCteePrivateWorkspaceSurface();

  assert.throws(
    () => surface.executeCteePrivateWorkspaceAction(store(), "thread_surface", {}),
    (error) => error.code === "ctee_private_workspace_action_required",
  );
});
