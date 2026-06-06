import assert from "node:assert/strict";
import test from "node:test";

import {
  CTEE_PRIVATE_WORKSPACE_COMMAND_ENV,
  RustCteePrivateWorkspaceRunner,
  createCteePrivateWorkspaceRunnerFromEnv,
} from "./runtime-ctee-private-workspace-runner.mjs";

function cteeRequest() {
  return {
    invocation: {
      schema_version: "ioi.step_module_invocation.v1",
      invocation_id: "invocation://ctee/daemon-runner",
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
        idempotency_key: "idem:ctee.daemon-runner",
        deadline_ms: 300000,
        resource_lease_ref: "lease://ctee",
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

test("cTEE private workspace runner sends execution bridge request", () => {
  const calls = [];
  const runner = new RustCteePrivateWorkspaceRunner({
    command: "mock-ctee-bridge",
    args: ["--ctee"],
    spawnSyncImpl(command, args, options) {
      const bridgeRequest = JSON.parse(options.input);
      calls.push({ command, args, bridgeRequest });
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_ctee_private_workspace_command",
            backend: "ctee_operator",
            record: {
              receipt: {
                receipt_ref: "receipt://ctee/private-workspace/daemon-runner",
                custody_proof_ref: "artifact://custody-proof",
              },
              result: {
                status: "success",
                receipt_refs: ["receipt://ctee/private-workspace/daemon-runner"],
              },
              receipt_binding: {
                binding_hash: "sha256:ctee-binding",
              },
              agentgres_admission: {
                operation_ref: "agentgres://ctee/private-workspace/operations/daemon-runner",
              },
              projection: {
                evidence_refs: ["receipt://ctee/private-workspace/daemon-runner"],
              },
            },
            receipt: {
              receipt_ref: "receipt://ctee/private-workspace/daemon-runner",
              custody_proof_ref: "artifact://custody-proof",
            },
            result: {
              status: "success",
              receipt_refs: ["receipt://ctee/private-workspace/daemon-runner"],
            },
            receipt_binding: {
              binding_hash: "sha256:ctee-binding",
            },
            accepted_receipt_append: {
              issuer: "rust_receipt_core",
            },
            agentgres_admission: {
              operation_ref: "agentgres://ctee/private-workspace/operations/daemon-runner",
            },
            projection_record: {
              evidence_refs: ["receipt://ctee/private-workspace/daemon-runner"],
            },
            receipt_refs: ["receipt://ctee/private-workspace/daemon-runner"],
            evidence_refs: ["receipt://ctee/private-workspace/daemon-runner"],
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.executeAction(cteeRequest());

  assert.equal(calls[0].command, "mock-ctee-bridge");
  assert.deepEqual(calls[0].args, ["--ctee"]);
  assert.equal(calls[0].bridgeRequest.operation, "execute_private_workspace_ctee_action");
  assert.equal(calls[0].bridgeRequest.backend, "ctee_operator");
  assert.equal(calls[0].bridgeRequest.invocation.invocation_id, "invocation://ctee/daemon-runner");
  assert.equal(calls[0].bridgeRequest.node_trust.trusted_for_plaintext, false);
  assert.deepEqual(calls[0].bridgeRequest.expected_heads, [
    "agentgres://ctee/private-workspace/head/before",
  ]);
  assert.equal(result.source, "rust_ctee_private_workspace_command");
  assert.equal(result.receipt.custody_proof_ref, "artifact://custody-proof");
  assert.equal(result.receipt_binding.binding_hash, "sha256:ctee-binding");
  assert.equal(result.accepted_receipt_append.issuer, "rust_receipt_core");
  assert.deepEqual(result.receipt_refs, ["receipt://ctee/private-workspace/daemon-runner"]);
});

test("cTEE private workspace runner can be configured from env", () => {
  const runner = createCteePrivateWorkspaceRunnerFromEnv({
    [CTEE_PRIVATE_WORKSPACE_COMMAND_ENV]: "mock-ctee-bridge",
  });

  assert.equal(runner.command, "mock-ctee-bridge");
});

test("cTEE private workspace runner rejects retired bridge request aliases before command invocation", () => {
  const calls = [];
  const runner = new RustCteePrivateWorkspaceRunner({
    command: "mock-ctee-bridge",
    spawnSyncImpl() {
      calls.push("spawned");
      return { status: 0, stdout: "{}", stderr: "" };
    },
  });
  const request = cteeRequest();

  assert.throws(
    () =>
      runner.executeAction({
        ...request,
        nodeTrust: request.node_trust,
        expectedHeads: request.expected_heads,
      }),
    (error) =>
      error.code === "ctee_private_workspace_runner_request_aliases_retired" &&
      error.details.status === 400 &&
      error.details.retired_aliases.includes("nodeTrust") &&
      error.details.retired_aliases.includes("expectedHeads") &&
      Object.hasOwn(error.details, "nodeTrust") === false &&
      Object.hasOwn(error.details, "expectedHeads") === false,
  );
  assert.deepEqual(calls, []);
});

test("cTEE private workspace runner fails closed without command", () => {
  const runner = createCteePrivateWorkspaceRunnerFromEnv({});

  assert.throws(
    () => runner.executeAction(cteeRequest()),
    (error) => error.code === "ctee_private_workspace_bridge_unconfigured",
  );
});

test("cTEE private workspace runner surfaces Rust execution rejection", () => {
  const runner = new RustCteePrivateWorkspaceRunner({
    command: "mock-ctee-bridge",
    spawnSyncImpl() {
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: false,
          error: {
            code: "ctee_execution_invalid",
            message: "untrusted node plaintext mount fails",
          },
        }),
        stderr: "",
      };
    },
  });

  assert.throws(
    () => runner.executeAction(cteeRequest()),
    (error) =>
      error.code === "ctee_execution_invalid" &&
      /untrusted node plaintext mount fails/.test(error.message),
  );
});
