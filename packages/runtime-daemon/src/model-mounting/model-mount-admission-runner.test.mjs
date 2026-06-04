import assert from "node:assert/strict";
import test from "node:test";

import {
  MODEL_MOUNT_ADMISSION_COMMAND_ENV,
  MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
  ModelMountAdmissionRunnerError,
  createModelMountAdmissionRunnerFromEnv,
  RustModelMountAdmissionRunner,
} from "./model-mount-admission-runner.mjs";

function routeRequest() {
  return {
    schema_version: "ioi.model_mount.route_decision.v1",
    route_ref: "route.local-first",
    provider_ref: "provider.local",
    endpoint_ref: "endpoint.local",
    model_ref: "model.local",
    capability: "chat",
    policy_hash: "sha256:policy",
    idempotency_key: "model_route_decision:test",
    receipt_refs: ["receipt://route"],
    authority_grant_refs: [],
    authority_receipt_refs: [],
    privacy_profile: "local_private",
    node_plaintext_allowed: false,
  };
}

function invocationRequest() {
  return {
    schema_version: "ioi.model_mount.invocation_admission.v1",
    invocation_ref: "model-invocation://response/test",
    route_decision_ref: "model_mount://route_decision/test",
    route_receipt_ref: "receipt://route",
    invocation_receipt_ref: "receipt://invocation",
    route_ref: "route.local-first",
    provider_ref: "provider.local",
    endpoint_ref: "endpoint.local",
    model_ref: "model.local",
    capability: "chat",
    invocation_kind: "responses",
    policy_hash: "sha256:policy",
    input_hash: "sha256:input",
    output_hash: "sha256:output",
    idempotency_key: "model_invocation:test",
    receipt_refs: ["receipt://route", "receipt://invocation"],
    authority_grant_refs: ["grant://wallet/model-chat"],
    authority_receipt_refs: [],
    provider_auth_evidence_refs: [],
    backend_evidence_refs: [],
    tool_receipt_refs: [],
    privacy_profile: "local_private",
    node_plaintext_allowed: false,
  };
}

function providerExecutionRequest() {
  return {
    schema_version: "ioi.model_mount.provider_execution.v1",
    invocation_ref: "model-provider-execution://response/test",
    route_decision_ref: "model_mount://route_decision/test",
    route_receipt_ref: "receipt://route",
    route_ref: "route.local-first",
    provider_ref: "provider.local",
    endpoint_ref: "endpoint.local",
    model_ref: "model.local",
    capability: "chat",
    invocation_kind: "responses",
    policy_hash: "sha256:policy",
    input_hash: "sha256:input",
    request_hash: "sha256:request",
    idempotency_key: "model_provider_execution:test",
    receipt_refs: ["receipt://route"],
    authority_grant_refs: ["grant://wallet/model-chat"],
    authority_receipt_refs: [],
    provider_auth_evidence_refs: [],
    backend_evidence_refs: [],
    tool_receipt_refs: [],
    privacy_profile: "local_private",
    node_plaintext_allowed: false,
  };
}

function providerInvocationRequest() {
  return {
    schema_version: "ioi.model_mount.provider_invocation.v1",
    provider_execution_ref: "model_mount://provider_execution/test",
    provider_execution_hash: "sha256:provider-execution-test",
    route_decision_ref: "model_mount://route_decision/test",
    route_receipt_ref: "receipt://route",
    route_ref: "route.local-first",
    provider_ref: "provider.local",
    provider_kind: "local_folder",
    endpoint_ref: "endpoint.local",
    model_ref: "model.local",
    capability: "chat",
    invocation_kind: "responses",
    input: "user: hello",
    request_hash: "sha256:request",
    execution_backend: "rust_model_mount_fixture",
    api_format: "ioi_fixture",
    driver: "fixture",
    backend_ref: "backend.fixture",
    receipt_refs: ["receipt://route"],
    evidence_refs: ["model_mount://provider_execution/test"],
    admitted_provider_execution: {
      ...providerExecutionRequest(),
      provider_execution_ref: "model_mount://provider_execution/test",
      provider_execution_hash: "sha256:provider-execution-test",
    },
  };
}

function providerResultRequest() {
  return {
    schema_version: "ioi.model_mount.provider_result.v1",
    provider_execution_ref: "model_mount://provider_execution/test",
    provider_execution_hash: "sha256:provider-execution-test",
    route_decision_ref: "model_mount://route_decision/test",
    route_receipt_ref: "receipt://route",
    route_ref: "route.local-first",
    provider_ref: "provider.openai",
    provider_kind: "openai",
    endpoint_ref: "endpoint.openai",
    model_ref: "model.openai",
    capability: "chat",
    invocation_kind: "responses",
    request_hash: "sha256:request",
    output_text: "hosted provider answer",
    output_hash: "sha256:output",
    token_count: { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3 },
    provider_response_kind: "openai.chat",
    execution_backend: "js_provider_driver_observation",
    backend_ref: "backend.openai-compatible",
    receipt_refs: ["receipt://route"],
    provider_auth_evidence_refs: ["provider.auth"],
    backend_evidence_refs: ["backend.openai-compatible"],
    evidence_refs: ["model_mount://provider_execution/test"],
    admitted_provider_execution: {
      ...providerExecutionRequest(),
      provider_execution_ref: "model_mount://provider_execution/test",
      provider_execution_hash: "sha256:provider-execution-test",
    },
  };
}

test("Rust model_mount admission runner sends route-decision bridge request", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    command: "mock-model-mount-bridge",
    spawnSyncImpl(command, args, options) {
      const request = JSON.parse(options.input);
      calls.push({ command, args, request });
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_model_mount_command",
            backend: "rust_model_mount_live",
            record: {
              ...request.request,
              route_decision_ref: "model_mount://route_decision/test",
              route_decision_hash: "sha256:test",
            },
            route_decision_ref: "model_mount://route_decision/test",
            route_decision_hash: "sha256:test",
            receipt_refs: request.request.receipt_refs,
            evidence_refs: ["rust_model_mount_core"],
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.admitRouteDecision(routeRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, "mock-model-mount-bridge");
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "admit_model_mount_route_decision");
  assert.equal(calls[0].request.backend, "rust_model_mount_live");
  assert.equal(calls[0].request.request.model_ref, "model.local");
  assert.equal(result.route_decision_ref, "model_mount://route_decision/test");
  assert.equal(result.record.route_decision_hash, "sha256:test");
});

test("Rust model_mount admission runner sends invocation bridge request", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    command: "mock-model-mount-bridge",
    spawnSyncImpl(command, args, options) {
      const request = JSON.parse(options.input);
      calls.push({ command, args, request });
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_model_mount_invocation_command",
            backend: "rust_model_mount_live",
            record: {
              ...request.request,
              invocation_admission_ref: "model_mount://invocation_admission/test",
              invocation_admission_hash: "sha256:invocation-test",
            },
            invocation_admission_ref: "model_mount://invocation_admission/test",
            invocation_admission_hash: "sha256:invocation-test",
            receipt_refs: request.request.receipt_refs,
            evidence_refs: ["rust_model_mount_core"],
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.admitInvocation(invocationRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "admit_model_mount_invocation");
  assert.equal(calls[0].request.request.route_decision_ref, "model_mount://route_decision/test");
  assert.equal(result.invocation_admission_ref, "model_mount://invocation_admission/test");
  assert.equal(result.record.invocation_admission_hash, "sha256:invocation-test");
});

test("Rust model_mount admission runner sends provider execution bridge request", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    command: "mock-model-mount-bridge",
    spawnSyncImpl(command, args, options) {
      const request = JSON.parse(options.input);
      calls.push({ command, args, request });
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_model_mount_provider_execution_command",
            backend: "rust_model_mount_live",
            record: {
              ...request.request,
              provider_execution_ref: "model_mount://provider_execution/test",
              provider_execution_hash: "sha256:provider-execution-test",
            },
            provider_execution_ref: "model_mount://provider_execution/test",
            provider_execution_hash: "sha256:provider-execution-test",
            receipt_refs: request.request.receipt_refs,
            evidence_refs: ["rust_model_mount_core"],
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.admitProviderExecution(providerExecutionRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "admit_model_mount_provider_execution");
  assert.equal(calls[0].request.request.request_hash, "sha256:request");
  assert.equal(result.provider_execution_ref, "model_mount://provider_execution/test");
  assert.equal(result.record.provider_execution_hash, "sha256:provider-execution-test");
});

test("Rust model_mount admission runner sends fixture provider invocation bridge request", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    command: "mock-model-mount-bridge",
    spawnSyncImpl(command, args, options) {
      const request = JSON.parse(options.input);
      calls.push({ command, args, request });
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_model_mount_fixture_provider_invocation_command",
            backend: "rust_model_mount_fixture",
            result: {
              ...request.request,
              output_text: "IOI model router fixture response from model.local. input_hash=abc123",
              token_count: { prompt_tokens: 3, completion_tokens: 8, total_tokens: 11 },
              provider_response_kind: "rust_model_mount.fixture",
              backend: "ioi_fixture",
              backend_id: "backend.fixture",
              execution_backend: "rust_model_mount_fixture",
              evidence_refs: ["rust_model_mount_provider_invocation"],
              invocation_hash: "sha256:invocation",
            },
            outputText: "IOI model router fixture response from model.local. input_hash=abc123",
            tokenCount: { prompt_tokens: 3, completion_tokens: 8, total_tokens: 11 },
            providerResponseKind: "rust_model_mount.fixture",
            execution_backend: "rust_model_mount_fixture",
            backendId: "backend.fixture",
            provider_execution_ref: "model_mount://provider_execution/test",
            provider_execution_hash: "sha256:provider-execution-test",
            invocation_hash: "sha256:invocation",
            evidence_refs: ["rust_model_mount_provider_invocation"],
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.executeProviderInvocation(providerInvocationRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "execute_model_mount_fixture_provider_invocation");
  assert.equal(calls[0].request.backend, "rust_model_mount_fixture");
  assert.equal(calls[0].request.request.provider_execution_ref, "model_mount://provider_execution/test");
  assert.equal(result.outputText.startsWith("IOI model router fixture response"), true);
  assert.equal(result.executionBackend, "rust_model_mount_fixture");
  assert.equal(result.backendId, "backend.fixture");
  assert.equal(result.invocation_hash, "sha256:invocation");
});

test("Rust model_mount admission runner sends provider result admission bridge request", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    command: "mock-model-mount-bridge",
    spawnSyncImpl(command, args, options) {
      const request = JSON.parse(options.input);
      calls.push({ command, args, request });
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_model_mount_provider_result_command",
            backend: "rust_model_mount_live",
            record: {
              ...request.request,
              provider_result_ref: "model_mount://provider_result/test",
              provider_result_hash: "sha256:provider-result-test",
            },
            provider_result_ref: "model_mount://provider_result/test",
            provider_result_hash: "sha256:provider-result-test",
            receipt_refs: request.request.receipt_refs,
            evidence_refs: ["rust_model_mount_provider_result_admission"],
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.admitProviderResult(providerResultRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "admit_model_mount_provider_result");
  assert.equal(calls[0].request.backend, "rust_model_mount_live");
  assert.equal(calls[0].request.request.execution_backend, "js_provider_driver_observation");
  assert.equal(result.provider_result_ref, "model_mount://provider_result/test");
  assert.equal(result.provider_result_hash, "sha256:provider-result-test");
  assert.deepEqual(result.evidence_refs, ["rust_model_mount_provider_result_admission"]);
});

test("Rust model_mount admission runner sends invocation receipt binding request", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    command: "mock-model-mount-bridge",
    spawnSyncImpl(command, args, options) {
      const request = JSON.parse(options.input);
      calls.push({ command, args, request });
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_model_mount_receipt_binding_command",
            backend: "rust_model_mount_live",
            receipt_binding: {
              schema_version: "ioi.step_module_receipt_binding.v1",
              binding_hash: "sha256:binding",
              receipt_refs: ["receipt://invocation"],
            },
            accepted_receipt_append: {
              schema_version: "ioi.accepted_receipt_append.v1",
              append_hash: "sha256:append",
              receipt_ref: "receipt://invocation",
            },
            agentgres_admission: {
              schema_version: "ioi.agentgres_admission.v1",
              operation_ref: "agentgres://model-mounting/operation-log/op_00000001_model_invocation",
              expected_heads: ["agentgres://model-mounting/operation-log/head/0"],
              state_root_before: "sha256:state-before",
              state_root_after: "sha256:state-after",
              resulting_head: "agentgres://model-mounting/operation-log/head/1",
              admission_hash: "sha256:agentgres",
            },
            projection_record: {
              component_kind: "ModelInvocationNode",
            },
            receipt_refs: ["receipt://invocation"],
            evidence_refs: ["rust_receipt_binder_core", "sha256:binding", "sha256:append"],
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.bindInvocationReceipt({
    invocation: {
      invocation_id: "model-invocation://test",
      input: { state_root_before: "sha256:state-before" },
    },
    result: {
      receipt_refs: ["receipt://invocation"],
      agentgres_operation_refs: ["agentgres://model-mounting/operation-log/op_00000001_model_invocation"],
      state_root_after: "sha256:state-after",
      resulting_head: "agentgres://model-mounting/operation-log/head/1",
    },
    expectedHeads: ["agentgres://model-mounting/operation-log/head/0"],
    receiptRef: "receipt://invocation",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "bind_model_mount_invocation_receipt");
  assert.deepEqual(calls[0].request.expected_heads, ["agentgres://model-mounting/operation-log/head/0"]);
  assert.equal(calls[0].request.receipt_ref, "receipt://invocation");
  assert.equal(result.receipt_binding.binding_hash, "sha256:binding");
  assert.equal(
    result.agentgres_admission.operation_ref,
    "agentgres://model-mounting/operation-log/op_00000001_model_invocation",
  );
  assert.equal(result.accepted_receipt_append.append_hash, "sha256:append");
  assert.deepEqual(result.evidence_refs, ["rust_receipt_binder_core", "sha256:binding", "sha256:append"]);
});

test("Rust model_mount admission runner reads the generic admission command env", () => {
  const runner = createModelMountAdmissionRunnerFromEnv({
    [MODEL_MOUNT_ADMISSION_COMMAND_ENV]: "mock-model-mount-bridge",
  });

  assert.equal(runner.command, "mock-model-mount-bridge");
});

test("Rust model_mount admission runner fails closed without command", () => {
  const runner = new RustModelMountAdmissionRunner();

  assert.throws(
    () => runner.admitRouteDecision(routeRequest()),
    (error) =>
      error instanceof ModelMountAdmissionRunnerError &&
      error.code === "model_mount_admission_bridge_unconfigured",
  );
});
