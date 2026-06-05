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

function providerStreamInvocationRequest() {
  return {
    ...providerInvocationRequest(),
    provider_ref: "provider.autopilot.local",
    provider_kind: "ioi_native_local",
    endpoint_ref: "endpoint.native-local",
    model_ref: "model://qwen/qwen3.5-9b",
    execution_backend: "rust_model_mount_native_local_stream",
    api_format: "ioi_native",
    driver: "native_local",
    backend_ref: "backend.autopilot.native-local.fixture",
    stream_status: "started",
    admitted_provider_execution: {
      ...providerExecutionRequest(),
      provider_ref: "provider.autopilot.local",
      endpoint_ref: "endpoint.native-local",
      model_ref: "model://qwen/qwen3.5-9b",
      provider_execution_ref: "model_mount://provider_execution/test",
      provider_execution_hash: "sha256:provider-execution-test",
      stream_status: "started",
    },
  };
}

function providerLifecycleRequest() {
  return {
    schema_version: "ioi.model_mount.provider_lifecycle.v1",
    provider_ref: "provider.autopilot.local",
    provider_kind: "ioi_native_local",
    endpoint_ref: "endpoint.native-local",
    model_ref: "model.native-local",
    action: "load",
    execution_backend: "rust_model_mount_native_local_lifecycle",
    api_format: "ioi_native",
    driver: "native_local",
    backend_ref: "backend.autopilot.native-local.fixture",
    evidence_refs: ["daemon_native_local_load_request"],
    process_evidence_refs: ["fake_process"],
  };
}

function providerInventoryRequest() {
  return {
    schema_version: "ioi.model_mount.provider_inventory.v1",
    provider_ref: "provider.autopilot.local",
    provider_kind: "ioi_native_local",
    action: "list_loaded",
    execution_backend: "rust_model_mount_native_local_inventory",
    api_format: "ioi_native",
    driver: "native_local",
    backend_ref: "backend.autopilot.native-local.fixture",
    item_refs: ["model_instance://native/qwen3"],
    evidence_refs: ["daemon_native_local_list_loaded_request"],
  };
}

function instanceLifecycleRequest() {
  return {
    schema_version: "ioi.model_mount.instance_lifecycle.v1",
    instance_ref: "model_instance://native/qwen3",
    endpoint_ref: "endpoint.native-local",
    model_ref: "model://qwen/qwen3.5-9b",
    provider_ref: "provider.autopilot.local",
    action: "load",
    target_status: "loaded",
    execution_backend: "rust_model_mount_instance_lifecycle",
    backend_ref: "backend.autopilot.native-local.fixture",
    driver: "native_local",
    provider_lifecycle_hash: "sha256:provider-lifecycle",
    evidence_refs: ["rust_model_mount_provider_lifecycle"],
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

test("Rust model_mount admission runner sends provider invocation bridge request", () => {
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
            source: "rust_model_mount_provider_invocation_command",
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
  assert.equal(calls[0].request.operation, "execute_model_mount_provider_invocation");
  assert.equal(calls[0].request.backend, "rust_model_mount_fixture");
  assert.equal(calls[0].request.request.provider_execution_ref, "model_mount://provider_execution/test");
  assert.equal(result.outputText.startsWith("IOI model router fixture response"), true);
  assert.equal(result.executionBackend, "rust_model_mount_fixture");
  assert.equal(result.backendId, "backend.fixture");
  assert.equal(result.invocation_hash, "sha256:invocation");
});

test("Rust model_mount admission runner sends native-local provider stream invocation bridge request", () => {
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
            source: "rust_model_mount_provider_stream_invocation_command",
            backend: "rust_model_mount_native_local_stream",
            result: {
              ...request.request,
              schema_version: "ioi.model_mount.provider_stream_invocation.v1",
              output_text: "Autopilot native local stream response",
              token_count: { prompt_tokens: 3, completion_tokens: 8, total_tokens: 11 },
              provider_response_kind: "rust_model_mount.native_local.stream",
              backend: "autopilot.native_local.fixture",
              backend_id: "backend.autopilot.native-local.fixture",
              execution_backend: "rust_model_mount_native_local_stream",
              stream_format: "ioi_jsonl",
              stream_kind: "openai_responses_native_local",
              stream_chunks: [
                "{\"delta\":\"Autopilot native local stream response\",\"done\":false}\n",
                "{\"delta\":\"\",\"done\":true,\"done_reason\":\"stop\",\"prompt_eval_count\":3,\"eval_count\":8}\n",
              ],
              evidence_refs: ["rust_model_mount_provider_stream_invocation"],
              invocation_hash: "sha256:stream-invocation",
            },
            outputText: "Autopilot native local stream response",
            tokenCount: { prompt_tokens: 3, completion_tokens: 8, total_tokens: 11 },
            providerResponseKind: "rust_model_mount.native_local.stream",
            execution_backend: "rust_model_mount_native_local_stream",
            backendId: "backend.autopilot.native-local.fixture",
            streamFormat: "ioi_jsonl",
            streamKind: "openai_responses_native_local",
            streamChunks: [
              "{\"delta\":\"Autopilot native local stream response\",\"done\":false}\n",
              "{\"delta\":\"\",\"done\":true,\"done_reason\":\"stop\",\"prompt_eval_count\":3,\"eval_count\":8}\n",
            ],
            provider_execution_ref: "model_mount://provider_execution/test",
            provider_execution_hash: "sha256:provider-execution-test",
            invocation_hash: "sha256:stream-invocation",
            evidence_refs: ["rust_model_mount_provider_stream_invocation"],
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.executeProviderStreamInvocation(providerStreamInvocationRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "execute_model_mount_provider_stream_invocation");
  assert.equal(calls[0].request.backend, "rust_model_mount_native_local_stream");
  assert.equal(calls[0].request.request.provider_kind, "ioi_native_local");
  assert.equal(calls[0].request.request.stream_status, "started");
  assert.equal(result.outputText, "Autopilot native local stream response");
  assert.equal(result.providerResponseKind, "rust_model_mount.native_local.stream");
  assert.equal(result.executionBackend, "rust_model_mount_native_local_stream");
  assert.equal(result.backendId, "backend.autopilot.native-local.fixture");
  assert.equal(result.streamFormat, "ioi_jsonl");
  assert.equal(result.streamKind, "openai_responses_native_local");
  assert.equal(result.streamChunks.some((chunk) => chunk.includes("\"done\":true")), true);
  assert.equal(result.invocation_hash, "sha256:stream-invocation");
});

test("Rust model_mount admission runner sends native-local provider lifecycle bridge request", () => {
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
            source: "rust_model_mount_provider_lifecycle_command",
            backend: "rust_model_mount_native_local_lifecycle",
            result: {
              ...request.request,
              status: "loaded",
              backend: "autopilot.native_local.fixture",
              backend_id: "backend.autopilot.native-local.fixture",
              driver: "native_local",
              lifecycle_hash: "sha256:lifecycle",
              evidence_refs: ["rust_model_mount_provider_lifecycle"],
            },
            status: "loaded",
            backendId: "backend.autopilot.native-local.fixture",
            providerBackend: "autopilot.native_local.fixture",
            driver: "native_local",
            execution_backend: "rust_model_mount_native_local_lifecycle",
            lifecycle_hash: "sha256:lifecycle",
            evidence_refs: ["rust_model_mount_provider_lifecycle"],
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.planProviderLifecycle(providerLifecycleRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "plan_model_mount_provider_lifecycle");
  assert.equal(calls[0].request.backend, "rust_model_mount_native_local_lifecycle");
  assert.equal(calls[0].request.request.action, "load");
  assert.equal(result.status, "loaded");
  assert.equal(result.providerBackend, "autopilot.native_local.fixture");
  assert.equal(result.backendId, "backend.autopilot.native-local.fixture");
  assert.equal(result.executionBackend, "rust_model_mount_native_local_lifecycle");
  assert.equal(result.lifecycle_hash, "sha256:lifecycle");
});

test("Rust model_mount admission runner sends local provider inventory bridge request", () => {
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
            source: "rust_model_mount_provider_inventory_command",
            backend: "rust_model_mount_native_local_inventory",
            result: {
              ...request.request,
              status: "listed",
              backend: "autopilot.native_local.fixture",
              backend_id: "backend.autopilot.native-local.fixture",
              driver: "native_local",
              item_count: 1,
              inventory_hash: "sha256:inventory",
              evidence_refs: ["rust_model_mount_provider_inventory"],
            },
            status: "listed",
            backendId: "backend.autopilot.native-local.fixture",
            providerBackend: "autopilot.native_local.fixture",
            driver: "native_local",
            execution_backend: "rust_model_mount_native_local_inventory",
            itemRefs: ["model_instance://native/qwen3"],
            itemCount: 1,
            inventory_hash: "sha256:inventory",
            evidence_refs: ["rust_model_mount_provider_inventory"],
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.planProviderInventory(providerInventoryRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "plan_model_mount_provider_inventory");
  assert.equal(calls[0].request.backend, "rust_model_mount_native_local_inventory");
  assert.equal(calls[0].request.request.action, "list_loaded");
  assert.equal(result.status, "listed");
  assert.equal(result.providerBackend, "autopilot.native_local.fixture");
  assert.equal(result.backendId, "backend.autopilot.native-local.fixture");
  assert.equal(result.executionBackend, "rust_model_mount_native_local_inventory");
  assert.deepEqual(result.itemRefs, ["model_instance://native/qwen3"]);
  assert.equal(result.itemCount, 1);
  assert.equal(result.inventory_hash, "sha256:inventory");
});

test("Rust model_mount admission runner sends model instance lifecycle bridge request", () => {
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
            source: "rust_model_mount_instance_lifecycle_command",
            backend: "rust_model_mount_instance_lifecycle",
            result: {
              ...request.request,
              status: "loaded",
              backend_id: "backend.autopilot.native-local.fixture",
              instance_lifecycle_hash: "sha256:instance-lifecycle",
              evidence_refs: ["rust_model_mount_instance_lifecycle"],
            },
            status: "loaded",
            backendId: "backend.autopilot.native-local.fixture",
            driver: "native_local",
            execution_backend: "rust_model_mount_instance_lifecycle",
            provider_lifecycle_hash: "sha256:provider-lifecycle",
            instance_lifecycle_hash: "sha256:instance-lifecycle",
            evidence_refs: ["rust_model_mount_instance_lifecycle"],
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.planInstanceLifecycle(instanceLifecycleRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "plan_model_mount_instance_lifecycle");
  assert.equal(calls[0].request.backend, "rust_model_mount_instance_lifecycle");
  assert.equal(calls[0].request.request.action, "load");
  assert.equal(result.status, "loaded");
  assert.equal(result.backendId, "backend.autopilot.native-local.fixture");
  assert.equal(result.executionBackend, "rust_model_mount_instance_lifecycle");
  assert.equal(result.provider_lifecycle_hash, "sha256:provider-lifecycle");
  assert.equal(result.providerLifecycleHash, undefined);
  assert.equal(result.instance_lifecycle_hash, "sha256:instance-lifecycle");
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
