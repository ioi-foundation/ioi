import assert from "node:assert/strict";
import test from "node:test";

import {
  MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
  ModelMountAdmissionRunnerError,
  RUST_MODEL_MOUNT_ARTIFACT_ENDPOINT_BACKEND,
  RUST_MODEL_MOUNT_BACKEND_LIFECYCLE_BACKEND,
  RUST_MODEL_MOUNT_CAPABILITY_TOKEN_CONTROL_BACKEND,
  RUST_MODEL_MOUNT_CATALOG_PROVIDER_CONTROL_BACKEND,
  RUST_MODEL_MOUNT_CONVERSATION_STATE_BACKEND,
  RUST_MODEL_MOUNT_MCP_WORKFLOW_BACKEND,
  RUST_MODEL_MOUNT_PROVIDER_CONTROL_BACKEND,
  RUST_MODEL_MOUNT_RECEIPT_GATE_BACKEND,
  RUST_MODEL_MOUNT_ROUTE_CONTROL_BACKEND,
  RUST_MODEL_MOUNT_ROUTE_CONTROL_REQUIRED_BACKEND,
  RUST_MODEL_MOUNT_RUNTIME_ENGINE_BACKEND,
  RUST_MODEL_MOUNT_RUNTIME_SURVEY_BACKEND,
  RUST_MODEL_MOUNT_SERVER_CONTROL_BACKEND,
  RUST_MODEL_MOUNT_STORAGE_CONTROL_BACKEND,
  RUST_MODEL_MOUNT_STREAM_COMPLETION_BACKEND,
  RUST_MODEL_MOUNT_TOKENIZER_BACKEND,
  RUST_MODEL_MOUNT_TOKENIZER_REQUIRED_BACKEND,
  RUST_MODEL_MOUNT_VAULT_CONTROL_BACKEND,
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
    provider_ref: "provider.autopilot.local",
    provider_kind: "ioi_native_local",
    endpoint_ref: "endpoint.autopilot.local",
    model_ref: "model.autopilot.local",
    capability: "chat",
    invocation_kind: "responses",
    request_hash: "sha256:request",
    output_text: "native-local stream answer",
    output_hash: "sha256:output",
    token_count: { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3 },
    provider_response_kind: "rust_model_mount.native_local.stream",
    execution_backend: "rust_model_mount_native_local_stream",
    backend_ref: "backend.autopilot.native-local.fixture",
    receipt_refs: ["receipt://route"],
    provider_auth_evidence_refs: [],
    backend_evidence_refs: ["rust_model_mount_native_local_stream_backend"],
    evidence_refs: ["model_mount://provider_execution/test"],
    admitted_provider_execution: {
      ...providerExecutionRequest(),
      provider_execution_ref: "model_mount://provider_execution/test",
      provider_execution_hash: "sha256:provider-execution-test",
    },
  };
}

function backendProcessPlanRequest() {
  return {
    schema_version: "ioi.model_mount.backend_process_plan.v1",
    backend_ref: "backend.llama",
    backend_kind: "llama_cpp",
    base_url: "http://127.0.0.1:8091/v1",
    model_ref: "model.local",
    artifact_path: "/models/private/model.gguf",
    binary_configured: true,
    load_options: {
      context_length: 4096,
      parallel: 2,
      gpu: "auto",
      identifier: "llama profile",
      embeddings: true,
    },
  };
}

function backendLifecycleRequest() {
  return {
    schema_version: "ioi.model_mount.backend_lifecycle.v1",
    operation_kind: "model_mount.backend.start",
    backend_id: "backend.llama_cpp",
    backend_kind: "llama_cpp",
    source: "runtime-daemon.model_mounting.backend_lifecycle",
    generated_at: "2026-06-13T12:00:00.000Z",
    body: {
      backend_id: "backend.llama_cpp",
      backend_kind: "llama_cpp",
      load_options: { context_length: 4096 },
    },
    receipt_refs: ["receipt://backend-lifecycle"],
  };
}

function serverControlRequest() {
  return {
    schema_version: "ioi.model_mount.server_control.v1",
    operation_kind: "model_mount.server_control.start",
    server_control_id: "server-control.default",
    source: "runtime-daemon.model_mounting.server_control",
    generated_at: "2026-06-13T12:00:00.000Z",
    body: {
      base_url: "http://daemon.test",
    },
    receipt_refs: ["receipt://server-control"],
  };
}

function runtimeEngineRequest() {
  return {
    schema_version: "ioi.model_mount.runtime_engine.v1",
    operation_kind: "model_mount.runtime_engine_profile.write",
    engine_id: "backend.llama-cpp",
    source: "runtime-daemon.model_mounting.runtime_engine",
    generated_at: "2026-06-13T12:00:00.000Z",
    body: {
      engine_id: "backend.llama-cpp",
      default_load_options: { gpu_layers: 4 },
    },
    receipt_refs: ["receipt://runtime-engine"],
  };
}

function runtimeSurveyRequest() {
  return {
    schema_version: "ioi.model_mount.runtime_survey.v1",
    operation_kind: "model_mount.runtime_survey.capture",
    source: "runtime-daemon.model_mounting.runtime_survey",
    generated_at: "2026-06-13T12:00:00.000Z",
    state_dir: "/runtime-state",
    body: {},
  };
}

function tokenizerRequiredRequest() {
  return {
    schema_version: "ioi.model_mount.tokenizer_required.v1",
    operation: "context_fit",
    source: "runtime-daemon.model_mounting.tokenizer",
    evidence_refs: [
      "model_mount_tokenizer_js_facade_retired",
      "model_mount_context_fit_js_facade_retired",
      "rust_daemon_core_model_tokenizer_required",
      "rust_daemon_core_model_context_fit_required",
      "agentgres_model_tokenizer_truth_required",
    ],
    details: {
      model: "llama-test",
      route_id: "route.local-first",
      requested_scope: "model.context:*",
    },
  };
}

function tokenizerRequest() {
  return {
    schema_version: "ioi.model_mount.tokenizer.v1",
    operation: "tokenize",
    source: "runtime-daemon.model_mounting.tokenizer",
    required_scope: "model.tokenize:*",
    body: {
      model: "llama-test",
      route_id: "route.local-first",
      input: "one two three",
    },
    route_selection: {
      route: { id: "route.local-first" },
      endpoint: {
        id: "endpoint.local.llama",
        modelId: "llama-test",
        providerId: "provider.local",
      },
      provider: { id: "provider.local" },
      route_decision: {
        route_ref: "route.local-first",
        provider_ref: "provider.local",
        endpoint_ref: "endpoint.local.llama",
        model_ref: "llama-test",
        route_decision_ref: "model_mount://route_decision/test",
        route_decision_hash: "sha256:route-decision",
        receipt_refs: ["receipt://route-selection/test"],
      },
      route_receipt: { id: "model-mount/route-control/model_mount.route.select/test" },
      route_control: {
        record_dir: "model-route-selections",
        record_id: "route_selection:route.local-first:test",
      },
    },
    artifacts: [],
  };
}

function routeControlRequiredRequest() {
  return {
    schema_version: "ioi.model_mount.route_control_required.v1",
    operation: "model_mount.route_control",
    operation_kind: "model_mount.route.selection_update",
    source: "runtime-daemon.model_mounting.route_control",
    evidence_refs: [
      "model_mount_route_control_js_facade_retired",
      "rust_daemon_core_route_control_required",
      "agentgres_route_truth_required",
    ],
    details: {
      route_id: "route.local-first",
      selected_model: "model.local",
      receipt_id: "receipt-route-test",
      route_selection_boundary: "model_mount.route_selection",
    },
  };
}

function routeControlRequest() {
  return {
    schema_version: "ioi.model_mount.route_control.v1",
    operation_kind: "model_mount.route.write",
    source: "runtime-daemon.model_mounting.route_control",
    route_id: "route.review",
    generated_at: "2026-06-13T00:00:00.000Z",
    body: {
      id: "route.review",
      role: "Review",
      fallback: ["endpoint.local"],
      provider_eligibility: ["local_folder"],
    },
    current_route: null,
  };
}

function receiptGateRequest() {
  return {
    schema_version: "ioi.model_mount.receipt_gate.v1",
    operation_kind: "workflow_receipt_gate",
    receipt_id: "receipt-route",
    receipt: {
      id: "receipt-route",
      kind: "model_invocation",
      redaction: "redacted",
      details: {
        route_id: "route.local-first",
        selected_model: "model.local",
        endpoint_id: "endpoint.local",
        backend_id: "backend.local",
        tool_receipt_ids: ["receipt-tool"],
      },
    },
    required_tool_receipt_ids: ["receipt-tool"],
    tool_receipts: [
      {
        id: "receipt-tool",
        kind: "mcp_tool_invocation",
        redaction: "redacted",
        details: {},
      },
    ],
    required_redaction: "redacted",
    required_route_id: "route.local-first",
    required_selected_model: "model.local",
    required_endpoint_id: "endpoint.local",
    required_backend_id: "backend.local",
    source: "test",
    generated_at: "2026-06-13T12:00:00.000Z",
  };
}

function catalogProviderControlRequest() {
  return {
    schema_version: "ioi.model_mount.catalog_provider_control.v1",
    operation_kind: "model_mount.catalog_provider_configuration.write",
    provider_id: "catalog.huggingface",
    source: "runtime-daemon.model_mounting.catalog_provider_control",
    generated_at: "2026-06-13T00:00:00.000Z",
    body: {
      enabled: true,
      authority_grant_refs: ["grant://wallet/provider-write"],
      authority_receipt_refs: ["receipt://wallet/provider-write"],
      custody_ref: "ctee://catalog-provider/huggingface",
    },
    receipt_refs: ["receipt://catalog-provider-control"],
    authority_grant_refs: ["grant://wallet/provider-write"],
    authority_receipt_refs: ["receipt://wallet/provider-write"],
    custody_ref: "ctee://catalog-provider/huggingface",
    required_scope: "provider.write:catalog.huggingface",
  };
}

function providerControlRequest() {
  return {
    schema_version: "ioi.model_mount.provider_control.v1",
    operation_kind: "model_mount.provider.write",
    provider_id: "provider.openai",
    source: "runtime-daemon.model_mounting.provider_control",
    generated_at: "2026-06-13T00:00:00.000Z",
    body: {
      id: "provider.openai",
      kind: "openai",
      label: "OpenAI",
      secret_ref: "vault://provider/openai",
      auth_header_name: "authorization",
      api_format: "openai",
      base_url: "https://api.openai.example/v1",
      privacy_class: "hosted_private",
      capabilities: ["chat", "responses"],
      evidence_refs: ["operator_provider_config"],
    },
    receipt_refs: ["receipt://provider-control"],
    authority_grant_refs: ["grant://wallet/provider-write"],
    authority_receipt_refs: ["receipt://wallet/provider-write"],
    custody_ref: "ctee://provider/openai",
    required_scope: "provider.write:provider.openai",
  };
}

function artifactEndpointRequest() {
  return {
    schema_version: "ioi.model_mount.artifact_endpoint.v1",
    operation_kind: "model_mount.endpoint.mount",
    source: "runtime-daemon.model_mounting.artifact_endpoint",
    generated_at: "2026-06-13T00:00:00.000Z",
    body: {
      model_id: "local:test",
      provider_id: "provider.local.folder",
      load_policy: { mode: "on_demand", idle_ttl_seconds: 900, auto_evict: true },
      receipt_refs: ["receipt://artifact-endpoint"],
      authority_grant_refs: ["grant://wallet/model-mount"],
      authority_receipt_refs: ["receipt://wallet/model-mount"],
      custody_ref: "ctee://workspace/private-models",
    },
    receipt_refs: ["receipt://artifact-endpoint"],
    authority_grant_refs: ["grant://wallet/model-mount"],
    authority_receipt_refs: ["receipt://wallet/model-mount"],
    custody_ref: "ctee://workspace/private-models",
    required_scope: "model.endpoint.mount:local:test",
  };
}

function storageControlRequest() {
  return {
    schema_version: "ioi.model_mount.storage_control.v1",
    operation_kind: "model_mount.download.queue",
    source: "runtime-daemon.model_mounting.storage_control",
    generated_at: "2026-06-13T00:00:00.000Z",
    body: {
      model_id: "local:test",
      provider_id: "provider.local.folder",
      source_url: "fixture://models/local-test",
      queued_only: true,
      receipt_refs: ["receipt://storage-control"],
      authority_grant_refs: ["grant://wallet/storage"],
      authority_receipt_refs: ["receipt://wallet/storage"],
      custody_ref: "ctee://workspace/private-models",
    },
    receipt_refs: ["receipt://storage-control"],
    authority_grant_refs: ["grant://wallet/storage"],
    authority_receipt_refs: ["receipt://wallet/storage"],
    custody_ref: "ctee://workspace/private-models",
    required_scope: "model.download.queue:local:test",
  };
}

function capabilityTokenControlRequest() {
  return {
    schema_version: "ioi.model_mount.capability_token_control.v1",
    operation_kind: "model_mount.capability_token.create",
    token_id: null,
    token_hash: null,
    required_scope: null,
    source: "runtime-daemon.model_mounting.capability_token_control",
    generated_at: "2026-06-13T00:00:00.000Z",
    state_dir: "/tmp/ioi-model-mount-state",
    body: {
      audience: "agent-studio",
      allowed: ["model.chat:*"],
      denied: ["shell.exec"],
      grant_id: "grant://wallet/capability",
      authority_grant_refs: ["grant://wallet/capability"],
      authority_receipt_refs: ["receipt://wallet/capability"],
    },
    receipt_refs: ["receipt://capability-token-control"],
    authority_grant_refs: ["grant://wallet/capability"],
    authority_receipt_refs: ["receipt://wallet/capability"],
  };
}

function vaultControlRequest() {
  return {
    schema_version: "ioi.model_mount.vault_control.v1",
    operation_kind: "model_mount.vault_ref.bind",
    vault_ref: "vault://provider/custom/api-key",
    material_hash: "sha256:vault-material",
    custody_ref: "ctee://vault/custom",
    source: "runtime-daemon.model_mounting.vault_control",
    generated_at: "2026-06-13T00:00:00.000Z",
    state_dir: "/tmp/ioi-model-mount-state",
    body: {
      label: "Custom auth",
      purpose: "provider.auth:custom",
      custody_ref: "ctee://vault/custom",
      authority_grant_refs: ["grant://wallet/vault"],
      authority_receipt_refs: ["receipt://wallet/vault"],
    },
    receipt_refs: ["receipt://vault-control"],
    authority_grant_refs: ["grant://wallet/vault"],
    authority_receipt_refs: ["receipt://wallet/vault"],
  };
}

function conversationStateRequest() {
  return {
    schema_version: "ioi.model_mount.conversation_state.v1",
    operation: "model_conversation_state_write",
    response_id: "resp.current",
    previous_response_id: "resp.previous",
    root_response_id: "resp.root",
    previous_message_count: 4,
    kind: "responses",
    status: "completed",
    source: "runtime-daemon.model_mounting.conversation_state",
    generated_at: "2026-06-13T00:00:00.000Z",
    route_ref: "route.local-first",
    endpoint_ref: "endpoint.local",
    provider_ref: "provider.local",
    model_ref: "llama-test",
    instance_ref: "instance.local",
    route_decision_ref: "model_mount://route_decision/test",
    route_receipt_ref: "receipt://route",
    invocation_receipt_ref: "receipt://invocation",
    input_text: "hello",
    output_text: "world",
    token_count: { total_tokens: 2 },
    continuation_safety: { status: "accepted" },
    receipt_refs: ["receipt://route", "receipt://invocation"],
  };
}

function streamCompletionRequest() {
  return {
    schema_version: "ioi.model_mount.stream_completion.v1",
    operation: "model_stream_completion",
    response_id: "resp.stream",
    previous_response_id: null,
    root_response_id: "resp.stream",
    previous_message_count: null,
    kind: "responses",
    stream_kind: "responses",
    source: "runtime-daemon.model_mounting.stream_completion",
    generated_at: "2026-06-13T00:00:00.000Z",
    receipt_id: "receipt.stream",
    current_sequence: 2,
    current_head_ref: "agentgres://model-mounting/accepted-receipts/head/2",
    current_state_root: "sha256:state-2",
    invocation_receipt_ref: "receipt://invocation",
    route_decision_ref: "model_mount://route_decision/test",
    route_receipt_ref: "receipt://route",
    route_ref: "route.local-first",
    endpoint_ref: "endpoint.local",
    provider_ref: "provider.local",
    model_ref: "llama-test",
    instance_ref: "instance.local",
    input_text: "hello",
    output_text: "world",
    token_count: { total_tokens: 3 },
    provider_usage: { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3 },
    provider_result: { provider_response_kind: "openai.responses" },
    provider_stream_shape_summary: { frames_forwarded: 3 },
    chunks_forwarded: 3,
    finish_reason: "stop",
    provider_response_kind: "openai.responses",
    receipt_refs: ["receipt://route", "receipt://invocation"],
  };
}

test("Rust model_mount runner does not synthesize Rust-owned receipt, required-boundary evidence, or process fields", () => {
  const sparseResultByOperation = new Map([
    ["admit_model_mount_route_decision", { record: {} }],
    ["admit_model_mount_invocation", { record: {} }],
    ["admit_model_mount_provider_execution", { record: {} }],
    ["execute_model_mount_provider_invocation", { result: {} }],
    ["execute_model_mount_provider_stream_invocation", { result: {} }],
    ["plan_model_mount_provider_lifecycle", { result: {} }],
    ["plan_model_mount_provider_inventory", { result: {} }],
    ["plan_model_mount_instance_lifecycle", { result: {} }],
    ["admit_model_mount_provider_result", { record: {} }],
    ["plan_model_mount_backend_process", { result: {} }],
    ["plan_model_mount_accepted_receipt_head", { head: {} }],
    ["plan_model_mount_accepted_receipt_transition", { transition: {} }],
    ["bind_model_mount_invocation_receipt", {}],
    ["plan_model_mount_read_projection", {}],
    ["plan_model_mount_tokenizer_required", { record: { details: {} } }],
    ["plan_model_mount_route_control_required", { record: { details: {} } }],
  ]);
  const runner = new RustModelMountAdmissionRunner({
    daemonCoreInvoker(request) {
      return {
        ok: true,
        result: sparseResultByOperation.get(request.operation) ?? {},
      };
    },
  });

  const route = runner.admitRouteDecision(routeRequest());
  assert.equal(route.receipt_refs, null);
  assert.equal(route.evidence_refs, null);

  const invocation = runner.admitInvocation(invocationRequest());
  assert.equal(invocation.receipt_refs, null);
  assert.equal(invocation.evidence_refs, null);

  const providerExecution = runner.admitProviderExecution(providerExecutionRequest());
  assert.equal(providerExecution.receipt_refs, null);
  assert.equal(providerExecution.evidence_refs, null);

  const providerInvocation = runner.executeProviderInvocation(providerInvocationRequest());
  assert.equal(providerInvocation.evidence_refs, null);
  assert.equal(providerInvocation.backendEvidenceRefs, null);

  const providerStream = runner.executeProviderStreamInvocation(providerStreamInvocationRequest());
  assert.equal(providerStream.evidence_refs, null);
  assert.equal(providerStream.backendEvidenceRefs, null);

  const providerLifecycle = runner.planProviderLifecycle(providerLifecycleRequest());
  assert.equal(providerLifecycle.evidence_refs, null);
  assert.equal(providerLifecycle.backendEvidenceRefs, null);

  const providerInventory = runner.planProviderInventory(providerInventoryRequest());
  assert.equal(providerInventory.itemRefs, null);
  assert.equal(providerInventory.itemCount, null);
  assert.equal(providerInventory.evidence_refs, null);
  assert.equal(providerInventory.backendEvidenceRefs, null);

  const instanceLifecycle = runner.planInstanceLifecycle(instanceLifecycleRequest());
  assert.equal(instanceLifecycle.evidence_refs, null);
  assert.equal(instanceLifecycle.backendEvidenceRefs, null);

  const providerResult = runner.admitProviderResult(providerResultRequest());
  assert.equal(providerResult.receipt_refs, null);
  assert.equal(providerResult.evidence_refs, null);

  const backendProcess = runner.planBackendProcess(backendProcessPlanRequest());
  assert.equal(backendProcess.supports_supervision, null);
  assert.equal(backendProcess.public_args, null);
  assert.equal(backendProcess.spawn_args, null);
  assert.equal(backendProcess.spawn_required, null);
  assert.equal(backendProcess.evidence_refs, null);

  const head = runner.planAcceptedReceiptHead({});
  assert.equal(head.evidence_refs, null);

  const transition = runner.planAcceptedReceiptTransition({});
  assert.equal(transition.expected_heads, null);
  assert.equal(transition.evidence_refs, null);

  const binding = runner.bindInvocationReceipt({ invocation: {}, result: {} });
  assert.equal(binding.receipt_refs, null);
  assert.equal(binding.evidence_refs, null);

  const projection = runner.planReadProjection({});
  assert.equal(projection.evidence_refs, null);

  const tokenizerRequired = runner.planTokenizerRequired(tokenizerRequiredRequest());
  assert.equal(tokenizerRequired.evidence_refs, null);

  const routeControlRequired = runner.planRouteControlRequired(routeControlRequiredRequest());
  assert.equal(routeControlRequired.evidence_refs, null);
});

test("Rust model_mount admission runner sends route-decision through direct daemon-core invoker", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    daemonCoreInvoker(request) {
      calls.push({ request });
      return {
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
      };
    },
  });

  const result = runner.admitRouteDecision(routeRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "admit_model_mount_route_decision");
  assert.equal(calls[0].request.backend, "rust_model_mount_live");
  assert.equal(calls[0].request.request.model_ref, "model.local");
  assert.equal(result.route_decision_ref, "model_mount://route_decision/test");
  assert.equal(result.record.route_decision_hash, "sha256:test");
});

test("Rust model_mount admission runner sends invocation through direct daemon-core invoker", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    daemonCoreInvoker(request) {
      calls.push({ request });
      return {
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

test("Rust model_mount admission runner sends provider execution through direct daemon-core invoker", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    daemonCoreInvoker(request) {
      calls.push({ request });
      return {
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

test("Rust model_mount admission runner sends provider invocation through direct daemon-core invoker", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    daemonCoreInvoker(request) {
      calls.push({ request });
      return {
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

test("Rust model_mount admission runner sends native-local provider stream invocation through direct daemon-core invoker", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    daemonCoreInvoker(request) {
      calls.push({ request });
      return {
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

test("Rust model_mount admission runner sends native-local provider lifecycle through direct daemon-core invoker", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    daemonCoreInvoker(request) {
      calls.push({ request });
      return {
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
            backend_id: "backend.autopilot.native-local.fixture",
            provider_backend: "autopilot.native_local.fixture",
            driver: "native_local",
            execution_backend: "rust_model_mount_native_local_lifecycle",
            lifecycle_hash: "sha256:lifecycle",
            evidence_refs: ["rust_model_mount_provider_lifecycle"],
          },
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
  assert.equal(Object.hasOwn(result.result, "providerBackend"), false);
  assert.equal(Object.hasOwn(result.result, "backendId"), false);
});

test("Rust model_mount admission runner sends local provider inventory through direct daemon-core invoker", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    daemonCoreInvoker(request) {
      calls.push({ request });
      const record = {
        id: "provider_inventory_native_list_loaded",
        object: "ioi.model_mount_provider_inventory",
        schema_version: request.request.schema_version,
        provider_ref: request.request.provider_ref,
        provider_kind: request.request.provider_kind,
        action: "list_loaded",
        operation_kind: "model_mount.provider.inventory.list_loaded",
        status: "listed",
        backend: "autopilot.native_local.fixture",
        backend_id: "backend.autopilot.native-local.fixture",
        driver: "native_local",
        execution_backend: "rust_model_mount_native_local_inventory",
        item_refs: ["model_instance://native/qwen3"],
        item_count: 1,
        inventory_hash: "sha256:inventory",
        record_dir: "model-provider-inventory",
        record_id: "provider_inventory_native_list_loaded",
        receipt_refs: [],
        rust_core_boundary: "model_mount.provider_inventory",
        evidence_refs: [
          "rust_model_mount_provider_inventory",
          "agentgres_provider_inventory_truth_required",
        ],
      };
      return {
        ok: true,
        result: {
            source: "rust_model_mount_provider_inventory_command",
            backend: "rust_model_mount_native_local_inventory",
            result: {
              ...request.request,
              operation_kind: "model_mount.provider.inventory.list_loaded",
              status: "listed",
              backend: "autopilot.native_local.fixture",
              backend_id: "backend.autopilot.native-local.fixture",
              driver: "native_local",
              item_count: 1,
              inventory_hash: "sha256:inventory",
              rust_core_boundary: "model_mount.provider_inventory",
              record_dir: "model-provider-inventory",
              record_id: "provider_inventory_native_list_loaded",
              record,
              receipt_refs: [],
              evidence_refs: [
                "rust_model_mount_provider_inventory",
                "agentgres_provider_inventory_truth_required",
              ],
            },
            status: "listed",
            backend_id: "backend.autopilot.native-local.fixture",
            provider_backend: "autopilot.native_local.fixture",
            driver: "native_local",
            execution_backend: "rust_model_mount_native_local_inventory",
            item_refs: ["model_instance://native/qwen3"],
            item_count: 1,
            inventory_hash: "sha256:inventory",
            operation_kind: "model_mount.provider.inventory.list_loaded",
            rust_core_boundary: "model_mount.provider_inventory",
            record_dir: "model-provider-inventory",
            record_id: "provider_inventory_native_list_loaded",
            record,
            receipt_refs: [],
            evidence_refs: [
              "rust_model_mount_provider_inventory",
              "agentgres_provider_inventory_truth_required",
            ],
          },
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
  assert.equal(result.operation_kind, "model_mount.provider.inventory.list_loaded");
  assert.equal(result.rust_core_boundary, "model_mount.provider_inventory");
  assert.equal(result.record_dir, "model-provider-inventory");
  assert.equal(result.record_id, "provider_inventory_native_list_loaded");
  assert.equal(result.record.object, "ioi.model_mount_provider_inventory");
  assert.deepEqual(result.receipt_refs, []);
  assert.equal(Object.hasOwn(result.result, "providerBackend"), false);
  assert.equal(Object.hasOwn(result.result, "backendId"), false);
  assert.equal(Object.hasOwn(result.result, "itemRefs"), false);
  assert.equal(Object.hasOwn(result.result, "itemCount"), false);
});

test("Rust model_mount admission runner sends model instance lifecycle through direct daemon-core invoker", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    daemonCoreInvoker(request) {
      calls.push({ request });
      return {
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

test("Rust model_mount admission runner sends provider result admission through direct daemon-core invoker", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    daemonCoreInvoker(request) {
      calls.push({ request });
      return {
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
      };
    },
  });

  const result = runner.admitProviderResult(providerResultRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "admit_model_mount_provider_result");
  assert.equal(calls[0].request.backend, "rust_model_mount_live");
  assert.equal(calls[0].request.request.execution_backend, "rust_model_mount_native_local_stream");
  assert.equal(result.provider_result_ref, "model_mount://provider_result/test");
  assert.equal(result.provider_result_hash, "sha256:provider-result-test");
  assert.equal(Object.hasOwn(result, "providerResultRef"), false);
  assert.equal(Object.hasOwn(result, "providerResultHash"), false);
  assert.deepEqual(result.evidence_refs, ["rust_model_mount_provider_result_admission"]);
});

test("Rust model_mount admission runner sends backend process plan request", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    daemonCoreInvoker(request) {
      calls.push({ request });
      return {
        ok: true,
        result: {
            source: "rust_model_mount_backend_process_command",
            backend: "rust_model_mount_backend_process",
            result: {
              schema_version: "ioi.model_mount.backend_process_plan.v1",
              backend_ref: request.request.backend_ref,
              backend_kind: request.request.backend_kind,
              supports_supervision: true,
              supervisor_kind: "external_process",
              public_args: ["llama-server", "--model", "artifact:abc123"],
              spawn_args: ["--model", "/models/private/model.gguf"],
              spawn_required: true,
              spawn_status: "spawn_ready",
              evidence_refs: ["rust_model_mount_backend_process_plan"],
              plan_hash: "sha256:backend-process-plan",
            },
            supports_supervision: true,
            supervisor_kind: "external_process",
            public_args: ["llama-server", "--model", "artifact:abc123"],
            spawn_args: ["--model", "/models/private/model.gguf"],
            spawn_required: true,
            spawn_status: "spawn_ready",
            plan_hash: "sha256:backend-process-plan",
            evidence_refs: ["rust_model_mount_backend_process_plan"],
          },
      };
    },
  });

  const result = runner.planBackendProcess(backendProcessPlanRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "plan_model_mount_backend_process");
  assert.equal(calls[0].request.backend, "rust_model_mount_backend_process");
  assert.equal(calls[0].request.request.backend_kind, "llama_cpp");
  assert.equal(calls[0].request.request.load_options.context_length, 4096);
  assert.equal(result.supports_supervision, true);
  assert.equal(result.spawn_status, "spawn_ready");
  assert.deepEqual(result.public_args, ["llama-server", "--model", "artifact:abc123"]);
  assert.deepEqual(result.spawn_args, ["--model", "/models/private/model.gguf"]);
  assert.equal(result.plan_hash, "sha256:backend-process-plan");
  assert.equal(Object.hasOwn(result, "spawnStatus"), false);
  assert.equal(Object.hasOwn(result, "publicArgs"), false);
});

test("Rust model_mount admission runner sends positive backend lifecycle request", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    daemonCoreInvoker(request) {
      calls.push({ request });
      const record = {
        id: "backend-lifecycle-control:test",
        object: "ioi.model_mount_backend_lifecycle_record",
        backend_id: request.request.backend_id,
        backend_kind: request.request.backend_kind,
        operation_kind: request.request.operation_kind,
        rust_core_boundary: "model_mount.backend_lifecycle",
        receipt_refs: [...request.request.receipt_refs, "sha256:backend-lifecycle-control"],
        evidence_refs: [
          "public_backend_lifecycle_js_facade_retired",
          "rust_daemon_core_backend_lifecycle",
          "agentgres_backend_lifecycle_truth_required",
        ],
      };
      const publicResponse = {
        object: "ioi.model_mount_backend_lifecycle",
        status: "planned",
        backend_id: request.request.backend_id,
        backend_kind: request.request.backend_kind,
        operation_kind: request.request.operation_kind,
        rust_core_boundary: "model_mount.backend_lifecycle",
        backend_status: "start_planned",
        load_options: request.request.body.load_options,
        js_backend_registry_read: false,
        js_process_control: false,
        js_log_read: false,
        js_log_write: false,
      };
      return {
        ok: true,
        result: {
          source: "rust_model_mount_backend_lifecycle_command",
          backend: RUST_MODEL_MOUNT_BACKEND_LIFECYCLE_BACKEND,
          plan: {
            schema_version: "ioi.model_mount.backend_lifecycle_plan.v1",
            object: "ioi.model_mount_backend_lifecycle_plan",
            status: "planned",
            rust_core_boundary: "model_mount.backend_lifecycle",
            operation_kind: request.request.operation_kind,
            source: request.request.source,
            record_dir: "model-backend-lifecycle-controls",
            record_id: "backend-lifecycle-control:test",
            record,
            public_response: publicResponse,
            receipt_refs: request.request.receipt_refs,
            evidence_refs: record.evidence_refs,
            control_hash: "sha256:backend-lifecycle-control",
          },
          record_dir: "model-backend-lifecycle-controls",
          record_id: "backend-lifecycle-control:test",
          record,
          public_response: publicResponse,
          operation_kind: request.request.operation_kind,
          rust_core_boundary: "model_mount.backend_lifecycle",
          receipt_refs: request.request.receipt_refs,
          evidence_refs: record.evidence_refs,
          control_hash: "sha256:backend-lifecycle-control",
        },
      };
    },
  });

  const result = runner.planBackendLifecycle(backendLifecycleRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "plan_model_mount_backend_lifecycle");
  assert.equal(calls[0].request.backend, RUST_MODEL_MOUNT_BACKEND_LIFECYCLE_BACKEND);
  assert.equal(calls[0].request.request.schema_version, "ioi.model_mount.backend_lifecycle.v1");
  assert.equal(calls[0].request.request.backend_id, "backend.llama_cpp");
  assert.equal(calls[0].request.request.backend_kind, "llama_cpp");
  assert.equal(calls[0].request.request.operation_kind, "model_mount.backend.start");
  assert.equal(result.source, "rust_model_mount_backend_lifecycle_command");
  assert.equal(result.backend, RUST_MODEL_MOUNT_BACKEND_LIFECYCLE_BACKEND);
  assert.equal(result.record_dir, "model-backend-lifecycle-controls");
  assert.equal(result.record_id, "backend-lifecycle-control:test");
  assert.equal(result.record.id, "backend-lifecycle-control:test");
  assert.equal(result.public_response.backend_status, "start_planned");
  assert.equal(result.public_response.js_process_control, false);
  assert.equal(result.operation_kind, "model_mount.backend.start");
  assert.equal(result.rust_core_boundary, "model_mount.backend_lifecycle");
  assert.deepEqual(result.receipt_refs, ["receipt://backend-lifecycle"]);
  assert.ok(result.evidence_refs.includes("rust_daemon_core_backend_lifecycle"));
  assert.ok(result.evidence_refs.includes("agentgres_backend_lifecycle_truth_required"));
  assert.equal(result.control_hash, "sha256:backend-lifecycle-control");
  assert.equal(Object.hasOwn(result, "status_code"), false);
});
test("Rust model_mount admission runner sends positive server-control request", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    daemonCoreInvoker(request) {
      calls.push({ request });
      return {
        ok: true,
        result: {
          source: "rust_model_mount_server_control_command",
          backend: RUST_MODEL_MOUNT_SERVER_CONTROL_BACKEND,
          plan: {
            schema_version: "ioi.model_mount.server_control_plan.v1",
            object: "ioi.model_mount_server_control_plan",
            status: "planned",
            rust_core_boundary: "model_mount.server_control",
            operation_kind: request.request.operation_kind,
            source: request.request.source,
            record_dir: "model-server-controls",
            record_id: "server-control:positive",
            record: {
              id: "server-control:positive",
              object: "ioi.model_mount_server_control_record",
              rust_core_boundary: "model_mount.server_control",
              operation_kind: request.request.operation_kind,
            },
            public_response: {
              object: "ioi.model_mount_server_control",
              status: "planned",
              operation_kind: request.request.operation_kind,
            },
            receipt_refs: request.request.receipt_refs,
            evidence_refs: [
              "public_server_control_js_facade_retired",
              "rust_daemon_core_server_control",
              "agentgres_server_control_truth_required",
            ],
            control_hash: "sha256:server-control",
          },
          record_dir: "model-server-controls",
          record_id: "server-control:positive",
          record: {
            id: "server-control:positive",
            object: "ioi.model_mount_server_control_record",
            rust_core_boundary: "model_mount.server_control",
            operation_kind: request.request.operation_kind,
          },
          public_response: {
            object: "ioi.model_mount_server_control",
            status: "planned",
            operation_kind: request.request.operation_kind,
          },
          receipt_refs: request.request.receipt_refs,
          evidence_refs: [
            "public_server_control_js_facade_retired",
            "rust_daemon_core_server_control",
            "agentgres_server_control_truth_required",
          ],
          control_hash: "sha256:server-control",
          operation_kind: request.request.operation_kind,
          rust_core_boundary: "model_mount.server_control",
        },
      };
    },
  });

  const result = runner.planServerControl(serverControlRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "plan_model_mount_server_control");
  assert.equal(calls[0].request.backend, RUST_MODEL_MOUNT_SERVER_CONTROL_BACKEND);
  assert.equal(calls[0].request.request.schema_version, "ioi.model_mount.server_control.v1");
  assert.equal(calls[0].request.request.operation_kind, "model_mount.server_control.start");
  assert.equal(calls[0].request.request.body.base_url, "http://daemon.test");
  assert.equal(result.record_dir, "model-server-controls");
  assert.equal(result.operation_kind, "model_mount.server_control.start");
  assert.equal(result.rust_core_boundary, "model_mount.server_control");
  assert.equal(result.evidence_refs.includes("rust_daemon_core_server_control"), true);
  assert.equal(result.control_hash, "sha256:server-control");
});

test("Rust model_mount admission runner sends positive runtime-engine request", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    daemonCoreInvoker(request) {
      calls.push({ request });
      return {
        ok: true,
        result: {
          source: "rust_model_mount_runtime_engine_command",
          backend: RUST_MODEL_MOUNT_RUNTIME_ENGINE_BACKEND,
          plan: {
            schema_version: "ioi.model_mount.runtime_engine_plan.v1",
            object: "ioi.model_mount_runtime_engine_plan",
            status: "planned",
            rust_core_boundary: "model_mount.runtime_engine",
            operation_kind: request.request.operation_kind,
            source: request.request.source,
            record_dir: "runtime-engine-controls",
            record_id: "runtime-engine-control:positive",
            record: {
              id: "runtime-engine-control:positive",
              object: "ioi.model_mount_runtime_engine_record",
              engine_id: request.request.engine_id,
              rust_core_boundary: "model_mount.runtime_engine",
              operation_kind: request.request.operation_kind,
            },
            public_response: {
              object: "ioi.model_mount_runtime_engine",
              status: "planned",
              engine_id: request.request.engine_id,
              operation_kind: request.request.operation_kind,
            },
            receipt_refs: request.request.receipt_refs,
            evidence_refs: [
              "public_runtime_engine_js_facade_retired",
              "rust_daemon_core_runtime_engine",
              "agentgres_runtime_engine_truth_required",
            ],
            control_hash: "sha256:runtime-engine",
          },
          record_dir: "runtime-engine-controls",
          record_id: "runtime-engine-control:positive",
          record: {
            id: "runtime-engine-control:positive",
            object: "ioi.model_mount_runtime_engine_record",
            engine_id: request.request.engine_id,
            rust_core_boundary: "model_mount.runtime_engine",
            operation_kind: request.request.operation_kind,
          },
          public_response: {
            object: "ioi.model_mount_runtime_engine",
            status: "planned",
            engine_id: request.request.engine_id,
            operation_kind: request.request.operation_kind,
          },
          receipt_refs: request.request.receipt_refs,
          evidence_refs: [
            "public_runtime_engine_js_facade_retired",
            "rust_daemon_core_runtime_engine",
            "agentgres_runtime_engine_truth_required",
          ],
          control_hash: "sha256:runtime-engine",
          operation_kind: request.request.operation_kind,
          rust_core_boundary: "model_mount.runtime_engine",
        },
      };
    },
  });

  const result = runner.planRuntimeEngine(runtimeEngineRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "plan_model_mount_runtime_engine");
  assert.equal(calls[0].request.backend, RUST_MODEL_MOUNT_RUNTIME_ENGINE_BACKEND);
  assert.equal(calls[0].request.request.schema_version, "ioi.model_mount.runtime_engine.v1");
  assert.equal(calls[0].request.request.operation_kind, "model_mount.runtime_engine_profile.write");
  assert.equal(calls[0].request.request.engine_id, "backend.llama-cpp");
  assert.equal(calls[0].request.request.body.default_load_options.gpu_layers, 4);
  assert.equal(result.record_dir, "runtime-engine-controls");
  assert.equal(result.operation_kind, "model_mount.runtime_engine_profile.write");
  assert.equal(result.rust_core_boundary, "model_mount.runtime_engine");
  assert.equal(result.evidence_refs.includes("rust_daemon_core_runtime_engine"), true);
  assert.equal(result.control_hash, "sha256:runtime-engine");
});

test("Rust model_mount admission runner sends positive runtime-survey request", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    daemonCoreInvoker(request) {
      calls.push({ request });
      return {
        ok: true,
        result: {
          source: "rust_model_mount_runtime_survey_command",
          backend: RUST_MODEL_MOUNT_RUNTIME_SURVEY_BACKEND,
          plan: {
            schema_version: "ioi.model_mount.runtime_survey_plan.v1",
            object: "ioi.model_mount_runtime_survey_plan",
            status: "planned",
            rust_core_boundary: "model_mount.runtime_survey",
            operation_kind: request.request.operation_kind,
            source: request.request.source,
            receipt: {
              id: "receipt_runtime_survey_test",
              kind: "runtime_survey",
              schemaVersion: "ioi.model-mounting.runtime.v1",
              createdAt: request.request.generated_at,
              redaction: "redacted",
              evidenceRefs: [
                "model_mount_runtime_survey_js_facade_retired",
                "rust_daemon_core_runtime_survey",
                "agentgres_runtime_survey_truth_required",
                "rust_model_mount_core",
              ],
              details: {
                checked_at: request.request.generated_at,
                engine_count: 1,
                selected_engines: [{ id: "backend.llama-cpp", selected: true }],
                runtime_preference: { selected_engine_id: "backend.llama-cpp" },
                hardware: { status: "checked", js_probe_execution: false },
                lm_studio: { status: "not_checked", js_cli_execution: false },
                runtime_survey_hash: "sha256:runtime-survey",
                rust_daemon_core_receipt_author: "model_mount.runtime_survey",
                js_hardware_probe_executed: false,
                js_runtime_engine_read_executed: false,
                js_lm_studio_probe_executed: false,
              },
            },
            public_response: {
              object: "ioi.model_mount_runtime_survey",
              status: "checked",
              receiptId: "receipt_runtime_survey_test",
              engineCount: 1,
            },
            receipt_refs: ["receipt_runtime_survey_test"],
            evidence_refs: [
              "model_mount_runtime_survey_js_facade_retired",
              "rust_daemon_core_runtime_survey",
              "agentgres_runtime_survey_truth_required",
              "rust_model_mount_core",
            ],
            survey_hash: "sha256:runtime-survey",
          },
          receipt: {
            id: "receipt_runtime_survey_test",
            kind: "runtime_survey",
            schemaVersion: "ioi.model-mounting.runtime.v1",
            createdAt: request.request.generated_at,
            redaction: "redacted",
            evidenceRefs: [
              "model_mount_runtime_survey_js_facade_retired",
              "rust_daemon_core_runtime_survey",
              "agentgres_runtime_survey_truth_required",
              "rust_model_mount_core",
            ],
            details: {
              checked_at: request.request.generated_at,
              engine_count: 1,
              selected_engines: [{ id: "backend.llama-cpp", selected: true }],
              runtime_preference: { selected_engine_id: "backend.llama-cpp" },
              hardware: { status: "checked", js_probe_execution: false },
              lm_studio: { status: "not_checked", js_cli_execution: false },
              runtime_survey_hash: "sha256:runtime-survey",
              rust_daemon_core_receipt_author: "model_mount.runtime_survey",
              js_hardware_probe_executed: false,
              js_runtime_engine_read_executed: false,
              js_lm_studio_probe_executed: false,
            },
          },
          public_response: {
            object: "ioi.model_mount_runtime_survey",
            status: "checked",
            receiptId: "receipt_runtime_survey_test",
            engineCount: 1,
          },
          receipt_refs: ["receipt_runtime_survey_test"],
          evidence_refs: [
            "model_mount_runtime_survey_js_facade_retired",
            "rust_daemon_core_runtime_survey",
            "agentgres_runtime_survey_truth_required",
            "rust_model_mount_core",
          ],
          survey_hash: "sha256:runtime-survey",
          operation_kind: request.request.operation_kind,
          rust_core_boundary: "model_mount.runtime_survey",
        },
      };
    },
  });

  const result = runner.planRuntimeSurvey(runtimeSurveyRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "plan_model_mount_runtime_survey");
  assert.equal(calls[0].request.backend, RUST_MODEL_MOUNT_RUNTIME_SURVEY_BACKEND);
  assert.equal(calls[0].request.request.schema_version, "ioi.model_mount.runtime_survey.v1");
  assert.equal(calls[0].request.request.operation_kind, "model_mount.runtime_survey.capture");
  assert.equal(calls[0].request.request.state_dir, "/runtime-state");
  assert.equal(Object.hasOwn(calls[0].request.request, "hardware"), false);
  assert.equal(Object.hasOwn(calls[0].request.request, "engines"), false);
  assert.equal(result.receipt.kind, "runtime_survey");
  assert.equal(result.receipt.details.engine_count, 1);
  assert.equal(result.rust_core_boundary, "model_mount.runtime_survey");
  assert.equal(result.survey_hash, "sha256:runtime-survey");
});

test("Rust model_mount admission runner sends tokenizer required request", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    daemonCoreInvoker(request) {
      calls.push({ request });
      return {
        ok: true,
        result: {
            source: "rust_model_mount_tokenizer_required_command",
            backend: RUST_MODEL_MOUNT_TOKENIZER_REQUIRED_BACKEND,
            record: {
              schema_version: "ioi.model_mount.tokenizer_required_result.v1",
              object: "ioi.model_mount_tokenizer_required",
              status: "rust_core_required",
              status_code: 501,
              code: "model_mount_tokenizer_rust_core_required",
              message:
                "Model tokenization and context-fit utilities require direct Rust daemon-core admission and projection.",
              rust_core_boundary: "model_mount.tokenizer",
              operation: request.request.operation,
              source: request.request.source,
              evidence_refs: request.request.evidence_refs,
              details: {
                operation: request.request.operation,
                ...request.request.details,
                rust_core_boundary: "model_mount.tokenizer",
                source: request.request.source,
                evidence_refs: request.request.evidence_refs,
              },
              generated_at: "rust_model_mount_core",
            },
            status: "rust_core_required",
            status_code: 501,
            code: "model_mount_tokenizer_rust_core_required",
            message:
              "Model tokenization and context-fit utilities require direct Rust daemon-core admission and projection.",
            rust_core_boundary: "model_mount.tokenizer",
            operation: request.request.operation,
            details: {
              operation: request.request.operation,
              ...request.request.details,
              rust_core_boundary: "model_mount.tokenizer",
              source: request.request.source,
              evidence_refs: request.request.evidence_refs,
            },
          },
      };
    },
  });

  const result = runner.planTokenizerRequired(tokenizerRequiredRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "plan_model_mount_tokenizer_required");
  assert.equal(calls[0].request.backend, RUST_MODEL_MOUNT_TOKENIZER_REQUIRED_BACKEND);
  assert.equal(calls[0].request.request.schema_version, "ioi.model_mount.tokenizer_required.v1");
  assert.equal(calls[0].request.request.operation, "context_fit");
  assert.equal(calls[0].request.request.details.route_id, "route.local-first");
  assert.equal(result.status, "rust_core_required");
  assert.equal(result.status_code, 501);
  assert.equal(result.code, "model_mount_tokenizer_rust_core_required");
  assert.equal(result.details.operation, "context_fit");
  assert.equal(result.details.model, "llama-test");
  assert.equal(result.details.route_id, "route.local-first");
  assert.equal(result.details.requested_scope, "model.context:*");
  assert.equal(Object.hasOwn(result.details, "routeId"), false);
  assert.equal(Object.hasOwn(result.details, "requestedScope"), false);
});

test("Rust model_mount admission runner sends route control required request", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    daemonCoreInvoker(request) {
      calls.push({ request });
      return {
        ok: true,
        result: {
            source: "rust_model_mount_route_control_required_command",
            backend: RUST_MODEL_MOUNT_ROUTE_CONTROL_REQUIRED_BACKEND,
            record: {
              schema_version: "ioi.model_mount.route_control_required_result.v1",
              object: "ioi.model_mount_route_control_required",
              status: "rust_core_required",
              status_code: 501,
              code: "model_mount_route_control_rust_core_required",
              message: "Model route control requires Rust daemon-core ownership.",
              rust_core_boundary: "model_mount.route_control",
              operation: request.request.operation,
              operation_kind: request.request.operation_kind,
              source: request.request.source,
              evidence_refs: request.request.evidence_refs,
              details: {
                operation: request.request.operation,
                ...request.request.details,
                operation_kind: request.request.operation_kind,
                rust_core_boundary: "model_mount.route_control",
                source: request.request.source,
                evidence_refs: request.request.evidence_refs,
              },
              generated_at: "rust_model_mount_core",
            },
            status: "rust_core_required",
            status_code: 501,
            code: "model_mount_route_control_rust_core_required",
            message: "Model route control requires Rust daemon-core ownership.",
            rust_core_boundary: "model_mount.route_control",
            operation: request.request.operation,
            operation_kind: request.request.operation_kind,
            details: {
              operation: request.request.operation,
              ...request.request.details,
              operation_kind: request.request.operation_kind,
              rust_core_boundary: "model_mount.route_control",
              source: request.request.source,
              evidence_refs: request.request.evidence_refs,
            },
          },
      };
    },
  });

  const result = runner.planRouteControlRequired(routeControlRequiredRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "plan_model_mount_route_control_required");
  assert.equal(calls[0].request.backend, RUST_MODEL_MOUNT_ROUTE_CONTROL_REQUIRED_BACKEND);
  assert.equal(calls[0].request.request.schema_version, "ioi.model_mount.route_control_required.v1");
  assert.equal(calls[0].request.request.operation_kind, "model_mount.route.selection_update");
  assert.equal(calls[0].request.request.details.route_id, "route.local-first");
  assert.equal(result.status, "rust_core_required");
  assert.equal(result.status_code, 501);
  assert.equal(result.code, "model_mount_route_control_rust_core_required");
  assert.equal(result.details.route_id, "route.local-first");
  assert.equal(result.details.selected_model, "model.local");
  assert.equal(result.details.receipt_id, "receipt-route-test");
  assert.equal(result.details.route_selection_boundary, "model_mount.route_selection");
  assert.equal(Object.hasOwn(result.details, "routeId"), false);
  assert.equal(Object.hasOwn(result.details, "selectedModel"), false);
  assert.equal(Object.hasOwn(result.details, "receiptId"), false);
});

test("Rust model_mount admission runner sends positive tokenizer request", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    daemonCoreInvoker(request) {
      calls.push({ request });
      const record = {
        id: "model_tokenizer:tokenize:test",
        object: "ioi.model_mount_tokenizer_result",
        status: "planned",
        operation: request.request.operation,
        route_id: "route.local-first",
        model: "llama-test",
        endpoint_id: "endpoint.local.llama",
        provider_id: "provider.local",
        token_count: 3,
        tokens: ["one", "two", "three"],
      };
      return {
        ok: true,
        result: {
          source: "rust_model_mount_tokenizer_command",
          backend: RUST_MODEL_MOUNT_TOKENIZER_BACKEND,
          plan: {
            schema_version: "ioi.model_mount.tokenizer_plan.v1",
            object: "ioi.model_mount_tokenizer_plan",
            status: "planned",
            rust_core_boundary: "model_mount.tokenizer",
            operation: request.request.operation,
            source: request.request.source,
            record_dir: "model-tokenizer-utilities",
            record_id: record.id,
            record,
            receipt_refs: ["receipt://route-selection/test"],
            evidence_refs: ["model_mount_tokenizer_rust_owned"],
            control_hash: "sha256:tokenizer-control",
          },
          record_dir: "model-tokenizer-utilities",
          record_id: record.id,
          record,
          receipt_refs: ["receipt://route-selection/test"],
          evidence_refs: ["model_mount_tokenizer_rust_owned"],
          operation: request.request.operation,
          rust_core_boundary: "model_mount.tokenizer",
          control_hash: "sha256:tokenizer-control",
        },
      };
    },
  });

  const result = runner.planTokenizer(tokenizerRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "plan_model_mount_tokenizer");
  assert.equal(calls[0].request.backend, RUST_MODEL_MOUNT_TOKENIZER_BACKEND);
  assert.equal(calls[0].request.request.schema_version, "ioi.model_mount.tokenizer.v1");
  assert.equal(calls[0].request.request.operation, "tokenize");
  assert.equal(calls[0].request.request.route_selection.route_decision.route_decision_ref, "model_mount://route_decision/test");
  assert.equal(result.record_dir, "model-tokenizer-utilities");
  assert.equal(result.record_id, "model_tokenizer:tokenize:test");
  assert.equal(result.record.token_count, 3);
  assert.deepEqual(result.receipt_refs, ["receipt://route-selection/test"]);
  assert.equal(result.rust_core_boundary, "model_mount.tokenizer");
  assert.equal(result.evidence_refs.includes("model_mount_tokenizer_rust_owned"), true);
});

test("Rust model_mount admission runner sends positive route control request", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    daemonCoreInvoker(request) {
      calls.push({ request });
      const record = {
        id: request.request.route_id,
        role: request.request.body.role,
        fallback: request.request.body.fallback,
        providerEligibility: request.request.body.provider_eligibility,
        receiptRefs: ["receipt://route-control/write"],
      };
      return {
        ok: true,
        result: {
          source: "rust_model_mount_route_control_command",
          backend: RUST_MODEL_MOUNT_ROUTE_CONTROL_BACKEND,
          plan: {
            schema_version: "ioi.model_mount.route_control_plan.v1",
            object: "ioi.model_mount_route_control_plan",
            status: "planned",
            rust_core_boundary: "model_mount.route_control",
            operation_kind: request.request.operation_kind,
            source: request.request.source,
            record_dir: "model-routes",
            record_id: record.id,
            record,
            receipt_refs: ["receipt://route-control/write"],
            evidence_refs: ["model_mount_route_control_rust_owned"],
            control_hash: "sha256:route-control",
          },
          record_dir: "model-routes",
          record_id: record.id,
          record,
          receipt_refs: ["receipt://route-control/write"],
          evidence_refs: ["model_mount_route_control_rust_owned"],
          operation_kind: request.request.operation_kind,
          rust_core_boundary: "model_mount.route_control",
          control_hash: "sha256:route-control",
        },
      };
    },
  });

  const result = runner.planRouteControl(routeControlRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "plan_model_mount_route_control");
  assert.equal(calls[0].request.backend, RUST_MODEL_MOUNT_ROUTE_CONTROL_BACKEND);
  assert.equal(calls[0].request.request.schema_version, "ioi.model_mount.route_control.v1");
  assert.equal(calls[0].request.request.operation_kind, "model_mount.route.write");
  assert.equal(result.record_dir, "model-routes");
  assert.equal(result.record_id, "route.review");
  assert.equal(result.record.id, "route.review");
  assert.deepEqual(result.receipt_refs, ["receipt://route-control/write"]);
  assert.equal(result.rust_core_boundary, "model_mount.route_control");
  assert.equal(result.evidence_refs.includes("model_mount_route_control_rust_owned"), true);
});

test("Rust model_mount admission runner sends positive artifact-endpoint request", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    daemonCoreInvoker(request) {
      calls.push({ request });
      const record = {
        id: "endpoint.provider.local.folder.local.test",
        record_id: "endpoint.provider.local.folder.local.test",
        object: "ioi.model_mount_endpoint",
        status: "mounted",
        operation_kind: request.request.operation_kind,
        rust_core_boundary: "model_mount.artifact_endpoint",
        model_id: request.request.body.model_id,
        provider_id: request.request.body.provider_id,
        public_response: {
          object: "ioi.model_mount_endpoint",
          status: "mounted",
          id: "endpoint.provider.local.folder.local.test",
          endpoint_id: "endpoint.provider.local.folder.local.test",
          model_id: request.request.body.model_id,
          provider_id: request.request.body.provider_id,
          plaintext_transport_material_returned: false,
        },
        receipt_refs: ["receipt://artifact-endpoint"],
        evidence_refs: [
          "public_artifact_endpoint_js_facade_retired",
          "rust_daemon_core_artifact_endpoint",
          "agentgres_artifact_endpoint_truth_required",
          "rust_daemon_core_model_endpoint_mount",
        ],
        control_hash: "sha256:artifact-endpoint-control",
        authority_hash: "sha256:artifact-endpoint-authority",
      };
      return {
        ok: true,
        result: {
          source: "rust_model_mount_artifact_endpoint_command",
          backend: RUST_MODEL_MOUNT_ARTIFACT_ENDPOINT_BACKEND,
          plan: {
            schema_version: "ioi.model_mount.artifact_endpoint_plan.v1",
            object: "ioi.model_mount_artifact_endpoint_plan",
            status: "planned",
            rust_core_boundary: "model_mount.artifact_endpoint",
            operation_kind: request.request.operation_kind,
            source: request.request.source,
            record_dir: "model-endpoints",
            record_id: record.id,
            record,
            public_response: record.public_response,
            receipt_refs: ["receipt://artifact-endpoint"],
            authority_grant_refs: ["grant://wallet/model-mount"],
            authority_receipt_refs: ["receipt://wallet/model-mount"],
            evidence_refs: record.evidence_refs,
            control_hash: "sha256:artifact-endpoint-control",
            authority_hash: "sha256:artifact-endpoint-authority",
          },
          record_dir: "model-endpoints",
          record_id: record.id,
          record,
          public_response: record.public_response,
          receipt_refs: ["receipt://artifact-endpoint"],
          authority_grant_refs: ["grant://wallet/model-mount"],
          authority_receipt_refs: ["receipt://wallet/model-mount"],
          evidence_refs: record.evidence_refs,
          operation_kind: request.request.operation_kind,
          rust_core_boundary: "model_mount.artifact_endpoint",
          control_hash: "sha256:artifact-endpoint-control",
          authority_hash: "sha256:artifact-endpoint-authority",
        },
      };
    },
  });

  const result = runner.planArtifactEndpoint(artifactEndpointRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "plan_model_mount_artifact_endpoint");
  assert.equal(calls[0].request.backend, RUST_MODEL_MOUNT_ARTIFACT_ENDPOINT_BACKEND);
  assert.equal(calls[0].request.request.schema_version, "ioi.model_mount.artifact_endpoint.v1");
  assert.equal(calls[0].request.request.operation_kind, "model_mount.endpoint.mount");
  assert.equal(calls[0].request.request.body.model_id, "local:test");
  assert.equal(calls[0].request.request.required_scope, "model.endpoint.mount:local:test");
  assert.equal(result.record_dir, "model-endpoints");
  assert.equal(result.record_id, "endpoint.provider.local.folder.local.test");
  assert.equal(result.record.public_response.plaintext_transport_material_returned, false);
  assert.deepEqual(result.authority_grant_refs, ["grant://wallet/model-mount"]);
  assert.equal(result.authority_hash, "sha256:artifact-endpoint-authority");
  assert.equal(result.rust_core_boundary, "model_mount.artifact_endpoint");
  assert.equal(result.evidence_refs.includes("agentgres_artifact_endpoint_truth_required"), true);
});

test("Rust model_mount admission runner sends positive storage-control request", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    daemonCoreInvoker(request) {
      calls.push({ request });
      const record = {
        id: "download.local.test",
        record_id: "download.local.test",
        object: "ioi.model_mount_download",
        status: "queued",
        operation_kind: request.request.operation_kind,
        rust_core_boundary: "model_mount.storage_control",
        details: {
          model_id: request.request.body.model_id,
          provider_id: request.request.body.provider_id,
          network_transfer_executed: false,
        },
        public_response: {
          object: "ioi.model_mount_download",
          status: "queued",
          id: "download.local.test",
          record_id: "download.local.test",
          record_dir: "model-downloads",
          operation_kind: request.request.operation_kind,
          rust_core_boundary: "model_mount.storage_control",
          js_network_transfer_executed: false,
          js_filesystem_mutation_executed: false,
        },
        receipt_refs: ["receipt://storage-control"],
        evidence_refs: [
          "public_model_storage_js_facade_retired",
          "rust_daemon_core_model_storage",
          "agentgres_model_storage_truth_required",
          "public_catalog_download_js_facade_retired",
          "rust_daemon_core_catalog_download",
          "agentgres_catalog_download_truth_required",
        ],
        control_hash: "sha256:storage-control",
        authority_hash: "sha256:storage-authority",
      };
      return {
        ok: true,
        result: {
          source: "rust_model_mount_storage_control_command",
          backend: RUST_MODEL_MOUNT_STORAGE_CONTROL_BACKEND,
          plan: {
            schema_version: "ioi.model_mount.storage_control_plan.v1",
            object: "ioi.model_mount_storage_control_plan",
            status: "planned",
            rust_core_boundary: "model_mount.storage_control",
            operation_kind: request.request.operation_kind,
            source: request.request.source,
            record_dir: "model-downloads",
            record_id: record.id,
            record,
            public_response: record.public_response,
            receipt_refs: ["receipt://storage-control"],
            authority_grant_refs: ["grant://wallet/storage"],
            authority_receipt_refs: ["receipt://wallet/storage"],
            evidence_refs: record.evidence_refs,
            control_hash: "sha256:storage-control",
            authority_hash: "sha256:storage-authority",
          },
          record_dir: "model-downloads",
          record_id: record.id,
          record,
          public_response: record.public_response,
          receipt_refs: ["receipt://storage-control"],
          authority_grant_refs: ["grant://wallet/storage"],
          authority_receipt_refs: ["receipt://wallet/storage"],
          evidence_refs: record.evidence_refs,
          operation_kind: request.request.operation_kind,
          rust_core_boundary: "model_mount.storage_control",
          control_hash: "sha256:storage-control",
          authority_hash: "sha256:storage-authority",
        },
      };
    },
  });

  const result = runner.planStorageControl(storageControlRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "plan_model_mount_storage_control");
  assert.equal(calls[0].request.backend, RUST_MODEL_MOUNT_STORAGE_CONTROL_BACKEND);
  assert.equal(calls[0].request.request.schema_version, "ioi.model_mount.storage_control.v1");
  assert.equal(calls[0].request.request.operation_kind, "model_mount.download.queue");
  assert.equal(calls[0].request.request.body.model_id, "local:test");
  assert.equal(calls[0].request.request.required_scope, "model.download.queue:local:test");
  assert.equal(result.record_dir, "model-downloads");
  assert.equal(result.record_id, "download.local.test");
  assert.equal(result.record.public_response.js_network_transfer_executed, false);
  assert.deepEqual(result.authority_grant_refs, ["grant://wallet/storage"]);
  assert.equal(result.authority_hash, "sha256:storage-authority");
  assert.equal(result.rust_core_boundary, "model_mount.storage_control");
  assert.equal(result.evidence_refs.includes("agentgres_model_storage_truth_required"), true);
});

test("Rust model_mount admission runner sends positive MCP workflow request", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    daemonCoreInvoker(request) {
      calls.push({ request });
      const record = {
        id: "mcp_import.alpha",
        object: "ioi.model_mount_mcp_workflow",
        status: "committed",
        operation_kind: request.request.operation_kind,
        rust_core_boundary: "model_mount.mcp_workflow",
        details: {
          server_ids: ["mcp.docs"],
          js_registry_mutation: false,
        },
        receipt_refs: ["receipt://mcp-import"],
        evidence_refs: [
          "rust_daemon_core_model_mount_mcp_workflow",
          "agentgres_mcp_workflow_truth_required",
        ],
        workflow_hash: "sha256:mcp-workflow",
        authority_hash: "sha256:mcp-authority",
      };
      return {
        ok: true,
        result: {
          source: "rust_model_mount_mcp_workflow_command",
          backend: request.backend,
          plan: {
            status: "committed",
            rust_core_boundary: "model_mount.mcp_workflow",
            operation_kind: request.request.operation_kind,
            record_dir: "mcp-servers",
            record_id: record.id,
            record,
            public_response: {
              status: "committed",
              operation_kind: request.request.operation_kind,
              server_ids: ["mcp.docs"],
            },
            receipt_refs: ["receipt://mcp-import"],
            authority_grant_refs: [],
            authority_receipt_refs: [],
            evidence_refs: record.evidence_refs,
            workflow_hash: record.workflow_hash,
            authority_hash: record.authority_hash,
          },
          record_dir: "mcp-servers",
          record_id: record.id,
          record,
          public_response: {
            status: "committed",
            operation_kind: request.request.operation_kind,
            server_ids: ["mcp.docs"],
          },
          receipt_refs: ["receipt://mcp-import"],
          authority_grant_refs: [],
          authority_receipt_refs: [],
          evidence_refs: record.evidence_refs,
          operation_kind: request.request.operation_kind,
          rust_core_boundary: "model_mount.mcp_workflow",
          workflow_hash: record.workflow_hash,
          authority_hash: record.authority_hash,
        },
      };
    },
  });

  const result = runner.planMcpWorkflow({
    schema_version: "ioi.model_mount.mcp_workflow.v1",
    operation_kind: "model_mount.mcp_server.import",
    body: {
      mcp_servers: {
        Docs: { url: "https://example.test/mcp", allowed_tools: ["search"] },
      },
    },
    required_scope: "model.mcp.import",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "plan_model_mount_mcp_workflow");
  assert.equal(calls[0].request.backend, RUST_MODEL_MOUNT_MCP_WORKFLOW_BACKEND);
  assert.equal(calls[0].request.request.schema_version, "ioi.model_mount.mcp_workflow.v1");
  assert.equal(calls[0].request.request.operation_kind, "model_mount.mcp_server.import");
  assert.equal(calls[0].request.request.body.mcp_servers.Docs.url, "https://example.test/mcp");
  assert.equal(result.record_dir, "mcp-servers");
  assert.equal(result.record_id, "mcp_import.alpha");
  assert.equal(result.rust_core_boundary, "model_mount.mcp_workflow");
  assert.equal(result.workflow_hash, "sha256:mcp-workflow");
  assert.equal(result.evidence_refs.includes("agentgres_mcp_workflow_truth_required"), true);
});

test("Rust model_mount admission runner sends positive catalog-provider-control request", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    daemonCoreInvoker(request) {
      calls.push({ request });
      const record = {
        id: "catalog_provider_control:catalog.huggingface:test",
        object: "ioi.model_mount_catalog_provider_control",
        status: "planned",
        operation_kind: request.request.operation_kind,
        provider_id: request.request.provider_id,
        rust_core_boundary: "model_mount.catalog_provider_control",
        plaintext_material_returned: false,
        public_response: {
          object: "ioi.model_catalog_provider_config_write",
          provider_id: request.request.provider_id,
          status: "accepted",
          private_material_returned: false,
        },
      };
      return {
        ok: true,
        result: {
          source: "rust_model_mount_catalog_provider_control_command",
          backend: RUST_MODEL_MOUNT_CATALOG_PROVIDER_CONTROL_BACKEND,
          plan: {
            schema_version: "ioi.model_mount.catalog_provider_control_plan.v1",
            object: "ioi.model_mount_catalog_provider_control_plan",
            status: "planned",
            rust_core_boundary: "model_mount.catalog_provider_control",
            operation_kind: request.request.operation_kind,
            source: request.request.source,
            record_dir: "model-catalog-provider-controls",
            record_id: record.id,
            record,
            receipt_refs: ["receipt://catalog-provider-control"],
            authority_grant_refs: ["grant://wallet/provider-write"],
            authority_receipt_refs: ["receipt://wallet/provider-write"],
            evidence_refs: [
              "rust_daemon_core_catalog_provider_control",
              "ctee_catalog_provider_custody_enforced",
              "agentgres_catalog_provider_control_truth_required",
            ],
            control_hash: "sha256:catalog-provider-control",
            authority_hash: "sha256:catalog-provider-authority",
          },
          record_dir: "model-catalog-provider-controls",
          record_id: record.id,
          record,
          receipt_refs: ["receipt://catalog-provider-control"],
          authority_grant_refs: ["grant://wallet/provider-write"],
          authority_receipt_refs: ["receipt://wallet/provider-write"],
          evidence_refs: [
            "rust_daemon_core_catalog_provider_control",
            "ctee_catalog_provider_custody_enforced",
            "agentgres_catalog_provider_control_truth_required",
          ],
          operation_kind: request.request.operation_kind,
          rust_core_boundary: "model_mount.catalog_provider_control",
          control_hash: "sha256:catalog-provider-control",
          authority_hash: "sha256:catalog-provider-authority",
        },
      };
    },
  });

  const result = runner.planCatalogProviderControl(catalogProviderControlRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "plan_model_mount_catalog_provider_control");
  assert.equal(calls[0].request.backend, RUST_MODEL_MOUNT_CATALOG_PROVIDER_CONTROL_BACKEND);
  assert.equal(calls[0].request.request.schema_version, "ioi.model_mount.catalog_provider_control.v1");
  assert.equal(calls[0].request.request.operation_kind, "model_mount.catalog_provider_configuration.write");
  assert.equal(calls[0].request.request.provider_id, "catalog.huggingface");
  assert.equal(calls[0].request.request.custody_ref, "ctee://catalog-provider/huggingface");
  assert.equal(result.record_dir, "model-catalog-provider-controls");
  assert.equal(result.record_id, "catalog_provider_control:catalog.huggingface:test");
  assert.equal(result.record.plaintext_material_returned, false);
  assert.deepEqual(result.authority_grant_refs, ["grant://wallet/provider-write"]);
  assert.deepEqual(result.authority_receipt_refs, ["receipt://wallet/provider-write"]);
  assert.equal(result.authority_hash, "sha256:catalog-provider-authority");
  assert.equal(result.rust_core_boundary, "model_mount.catalog_provider_control");
  assert.equal(result.evidence_refs.includes("ctee_catalog_provider_custody_enforced"), true);
});

test("Rust model_mount admission runner sends positive provider-control request", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    daemonCoreInvoker(request) {
      calls.push({ request });
      const record = {
        id: "provider.openai",
        record_id: "provider.openai",
        object: "ioi.model_mount_provider",
        schema_version: "ioi.model_mount.provider_control.v1",
        status: "configured",
        operation_kind: request.request.operation_kind,
        provider_id: request.request.provider_id,
        provider_ref: "provider://provider.openai",
        rust_core_boundary: "model_mount.provider_control",
        plaintext_material_returned: false,
        public_response: {
          object: "ioi.model_mount_provider",
          provider_id: request.request.provider_id,
          status: "configured",
          private_material_returned: false,
          plaintext_material_persisted: false,
        },
        evidence_refs: [
          "rust_daemon_core_provider_control",
          "ctee_provider_custody_enforced",
          "agentgres_provider_control_truth_required",
          "public_provider_control_js_facade_retired",
        ],
      };
      return {
        ok: true,
        result: {
          source: "rust_model_mount_provider_control_command",
          backend: RUST_MODEL_MOUNT_PROVIDER_CONTROL_BACKEND,
          plan: {
            schema_version: "ioi.model_mount.provider_control_plan.v1",
            object: "ioi.model_mount_provider_control_plan",
            status: "planned",
            rust_core_boundary: "model_mount.provider_control",
            operation_kind: request.request.operation_kind,
            source: request.request.source,
            record_dir: "model-providers",
            record_id: record.id,
            record,
            receipt_refs: ["receipt://provider-control"],
            authority_grant_refs: ["grant://wallet/provider-write"],
            authority_receipt_refs: ["receipt://wallet/provider-write"],
            evidence_refs: record.evidence_refs,
            control_hash: "sha256:provider-control",
            authority_hash: "sha256:provider-authority",
          },
          record_dir: "model-providers",
          record_id: record.id,
          record,
          receipt_refs: ["receipt://provider-control"],
          authority_grant_refs: ["grant://wallet/provider-write"],
          authority_receipt_refs: ["receipt://wallet/provider-write"],
          evidence_refs: record.evidence_refs,
          operation_kind: request.request.operation_kind,
          rust_core_boundary: "model_mount.provider_control",
          control_hash: "sha256:provider-control",
          authority_hash: "sha256:provider-authority",
        },
      };
    },
  });

  const result = runner.planProviderControl(providerControlRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "plan_model_mount_provider_control");
  assert.equal(calls[0].request.backend, RUST_MODEL_MOUNT_PROVIDER_CONTROL_BACKEND);
  assert.equal(calls[0].request.request.schema_version, "ioi.model_mount.provider_control.v1");
  assert.equal(calls[0].request.request.operation_kind, "model_mount.provider.write");
  assert.equal(calls[0].request.request.provider_id, "provider.openai");
  assert.equal(calls[0].request.request.custody_ref, "ctee://provider/openai");
  assert.equal(result.record_dir, "model-providers");
  assert.equal(result.record_id, "provider.openai");
  assert.equal(result.record.plaintext_material_returned, false);
  assert.deepEqual(result.authority_grant_refs, ["grant://wallet/provider-write"]);
  assert.deepEqual(result.authority_receipt_refs, ["receipt://wallet/provider-write"]);
  assert.equal(result.authority_hash, "sha256:provider-authority");
  assert.equal(result.rust_core_boundary, "model_mount.provider_control");
  assert.equal(result.evidence_refs.includes("ctee_provider_custody_enforced"), true);
});

test("Rust model_mount admission runner sends positive capability-token-control request", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    daemonCoreInvoker(request) {
      calls.push({ request });
      const record = {
        id: "capability_token_control:capability_token.test:create",
        record_id: "capability_token_control:capability_token.test:create",
        object: "ioi.model_mount_capability_token_control",
        status: "planned",
        operation_kind: request.request.operation_kind,
        token_id: "capability_token:test",
        token_hash: "sha256:capability-token",
        rust_core_boundary: "model_mount.capability_token",
        wallet_authority_boundary: "wallet.network.capability_token",
        capability_token_authority: {
          authority_hash: "sha256:capability-token-authority",
          authority_grant_refs: request.request.authority_grant_refs,
          authority_receipt_refs: request.request.authority_receipt_refs,
        },
        public_response: {
          object: "ioi.model_mount_capability_token",
          status: "issued",
          token_id: "capability_token:test",
          token_material_returned_once: true,
          plaintext_material_persisted: false,
          token_hash: "sha256:capability-token",
        },
        receipt_refs: ["receipt://capability-token-control"],
        evidence_refs: [
          "rust_daemon_core_capability_token_control",
          "wallet_network_capability_token_authority_required",
          "agentgres_capability_token_truth_required",
          "public_capability_token_js_facade_retired",
        ],
        control_hash: "sha256:capability-token-control",
      };
      return {
        ok: true,
        result: {
          source: "rust_model_mount_capability_token_control_command",
          backend: RUST_MODEL_MOUNT_CAPABILITY_TOKEN_CONTROL_BACKEND,
          plan: {
            schema_version: "ioi.model_mount.capability_token_control_plan.v1",
            object: "ioi.model_mount_capability_token_control_plan",
            status: "planned",
            rust_core_boundary: "model_mount.capability_token",
            operation_kind: request.request.operation_kind,
            source: request.request.source,
            record_dir: "capability-tokens",
            record_id: record.id,
            record,
            public_response: {
              ...record.public_response,
              token: "ioi_mnt_positive_token",
            },
            receipt_refs: ["receipt://capability-token-control"],
            authority_grant_refs: ["grant://wallet/capability"],
            authority_receipt_refs: ["receipt://wallet/capability"],
            evidence_refs: record.evidence_refs,
            control_hash: "sha256:capability-token-control",
            authority_hash: "sha256:capability-token-authority",
          },
          record_dir: "capability-tokens",
          record_id: record.id,
          record,
          public_response: {
            ...record.public_response,
            token: "ioi_mnt_positive_token",
          },
          receipt_refs: ["receipt://capability-token-control"],
          authority_grant_refs: ["grant://wallet/capability"],
          authority_receipt_refs: ["receipt://wallet/capability"],
          evidence_refs: record.evidence_refs,
          operation_kind: request.request.operation_kind,
          rust_core_boundary: "model_mount.capability_token",
          control_hash: "sha256:capability-token-control",
          authority_hash: "sha256:capability-token-authority",
        },
      };
    },
  });

  const result = runner.planCapabilityTokenControl(capabilityTokenControlRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "plan_model_mount_capability_token_control");
  assert.equal(calls[0].request.backend, RUST_MODEL_MOUNT_CAPABILITY_TOKEN_CONTROL_BACKEND);
  assert.equal(calls[0].request.request.schema_version, "ioi.model_mount.capability_token_control.v1");
  assert.equal(calls[0].request.request.operation_kind, "model_mount.capability_token.create");
  assert.equal(calls[0].request.request.state_dir, "/tmp/ioi-model-mount-state");
  assert.deepEqual(calls[0].request.request.body.allowed, ["model.chat:*"]);
  assert.deepEqual(calls[0].request.request.authority_grant_refs, ["grant://wallet/capability"]);
  assert.equal(result.record_dir, "capability-tokens");
  assert.equal(result.record_id, "capability_token_control:capability_token.test:create");
  assert.equal(result.record.public_response.token, undefined);
  assert.equal(result.record.public_response.plaintext_material_persisted, false);
  assert.equal(result.public_response.token, "ioi_mnt_positive_token");
  assert.equal(result.authority_hash, "sha256:capability-token-authority");
  assert.equal(result.rust_core_boundary, "model_mount.capability_token");
  assert.equal(
    result.evidence_refs.includes("wallet_network_capability_token_authority_required"),
    true,
  );
});

test("Rust model_mount admission runner sends positive vault-control request", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    daemonCoreInvoker(request) {
      calls.push({ request });
      const record = {
        id: "vault_control:vault_ref.test:bind",
        record_id: "vault_control:vault_ref.test:bind",
        object: "ioi.model_mount_vault_control",
        status: "planned",
        operation_kind: request.request.operation_kind,
        vault_ref_hash: "sha256:vault-ref",
        material_hash: request.request.material_hash,
        rust_core_boundary: "model_mount.vault",
        wallet_authority_boundary: "wallet.network.vault",
        ctee_custody_boundary: "ctee.vault_custody",
        vault_authority: {
          authority_hash: "sha256:vault-authority",
          vault_ref_hash: "sha256:vault-ref",
          material_hash: request.request.material_hash,
          authority_grant_refs: request.request.authority_grant_refs,
          authority_receipt_refs: request.request.authority_receipt_refs,
        },
        ctee_custody: {
          custody_ref: "ctee://vault/custom",
          plaintext_material_persisted: false,
          plaintext_material_returned: false,
          material_hash: request.request.material_hash,
        },
        public_response: {
          object: "ioi.model_mount_vault_ref",
          status: "bound",
          id: "vault_ref.sha256:vault-ref",
          vault_ref_hash: "sha256:vault-ref",
          vault_ref: { redacted: true, hash: "sha256:vault-ref" },
          label: "Custom auth",
          purpose: "provider.auth:custom",
          material_hash: request.request.material_hash,
          custody_ref: "ctee://vault/custom",
          configured: true,
          material_bound: true,
          plaintext_material_persisted: false,
          plaintext_material_returned: false,
        },
        receipt_refs: ["receipt://vault-control"],
        evidence_refs: [
          "rust_daemon_core_vault_control",
          "wallet_network_vault_authority_required",
          "ctee_vault_custody_enforced",
          "agentgres_vault_truth_required",
          "public_vault_js_facade_retired",
        ],
        control_hash: "sha256:vault-control",
      };
      return {
        ok: true,
        result: {
          source: "rust_model_mount_vault_control_command",
          backend: RUST_MODEL_MOUNT_VAULT_CONTROL_BACKEND,
          plan: {
            schema_version: "ioi.model_mount.vault_control_plan.v1",
            object: "ioi.model_mount_vault_control_plan",
            status: "planned",
            rust_core_boundary: "model_mount.vault",
            operation_kind: request.request.operation_kind,
            source: request.request.source,
            record_dir: "vault-refs",
            record_id: record.id,
            record,
            public_response: record.public_response,
            receipt_refs: ["receipt://vault-control"],
            authority_grant_refs: ["grant://wallet/vault"],
            authority_receipt_refs: ["receipt://wallet/vault"],
            evidence_refs: record.evidence_refs,
            control_hash: "sha256:vault-control",
            authority_hash: "sha256:vault-authority",
          },
          record_dir: "vault-refs",
          record_id: record.id,
          record,
          public_response: record.public_response,
          receipt_refs: ["receipt://vault-control"],
          authority_grant_refs: ["grant://wallet/vault"],
          authority_receipt_refs: ["receipt://wallet/vault"],
          evidence_refs: record.evidence_refs,
          operation_kind: request.request.operation_kind,
          rust_core_boundary: "model_mount.vault",
          control_hash: "sha256:vault-control",
          authority_hash: "sha256:vault-authority",
        },
      };
    },
  });

  const result = runner.planVaultControl(vaultControlRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "plan_model_mount_vault_control");
  assert.equal(calls[0].request.backend, RUST_MODEL_MOUNT_VAULT_CONTROL_BACKEND);
  assert.equal(calls[0].request.request.schema_version, "ioi.model_mount.vault_control.v1");
  assert.equal(calls[0].request.request.operation_kind, "model_mount.vault_ref.bind");
  assert.equal(calls[0].request.request.state_dir, "/tmp/ioi-model-mount-state");
  assert.equal(calls[0].request.request.material_hash, "sha256:vault-material");
  assert.equal(Object.hasOwn(calls[0].request.request.body, "material"), false);
  assert.deepEqual(calls[0].request.request.authority_grant_refs, ["grant://wallet/vault"]);
  assert.equal(result.record_dir, "vault-refs");
  assert.equal(result.record_id, "vault_control:vault_ref.test:bind");
  assert.equal(result.record.public_response.material, undefined);
  assert.equal(result.record.ctee_custody.plaintext_material_persisted, false);
  assert.equal(result.record.ctee_custody.plaintext_material_returned, false);
  assert.equal(result.public_response.status, "bound");
  assert.equal(result.authority_hash, "sha256:vault-authority");
  assert.equal(result.rust_core_boundary, "model_mount.vault");
  assert.equal(result.evidence_refs.includes("ctee_vault_custody_enforced"), true);
});

test("Rust model_mount admission runner sends positive receipt-gate request", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    daemonCoreInvoker(request) {
      calls.push({ request });
      return {
        ok: true,
        result: {
          source: "rust_model_mount_receipt_gate_command",
          backend: RUST_MODEL_MOUNT_RECEIPT_GATE_BACKEND,
          plan: {
            schema_version: "ioi.model_mount.receipt_gate_plan.v1",
            object: "ioi.model_mount_receipt_gate_plan",
            status: "planned",
            rust_core_boundary: "model_mount.receipt_gate",
            operation_kind: request.request.operation_kind,
            receipt_id: request.request.receipt_id,
            gate_status: "passed",
            failures: [],
            receipt: {
              id: "receipt.workflow_receipt_gate.test",
              kind: "workflow_receipt_gate",
              redaction: "redacted",
              evidenceRefs: [
                "model_mount_receipt_gate_rust_owned",
                "model_mount_receipt_gate_js_facade_retired",
                "rust_receipt_binder_core",
                "agentgres_model_receipt_gate_truth_required",
              ],
              details: {
                model_mount_receipt_gate_hash: "sha256:receipt-gate",
                model_mount_receipt_binding_ref: "sha256:receipt-binding",
                model_mount_agentgres_operation_ref:
                  "agentgres://model-mounting/receipt-gates/receipt-gate",
              },
            },
            public_response: {
              object: "ioi.model_mount_receipt_gate_result",
              status: "passed",
              receipt_id: request.request.receipt_id,
              gate_receipt_id: "receipt.workflow_receipt_gate.test",
              failures: [],
            },
            receipt_refs: ["receipt-route", "receipt-tool"],
            evidence_refs: [
              "model_mount_receipt_gate_rust_owned",
              "model_mount_receipt_gate_js_facade_retired",
              "rust_receipt_binder_core",
              "agentgres_model_receipt_gate_truth_required",
            ],
            gate_hash: "sha256:receipt-gate",
          },
          receipt: {
            id: "receipt.workflow_receipt_gate.test",
            kind: "workflow_receipt_gate",
            redaction: "redacted",
            evidenceRefs: [
              "model_mount_receipt_gate_rust_owned",
              "model_mount_receipt_gate_js_facade_retired",
              "rust_receipt_binder_core",
              "agentgres_model_receipt_gate_truth_required",
            ],
            details: {
              model_mount_receipt_gate_hash: "sha256:receipt-gate",
              model_mount_receipt_binding_ref: "sha256:receipt-binding",
              model_mount_agentgres_operation_ref:
                "agentgres://model-mounting/receipt-gates/receipt-gate",
            },
          },
          public_response: {
            object: "ioi.model_mount_receipt_gate_result",
            status: "passed",
            receipt_id: request.request.receipt_id,
            gate_receipt_id: "receipt.workflow_receipt_gate.test",
            failures: [],
          },
          receipt_refs: ["receipt-route", "receipt-tool"],
          evidence_refs: [
            "model_mount_receipt_gate_rust_owned",
            "model_mount_receipt_gate_js_facade_retired",
            "rust_receipt_binder_core",
            "agentgres_model_receipt_gate_truth_required",
          ],
          operation_kind: request.request.operation_kind,
          rust_core_boundary: "model_mount.receipt_gate",
          gate_hash: "sha256:receipt-gate",
        },
      };
    },
  });

  const result = runner.planReceiptGate(receiptGateRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "plan_model_mount_receipt_gate");
  assert.equal(calls[0].request.backend, RUST_MODEL_MOUNT_RECEIPT_GATE_BACKEND);
  assert.equal(calls[0].request.request.schema_version, "ioi.model_mount.receipt_gate.v1");
  assert.equal(calls[0].request.request.operation_kind, "workflow_receipt_gate");
  assert.equal(calls[0].request.request.receipt_id, "receipt-route");
  assert.equal(result.receipt.kind, "workflow_receipt_gate");
  assert.equal(result.receipt.details.model_mount_receipt_binding_ref, "sha256:receipt-binding");
  assert.equal(result.gate_hash, "sha256:receipt-gate");
  assert.equal(result.rust_core_boundary, "model_mount.receipt_gate");
});

test("Rust model_mount admission runner sends positive conversation-state request", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    daemonCoreInvoker(request) {
      calls.push({ request });
      const record = {
        id: request.request.response_id,
        object: "ioi.model_mount_conversation_state",
        response_id: request.request.response_id,
        route_id: request.request.route_ref,
        selected_model: request.request.model_ref,
        conversation_hash: "sha256:conversation-state",
      };
      return {
        ok: true,
        result: {
          source: "rust_model_mount_conversation_state_command",
          backend: RUST_MODEL_MOUNT_CONVERSATION_STATE_BACKEND,
          plan: {
            schema_version: "ioi.model_mount.conversation_state_plan.v1",
            object: "ioi.model_mount_conversation_state_plan",
            status: "planned",
            rust_core_boundary: "model_mount.conversation",
            operation: request.request.operation,
            operation_kind: "model_mount.conversation.state_write",
            source: request.request.source,
            record_dir: "model-conversations",
            record_id: record.id,
            record,
            receipt_refs: request.request.receipt_refs,
            evidence_refs: ["model_mount_conversation_state_rust_owned"],
            conversation_hash: "sha256:conversation-state",
          },
          record_dir: "model-conversations",
          record_id: record.id,
          record,
          receipt_refs: request.request.receipt_refs,
          evidence_refs: ["model_mount_conversation_state_rust_owned"],
          operation: request.request.operation,
          operation_kind: "model_mount.conversation.state_write",
          rust_core_boundary: "model_mount.conversation",
          conversation_hash: "sha256:conversation-state",
        },
      };
    },
  });

  const result = runner.planConversationState(conversationStateRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "plan_model_mount_conversation_state");
  assert.equal(calls[0].request.backend, RUST_MODEL_MOUNT_CONVERSATION_STATE_BACKEND);
  assert.equal(calls[0].request.request.schema_version, "ioi.model_mount.conversation_state.v1");
  assert.equal(calls[0].request.request.operation, "model_conversation_state_write");
  assert.equal(result.record_dir, "model-conversations");
  assert.equal(result.record_id, "resp.current");
  assert.equal(result.record.selected_model, "llama-test");
  assert.equal(result.rust_core_boundary, "model_mount.conversation");
  assert.equal(result.evidence_refs.includes("model_mount_conversation_state_rust_owned"), true);
});

test("Rust model_mount admission runner sends positive stream-completion request", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    daemonCoreInvoker(request) {
      calls.push({ request });
      const record = {
        id: request.request.response_id,
        object: "ioi.model_mount_conversation_state",
        response_id: request.request.response_id,
        stream_receipt_ref: `receipt://${request.request.receipt_id}`,
        conversation_hash: "sha256:conversation-stream",
        stream_completion_hash: "sha256:stream-completion",
      };
      const receipt = {
        id: request.request.receipt_id,
        kind: "model_invocation_stream_completed",
        evidenceRefs: ["rust_model_mount_core", "model_mount_stream_completion_rust_owned"],
        createdAt: request.request.generated_at,
        schemaVersion: "ioi.model-mounting.runtime.v1",
        details: {
          rust_daemon_core_receipt_author: "ModelMountCore.plan_model_mount_stream_completion",
          model_mount_route_decision_ref: request.request.route_decision_ref,
          model_mount_step_module_result: {
            agentgres_operation_refs: ["agentgres://model-mounting/accepted-receipts/op_stream"],
          },
        },
      };
      return {
        ok: true,
        result: {
          source: "rust_model_mount_stream_completion_command",
          backend: RUST_MODEL_MOUNT_STREAM_COMPLETION_BACKEND,
          plan: {
            schema_version: "ioi.model_mount.stream_completion_plan.v1",
            object: "ioi.model_mount_stream_completion_plan",
            status: "planned",
            rust_core_boundary: "model_mount.conversation",
            operation: request.request.operation,
            operation_kind: "model_mount.conversation.stream_completion",
            source: request.request.source,
            record_dir: "model-conversations",
            record_id: record.id,
            record,
            receipt,
            receipt_refs: request.request.receipt_refs,
            evidence_refs: ["model_mount_stream_completion_rust_owned"],
            stream_completion_hash: "sha256:stream-completion",
            conversation_hash: "sha256:conversation-stream",
          },
          record_dir: "model-conversations",
          record_id: record.id,
          record,
          receipt,
          receipt_refs: request.request.receipt_refs,
          evidence_refs: ["model_mount_stream_completion_rust_owned"],
          operation: request.request.operation,
          operation_kind: "model_mount.conversation.stream_completion",
          rust_core_boundary: "model_mount.conversation",
          stream_completion_hash: "sha256:stream-completion",
          conversation_hash: "sha256:conversation-stream",
        },
      };
    },
  });

  const result = runner.planStreamCompletion(streamCompletionRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "plan_model_mount_stream_completion");
  assert.equal(calls[0].request.backend, RUST_MODEL_MOUNT_STREAM_COMPLETION_BACKEND);
  assert.equal(calls[0].request.request.schema_version, "ioi.model_mount.stream_completion.v1");
  assert.equal(calls[0].request.request.operation, "model_stream_completion");
  assert.equal(calls[0].request.request.route_decision_ref, "model_mount://route_decision/test");
  assert.equal(result.record_dir, "model-conversations");
  assert.equal(result.record_id, "resp.stream");
  assert.equal(result.receipt.kind, "model_invocation_stream_completed");
  assert.equal(result.stream_completion_hash, "sha256:stream-completion");
  assert.equal(result.rust_core_boundary, "model_mount.conversation");
  assert.equal(result.evidence_refs.includes("model_mount_stream_completion_rust_owned"), true);
});

test("Rust model_mount admission runner sends invocation receipt binding request", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    daemonCoreInvoker(request) {
      calls.push({ request });
      return {
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
              operation_ref: "agentgres://model-mounting/accepted-receipts/op_00000001_model_invocation",
              expected_heads: ["agentgres://model-mounting/accepted-receipts/head/0"],
              state_root_before: "sha256:state-before",
              state_root_after: "sha256:state-after",
              resulting_head: "agentgres://model-mounting/accepted-receipts/head/1",
              admission_hash: "sha256:agentgres",
            },
            projection_record: {
              component_kind: "ModelInvocationNode",
            },
            receipt_refs: ["receipt://invocation"],
            evidence_refs: ["rust_receipt_binder_core", "sha256:binding", "sha256:append"],
          },
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
      agentgres_operation_refs: ["agentgres://model-mounting/accepted-receipts/op_00000001_model_invocation"],
      state_root_after: "sha256:state-after",
      resulting_head: "agentgres://model-mounting/accepted-receipts/head/1",
    },
    acceptedReceiptTransition: {
      schema_version: "ioi.model_mount.accepted_receipt_transition.v1",
      operation_id: "op_00000001_model_invocation",
      operation_ref: "agentgres://model-mounting/accepted-receipts/op_00000001_model_invocation",
      expected_heads: ["agentgres://model-mounting/accepted-receipts/head/0"],
      state_root_before: "sha256:state-before",
      state_root_after: "sha256:state-after",
      resulting_head: "agentgres://model-mounting/accepted-receipts/head/1",
      projection_watermark: "model-mounting-accepted-receipts:1",
      transition_hash: "sha256:transition",
      evidence_refs: ["rust_model_mount_accepted_receipt_transition"],
    },
    receiptRef: "receipt://invocation",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "bind_model_mount_invocation_receipt");
  assert.equal(Object.hasOwn(calls[0].request, "expected_heads"), false);
  assert.deepEqual(calls[0].request.accepted_receipt_transition.expected_heads, [
    "agentgres://model-mounting/accepted-receipts/head/0",
  ]);
  assert.equal(calls[0].request.receipt_ref, "receipt://invocation");
  assert.equal(result.receipt_binding.binding_hash, "sha256:binding");
  assert.equal(
    result.agentgres_admission.operation_ref,
    "agentgres://model-mounting/accepted-receipts/op_00000001_model_invocation",
  );
  assert.equal(result.accepted_receipt_append.append_hash, "sha256:append");
  assert.deepEqual(result.evidence_refs, ["rust_receipt_binder_core", "sha256:binding", "sha256:append"]);
});

test("Rust model_mount admission runner rejects direct expected head binding input", () => {
  const runner = new RustModelMountAdmissionRunner();

  assert.throws(
    () =>
      runner.bindInvocationReceipt({
        invocation: {},
        result: {},
        expectedHeads: ["agentgres://model-mounting/accepted-receipts/head/client"],
      }),
    (error) => error.code === "model_mount_invocation_expected_heads_retired" && error.status === 400,
  );
});

test("Rust model_mount admission runner sends accepted receipt transition plan request", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    daemonCoreInvoker(request) {
      calls.push({ request });
      return {
        ok: true,
        result: {
            source: "rust_model_mount_accepted_receipt_transition_command",
            backend: "rust_model_mount_accepted_receipt_transition",
            transition: {
              schema_version: "ioi.model_mount.accepted_receipt_transition.v1",
              operation_id: "op_00000001_model_invocation",
              operation_ref: "agentgres://model-mounting/accepted-receipts/op_00000001_model_invocation",
              expected_heads: ["agentgres://model-mounting/accepted-receipts/head/0"],
              state_root_before: "sha256:state-0",
              state_root_after: "sha256:state-1",
              resulting_head: "agentgres://model-mounting/accepted-receipts/head/1",
              projection_watermark: "model-mounting-accepted-receipts:1",
              transition_hash: "sha256:transition",
              evidence_refs: ["rust_model_mount_accepted_receipt_transition"],
            },
            operation_id: "op_00000001_model_invocation",
            operation_ref: "agentgres://model-mounting/accepted-receipts/op_00000001_model_invocation",
            expected_heads: ["agentgres://model-mounting/accepted-receipts/head/0"],
            state_root_before: "sha256:state-0",
            state_root_after: "sha256:state-1",
            resulting_head: "agentgres://model-mounting/accepted-receipts/head/1",
            projection_watermark: "model-mounting-accepted-receipts:1",
            transition_hash: "sha256:transition",
            evidence_refs: ["rust_model_mount_accepted_receipt_transition"],
          },
      };
    },
  });

  const result = runner.planAcceptedReceiptTransition({
    schema_version: "ioi.model_mount.accepted_receipt_transition.v1",
    current_sequence: 0,
    current_head_ref: "agentgres://model-mounting/accepted-receipts/head/0",
    current_state_root: "sha256:state-0",
    receipt_id: "receipt.invoke",
    receipt_kind: "model_invocation",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "plan_model_mount_accepted_receipt_transition");
  assert.equal(calls[0].request.backend, "rust_model_mount_accepted_receipt_transition");
  assert.equal(calls[0].request.request.current_sequence, 0);
  assert.equal(result.operation_id, "op_00000001_model_invocation");
  assert.equal(
    result.operation_ref,
    "agentgres://model-mounting/accepted-receipts/op_00000001_model_invocation",
  );
  assert.deepEqual(result.expected_heads, ["agentgres://model-mounting/accepted-receipts/head/0"]);
  assert.equal(result.state_root_before, "sha256:state-0");
  assert.equal(result.state_root_after, "sha256:state-1");
  assert.equal(result.resulting_head, "agentgres://model-mounting/accepted-receipts/head/1");
  assert.equal(result.projection_watermark, "model-mounting-accepted-receipts:1");
  assert.equal(result.transition_hash, "sha256:transition");
  assert.equal(Object.hasOwn(result, "stateRootBefore"), false);
  assert.equal(Object.hasOwn(result, "resultingHead"), false);
});

test("Rust model_mount admission runner sends accepted receipt head plan request", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    daemonCoreInvoker(request) {
      calls.push({ request });
      return {
        ok: true,
        result: {
            source: "rust_model_mount_accepted_receipt_head_command",
            backend: "rust_model_mount_accepted_receipt_head",
            head: {
              schema_version: "ioi.model_mount.accepted_receipt_head.v1",
              sequence: 2,
              head_ref: "agentgres://model-mounting/accepted-receipts/head/2",
              state_root: "sha256:state-2",
              projection_watermark: "model-mounting-accepted-receipts:2",
              head_hash: "sha256:head",
              evidence_refs: ["rust_model_mount_accepted_receipt_head"],
            },
            sequence: 2,
            head_ref: "agentgres://model-mounting/accepted-receipts/head/2",
            state_root: "sha256:state-2",
            projection_watermark: "model-mounting-accepted-receipts:2",
            head_hash: "sha256:head",
            evidence_refs: ["rust_model_mount_accepted_receipt_head"],
          },
      };
    },
  });

  const result = runner.planAcceptedReceiptHead({
    schema_version: "ioi.model_mount.accepted_receipt_head.v1",
    sequence: 2,
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "plan_model_mount_accepted_receipt_head");
  assert.equal(calls[0].request.backend, "rust_model_mount_accepted_receipt_head");
  assert.equal(calls[0].request.request.sequence, 2);
  assert.equal(result.sequence, 2);
  assert.equal(result.head_ref, "agentgres://model-mounting/accepted-receipts/head/2");
  assert.equal(result.state_root, "sha256:state-2");
  assert.equal(result.projection_watermark, "model-mounting-accepted-receipts:2");
  assert.equal(result.head_hash, "sha256:head");
  assert.equal(Object.hasOwn(result, "headRef"), false);
  assert.equal(Object.hasOwn(result, "stateRoot"), false);
});

test("Rust model_mount admission runner sends read projection plan request", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    daemonCoreInvoker(request) {
      calls.push({ request });
      return {
        ok: true,
        result: {
            source: "rust_model_mount_read_projection_command",
            backend: "rust_model_mount_read_projection",
            projection_kind: "projection_summary",
            projection: {
              schemaVersion: "model.mount.schema",
              source: "agentgres_model_mounting_projection",
              watermark: 1,
              receiptCount: 1,
              generatedAt: "2026-06-08T00:00:00.000Z",
            },
            evidence_refs: [
              "rust_daemon_core_model_mount_projection",
              "model_mount_js_read_projection_authoring_retired",
            ],
          },
      };
    },
  });

  const result = runner.planReadProjection({
    projection_kind: "projection_summary",
    schema_version: "model.mount.schema",
    generated_at: "2026-06-08T00:00:00.000Z",
    state: { receipts: [{ id: "receipt.one" }] },
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "plan_model_mount_read_projection");
  assert.equal(calls[0].request.backend, "rust_model_mount_read_projection");
  assert.equal(calls[0].request.request.projection_kind, "projection_summary");
  assert.equal(result.projection_kind, "projection_summary");
  assert.equal(result.projection.receiptCount, 1);
  assert.equal(Object.hasOwn(result.projection, "receipt_count"), false);
  assert.equal(result.evidence_refs.includes("model_mount_js_read_projection_authoring_retired"), true);
});

test("Rust model_mount admission runner env uses daemon-level direct invoker", () => {
  const calls = [];
  const runner = createModelMountAdmissionRunnerFromEnv(
    {
      IOI_STEP_MODULE_COMMAND: "retired-step-module-bridge",
      IOI_STEP_MODULE_COMMAND_ARGS: "--retired-step",
    },
    {
      daemonCoreInvoker(request) {
        calls.push(request);
        return {
          source: "direct_daemon_core_api",
          backend: "rust_model_mount_live",
          record: {
            route_decision_ref: "model_mount://route_decision/direct",
            route_decision_hash: "sha256:direct",
          },
        };
      },
    },
  );

  const result = runner.admitRouteDecision(routeRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].operation, "admit_model_mount_route_decision");
  assert.equal(result.source, "direct_daemon_core_api");
  assert.equal(result.route_decision_ref, "model_mount://route_decision/direct");
});

test("Rust model_mount admission runner rejects retired daemon-core command env", () => {
  assert.throws(
    () =>
      createModelMountAdmissionRunnerFromEnv(
        {
          IOI_RUNTIME_DAEMON_CORE_COMMAND: "ioi-runtime-daemon-core",
        },
        {
          daemonCoreInvoker() {
            return {};
          },
        },
      ),
    (error) =>
      error instanceof ModelMountAdmissionRunnerError &&
      error.code === "model_mount_admission_command_selection_retired",
  );
});

test("Rust model_mount admission runner rejects retired model-mount command env", () => {
  assert.throws(
    () =>
      createModelMountAdmissionRunnerFromEnv(
        {
          IOI_MODEL_MOUNT_ADMISSION_COMMAND: "retired-model-mount-bridge",
        },
        {
          daemonCoreInvoker() {
            return {};
          },
        },
      ),
    (error) =>
      error instanceof ModelMountAdmissionRunnerError &&
      error.code === "model_mount_admission_command_selection_retired",
  );
});

test("Rust model_mount admission runner command args env fails closed", () => {
  assert.throws(
    () =>
      createModelMountAdmissionRunnerFromEnv({
        IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS: "--json",
      }),
    (error) =>
      error instanceof ModelMountAdmissionRunnerError &&
      error.code === "model_mount_admission_command_args_retired",
  );
});

test("Rust model_mount admission runner retired model-mount command args env fails closed", () => {
  assert.throws(
    () =>
      createModelMountAdmissionRunnerFromEnv({
        IOI_MODEL_MOUNT_ADMISSION_COMMAND_ARGS: "--retired-model-mount",
      }),
    (error) =>
      error instanceof ModelMountAdmissionRunnerError &&
      error.code === "model_mount_admission_command_args_retired",
  );
});

test("Rust model_mount admission runner command args constructor option fails closed", () => {
  assert.throws(
    () =>
      new RustModelMountAdmissionRunner({
        command: "ioi-runtime-daemon-core",
        args: ["--json"],
      }),
    (error) =>
      error instanceof ModelMountAdmissionRunnerError &&
      error.code === "model_mount_admission_command_args_retired",
  );
});

test("Rust model_mount admission runner command constructor option fails closed", () => {
  assert.throws(
    () => new RustModelMountAdmissionRunner({ command: "ioi-runtime-daemon-core" }),
    (error) =>
      error instanceof ModelMountAdmissionRunnerError &&
      error.code === "model_mount_admission_command_selection_retired",
  );
});

test("Rust model_mount admission runner fails closed without direct invoker", () => {
  const runner = new RustModelMountAdmissionRunner();

  assert.throws(
    () => runner.admitRouteDecision(routeRequest()),
    (error) =>
      error instanceof ModelMountAdmissionRunnerError &&
      error.code === "model_mount_admission_direct_invoker_unconfigured",
  );
});
