import assert from "node:assert/strict";
import test from "node:test";

import {
  capabilityForInvocationKind,
  invokeModel,
  modelMountInvocationAgentgresTransitionForReceipt,
  modelMountInvocationAdmissionRequestForReceipt,
  modelMountProviderExecutionRequestForInvocation,
  modelMountProviderInvocationRequestForExecution,
  modelMountProviderInvocationRequiresRust,
  modelMountProviderStreamInvocationRequestForExecution,
  modelMountProviderStreamInvocationRequiresRust,
  modelMountProviderResultAdmissionRequestForExecution,
  modelMountInvocationReceiptBindingRequestForReceipt,
  startModelStream,
} from "./model-invocation-operations.mjs";

function fakeState(overrides = {}) {
  const state = {
    authorizationCalls: [],
    conversations: new Map(),
    inflightModelInvocations: new Map(),
    nowMs: 1_000,
    receiptIdCounter: 0,
    receipts: [],
    receiptBindingRequests: [],
    providerExecutionRequests: [],
    providerInvocationRequests: [],
    providerStreamInvocationRequests: [],
    providerResultRequests: [],
    transitionRequests: [],
    recordStateCommits: [],
    recordedConversations: [],
    routes: new Map([["route.local-first", { id: "route.local-first" }]]),
    writes: [],
    appendOperations: [],
    authorize(authorization, requiredScope) {
      this.authorizationCalls.push({ authorization, requiredScope });
      return { grantId: "grant.test" };
    },
    compileEphemeralMcpIntegrations() {
      return {
        evidenceRefs: ["mcp.ephemeral"],
        serverIds: ["mcp.server"],
        toolReceiptIds: ["receipt.tool"],
      };
    },
    conversationState(responseId) {
      return this.conversations.get(responseId);
    },
    driverForProvider() {
      return this.driver;
    },
    async ensureLoaded(endpoint) {
      this.loadedEndpointId = endpoint.id;
      return {
        id: "instance.local",
        backendId: "backend.local",
      };
    },
    invokeModel(args) {
      this.fallbackInvocationArgs = args;
      return { fallback: true, args };
    },
    nextResponseId(requested) {
      return requested ?? "resp.generated";
    },
    now() {
      this.nowMs += 25;
      return { getTime: () => this.nowMs };
    },
    agentgresModelMountingHead() {
      const sequence = this.receipts.length;
      return {
        sequence,
        headRef: `agentgres://model-mounting/accepted-receipts/head/${sequence}`,
        stateRoot: `sha256:state-${sequence}`,
        projectionWatermark: `model-mounting-accepted-receipts:${sequence}`,
      };
    },
    nextReceiptId(kind) {
      this.receiptIdCounter += 1;
      return `receipt.${this.receiptIdCounter}.${kind}`;
    },
    admitModelMountInvocation(request) {
      return {
        source: "rust_model_mount_mock",
        backend: "rust_model_mount_live",
        record: {
          ...request,
          invocation_admission_ref: `model_mount://invocation_admission/${this.receiptIdCounter}`,
          invocation_admission_hash: `sha256:invocation-${this.receiptIdCounter}`,
        },
        invocation_admission_ref: `model_mount://invocation_admission/${this.receiptIdCounter}`,
        invocation_admission_hash: `sha256:invocation-${this.receiptIdCounter}`,
        receipt_refs: request.receipt_refs,
        evidence_refs: ["rust_model_mount_core", `model_mount://invocation_admission/${this.receiptIdCounter}`],
      };
    },
    admitModelMountProviderExecution(request) {
      this.providerExecutionRequests.push(request);
      return {
        source: "rust_model_mount_provider_execution_command",
        backend: "rust_model_mount_live",
        record: {
          ...request,
          provider_execution_ref: `model_mount://provider_execution/${this.providerExecutionRequests.length}`,
          provider_execution_hash: `sha256:provider-execution-${this.providerExecutionRequests.length}`,
        },
        provider_execution_ref: `model_mount://provider_execution/${this.providerExecutionRequests.length}`,
        provider_execution_hash: `sha256:provider-execution-${this.providerExecutionRequests.length}`,
        receipt_refs: request.receipt_refs,
        evidence_refs: [
          "rust_model_mount_core",
          `model_mount://provider_execution/${this.providerExecutionRequests.length}`,
        ],
      };
    },
    admitModelMountProviderResult(request) {
      this.providerResultRequests.push(request);
      return {
        source: "rust_model_mount_provider_result_command",
        backend: "rust_model_mount_live",
        record: {
          ...request,
          provider_result_ref: `model_mount://provider_result/${this.providerResultRequests.length}`,
          provider_result_hash: `sha256:provider-result-${this.providerResultRequests.length}`,
        },
        provider_result_ref: `model_mount://provider_result/${this.providerResultRequests.length}`,
        provider_result_hash: `sha256:provider-result-${this.providerResultRequests.length}`,
        receipt_refs: request.receipt_refs,
        evidence_refs: [
          "rust_model_mount_provider_result_admission",
          `model_mount://provider_result/${this.providerResultRequests.length}`,
        ],
      };
    },
    executeModelMountProviderInvocation(request) {
      this.providerInvocationRequests.push(request);
      return providerInvocationBridgeResult(request, {
        invocationHash: `sha256:provider-invocation-${this.providerInvocationRequests.length}`,
      });
    },
    executeModelMountProviderStreamInvocation(request) {
      this.providerStreamInvocationRequests.push(request);
      return providerStreamInvocationBridgeResult(request, {
        invocationHash: `sha256:provider-stream-invocation-${this.providerStreamInvocationRequests.length}`,
      });
    },
    planModelMountAcceptedReceiptTransition(request) {
      this.transitionRequests.push(request);
      const nextSequence = request.current_sequence + 1;
      const operationId = `op_${String(nextSequence).padStart(8, "0")}_${request.receipt_kind.replace(/[^a-z0-9]+/gi, "_")}`;
      return {
        source: "rust_model_mount_accepted_receipt_transition_command",
        backend: "rust_model_mount_accepted_receipt_transition",
        transition: {
          schema_version: "ioi.model_mount.accepted_receipt_transition.v1",
          operation_id: operationId,
          operation_ref: `agentgres://model-mounting/accepted-receipts/${operationId}`,
          expected_heads: [request.current_head_ref],
          state_root_before: request.current_state_root,
          state_root_after: `sha256:state-${nextSequence}`,
          resulting_head: `agentgres://model-mounting/accepted-receipts/head/${nextSequence}`,
          projection_watermark: `model-mounting-accepted-receipts:${nextSequence}`,
          transition_hash: `sha256:transition-${nextSequence}`,
          evidence_refs: ["rust_model_mount_accepted_receipt_transition"],
        },
        operationId,
        operationRef: `agentgres://model-mounting/accepted-receipts/${operationId}`,
        expectedHeads: [request.current_head_ref],
        stateRootBefore: request.current_state_root,
        stateRootAfter: `sha256:state-${nextSequence}`,
        resultingHead: `agentgres://model-mounting/accepted-receipts/head/${nextSequence}`,
        projectionWatermark: `model-mounting-accepted-receipts:${nextSequence}`,
        transitionHash: `sha256:transition-${nextSequence}`,
        evidenceRefs: ["rust_model_mount_accepted_receipt_transition"],
      };
    },
    bindModelMountInvocationReceipt(request) {
      this.receiptBindingRequests.push(request);
      return {
        source: "rust_model_mount_receipt_binding_command",
        backend: "rust_model_mount_live",
        invocation: request.invocation,
        result: request.result,
        router_admission: {
          schema_version: "ioi.step_module_router_admission.v1",
          invocation_id: request.invocation.invocation_id,
          backend: "model_mount",
          authoritative_transition: true,
        },
        receipt_binding: {
          schema_version: "ioi.step_module_receipt_binding.v1",
          invocation_id: request.invocation.invocation_id,
          receipt_refs: request.result.receipt_refs,
          binding_hash: `sha256:binding-${this.receiptIdCounter}`,
        },
        accepted_receipt_append: {
          schema_version: "ioi.accepted_receipt_append.v1",
          receipt_ref: request.receiptRef,
          invocation_id: request.invocation.invocation_id,
          receipt_binding_ref: `sha256:binding-${this.receiptIdCounter}`,
          append_hash: `sha256:append-${this.receiptIdCounter}`,
        },
        agentgres_admission: {
          schema_version: "ioi.agentgres_admission.v1",
          operation_ref: request.result.agentgres_operation_refs[0],
          expected_heads: request.acceptedReceiptTransition?.expected_heads ?? [],
          state_root_before: request.invocation.input.state_root_before,
          state_root_after: request.result.state_root_after,
          resulting_head: request.result.resulting_head,
          admission_hash: `sha256:agentgres-${this.receiptIdCounter}`,
        },
        projection_record: {
          schema_version: "ioi.step_module_projection.v1",
          component_kind: "ModelInvocationNode",
        },
        receipt_refs: request.result.receipt_refs,
        evidence_refs: ["rust_receipt_binder_core", `sha256:binding-${this.receiptIdCounter}`],
      };
    },
    receipt(kind, payload) {
      const receipt = { id: payload.id ?? `receipt.${this.receipts.length + 1}.${kind}`, kind, ...payload };
      this.receipts.push(receipt);
      return receipt;
    },
    recordConversationState(payload) {
      this.recordedConversations.push(payload);
      return { id: payload.responseId, payload };
    },
    routeSelectionReceipt(selection, payload) {
      this.routeSelectionPayload = { selection, payload };
      return {
        id: "receipt.route",
        kind: "model_route_selection",
        details: {
          model_mount_route_decision_ref: "model_mount://route_decision/test",
          workflow_graph_id: "workflow.graph",
          workflow_node_id: "workflow.node",
        },
      };
    },
    selectRoute(payload) {
      this.selectRoutePayload = payload;
      return selection();
    },
    validateContinuationSafety(payload) {
      this.continuationPayload = payload;
      return { mode: "matched" };
    },
    writeMap(name, map) {
      this.writes.push([name, [...map.values()].map((record) => ({ ...record }))]);
    },
    commitRuntimeModelMountRecordState(request) {
      this.recordStateCommits.push(request);
      return {
        record_id: request.record_id,
        object_ref: `agentgres://model-mounting/records/${request.record_dir}/${request.record_id}`,
        content_hash: `sha256:${request.record_id}`,
        admission_hash: `admit:${request.record_id}`,
        commit_hash: `commit:${request.record_id}`,
        written_record: request.record,
        storage_record: {
          object_ref: `agentgres://model-mounting/records/${request.record_dir}/${request.record_id}`,
          content_hash: `sha256:${request.record_id}`,
          admission: { admission_hash: `admit:${request.record_id}` },
        },
      };
    },
    appendOperation(kind, payload) {
      this.appendOperations.push({ kind, payload });
    },
    ...overrides,
  };
  state.driver ??= {
    async invoke() {
      return {
        outputText: "provider answer",
        providerResponse: { id: "provider.response" },
        providerResponseKind: "openai.chat",
        tokenCount: { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3 },
      };
    },
  };
  return state;
}

function selection(overrides = {}) {
  const base = {
    route: { id: "route.local-first", fallback: ["endpoint.local"] },
    endpoint: {
      id: "endpoint.local",
      modelId: "model.local",
      providerId: "provider.local",
      apiFormat: "openai",
      backendId: "backend.endpoint",
    },
    provider: {
      id: "provider.local",
      kind: "local_folder",
    },
  };
  return {
    route: { ...base.route, ...(overrides.route ?? {}) },
    endpoint: { ...base.endpoint, ...(overrides.endpoint ?? {}) },
    provider: { ...base.provider, ...(overrides.provider ?? {}) },
  };
}

function deps(overrides = {}) {
  return {
    estimateTokens: () => ({ prompt_tokens: 4, completion_tokens: 5, total_tokens: 9 }),
    inputText: () => "user: hello",
    modelInvocationCoalesceKey: () => null,
    optionalString: (value) => (typeof value === "string" && value ? value : null),
    providerRequestBodyForRoute: (body, endpoint) => ({ ...body, model: endpoint.modelId }),
    stableHash: (value) => `hash:${value}`,
    supportsResponseState: (kind) => kind === "responses",
    ...overrides,
  };
}

function providerInvocationBridgeResult(request, options = {}) {
  const nativeLocal = request.execution_backend === "rust_model_mount_native_local";
  const outputText =
    options.outputText ??
    (nativeLocal
      ? `Autopilot native local model response from ${request.model_ref}. input_hash=test`
      : "provider answer");
  const providerResponseKind = nativeLocal ? "rust_model_mount.native_local" : "rust_model_mount.fixture";
  const backend = nativeLocal ? "autopilot.native_local.fixture" : "ioi_fixture";
  const backendId = nativeLocal ? request.backend_ref ?? "backend.autopilot.native-local.fixture" : "backend.fixture";
  const executionBackend = request.execution_backend ?? "rust_model_mount_fixture";
  const evidenceRefs = [
    "rust_model_mount_provider_invocation",
    request.provider_execution_ref,
    ...(nativeLocal
      ? ["rust_model_mount_native_local_backend", "deterministic_native_local_fixture"]
      : ["rust_model_mount_fixture_backend", "deterministic_fixture"]),
  ];
  const invocationHash = options.invocationHash ?? "sha256:provider-invocation-test";
  return {
    source: "rust_model_mount_provider_invocation_command",
    backend: executionBackend,
    result: {
      ...request,
      output_text: outputText,
      token_count: { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3 },
      provider_response_kind: providerResponseKind,
      backend,
      backend_id: backendId,
      execution_backend: executionBackend,
      evidence_refs: evidenceRefs,
      invocation_hash: invocationHash,
    },
    outputText,
    tokenCount: { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3 },
    providerResponse: null,
    providerResponseKind,
    executionBackend,
    backendId,
    provider_execution_ref: request.provider_execution_ref,
    provider_execution_hash: request.provider_execution_hash,
    invocation_hash: invocationHash,
    evidence_refs: evidenceRefs,
    backendEvidenceRefs: evidenceRefs,
  };
}

function providerStreamInvocationBridgeResult(request, options = {}) {
  const outputText = options.outputText ?? "rust stream answer";
  const tokenCount = options.tokenCount ?? { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3 };
  const executionBackend = request.execution_backend ?? "rust_model_mount_native_local_stream";
  const backendId = request.backend_ref ?? "backend.autopilot.native-local.fixture";
  const streamKind =
    request.invocation_kind === "responses"
      ? "openai_responses_native_local"
      : "openai_chat_completions_native_local";
  const streamChunks =
    options.streamChunks ?? [
      `{"delta":${JSON.stringify(outputText)},"done":false}\n`,
      `{"delta":"","done":true,"done_reason":"stop","prompt_eval_count":${tokenCount.prompt_tokens},"eval_count":${tokenCount.completion_tokens}}\n`,
    ];
  const evidenceRefs = [
    "rust_model_mount_provider_stream_invocation",
    "rust_model_mount_native_local_stream_backend",
    request.provider_execution_ref,
  ];
  const invocationHash = options.invocationHash ?? "sha256:provider-stream-invocation-test";
  const result = {
    source: "rust_model_mount_provider_stream_invocation_command",
    backend: executionBackend,
    result: {
      ...request,
      schema_version: "ioi.model_mount.provider_stream_invocation.v1",
      output_text: outputText,
      token_count: tokenCount,
      provider_response_kind: "rust_model_mount.native_local.stream",
      backend: "autopilot.native_local.fixture",
      backend_id: backendId,
      execution_backend: executionBackend,
      stream_format: "ioi_jsonl",
      stream_kind: streamKind,
      stream_chunks: streamChunks,
      evidence_refs: evidenceRefs,
      invocation_hash: invocationHash,
    },
    outputText,
    tokenCount,
    providerResponse: null,
    providerResponseKind: "rust_model_mount.native_local.stream",
    executionBackend,
    backendId,
    streamFormat: "ioi_jsonl",
    streamKind,
    streamChunks,
    provider_execution_ref: request.provider_execution_ref,
    provider_execution_hash: request.provider_execution_hash,
    invocation_hash: invocationHash,
    evidence_refs: evidenceRefs,
    backendEvidenceRefs: evidenceRefs,
  };
  if (options.compatTranslation) {
    result.compatTranslation = options.compatTranslation;
  }
  return result;
}

async function readReadableStreamText(stream) {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let text = "";
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
    return text;
  } finally {
    reader.releaseLock();
  }
}

test("capabilityForInvocationKind maps model APIs to route capabilities", () => {
  assert.equal(capabilityForInvocationKind("embeddings"), "embeddings");
  assert.equal(capabilityForInvocationKind("rerank"), "rerank");
  assert.equal(capabilityForInvocationKind("responses"), "responses");
  assert.equal(capabilityForInvocationKind("chat.completions"), "chat");
});

test("model invocations reject retired camelCase request aliases before authorization", async () => {
  const state = fakeState();
  const body = {
    model: "model.local",
    routeId: "route.local-first",
    modelPolicy: { privacy: "legacy" },
    responseId: "resp.legacy",
    previousResponseId: "resp.previous",
    sendOptions: { memory: { enabled: true } },
  };

  await assert.rejects(
    () =>
      invokeModel(
        state,
        {
          authorization: "Bearer token",
          requiredScope: "model.responses:*",
          kind: "responses",
          body,
        },
        deps(),
      ),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "model_mount_invocation_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, [
        "routeId",
        "modelPolicy",
        "responseId",
        "previousResponseId",
        "sendOptions",
      ]);
      assert.equal(Object.hasOwn(error.details, "routeId"), false);
      return true;
    },
  );
  assert.deepEqual(state.authorizationCalls, []);

  await assert.rejects(
    () =>
      startModelStream(
        state,
        {
          authorization: "Bearer token",
          requiredScope: "model.responses:*",
          kind: "responses",
          body: { model: "model.local", routeId: "route.local-first", stream: true },
        },
        deps(),
      ),
    (error) => {
      assert.equal(error.code, "model_mount_invocation_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, ["routeId"]);
      return true;
    },
  );
  assert.deepEqual(state.authorizationCalls, []);
});

test("model invocations reject retired authority request aliases before authorization", async () => {
  const state = fakeState();
  const body = {
    model: "model.local",
    authorityGrantRefs: ["grant://model-chat"],
    authorityReceiptRefs: ["receipt://wallet/model-chat"],
    custodyRef: "ctee://custody/private-workspace",
    privacyProfile: "private_workspace_ctee",
    nodePlaintextAllowed: true,
  };

  await assert.rejects(
    () =>
      invokeModel(
        state,
        {
          authorization: "Bearer token",
          requiredScope: "model.responses:*",
          kind: "responses",
          body,
        },
        deps(),
      ),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "model_mount_invocation_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, [
        "authorityGrantRefs",
        "authorityReceiptRefs",
        "custodyRef",
        "privacyProfile",
        "nodePlaintextAllowed",
      ]);
      assert.equal(Object.hasOwn(error.details, "authorityGrantRefs"), false);
      assert.equal(Object.hasOwn(error.details, "privacyProfile"), false);
      return true;
    },
  );
  assert.deepEqual(state.authorizationCalls, []);
});

test("invokeModel routes provider calls, records receipts, updates route state, and finalizes response state", async () => {
  const state = fakeState();

  const result = await invokeModel(
    state,
    {
      authorization: "Bearer token",
      requiredScope: "model.chat:*",
      kind: "responses",
      body: { model: "model.local", response_id: "resp.custom", memory: { enabled: true } },
    },
    deps(),
  );

  assert.equal(result.outputText, "provider answer");
  assert.equal(result.responseId, "resp.custom");
  assert.equal(result.receipt.kind, "model_invocation");
  assert.equal(result.receipt.id, "receipt.1.model_invocation");
  assert.equal(result.receipt.details.route_id, "route.local-first");
  assert.equal(result.receipt.details.selected_model, "model.local");
  assert.equal(result.receipt.details.endpoint_id, "endpoint.local");
  assert.deepEqual(result.receipt.details.tool_receipt_ids, ["receipt.tool"]);
  assert.equal(result.receipt.details.model_mount_invocation_admission_ref, "model_mount://invocation_admission/1");
  assert.equal(result.receipt.details.model_mount_invocation_admission.route_decision_ref, "model_mount://route_decision/test");
  assert.equal(result.receipt.details.model_mount_provider_execution_ref, "model_mount://provider_execution/1");
  assert.equal(result.receipt.details.model_mount_provider_execution.request_hash.startsWith("sha256:"), true);
  assert.equal(result.receipt.details.model_mount_receipt_binding_ref, "sha256:binding-1");
  assert.equal(result.receipt.details.model_mount_accepted_receipt_append_hash, "sha256:append-1");
  assert.equal(result.receipt.details.model_mount_step_module_invocation.input.state_root_before, "sha256:state-0");
  assert.equal(result.receipt.details.model_mount_step_module_result.agentgres_operation_refs[0], "agentgres://model-mounting/accepted-receipts/op_00000001_model_invocation");
  assert.equal(result.receipt.details.model_mount_step_module_result.state_root_after.startsWith("sha256:"), true);
  assert.equal(result.receipt.details.model_mount_agentgres_admission.operation_ref, "agentgres://model-mounting/accepted-receipts/op_00000001_model_invocation");
  assert.equal(result.receipt.details.model_mount_step_module_invocation.module_ref.kind, "model_mount");
  assert.equal(result.receipt.details.model_mount_step_module_result.workflow_projection.status, "live");
  assert.equal(result.receipt.details.previous_response_id, null);
  assert.equal(Object.hasOwn(result, "compatTranslation"), false);
  assert.equal(Object.hasOwn(result.receipt.details, "compatTranslation"), false);
  assert.equal(Object.hasOwn(result.receipt.details, "routeId"), false);
  assert.equal(Object.hasOwn(result.receipt.details, "selectedModel"), false);
  assert.equal(Object.hasOwn(result.receipt.details, "endpointId"), false);
  assert.equal(Object.hasOwn(result.receipt.details, "toolReceiptIds"), false);
  assert.equal(Object.hasOwn(result.receipt.details, "previousResponseId"), false);
  assert.equal(Object.hasOwn(result.receipt.details, "modelMountReceiptBindingRef"), false);
  assert.equal(Object.hasOwn(result.receipt.details, "modelMountAgentgresAdmission"), false);
  assert.equal(Object.hasOwn(result.receipt.details, "modelMountStepModuleResult"), false);
  assert.equal(Object.hasOwn(result.receipt.details, "modelMountInvocationAdmissionRef"), false);
  assert.equal(Object.hasOwn(result.receipt.details, "modelMountProviderExecutionRef"), false);
  assert.equal(state.receiptBindingRequests[0].receiptRef, "receipt://receipt.1.model_invocation");
  assert.equal(state.providerExecutionRequests[0].route_decision_ref, "model_mount://route_decision/test");
  assert.equal(state.providerExecutionRequests[0].route_receipt_ref, "receipt://receipt.route");
  assert.equal(state.providerExecutionRequests[0].stream_status, null);
  assert.equal(state.providerInvocationRequests[0].provider_execution_ref, "model_mount://provider_execution/1");
  assert.equal(state.providerInvocationRequests[0].execution_backend, "rust_model_mount_fixture");
  assert.equal(state.providerInvocationRequests[0].admitted_provider_execution.provider_execution_hash, "sha256:provider-execution-1");
  assert.deepEqual(state.receiptBindingRequests[0].acceptedReceiptTransition.expected_heads, [
    "agentgres://model-mounting/accepted-receipts/head/0",
  ]);
  assert.deepEqual(result.receipt.details.model_mount_invocation_admission_receipt_refs, [
    "receipt://receipt.route",
    "receipt://receipt.1.model_invocation",
    "receipt://receipt.tool",
  ]);
  assert.equal(result.receipt.details.memory.enabled, true);
  assert.equal(result.receipt.details.coalesced, false);
  assert.equal(state.recordedConversations[0].responseId, "resp.custom");
  assert.equal(state.routes.get("route.local-first").lastReceiptId, result.receipt.id);
  assert.equal(state.writes.some(([name]) => name === "model-routes"), false);
  assert.equal(state.recordStateCommits.length, 1);
  assert.equal(state.recordStateCommits[0].schema_version, "ioi.runtime_model_mount_record_state_commit.v1");
  assert.equal(state.recordStateCommits[0].record_dir, "model-routes");
  assert.equal(state.recordStateCommits[0].record_id, "route.local-first");
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.route.invocation_selection");
  assert.deepEqual(state.recordStateCommits[0].receipt_refs, [result.receipt.id]);
  assert.equal(state.recordStateCommits[0].record.lastReceiptId, result.receipt.id);
});

test("invokeModel routes native-local non-stream provider invocation through Rust model_mount", async () => {
  let providerCalls = 0;
  const state = fakeState({
    async ensureLoaded(endpoint) {
      this.loadedEndpointId = endpoint.id;
      return {
        id: "instance.native-local",
        backendId: "backend.autopilot.native-local.fixture",
      };
    },
    selectRoute(payload) {
      this.selectRoutePayload = payload;
      return selection({
        route: { id: "route.native-local" },
        endpoint: {
          id: "endpoint.native-local",
          apiFormat: "ioi_native",
          driver: "native_local",
          modelId: "model://qwen/qwen3.5-9b",
          providerId: "provider.autopilot.local",
          backendId: "backend.autopilot.native-local.fixture",
        },
        provider: {
          id: "provider.autopilot.local",
          kind: "ioi_native_local",
          driver: "native_local",
        },
      });
    },
    driver: {
      async invoke() {
        providerCalls += 1;
        return { outputText: "should not run" };
      },
    },
  });

  const result = await invokeModel(
    state,
    {
      authorization: "Bearer token",
      requiredScope: "model.responses:*",
      kind: "responses",
      body: { model: "model://qwen/qwen3.5-9b", response_id: "resp.native-local" },
    },
    deps(),
  );

  assert.equal(providerCalls, 0);
  assert.equal(result.outputText.startsWith("Autopilot native local model response"), true);
  assert.equal(result.providerResponseKind, "rust_model_mount.native_local");
  assert.equal(state.providerInvocationRequests.length, 1);
  assert.equal(state.providerResultRequests.length, 0);
  assert.equal(state.providerInvocationRequests[0].execution_backend, "rust_model_mount_native_local");
  assert.equal(state.providerInvocationRequests[0].provider_kind, "ioi_native_local");
  assert.equal(state.providerInvocationRequests[0].api_format, "ioi_native");
  assert.equal(state.providerInvocationRequests[0].driver, "native_local");
  assert.equal(
    state.providerInvocationRequests[0].backend_ref,
    "backend.autopilot.native-local.fixture",
  );
  assert.equal(result.receipt.details.provider_response_kind, "rust_model_mount.native_local");
  assert.equal(result.receipt.details.backend_id, "backend.autopilot.native-local.fixture");
  assert.equal(result.receipt.details.selected_backend, "backend.autopilot.native-local.fixture");
  assert.ok(result.receipt.details.backend_evidence_refs.includes("rust_model_mount_native_local_backend"));
  assert.equal(Object.hasOwn(result.receipt.details, "providerResponseKind"), false);
  assert.equal(Object.hasOwn(result.receipt.details, "backendId"), false);
  assert.equal(Object.hasOwn(result.receipt.details, "selectedBackend"), false);
  assert.equal(Object.hasOwn(result.receipt.details, "backendEvidenceRefs"), false);
});

test("invokeModel reuses identical in-flight provider execution and marks coalesced receipts", async () => {
  let resolveProvider;
  let providerInvocationCalls = 0;
  const state = fakeState({
    async executeModelMountProviderInvocation(request) {
      this.providerInvocationRequests.push(request);
      providerInvocationCalls += 1;
      await new Promise((resolve) => {
        resolveProvider = resolve;
      });
      return providerInvocationBridgeResult(request, {
        outputText: "shared answer",
        invocationHash: "sha256:provider-invocation-shared",
      });
    },
  });
  const operation = { authorization: "Bearer token", requiredScope: "model.chat:*", kind: "chat.completions", body: { model: "model.local" } };
  const depSet = deps({ modelInvocationCoalesceKey: () => "coalesce-key" });

  const first = invokeModel(state, operation, depSet);
  const second = invokeModel(state, operation, depSet);
  await Promise.resolve();
  resolveProvider();
  const [firstResult, secondResult] = await Promise.all([first, second]);

  assert.equal(providerInvocationCalls, 1);
  assert.equal(firstResult.receipt.kind, "model_invocation");
  assert.equal(secondResult.receipt.kind, "model_invocation_coalesced");
  assert.equal(secondResult.receipt.details.coalesced, true);
  assert.equal(secondResult.receipt.details.coalesce_key_hash, "hash:coalesce-key");
  assert.equal(Object.hasOwn(secondResult.receipt.details, "coalesceKeyHash"), false);
  assert.equal(secondResult.receipt.details.model_mount_invocation_admission_ref, "model_mount://invocation_admission/2");
  assert.equal(secondResult.receipt.details.model_mount_provider_execution_ref, "model_mount://provider_execution/1");
  assert.equal(secondResult.receipt.details.model_mount_receipt_binding_ref, "sha256:binding-2");
  assert.equal(secondResult.receipt.details.model_mount_step_module_result.agentgres_operation_refs[0], "agentgres://model-mounting/accepted-receipts/op_00000002_model_invocation_coalesced");
  assert.equal(state.inflightModelInvocations.size, 0);
});

test("startModelStream returns native stream invocations with stream-only receipt fields", async () => {
  let streamCalls = 0;
  const state = fakeState({
    selectRoute(payload) {
      this.selectRoutePayload = payload;
      return selection({
        endpoint: {
          apiFormat: "ioi_native",
          driver: "native_local",
          providerId: "provider.autopilot.local",
          backendId: "backend.autopilot.native-local.fixture",
        },
        provider: {
          id: "provider.autopilot.local",
          kind: "ioi_native_local",
          driver: "native_local",
        },
      });
    },
    driver: {
      supportsStream: () => true,
      async streamInvoke() {
        streamCalls += 1;
        throw new Error("native-local stream production must execute through Rust model_mount");
      },
    },
  });

  const result = await startModelStream(
    state,
    {
      authorization: "Bearer token",
      requiredScope: "model.responses:*",
      kind: "responses",
      body: { model: "model.local", response_id: "resp.stream", stream: true },
    },
    deps(),
  );

  assert.equal(result.native, true);
  assert.equal(streamCalls, 0);
  assert.equal(typeof result.providerStream.getReader, "function");
  assert.equal((await readReadableStreamText(result.providerStream)).includes("rust stream answer"), true);
  assert.equal(result.providerResult.providerResponseKind, "rust_model_mount.native_local.stream");
  assert.equal(result.providerResult.streamFormat, "ioi_jsonl");
  assert.equal(result.providerResult.streamKind, "openai_responses_native_local");
  assert.equal(result.providerResult.streamChunks.some((chunk) => chunk.includes("\"done\":true")), true);
  assert.equal(result.invocation.responseId, "resp.stream");
  assert.equal(result.invocation.receipt.details.stream_status, "started");
  assert.equal(result.invocation.receipt.details.stream_source, "provider_native");
  assert.equal(result.invocation.receipt.details.model_mount_invocation_admission_ref, "model_mount://invocation_admission/1");
  assert.equal(result.invocation.receipt.details.model_mount_provider_execution_ref, "model_mount://provider_execution/1");
  assert.equal(result.invocation.receipt.details.model_mount_provider_result_admission_ref, "model_mount://provider_result/1");
  assert.equal(result.invocation.receipt.details.model_mount_provider_result_admission_hash, "sha256:provider-result-1");
  assert.equal(result.invocation.receipt.details.model_mount_provider_result_admission.stream_status, "started");
  assert.equal(result.invocation.receipt.details.model_mount_invocation_admission.stream_status, "started");
  assert.equal(result.invocation.receipt.details.model_mount_receipt_binding_ref, "sha256:binding-1");
  assert.equal(result.invocation.receipt.details.model_mount_accepted_receipt_append.receipt_ref, "receipt://receipt.1.model_invocation");
  assert.equal(result.invocation.receipt.details.model_mount_agentgres_admission.operation_ref, "agentgres://model-mounting/accepted-receipts/op_00000001_model_invocation");
  assert.equal(Object.hasOwn(result.invocation.receipt.details, "modelMountAcceptedReceiptAppend"), false);
  assert.equal(Object.hasOwn(result.invocation.receipt.details, "modelMountAgentgresOperationRef"), false);
  assert.equal(Object.hasOwn(result.invocation.receipt.details, "modelMountProviderResultAdmissionRef"), false);
  assert.equal(Object.hasOwn(result.invocation.receipt.details, "coalesced"), false);
  assert.equal(Object.hasOwn(result.invocation.receipt.details, "sendOptions"), false);
  assert.deepEqual(state.appendOperations, []);
  assert.equal(state.providerExecutionRequests[0].stream_status, "started");
  assert.equal(state.providerStreamInvocationRequests.length, 1);
  assert.equal(state.providerStreamInvocationRequests[0].execution_backend, "rust_model_mount_native_local_stream");
  assert.equal(state.providerStreamInvocationRequests[0].stream_status, "started");
  assert.equal(state.providerStreamInvocationRequests[0].provider_kind, "ioi_native_local");
  assert.equal(state.providerStreamInvocationRequests[0].api_format, "ioi_native");
  assert.equal(state.providerStreamInvocationRequests[0].driver, "native_local");
  assert.equal(state.providerInvocationRequests.length, 0);
  assert.equal(state.providerResultRequests[0].stream_status, "started");
  assert.equal(state.providerResultRequests[0].output_text, "rust stream answer");
  assert.equal(state.providerResultRequests[0].provider_response_kind, "rust_model_mount.native_local.stream");
  assert.equal(result.invocation.receipt.details.provider_response_kind, "rust_model_mount.native_local.stream");
  assert.equal(Object.hasOwn(result.invocation.receipt.details, "streamStatus"), false);
  assert.equal(Object.hasOwn(result.invocation.receipt.details, "streamSource"), false);
  assert.equal(Object.hasOwn(result.invocation.receipt.details, "providerResponseKind"), false);
  assert.equal(state.routes.get("route.local-first").lastReceiptId, result.invocation.receipt.id);
});

test("startModelStream fails closed when selected Rust provider backend lacks native stream execution", async () => {
  const state = fakeState({
    selectRoute(payload) {
      this.selectRoutePayload = payload;
      return selection({
        endpoint: {
          apiFormat: "ioi_fixture",
          driver: "fixture",
          providerId: "provider.fixture",
          backendId: "backend.fixture",
        },
        provider: {
          id: "provider.fixture",
          kind: "local_folder",
          driver: "fixture",
        },
      });
    },
    driver: {
      supportsStream: () => true,
    },
  });

  await assert.rejects(
    () =>
      startModelStream(
        state,
        {
          authorization: "Bearer token",
          requiredScope: "model.chat:*",
          kind: "chat.completions",
          body: { model: "model.local", stream: true },
        },
        deps(),
      ),
    (error) => error.code === "model_mount_native_stream_backend_required",
  );
  assert.equal(state.providerExecutionRequests.length, 0);
  assert.equal(state.providerResultRequests.length, 0);
  assert.equal(state.fallbackInvocationArgs, undefined);
  assert.deepEqual(state.appendOperations, []);
});

test("startModelStream fails closed when provider lacks native streaming", async () => {
  const state = fakeState({
    selectRoute(payload) {
      this.selectRoutePayload = payload;
      return selection({
        endpoint: {
          apiFormat: "openai_chat_completions",
          driver: "openai_compatible",
          providerId: "provider.openai-compatible",
          backendId: "backend.openai-compatible",
        },
        provider: {
          id: "provider.openai-compatible",
          kind: "openai_compatible",
          driver: "openai_compatible",
        },
      });
    },
    driver: {
      supportsStream: () => false,
    },
  });

  await assert.rejects(
    () =>
      startModelStream(
        state,
        {
          authorization: "Bearer token",
          requiredScope: "model.chat:*",
          kind: "chat.completions",
          body: { model: "model.local", stream: true },
        },
        deps(),
      ),
    (error) => error.code === "model_mount_native_stream_capability_required",
  );
  assert.equal(state.providerExecutionRequests.length, 0);
  assert.equal(state.providerResultRequests.length, 0);
  assert.equal(state.fallbackInvocationArgs, undefined);
  assert.deepEqual(state.appendOperations, []);
});

test("startModelStream fails closed when admitted hosted stream path returns no stream", async () => {
  let streamCalls = 0;
  const state = fakeState({
    selectRoute(payload) {
      this.selectRoutePayload = payload;
      return selection({
        endpoint: {
          apiFormat: "openai_chat_completions",
          driver: "openai_compatible",
          providerId: "provider.openai-compatible",
          backendId: "backend.openai-compatible",
        },
        provider: {
          id: "provider.openai-compatible",
          kind: "openai_compatible",
          driver: "openai_compatible",
        },
      });
    },
    driver: {
      supportsStream: () => true,
      async streamInvoke() {
        streamCalls += 1;
        return { providerResponseKind: "openai.responses.stream" };
      },
    },
  });

  await assert.rejects(
    () =>
      startModelStream(
        state,
        {
          authorization: "Bearer token",
          requiredScope: "model.responses:*",
          kind: "responses",
          body: { model: "model.local", response_id: "resp.stream", stream: true },
        },
        deps(),
      ),
    (error) => error.code === "model_mount_native_stream_result_required",
  );
  assert.equal(streamCalls, 1);
  assert.equal(state.providerExecutionRequests.length, 1);
  assert.equal(state.providerStreamInvocationRequests.length, 0);
  assert.equal(state.providerResultRequests.length, 0);
  assert.equal(state.fallbackInvocationArgs, undefined);
  assert.deepEqual(state.appendOperations, []);
});

test("startModelStream fails closed without Rust provider execution admission before stream call", async () => {
  let streamCalls = 0;
  const state = fakeState({
    admitModelMountProviderExecution: undefined,
    selectRoute(payload) {
      this.selectRoutePayload = payload;
      return selection({
        endpoint: {
          apiFormat: "ioi_native",
          driver: "native_local",
          providerId: "provider.autopilot.local",
          backendId: "backend.autopilot.native-local.fixture",
        },
        provider: {
          id: "provider.autopilot.local",
          kind: "ioi_native_local",
          driver: "native_local",
        },
      });
    },
    driver: {
      supportsStream: () => true,
      async streamInvoke() {
        streamCalls += 1;
        return {
          stream: { [Symbol.asyncIterator]: async function* noop() {} },
        };
      },
    },
  });

  await assert.rejects(
    () =>
      startModelStream(
        state,
        {
          authorization: "Bearer token",
          requiredScope: "model.responses:*",
          kind: "responses",
          body: { model: "model.local", response_id: "resp.stream", stream: true },
        },
        deps(),
      ),
    (error) => error.code === "model_mount_provider_execution_admission_required",
  );
  assert.equal(streamCalls, 0);
  assert.equal(state.providerStreamInvocationRequests.length, 0);
  assert.deepEqual(state.appendOperations, []);
});

test("startModelStream fails closed without Rust provider result admission before stream call", async () => {
  let streamCalls = 0;
  const state = fakeState({
    admitModelMountProviderResult: undefined,
    selectRoute(payload) {
      this.selectRoutePayload = payload;
      return selection({
        endpoint: {
          apiFormat: "ioi_native",
          driver: "native_local",
          providerId: "provider.autopilot.local",
          backendId: "backend.autopilot.native-local.fixture",
        },
        provider: {
          id: "provider.autopilot.local",
          kind: "ioi_native_local",
          driver: "native_local",
        },
      });
    },
    driver: {
      supportsStream: () => true,
      async streamInvoke() {
        streamCalls += 1;
        return {
          stream: { [Symbol.asyncIterator]: async function* noop() {} },
        };
      },
    },
  });

  await assert.rejects(
    () =>
      startModelStream(
        state,
        {
          authorization: "Bearer token",
          requiredScope: "model.responses:*",
          kind: "responses",
          body: { model: "model.local", response_id: "resp.stream", stream: true },
        },
        deps(),
      ),
    (error) => error.code === "model_mount_provider_result_admission_required",
  );
  assert.equal(streamCalls, 0);
  assert.equal(state.providerExecutionRequests.length, 1);
  assert.equal(state.providerStreamInvocationRequests.length, 0);
  assert.deepEqual(state.appendOperations, []);
});

test("startModelStream rejects provider compatibility translations before admission", async () => {
  let streamCalls = 0;
  const state = fakeState({
    selectRoute(payload) {
      this.selectRoutePayload = payload;
      return selection({
        endpoint: {
          apiFormat: "ioi_native",
          driver: "native_local",
          providerId: "provider.autopilot.local",
          backendId: "backend.autopilot.native-local.fixture",
        },
        provider: {
          id: "provider.autopilot.local",
          kind: "ioi_native_local",
          driver: "native_local",
        },
      });
    },
    driver: {
      supportsStream: () => true,
      async streamInvoke() {
        streamCalls += 1;
        throw new Error("native-local stream production must execute through Rust model_mount");
      },
    },
    executeModelMountProviderStreamInvocation(request) {
      this.providerStreamInvocationRequests.push(request);
      return providerStreamInvocationBridgeResult(request, { compatTranslation: "chat_completions" });
    },
  });

  await assert.rejects(
    () =>
      startModelStream(
        state,
        {
          authorization: "Bearer token",
          requiredScope: "model.responses:*",
          kind: "responses",
          body: { model: "model.local", response_id: "resp.stream", stream: true },
        },
        deps(),
      ),
    (error) =>
      error.code === "model_mount_provider_compat_translation_forbidden" &&
      error.details.compat_translation === "chat_completions" &&
      error.details.retired_aliases.includes("compatTranslation") &&
      Object.hasOwn(error.details, "compatTranslation") === false,
  );
  assert.equal(streamCalls, 0);
  assert.equal(state.providerExecutionRequests.length, 1);
  assert.equal(state.providerStreamInvocationRequests.length, 1);
  assert.equal(state.providerResultRequests.length, 0);
  assert.equal(state.receipts.length, 0);
});

test("modelMountInvocationAdmissionRequestForReceipt binds route decision and invocation receipts", () => {
  const request = modelMountInvocationAdmissionRequestForReceipt({
    body: {
      authority_receipt_refs: ["receipt://wallet/model-chat"],
      custody_ref: "ctee://custody/private-workspace",
      privacy_profile: "private_workspace_ctee",
    },
    capability: "chat",
    kind: "responses",
    receiptDetails: {
      route_id: "route.local-first",
      provider_id: "provider.local",
      endpoint_id: "endpoint.local",
      selected_model: "model.local",
      policy_hash: "policy",
      input_hash: "input",
      output_hash: "output",
      grant_id: "grant://wallet/model-chat",
      tool_receipt_ids: ["receipt.tool"],
      provider_auth_evidence_refs: ["provider.auth"],
      backend_evidence_refs: ["backend.evidence"],
      response_id: "resp.1",
      previous_response_id: "resp.0",
    },
    receiptId: "receipt.invoke",
    receiptKind: "model_invocation",
    routeReceipt: {
      id: "receipt.route",
      details: {
        model_mount_route_decision_ref: "model_mount://route_decision/test",
        workflow_graph_id: "graph.1",
        workflow_node_id: "node.1",
      },
    },
    selection: selection(),
  });

  assert.equal(request.schema_version, "ioi.model_mount.invocation_admission.v1");
  assert.equal(request.route_decision_ref, "model_mount://route_decision/test");
  assert.equal(request.route_receipt_ref, "receipt://receipt.route");
  assert.equal(request.invocation_receipt_ref, "receipt://receipt.invoke");
  assert.deepEqual(request.receipt_refs, [
    "receipt://receipt.route",
    "receipt://receipt.invoke",
    "receipt://receipt.tool",
  ]);
  assert.equal(request.policy_hash, "sha256:policy");
  assert.equal(request.input_hash, "sha256:input");
  assert.equal(request.output_hash, "sha256:output");
  assert.deepEqual(request.authority_grant_refs, ["grant://wallet/model-chat"]);
  assert.deepEqual(request.authority_receipt_refs, ["receipt://wallet/model-chat"]);
  assert.deepEqual(request.provider_auth_evidence_refs, ["provider.auth"]);
  assert.deepEqual(request.backend_evidence_refs, ["backend.evidence"]);
  assert.equal(request.custody_ref, "ctee://custody/private-workspace");
  assert.equal(request.privacy_profile, "private_workspace_ctee");
  assert.equal(request.workflow_graph_ref, "graph.1");
  assert.equal(request.workflow_node_ref, "node.1");
  assert.equal(request.response_ref, "resp.1");
  assert.equal(request.previous_response_ref, "resp.0");
});

test("modelMountInvocationAdmissionRequestForReceipt rejects retired route-decision detail alias", () => {
  assert.throws(
    () =>
      modelMountInvocationAdmissionRequestForReceipt({
        body: {},
        capability: "chat",
        kind: "responses",
        receiptDetails: {
          routeId: "route.local-first",
          providerId: "provider.local",
          endpointId: "endpoint.local",
          selectedModel: "model.local",
          policyHash: "policy",
          inputHash: "input",
          outputHash: "output",
        },
        receiptId: "receipt.invoke",
        receiptKind: "model_invocation",
        routeReceipt: {
          id: "receipt.route",
          details: {
            modelMountRouteDecisionRef: "model_mount://route_decision/test",
          },
        },
        selection: selection(),
      }),
    (error) => {
      assert.equal(error.code, "model_mount_invocation_ref_missing");
      assert.equal(error.details.field, "routeReceipt.details.model_mount_route_decision_ref");
      return true;
    },
  );
});

test("modelMountInvocationAdmissionRequestForReceipt rejects retired authority aliases before ref validation", () => {
  assert.throws(
    () =>
      modelMountInvocationAdmissionRequestForReceipt({
        body: {
          authorityGrantRefs: ["grant://model-chat"],
          authorityReceiptRefs: ["receipt://wallet/model-chat"],
          custodyRef: "ctee://custody/private-workspace",
          privacyProfile: "private_workspace_ctee",
          nodePlaintextAllowed: true,
        },
      }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "model_mount_invocation_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, [
        "authorityGrantRefs",
        "authorityReceiptRefs",
        "custodyRef",
        "privacyProfile",
        "nodePlaintextAllowed",
      ]);
      return true;
    },
  );
});

test("modelMountProviderExecutionRequestForInvocation gates provider driver execution", () => {
  const request = modelMountProviderExecutionRequestForInvocation({
    body: {
      authority_receipt_refs: ["receipt://wallet/model-chat"],
      custody_ref: "ctee://custody/private-workspace",
      privacy_profile: "private_workspace_ctee",
      model_policy: { privacy_profile: "private_workspace_ctee" },
    },
    capability: "chat",
    ephemeralMcp: {
      toolReceiptIds: ["receipt.tool"],
    },
    hash: (value) => `hash:${JSON.stringify(value)}`,
    input: "hello",
    instance: {
      id: "instance.local",
      backendId: "backend.local",
    },
    kind: "responses",
    previousResponseId: "resp.previous",
    providerBody: { model: "model.local", stream: false },
    responseId: "resp.1",
    routeReceipt: {
      id: "receipt.route",
      details: {
        model_mount_route_decision_ref: "model_mount://route_decision/test",
        workflow_graph_id: "graph.1",
        workflow_node_id: "node.1",
      },
    },
    selection: selection(),
    streamStatus: null,
    token: {
      grantId: "grant://wallet/model-chat",
    },
  });

  assert.equal(request.schema_version, "ioi.model_mount.provider_execution.v1");
  assert.equal(request.route_decision_ref, "model_mount://route_decision/test");
  assert.equal(request.route_receipt_ref, "receipt://receipt.route");
  assert.equal(request.model_ref, "model.local");
  assert.equal(request.request_hash.startsWith("sha256:"), true);
  assert.deepEqual(request.receipt_refs, ["receipt://receipt.route", "receipt://receipt.tool"]);
  assert.deepEqual(request.authority_grant_refs, ["grant://wallet/model-chat"]);
  assert.deepEqual(request.authority_receipt_refs, ["receipt://wallet/model-chat"]);
  assert.deepEqual(request.backend_evidence_refs, ["backend.local", "backend.endpoint"]);
  assert.equal(request.custody_ref, "ctee://custody/private-workspace");
  assert.equal(request.privacy_profile, "private_workspace_ctee");
  assert.equal(request.response_ref, "resp.1");
  assert.equal(request.previous_response_ref, "resp.previous");
});

test("modelMountProviderExecutionRequestForInvocation rejects retired authority aliases before route receipt validation", () => {
  assert.throws(
    () =>
      modelMountProviderExecutionRequestForInvocation({
        body: {
          authorityGrantRefs: ["grant://model-chat"],
          authorityReceiptRefs: ["receipt://wallet/model-chat"],
          custodyRef: "ctee://custody/private-workspace",
          privacyProfile: "private_workspace_ctee",
          nodePlaintextAllowed: true,
        },
      }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "model_mount_invocation_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, [
        "authorityGrantRefs",
        "authorityReceiptRefs",
        "custodyRef",
        "privacyProfile",
        "nodePlaintextAllowed",
      ]);
      return true;
    },
  );
});

test("model mount invocation admission builders ignore retired policy privacy profile alias", () => {
  const routeReceipt = {
    id: "receipt.route",
    details: {
      model_mount_route_decision_ref: "model_mount://route_decision/test",
    },
  };
  const selected = selection({ route: { privacy: "local_or_enterprise" } });
  const invocationAdmission = modelMountInvocationAdmissionRequestForReceipt({
    body: { model: "model.local", model_policy: { privacyProfile: "private_workspace_ctee" } },
    capability: "chat",
    kind: "responses",
    receiptDetails: {
      route_id: "route.local-first",
      provider_id: "provider.local",
      endpoint_id: "endpoint.local",
      selected_model: "model.local",
      policy_hash: "policy",
      input_hash: "input",
      output_hash: "output",
    },
    receiptId: "receipt.invoke",
    receiptKind: "model_invocation",
    routeReceipt,
    selection: selected,
  });
  const providerExecution = modelMountProviderExecutionRequestForInvocation({
    body: { model: "model.local", model_policy: { privacyProfile: "private_workspace_ctee" } },
    capability: "chat",
    hash: (value) => `hash:${JSON.stringify(value)}`,
    input: "hello",
    instance: { id: "instance.local", backendId: "backend.local" },
    kind: "responses",
    providerBody: { model: "model.local" },
    routeReceipt,
    selection: selected,
    token: { grantId: "grant://model-chat" },
  });

  assert.equal(invocationAdmission.privacy_profile, "local_or_enterprise");
  assert.equal(providerExecution.privacy_profile, "local_or_enterprise");
  assert.equal(Object.hasOwn(invocationAdmission, "privacyProfile"), false);
  assert.equal(Object.hasOwn(providerExecution, "privacyProfile"), false);
});

test("modelMountProviderInvocationRequestForExecution binds fixture execution to provider admission", () => {
  const admission = {
    source: "rust_model_mount_provider_execution_command",
    backend: "rust_model_mount_live",
    record: {
      schema_version: "ioi.model_mount.provider_execution.v1",
      provider_execution_ref: "model_mount://provider_execution/test",
      provider_execution_hash: "sha256:provider-execution-test",
      route_decision_ref: "model_mount://route_decision/test",
      route_receipt_ref: "receipt://route",
      route_ref: "route.local-first",
      provider_ref: "provider.local",
      endpoint_ref: "endpoint.local",
      model_ref: "model.local",
      capability: "chat",
      invocation_kind: "chat.completions",
      request_hash: "sha256:request",
      receipt_refs: ["receipt://route"],
    },
    provider_execution_ref: "model_mount://provider_execution/test",
    provider_execution_hash: "sha256:provider-execution-test",
    receipt_refs: ["receipt://route"],
    evidence_refs: ["rust_model_mount_core"],
  };

  const request = modelMountProviderInvocationRequestForExecution({
    input: "user: hello",
    instance: { backendId: "backend.fixture" },
    kind: "chat.completions",
    modelMountProviderExecutionAdmission: admission,
    selection: selection({
      endpoint: { apiFormat: "ioi_fixture", driver: "fixture" },
      provider: { driver: "fixture" },
    }),
  });

  assert.equal(request.schema_version, "ioi.model_mount.provider_invocation.v1");
  assert.equal(request.provider_execution_ref, "model_mount://provider_execution/test");
  assert.equal(request.provider_execution_hash, "sha256:provider-execution-test");
  assert.equal(request.execution_backend, "rust_model_mount_fixture");
  assert.equal(request.provider_kind, "local_folder");
  assert.equal(request.api_format, "ioi_fixture");
  assert.equal(request.driver, "fixture");
  assert.equal(request.backend_ref, "backend.fixture");
  assert.deepEqual(request.receipt_refs, ["receipt://route"]);
  assert.equal(request.admitted_provider_execution.provider_execution_hash, "sha256:provider-execution-test");
  assert.equal(modelMountProviderInvocationRequiresRust({ provider: { kind: "local_folder" }, endpoint: {} }), true);
  assert.equal(
    modelMountProviderInvocationRequiresRust({
      provider: { kind: "ioi_native_local", driver: "native_local" },
      endpoint: { apiFormat: "ioi_native", driver: "native_local" },
    }),
    true,
  );
  assert.equal(
    modelMountProviderInvocationRequiresRust(
      {
        provider: { kind: "ioi_native_local", driver: "native_local" },
        endpoint: { apiFormat: "ioi_native", driver: "native_local" },
      },
      { stream: true },
    ),
    false,
  );
  assert.equal(modelMountProviderInvocationRequiresRust({ provider: { kind: "openai" }, endpoint: {} }), false);
});

test("modelMountProviderStreamInvocationRequestForExecution binds native-local stream execution to provider admission", () => {
  const admission = {
    source: "rust_model_mount_provider_execution_command",
    backend: "rust_model_mount_live",
    record: {
      schema_version: "ioi.model_mount.provider_execution.v1",
      provider_execution_ref: "model_mount://provider_execution/stream-test",
      provider_execution_hash: "sha256:provider-execution-stream-test",
      route_decision_ref: "model_mount://route_decision/test",
      route_receipt_ref: "receipt://route",
      route_ref: "route.native-local",
      provider_ref: "provider.autopilot.local",
      endpoint_ref: "endpoint.native-local",
      model_ref: "model://qwen/qwen3.5-9b",
      capability: "responses",
      invocation_kind: "responses",
      request_hash: "sha256:request",
      stream_status: "started",
      receipt_refs: ["receipt://route"],
    },
    provider_execution_ref: "model_mount://provider_execution/stream-test",
    provider_execution_hash: "sha256:provider-execution-stream-test",
    receipt_refs: ["receipt://route"],
    evidence_refs: ["rust_model_mount_core"],
  };

  const request = modelMountProviderStreamInvocationRequestForExecution({
    input: "user: hello",
    instance: { backendId: "backend.autopilot.native-local.fixture" },
    kind: "responses",
    modelMountProviderExecutionAdmission: admission,
    selection: selection({
      endpoint: {
        apiFormat: "ioi_native",
        driver: "native_local",
        modelId: "model://qwen/qwen3.5-9b",
        providerId: "provider.autopilot.local",
      },
      provider: {
        id: "provider.autopilot.local",
        kind: "ioi_native_local",
        driver: "native_local",
      },
    }),
  });

  assert.equal(request.schema_version, "ioi.model_mount.provider_invocation.v1");
  assert.equal(request.provider_execution_ref, "model_mount://provider_execution/stream-test");
  assert.equal(request.provider_execution_hash, "sha256:provider-execution-stream-test");
  assert.equal(request.execution_backend, "rust_model_mount_native_local_stream");
  assert.equal(request.stream_status, "started");
  assert.equal(request.provider_kind, "ioi_native_local");
  assert.equal(request.api_format, "ioi_native");
  assert.equal(request.driver, "native_local");
  assert.equal(request.backend_ref, "backend.autopilot.native-local.fixture");
  assert.deepEqual(request.receipt_refs, ["receipt://route"]);
  assert.equal(request.admitted_provider_execution.provider_execution_hash, "sha256:provider-execution-stream-test");
  assert.equal(
    modelMountProviderStreamInvocationRequiresRust({
      provider: { kind: "ioi_native_local", driver: "native_local" },
      endpoint: { apiFormat: "ioi_native", driver: "native_local" },
    }),
    true,
  );
  assert.equal(modelMountProviderStreamInvocationRequiresRust({ provider: { kind: "local_folder" }, endpoint: {} }), false);
  assert.equal(modelMountProviderStreamInvocationRequiresRust({ provider: { kind: "openai" }, endpoint: {} }), false);
});

test("modelMountProviderResultAdmissionRequestForExecution binds JS provider observation to provider admission", () => {
  const admission = {
    source: "rust_model_mount_provider_execution_command",
    backend: "rust_model_mount_live",
    record: {
      schema_version: "ioi.model_mount.provider_execution.v1",
      provider_execution_ref: "model_mount://provider_execution/test",
      provider_execution_hash: "sha256:provider-execution-test",
      route_decision_ref: "model_mount://route_decision/test",
      route_receipt_ref: "receipt://route",
      route_ref: "route.hosted",
      provider_ref: "provider.openai",
      endpoint_ref: "endpoint.openai",
      model_ref: "model.openai",
      capability: "chat",
      invocation_kind: "chat.completions",
      request_hash: "sha256:request",
      receipt_refs: ["receipt://route"],
    },
    provider_execution_ref: "model_mount://provider_execution/test",
    provider_execution_hash: "sha256:provider-execution-test",
    receipt_refs: ["receipt://route"],
    evidence_refs: ["rust_model_mount_core"],
  };

  const request = modelMountProviderResultAdmissionRequestForExecution({
    input: "user: hello",
    instance: { backendId: "backend.instance" },
    kind: "chat.completions",
    modelMountProviderExecutionAdmission: admission,
    providerResult: {
      outputText: "hosted provider answer",
      providerResponseKind: "openai.chat",
      tokenCount: { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3 },
      providerAuthEvidenceRefs: ["provider.auth"],
      backendEvidenceRefs: ["backend.openai-compatible"],
    },
    selection: selection({
      endpoint: {
        apiFormat: "openai",
        providerId: "provider.openai",
        backendId: "backend.openai-compatible",
      },
      provider: {
        id: "provider.openai",
        kind: "openai",
        driver: "openai_compatible",
      },
    }),
  });

  assert.equal(request.schema_version, "ioi.model_mount.provider_result.v1");
  assert.equal(request.provider_execution_ref, "model_mount://provider_execution/test");
  assert.equal(request.provider_execution_hash, "sha256:provider-execution-test");
  assert.equal(request.provider_kind, "openai");
  assert.equal(request.execution_backend, "js_provider_driver_observation");
  assert.equal(request.provider_response_kind, "openai.chat");
  assert.equal(request.output_text, "hosted provider answer");
  assert.equal(request.output_hash.startsWith("sha256:"), true);
  assert.deepEqual(request.token_count, { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3 });
  assert.deepEqual(request.provider_auth_evidence_refs, ["provider.auth"]);
  assert.deepEqual(request.backend_evidence_refs, ["backend.openai-compatible"]);
  assert.equal(request.admitted_provider_execution.provider_execution_hash, "sha256:provider-execution-test");
});

test("modelMountInvocationReceiptBindingRequestForReceipt builds model_mount StepModule binding", () => {
  const admissionRequest = modelMountInvocationAdmissionRequestForReceipt({
    body: {},
    capability: "responses",
    kind: "responses",
    receiptDetails: {
      route_id: "route.local-first",
      provider_id: "provider.local",
      endpoint_id: "endpoint.local",
      selected_model: "model.local",
      policy_hash: "sha256:policy",
      input_hash: "sha256:input",
      output_hash: "sha256:output",
      grant_id: "grant://wallet/model-chat",
      response_id: "resp.1",
    },
    receiptId: "receipt.invoke",
    receiptKind: "model_invocation",
    routeReceipt: {
      id: "receipt.route",
      details: {
        model_mount_route_decision_ref: "model_mount://route_decision/test",
        workflow_graph_id: "graph.1",
        workflow_node_id: "node.1",
      },
    },
    selection: selection(),
  });
  const agentgresTransition = modelMountInvocationAgentgresTransitionForReceipt(fakeState(), {
    admission: {
      invocation_admission_ref: "model_mount://invocation_admission/test",
      invocation_admission_hash: "sha256:invocation-test",
    },
    admissionRequest,
    receiptDetails: {
      input_hash: "sha256:input",
      output_hash: "sha256:output",
    },
    receiptId: "receipt.invoke",
    receiptKind: "model_invocation",
  });
  const request = modelMountInvocationReceiptBindingRequestForReceipt({
    admission: {
      invocation_admission_ref: "model_mount://invocation_admission/test",
      evidence_refs: ["rust_model_mount_core"],
    },
    admissionRequest,
    agentgresTransition,
    receiptDetails: {
      provider_auth_evidence_refs: ["provider.auth"],
      backend_evidence_refs: ["backend.evidence"],
    },
    receiptId: "receipt.invoke",
  });

  assert.equal(request.receiptRef, "receipt://receipt.invoke");
  assert.deepEqual(request.acceptedReceiptTransition.expected_heads, [
    "agentgres://model-mounting/accepted-receipts/head/0",
  ]);
  assert.equal(request.invocation.module_ref.kind, "model_mount");
  assert.equal(request.invocation.execution.backend, "model_mount");
  assert.equal(request.invocation.input.state_root_before, "sha256:state-0");
  assert.equal(request.invocation.workflow_graph_id, "graph.1");
  assert.equal(request.invocation.workflow_node_id, "node.1");
  assert.deepEqual(request.invocation.authority.authority_grant_refs, ["grant://wallet/model-chat"]);
  assert.deepEqual(request.result.receipt_refs, ["receipt://receipt.invoke"]);
  assert.deepEqual(request.result.agentgres_operation_refs, [
    "agentgres://model-mounting/accepted-receipts/op_00000001_model_invocation",
  ]);
  assert.equal(request.result.resulting_head, "agentgres://model-mounting/accepted-receipts/head/1");
  assert.equal(request.result.workflow_projection.component_kind, "ModelInvocationNode");
  assert.equal(request.result.workflow_projection.status, "live");
  assert.ok(request.result.workflow_projection.evidence_refs.includes("provider.auth"));
});

test("invokeModel fails closed without invocation receipt id support", async () => {
  const state = fakeState({ nextReceiptId: undefined });

  await assert.rejects(
    () =>
      invokeModel(
        state,
        {
          authorization: "Bearer token",
          requiredScope: "model.chat:*",
          kind: "responses",
          body: { model: "model.local" },
        },
        deps(),
      ),
    (error) => error.code === "model_mount_invocation_receipt_id_required",
  );
});

test("invokeModel fails closed without Rust provider execution admission before provider call", async () => {
  let providerCalls = 0;
  const state = fakeState({
    admitModelMountProviderExecution: undefined,
    driver: {
      async invoke() {
        providerCalls += 1;
        return { outputText: "should not run" };
      },
    },
  });

  await assert.rejects(
    () =>
      invokeModel(
        state,
        {
          authorization: "Bearer token",
          requiredScope: "model.chat:*",
          kind: "responses",
          body: { model: "model.local" },
        },
        deps(),
      ),
    (error) => error.code === "model_mount_provider_execution_admission_required",
  );
  assert.equal(providerCalls, 0);
});

test("invokeModel fails closed for migrated fixture backend without Rust provider invocation execution", async () => {
  let providerCalls = 0;
  const state = fakeState({
    executeModelMountProviderInvocation: undefined,
    driver: {
      async invoke() {
        providerCalls += 1;
        return { outputText: "should not run" };
      },
    },
  });

  await assert.rejects(
    () =>
      invokeModel(
        state,
        {
          authorization: "Bearer token",
          requiredScope: "model.chat:*",
          kind: "responses",
          body: { model: "model.local" },
        },
        deps(),
      ),
    (error) => error.code === "model_mount_provider_invocation_execution_required",
  );
  assert.equal(providerCalls, 0);
});

test("invokeModel keeps unmigrated provider drivers behind provider execution admission", async () => {
  let providerCalls = 0;
  const state = fakeState({
    executeModelMountProviderInvocation: undefined,
    driver: {
      async invoke() {
        providerCalls += 1;
        return {
          outputText: "hosted provider answer",
          providerResponseKind: "openai.chat",
          tokenCount: { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3 },
        };
      },
    },
    selectRoute(payload) {
      this.selectRoutePayload = payload;
      return selection({
        endpoint: {
          apiFormat: "openai",
          providerId: "provider.openai",
          backendId: "backend.openai-compatible",
        },
        provider: {
          id: "provider.openai",
          kind: "openai",
          driver: "openai_compatible",
        },
      });
    },
  });

  const result = await invokeModel(
    state,
    {
      authorization: "Bearer token",
      requiredScope: "model.chat:*",
      kind: "responses",
      body: { model: "model.local" },
    },
    deps(),
  );

  assert.equal(providerCalls, 1);
  assert.equal(state.providerInvocationRequests.length, 0);
  assert.equal(state.providerResultRequests.length, 1);
  assert.equal(state.providerResultRequests[0].provider_execution_ref, "model_mount://provider_execution/1");
  assert.equal(state.providerResultRequests[0].execution_backend, "js_provider_driver_observation");
  assert.equal(result.outputText, "hosted provider answer");
  assert.equal(result.receipt.details.model_mount_provider_execution_ref, "model_mount://provider_execution/1");
  assert.equal(result.receipt.details.model_mount_provider_result_admission_ref, "model_mount://provider_result/1");
  assert.equal(result.receipt.details.model_mount_provider_result_admission_hash, "sha256:provider-result-1");
  assert.equal(
    result.receipt.details.model_mount_provider_result_admission.execution_backend,
    "js_provider_driver_observation",
  );
  assert.ok(result.receipt.evidenceRefs.includes("model_mount://provider_result/1"));
});

test("invokeModel rejects provider compatibility translations before result admission", async () => {
  let providerCalls = 0;
  const state = fakeState({
    executeModelMountProviderInvocation: undefined,
    driver: {
      async invoke() {
        providerCalls += 1;
        return {
          outputText: "translated provider answer",
          providerResponseKind: "openai.chat",
          compat_translation: "chat_completions",
          tokenCount: { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3 },
        };
      },
    },
    selectRoute(payload) {
      this.selectRoutePayload = payload;
      return selection({
        endpoint: {
          apiFormat: "openai",
          providerId: "provider.openai",
          backendId: "backend.openai-compatible",
        },
        provider: {
          id: "provider.openai",
          kind: "openai",
          driver: "openai_compatible",
        },
      });
    },
  });

  await assert.rejects(
    () =>
      invokeModel(
        state,
        {
          authorization: "Bearer token",
          requiredScope: "model.chat:*",
          kind: "responses",
          body: { model: "model.local" },
        },
        deps(),
      ),
    (error) =>
      error.code === "model_mount_provider_compat_translation_forbidden" &&
      error.details.compat_translation === "chat_completions" &&
      Object.hasOwn(error.details, "compatTranslation") === false &&
      Object.hasOwn(error.details, "retired_aliases") === false,
  );
  assert.equal(providerCalls, 1);
  assert.equal(state.providerExecutionRequests.length, 1);
  assert.equal(state.providerResultRequests.length, 0);
  assert.equal(state.receipts.length, 0);
});

test("invokeModel fails closed for unmigrated provider drivers without Rust provider result admission", async () => {
  let providerCalls = 0;
  const state = fakeState({
    admitModelMountProviderResult: undefined,
    executeModelMountProviderInvocation: undefined,
    driver: {
      async invoke() {
        providerCalls += 1;
        return { outputText: "should not run" };
      },
    },
    selectRoute(payload) {
      this.selectRoutePayload = payload;
      return selection({
        endpoint: {
          apiFormat: "openai",
          providerId: "provider.openai",
          backendId: "backend.openai-compatible",
        },
        provider: {
          id: "provider.openai",
          kind: "openai",
          driver: "openai_compatible",
        },
      });
    },
  });

  await assert.rejects(
    () =>
      invokeModel(
        state,
        {
          authorization: "Bearer token",
          requiredScope: "model.chat:*",
          kind: "responses",
          body: { model: "model.local" },
        },
        deps(),
      ),
    (error) => error.code === "model_mount_provider_result_admission_required",
  );
  assert.equal(providerCalls, 0);
  assert.equal(state.providerResultRequests.length, 0);
});

test("invokeModel fails closed without Rust receipt binding support", async () => {
  const state = fakeState({ bindModelMountInvocationReceipt: undefined });

  await assert.rejects(
    () =>
      invokeModel(
        state,
        {
          authorization: "Bearer token",
          requiredScope: "model.chat:*",
          kind: "responses",
          body: { model: "model.local" },
        },
        deps(),
      ),
    (error) => error.code === "model_mount_invocation_receipt_binding_required",
  );
});

test("invokeModel fails closed without Rust accepted receipt transition planning", async () => {
  const state = fakeState({ planModelMountAcceptedReceiptTransition: undefined });

  await assert.rejects(
    () =>
      invokeModel(
        state,
        {
          authorization: "Bearer token",
          requiredScope: "model.chat:*",
          kind: "responses",
          body: { model: "model.local" },
        },
        deps(),
      ),
    (error) => error.code === "model_mount_accepted_receipt_transition_planner_required",
  );
});

test("invokeModel fails closed without Agentgres operation head support", async () => {
  const state = fakeState({ agentgresModelMountingHead: undefined });

  await assert.rejects(
    () =>
      invokeModel(
        state,
        {
          authorization: "Bearer token",
          requiredScope: "model.chat:*",
          kind: "responses",
          body: { model: "model.local" },
        },
        deps(),
      ),
    (error) => error.code === "model_mount_agentgres_head_required",
  );
});
