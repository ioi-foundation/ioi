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
    agentgresConversationRecords: new Map(),
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
      return { grant_ref: "grant.test" };
    },
    compileEphemeralMcpIntegrations() {
      return {
        evidence_refs: ["mcp.ephemeral"],
        server_ids: ["mcp.server"],
        tool_receipt_ids: ["receipt.tool"],
      };
    },
    conversationState(responseId) {
      return this.agentgresConversationRecords.get(responseId);
    },
    driverForProvider() {
      return this.driver;
    },
    async ensureLoaded(endpoint) {
      this.loadedEndpointId = endpoint.id;
      return {
        id: "instance.local",
        backend_id: "backend.local",
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
        head_ref: `agentgres://model-mounting/accepted-receipts/head/${sequence}`,
        state_root: `sha256:state-${sequence}`,
        projection_watermark: `model-mounting-accepted-receipts:${sequence}`,
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
        source: "rust_daemon_core.model_mount.accepted_receipt_transition",
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
        operation_id: operationId,
        operation_ref: `agentgres://model-mounting/accepted-receipts/${operationId}`,
        expected_heads: [request.current_head_ref],
        state_root_before: request.current_state_root,
        state_root_after: `sha256:state-${nextSequence}`,
        resulting_head: `agentgres://model-mounting/accepted-receipts/head/${nextSequence}`,
        projection_watermark: `model-mounting-accepted-receipts:${nextSequence}`,
        transition_hash: `sha256:transition-${nextSequence}`,
        evidence_refs: ["rust_model_mount_accepted_receipt_transition"],
      };
    },
    bindModelMountInvocationReceipt(request) {
      this.receiptBindingRequests.push(request);
      return {
        source: "rust_daemon_core.model_mount.invocation_receipt_binding",
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
      return selectionWithRouteReceipt(this.routeSelection ?? selection());
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
    persistRustAuthoredReceipt(record) {
      this.receipts.push(record);
      return record;
    },
    appendOperation(kind, payload) {
      this.appendOperations.push({ kind, payload });
    },
    ...overrides,
  };
  state.driver ??= {
    async invoke() {
      return {
        output_text: "provider answer",
        providerResponse: { id: "provider.response" },
        provider_response_kind: "openai.chat",
        token_count: { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3 },
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
      model_id: "model.local",
      provider_id: "provider.local",
      api_format: "openai",
      backend_id: "backend.endpoint",
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

function selectionWithRouteReceipt(selected = selection()) {
  return {
    ...selected,
    route_decision: {
      route_decision_ref: "model_mount://route_decision/test",
      route_decision_hash: "sha256:route-decision-test",
    },
    route_receipt: {
      id: "receipt.route",
      kind: "model_route_selection",
      details: {
        rust_daemon_core_receipt_author: "ModelMountCore.admit_route_decision",
        model_mount_route_decision_ref: "model_mount://route_decision/test",
        workflow_graph_id: "workflow.graph",
        workflow_node_id: "workflow.node",
      },
      schemaVersion: "ioi.model-mounting.runtime.v1",
    },
  };
}

function deps(overrides = {}) {
  return {
    inputText: () => "user: hello",
    modelInvocationCoalesceKey: () => null,
    optionalString: (value) => (typeof value === "string" && value ? value : null),
    stableHash: (value) => `hash:${value}`,
    supportsResponseState: (kind) => kind === "responses",
    ...overrides,
  };
}

function providerInvocationBridgeResult(request, options = {}) {
  const nativeLocal = request.execution_backend === "rust_model_mount_native_local";
  const output_text =
    options.output_text ??
    (nativeLocal
      ? `Autopilot native local model response from ${request.model_ref}. input_hash=test`
      : "provider answer");
  const provider_response_kind = nativeLocal ? "rust_model_mount.native_local" : "rust_model_mount.fixture";
  const backend = nativeLocal ? "autopilot.native_local.fixture" : "ioi_fixture";
  const backend_id = nativeLocal ? request.backend_ref ?? "backend.autopilot.native-local.fixture" : "backend.fixture";
  const execution_backend = request.execution_backend ?? "rust_model_mount_fixture";
  const evidenceRefs = [
    "rust_model_mount_provider_invocation",
    request.provider_execution_ref,
    ...(nativeLocal
      ? ["rust_model_mount_native_local_backend", "deterministic_native_local_fixture"]
      : ["rust_model_mount_fixture_backend", "deterministic_fixture"]),
  ];
  const invocationHash = options.invocationHash ?? "sha256:provider-invocation-test";
  const result = {
    source: "rust_model_mount_provider_invocation_command",
    backend: execution_backend,
    result: {
      ...request,
      output_text: output_text,
      token_count: { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3 },
      provider_response_kind: provider_response_kind,
      backend,
      backend_id: backend_id,
      execution_backend: execution_backend,
      evidence_refs: evidenceRefs,
      invocation_hash: invocationHash,
    },
    output_text,
    token_count: { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3 },
    provider_response: null,
    provider_response_kind,
    execution_backend,
    backend_id,
    provider_execution_ref: request.provider_execution_ref,
    provider_execution_hash: request.provider_execution_hash,
    invocation_hash: invocationHash,
    evidence_refs: evidenceRefs,
    backend_evidence_refs: evidenceRefs,
  };
  if (options.compat_translation) {
    result.compat_translation = options.compat_translation;
  }
  return result;
}

function providerStreamInvocationBridgeResult(request, options = {}) {
  const output_text = options.output_text ?? "rust stream answer";
  const token_count = options.token_count ?? { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3 };
  const execution_backend = request.execution_backend ?? "rust_model_mount_native_local_stream";
  const backend_id = request.backend_ref ?? "backend.autopilot.native-local.fixture";
  const streamKind =
    request.invocation_kind === "responses"
      ? "openai_responses_native_local"
      : "openai_chat_completions_native_local";
  const streamChunks =
    options.stream_chunks ?? [
      `{"delta":${JSON.stringify(output_text)},"done":false}\n`,
      `{"delta":"","done":true,"done_reason":"stop","prompt_eval_count":${token_count.prompt_tokens},"eval_count":${token_count.completion_tokens}}\n`,
    ];
  const evidenceRefs = [
    "rust_model_mount_provider_stream_invocation",
    "rust_model_mount_native_local_stream_backend",
    request.provider_execution_ref,
  ];
  const invocationHash = options.invocationHash ?? "sha256:provider-stream-invocation-test";
  const result = {
    source: "rust_model_mount_provider_stream_invocation_command",
    backend: execution_backend,
    result: {
      ...request,
      schema_version: "ioi.model_mount.provider_stream_invocation.v1",
      output_text: output_text,
      token_count: token_count,
      provider_response_kind: "rust_model_mount.native_local.stream",
      backend: "autopilot.native_local.fixture",
      backend_id: backend_id,
      execution_backend: execution_backend,
      stream_format: "ioi_jsonl",
      stream_kind: streamKind,
      stream_chunks: streamChunks,
      evidence_refs: evidenceRefs,
      invocation_hash: invocationHash,
    },
    output_text,
    token_count,
    provider_response: null,
    provider_response_kind: "rust_model_mount.native_local.stream",
    execution_backend,
    backend_id,
    stream_format: "ioi_jsonl",
    stream_kind: streamKind,
    stream_chunks: streamChunks,
    provider_execution_ref: request.provider_execution_ref,
    provider_execution_hash: request.provider_execution_hash,
    invocation_hash: invocationHash,
    evidence_refs: evidenceRefs,
    backend_evidence_refs: evidenceRefs,
  };
  if (options.compat_translation) {
    result.compat_translation = options.compat_translation;
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

test("invokeModel public facade executes migrated fixture through Rust model_mount core, provider execution, and receipt binding", async () => {
  const state = fakeState();

  const invocation = await invokeModel(
    state,
    {
      authorization: "Bearer token",
      requiredScope: "model.chat:*",
      kind: "responses",
      body: { model: "model.local", response_id: "resp.custom", memory: { enabled: true } },
    },
    deps(),
  );

  assert.equal(invocation.outputText, "provider answer");
  assert.equal(invocation.model, "model.local");
  assert.equal(invocation.receipt.kind, "model_invocation");
  assert.equal(invocation.receipt.schemaVersion, "ioi.model-mounting.runtime.v1");
  assert.ok(invocation.receipt.evidenceRefs.includes("rust_model_mount_core"));
  assert.ok(invocation.receipt.evidenceRefs.includes("model_mount_invocation_positive_rust_path"));
  assert.equal(invocation.receipt.details.required_scope, "model.chat:*");
  assert.equal(
    invocation.receipt.details.rust_daemon_core_receipt_author,
    "daemonCoreModelMountApi.bindModelMountInvocationReceipt",
  );
  assert.equal(
    invocation.receipt.details.model_mount_route_decision_ref,
    "model_mount://route_decision/test",
  );
  assert.equal(
    invocation.receipt.details.model_mount_agentgres_operation_ref,
    "agentgres://model-mounting/accepted-receipts/op_00000001_model_invocation",
  );
  assert.equal(invocation.receipt.details.model_mount_provider_execution_ref, "model_mount://provider_execution/1");
  assert.equal(invocation.receipt.details.model_mount_provider_result_admission_ref, "model_mount://provider_result/1");
  assert.equal(invocation.receipt.details.model_mount_invocation_admission_ref, "model_mount://invocation_admission/1");
  assert.equal(invocation.receipt.details.model_mount_step_module_invocation.module_ref.kind, "model_mount");
  assert.equal(
    invocation.receipt.details.model_mount_step_module_result.resulting_head,
    "agentgres://model-mounting/accepted-receipts/head/1",
  );
  assert.deepEqual(state.authorizationCalls, []);
  assert.equal(state.selectRoutePayload.capability, "responses");
  assert.equal(state.routeSelectionPayload, undefined);
  assert.equal(state.loadedEndpointId, "endpoint.local");
  assert.equal(state.providerExecutionRequests.length, 1);
  assert.equal(state.providerInvocationRequests.length, 1);
  assert.equal(state.providerResultRequests.length, 1);
  assert.equal(state.receiptBindingRequests.length, 1);
  assert.equal(state.transitionRequests.length, 1);
  assert.equal(state.receipts.length, 1);
  assert.deepEqual(state.recordedConversations, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.deepEqual(state.writes, []);
  assert.deepEqual(state.appendOperations, []);
});

test("startModelStream public facade executes native-local stream through Rust model_mount without JS fallback", async () => {
  const state = fakeState({
    routeSelection: selection({
      route: { id: "route.native-local" },
      endpoint: {
        id: "endpoint.native-local",
        model_id: "model.native",
        provider_id: "provider.native",
        api_format: "ioi_native",
        driver: "native_local",
        backend_id: "backend.native",
      },
      provider: {
        id: "provider.native",
        kind: "ioi_native_local",
        driver: "native_local",
      },
    }),
  });

  const stream = await startModelStream(
    state,
    {
      authorization: "Bearer token",
      requiredScope: "model.responses:*",
      kind: "responses",
      body: { model: "model.native", route_id: "route.native-local", response_id: "resp.stream", stream: true },
    },
    deps(),
  );

  const streamText = await readReadableStreamText(stream.providerStream);
  assert.equal(stream.native, true);
  assert.equal(stream.invocation.outputText, "");
  assert.equal(stream.invocation.model, "model.native");
  assert.equal(stream.invocation.receipt.kind, "model_invocation");
  assert.equal(stream.invocation.receipt.details.stream_status, "started");
  assert.equal(stream.invocation.receipt.details.model_mount_provider_result_admission_ref, "model_mount://provider_result/1");
  assert.equal(stream.providerResult.streamFormat, "ioi_jsonl");
  assert.match(streamText, /done/);
  assert.deepEqual(state.authorizationCalls, []);
  assert.equal(state.selectRoutePayload.routeId, "route.native-local");
  assert.equal(state.routeSelectionPayload, undefined);
  assert.equal(state.providerExecutionRequests.length, 1);
  assert.equal(state.providerStreamInvocationRequests.length, 1);
  assert.equal(state.providerResultRequests.length, 1);
  assert.equal(state.fallbackInvocationArgs, undefined);
  assert.equal(state.receiptBindingRequests.length, 1);
  assert.equal(state.transitionRequests.length, 1);
  assert.equal(state.receipts.length, 1);
  assert.deepEqual(state.appendOperations, []);
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
          provider_id: "provider.local",
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
      backend_id: "backend.local",
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
      grant_ref: "grant://wallet/model-chat",
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
  assert.deepEqual(request.provider_auth_evidence_refs, []);
  assert.deepEqual(request.backend_evidence_refs, ["backend.local", "backend.endpoint"]);
  assert.equal(request.custody_ref, "ctee://custody/private-workspace");
  assert.equal(request.privacy_profile, "private_workspace_ctee");
  assert.equal(request.response_ref, "resp.1");
  assert.equal(request.previous_response_ref, "resp.previous");

  const hostedRequest = modelMountProviderExecutionRequestForInvocation({
    body: {
      authority_receipt_refs: ["receipt://wallet/hosted-model"],
      model_policy: { privacy_profile: "hosted" },
    },
    capability: "chat",
    hash: (value) => (typeof value === "string" ? "vault-hash" : `hash:${JSON.stringify(value)}`),
    input: "hello hosted",
    instance: {
      id: "instance.hosted",
      backend_id: "backend.openai-compatible",
    },
    kind: "responses",
    providerBody: { model: "gpt-4.1" },
    routeReceipt: {
      id: "receipt.route",
      details: {
        model_mount_route_decision_ref: "model_mount://route_decision/test",
      },
    },
    selection: selection({
      endpoint: {
        id: "endpoint.openai",
        model_id: "gpt-4.1",
        provider_id: "provider.openai",
        api_format: "openai",
        backend_id: "backend.openai-compatible",
      },
      provider: {
        id: "provider.openai",
        kind: "openai",
        api_format: "openai",
        secret_ref: "vault://provider.openai/api-key",
      },
    }),
    token: {
      grant_ref: "grant://wallet/hosted-model",
    },
  });

  assert.deepEqual(hostedRequest.authority_grant_refs, ["grant://wallet/hosted-model"]);
  assert.deepEqual(hostedRequest.authority_receipt_refs, ["receipt://wallet/hosted-model"]);
  assert.equal(hostedRequest.provider_auth_evidence_refs.includes("rust_model_mount_hosted_provider_auth_gate"), true);
  assert.equal(hostedRequest.provider_auth_evidence_refs.includes("wallet_network_provider_vault_ref_bound"), true);
  assert.equal(hostedRequest.provider_auth_evidence_refs.includes("ctee_hosted_provider_secret_not_exposed"), true);
  assert.equal(hostedRequest.provider_auth_evidence_refs.includes("rust_provider_auth_materialization_bound"), true);
  assert.equal(hostedRequest.provider_auth_evidence_refs.includes("hosted_provider_auth_header_materialized_by_rust"), true);
  assert.equal(hostedRequest.provider_auth_evidence_refs.includes("provider_vault_ref_hash:vault-hash"), true);
  assert.equal(hostedRequest.provider_auth_evidence_refs.some((ref) => ref.includes("vault://")), false);
});

test("model invocation migration helpers reject retired camelCase helper aliases", () => {
  const routeReceipt = {
    id: "receipt.route",
    details: {
      model_mount_route_decision_ref: "model_mount://route_decision/test",
    },
  };
  assert.throws(
    () =>
      modelMountProviderExecutionRequestForInvocation({
        body: { model: "model.local" },
        capability: "chat",
        hash: (value) => `hash:${JSON.stringify(value)}`,
        input: "hello",
        instance: { backendId: "backend.local" },
        kind: "responses",
        providerBody: { model: "model.local" },
        routeReceipt,
        selection: selection({
          endpoint: {
            modelId: "model.local",
            apiFormat: "ioi_fixture",
            backendId: "backend.endpoint",
            custodyRef: "ctee://custody/private-workspace",
            nodePlaintextAllowed: true,
            loadPolicy: { mode: "compat" },
          },
          provider: {
            privacyClass: "private_workspace_ctee",
          },
        }),
        token: {
          grantId: "grant://model-chat",
        },
      }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "model_mount_invocation_helper_aliases_retired");
      assert.deepEqual([...error.details.retired_aliases].sort(), [
        "modelId",
        "apiFormat",
        "backendId",
        "custodyRef",
        "nodePlaintextAllowed",
        "loadPolicy",
        "privacyClass",
        "grantId",
      ].sort());
      assert.deepEqual(error.details.canonical_fields.slice(0, 4), [
        "api_format",
        "backend_evidence_refs",
        "backend_id",
        "custody_ref",
      ]);
      return true;
    },
  );
  assert.throws(
    () =>
      modelMountProviderResultAdmissionRequestForExecution({
        input: "user: hello",
        instance: {
          backendProcess: { pid_hash: "sha256:compat" },
          backendProcessId: "backend-process.compat",
          backendProcessPidHash: "sha256:pid",
        },
        kind: "chat.completions",
        modelMountProviderExecutionAdmission: {
          record: {
            provider_execution_ref: "model_mount://provider_execution/test",
            provider_execution_hash: "sha256:provider-execution-test",
            route_decision_ref: "model_mount://route_decision/test",
            route_receipt_ref: "receipt://route",
            route_ref: "route.local-first",
            provider_ref: "provider.fixture",
            endpoint_ref: "endpoint.fixture",
            model_ref: "fixture:model",
            capability: "chat",
            invocation_kind: "chat.completions",
            request_hash: "sha256:request",
          },
        },
        providerResult: {
          outputText: "fixture provider answer",
          providerResponse: { id: "compat.response" },
          providerResponseKind: "rust_model_mount.fixture",
          executionBackend: "rust_model_mount_fixture",
          tokenCount: { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3 },
          providerAuthEvidenceRefs: [],
          backendEvidenceRefs: ["rust_model_mount_fixture_backend"],
          streamFormat: "ioi_jsonl",
          streamKind: "openai_chat_completions_native_local",
          streamChunks: [],
        },
        selection: {
          ...selection({
            endpoint: {
              api_format: "ioi_fixture",
              driver: "fixture",
              provider_id: "provider.fixture",
              backend_id: "backend.fixture",
            },
            provider: {
              id: "provider.fixture",
              kind: "local_folder",
              driver: "fixture",
            },
          }),
          routeDecision: {},
          routeReceipt: {},
          routeControl: {},
          acceptedReceiptRecord: {},
          evidenceRefs: ["compat.evidence"],
        },
      }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "model_mount_invocation_helper_aliases_retired");
      assert.deepEqual([...error.details.retired_aliases].sort(), [
        "acceptedReceiptRecord",
        "backendEvidenceRefs",
        "backendProcess",
        "backendProcessId",
        "backendProcessPidHash",
        "evidenceRefs",
        "executionBackend",
        "outputText",
        "providerAuthEvidenceRefs",
        "providerResponse",
        "providerResponseKind",
        "routeControl",
        "routeDecision",
        "routeReceipt",
        "streamChunks",
        "streamFormat",
        "streamKind",
        "tokenCount",
      ].sort());
      return true;
    },
  );
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
    instance: { id: "instance.local", backend_id: "backend.local" },
    kind: "responses",
    providerBody: { model: "model.local" },
    routeReceipt,
    selection: selected,
    token: { grant_ref: "grant://model-chat" },
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
    instance: { backend_id: "backend.fixture" },
    kind: "chat.completions",
    modelMountProviderExecutionAdmission: admission,
    selection: selection({
      endpoint: { api_format: "ioi_fixture", driver: "fixture" },
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
      endpoint: { api_format: "ioi_native", driver: "native_local" },
    }),
    true,
  );
  assert.equal(
    modelMountProviderInvocationRequiresRust(
      {
        provider: { kind: "ioi_native_local", driver: "native_local" },
        endpoint: { api_format: "ioi_native", driver: "native_local" },
      },
      { stream: true },
    ),
    true,
  );
  assert.equal(modelMountProviderInvocationRequiresRust({ provider: { kind: "openai" }, endpoint: {} }), true);
  const hostedRequest = modelMountProviderInvocationRequestForExecution({
    input: "user: hosted",
    instance: { backend_id: "backend.openai-compatible" },
    kind: "chat.completions",
    modelMountProviderExecutionAdmission: {
      record: {
        ...admission.record,
        provider_ref: "provider.openai",
        endpoint_ref: "endpoint.openai",
        model_ref: "model.openai",
      },
      provider_execution_ref: admission.provider_execution_ref,
      provider_execution_hash: admission.provider_execution_hash,
    },
    selection: selection({
      endpoint: { api_format: "openai" },
      provider: {
        id: "provider.openai",
        kind: "openai",
        base_url: "https://api.openai.example/v1",
        provider_auth_materialization_ref:
          "agentgres://model-mounting/model-provider-auth-materializations/provider.openai_auth_header",
        outbound_header_binding_ref:
          "provider_auth_header://provider.openai_auth_header#sha256:provider-auth",
        auth_header_materialization_status: "rust_ctee_outbound_header_bound",
      },
    }),
  });
  assert.equal(hostedRequest.execution_backend, "rust_model_mount_hosted_provider");
  assert.equal(hostedRequest.provider_kind, "openai");
  assert.equal(hostedRequest.api_format, "openai");
  assert.equal(hostedRequest.driver, null);
  assert.equal(hostedRequest.backend_ref, "backend.openai-compatible");
  assert.equal(hostedRequest.base_url, "https://api.openai.example/v1");
  assert.equal(
    hostedRequest.provider_auth_materialization_ref,
    "agentgres://model-mounting/model-provider-auth-materializations/provider.openai_auth_header",
  );
  assert.equal(
    hostedRequest.outbound_header_binding_ref,
    "provider_auth_header://provider.openai_auth_header#sha256:provider-auth",
  );
  assert.equal(hostedRequest.auth_header_materialization_status, "rust_ctee_outbound_header_bound");
  assert.equal(hostedRequest.admitted_provider_execution.provider_ref, "provider.openai");
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
    instance: { backend_id: "backend.autopilot.native-local.fixture" },
    kind: "responses",
    modelMountProviderExecutionAdmission: admission,
    selection: selection({
      endpoint: {
        api_format: "ioi_native",
        driver: "native_local",
        model_id: "model://qwen/qwen3.5-9b",
        provider_id: "provider.autopilot.local",
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
      endpoint: { api_format: "ioi_native", driver: "native_local" },
    }),
    true,
  );
  assert.equal(modelMountProviderStreamInvocationRequiresRust({ provider: { kind: "local_folder" }, endpoint: {} }), true);
  assert.equal(modelMountProviderStreamInvocationRequiresRust({ provider: { kind: "openai" }, endpoint: {} }), true);
  const hostedStreamRequest = modelMountProviderStreamInvocationRequestForExecution({
    input: "user: hosted stream",
    instance: { backend_id: "backend.openai-compatible" },
    kind: "responses",
    modelMountProviderExecutionAdmission: {
      record: {
        ...admission.record,
        provider_ref: "provider.openai",
        endpoint_ref: "endpoint.openai",
        model_ref: "model.openai",
        provider_auth_evidence_refs: [
          "rust_model_mount_hosted_provider_auth_gate",
          "wallet_network_provider_vault_ref_bound",
          "ctee_hosted_provider_secret_not_exposed",
          "rust_provider_auth_materialization_bound",
        ],
      },
      provider_execution_ref: admission.provider_execution_ref,
      provider_execution_hash: admission.provider_execution_hash,
    },
    selection: selection({
      endpoint: { api_format: "openai", driver: "openai_compatible" },
      provider: {
        id: "provider.openai",
        kind: "openai",
        driver: "openai_compatible",
        base_url: "https://api.openai.example/v1",
        provider_auth_materialization_ref:
          "agentgres://model-mounting/model-provider-auth-materializations/provider.openai_auth_header",
        outbound_header_binding_ref:
          "provider_auth_header://provider.openai_auth_header#sha256:provider-auth",
        auth_header_materialization_status: "rust_ctee_outbound_header_bound",
      },
    }),
  });
  assert.equal(hostedStreamRequest.execution_backend, "rust_model_mount_hosted_provider_stream");
  assert.equal(hostedStreamRequest.stream_status, "started");
  assert.equal(hostedStreamRequest.provider_kind, "openai");
  assert.equal(hostedStreamRequest.api_format, "openai");
  assert.equal(hostedStreamRequest.driver, "openai_compatible");
  assert.equal(hostedStreamRequest.backend_ref, "backend.openai-compatible");
  assert.equal(hostedStreamRequest.base_url, "https://api.openai.example/v1");
  assert.equal(
    hostedStreamRequest.provider_auth_materialization_ref,
    "agentgres://model-mounting/model-provider-auth-materializations/provider.openai_auth_header",
  );
  assert.equal(
    hostedStreamRequest.outbound_header_binding_ref,
    "provider_auth_header://provider.openai_auth_header#sha256:provider-auth",
  );
  assert.equal(
    hostedStreamRequest.auth_header_materialization_status,
    "rust_ctee_outbound_header_bound",
  );
  assert.equal(
    hostedStreamRequest.admitted_provider_execution.provider_auth_evidence_refs.includes(
      "ctee_hosted_provider_secret_not_exposed",
    ),
    true,
  );
  assert.equal(
    hostedStreamRequest.admitted_provider_execution.provider_auth_evidence_refs.includes(
      "rust_provider_auth_materialization_bound",
    ),
    true,
  );
});

test("modelMountProviderResultAdmissionRequestForExecution binds Rust provider result to provider admission", () => {
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
      provider_ref: "provider.fixture",
      endpoint_ref: "endpoint.fixture",
      model_ref: "fixture:model",
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
    instance: { backend_id: "backend.instance" },
    kind: "chat.completions",
    modelMountProviderExecutionAdmission: admission,
    providerResult: {
      output_text: "fixture provider answer",
      provider_response_kind: "rust_model_mount.fixture",
      execution_backend: "rust_model_mount_fixture",
      token_count: { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3 },
      provider_auth_evidence_refs: [],
      backend_evidence_refs: ["rust_model_mount_fixture_backend"],
    },
    selection: selection({
      endpoint: {
        api_format: "ioi_fixture",
        driver: "fixture",
        provider_id: "provider.fixture",
        backend_id: "backend.fixture",
      },
      provider: {
        id: "provider.fixture",
        kind: "local_folder",
        driver: "fixture",
      },
    }),
  });

  assert.equal(request.schema_version, "ioi.model_mount.provider_result.v1");
  assert.equal(request.provider_execution_ref, "model_mount://provider_execution/test");
  assert.equal(request.provider_execution_hash, "sha256:provider-execution-test");
  assert.equal(request.provider_kind, "local_folder");
  assert.equal(request.execution_backend, "rust_model_mount_fixture");
  assert.equal(request.provider_response_kind, "rust_model_mount.fixture");
  assert.equal(request.output_text, "fixture provider answer");
  assert.equal(request.output_hash.startsWith("sha256:"), true);
  assert.deepEqual(request.token_count, { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3 });
  assert.deepEqual(request.provider_auth_evidence_refs, []);
  assert.deepEqual(request.backend_evidence_refs, ["rust_model_mount_fixture_backend"]);
  assert.equal(request.admitted_provider_execution.provider_execution_hash, "sha256:provider-execution-test");
  const hostedRequest = modelMountProviderResultAdmissionRequestForExecution({
    input: "user: hosted",
    instance: { backend_id: "backend.openai-compatible" },
    kind: "chat.completions",
    modelMountProviderExecutionAdmission: {
      record: {
        ...admission.record,
        provider_ref: "provider.openai",
        endpoint_ref: "endpoint.openai",
        model_ref: "model.openai",
        provider_auth_evidence_refs: [
          "rust_model_mount_hosted_provider_auth_gate",
          "wallet_network_provider_vault_ref_bound",
          "ctee_hosted_provider_secret_not_exposed",
          "rust_provider_auth_materialization_bound",
        ],
      },
      provider_execution_ref: admission.provider_execution_ref,
      provider_execution_hash: admission.provider_execution_hash,
      receipt_refs: ["receipt://route"],
      evidence_refs: ["rust_model_mount_core"],
    },
    providerResult: {
      output_text: "Rust hosted provider transport response from /chat/completions for model.openai",
      provider_response_kind: "rust_model_mount.hosted_provider",
      execution_backend: "rust_model_mount_hosted_provider",
      token_count: { prompt_tokens: 2, completion_tokens: 8, total_tokens: 10 },
      hosted_transport_request_ref: "model_mount://hosted_transport_request/js-provider-result",
      hosted_transport_request_hash: "sha256:hosted-transport-request",
      hosted_transport_response_hash: "sha256:hosted-transport-response",
      hosted_transport_status: "rust_hosted_provider_transport_response_bound",
      provider_auth_evidence_refs: [
        "rust_model_mount_hosted_provider_auth_gate",
        "wallet_network_provider_vault_ref_bound",
        "ctee_hosted_provider_secret_not_exposed",
        "rust_provider_auth_materialization_bound",
      ],
      backend_evidence_refs: [
        "rust_model_mount_hosted_provider_backend",
        "rust_hosted_provider_invocation_transport_materialized",
        "rust_hosted_provider_transport_request_bound",
        "rust_hosted_provider_transport_response_bound",
        "hosted_provider_auth_header_materialization_contract_bound",
      ],
    },
    selection: selection({
      endpoint: { api_format: "openai", driver: "openai_compatible" },
      provider: { id: "provider.openai", kind: "openai", driver: "openai_compatible" },
    }),
  });

  assert.equal(hostedRequest.execution_backend, "rust_model_mount_hosted_provider");
  assert.equal(hostedRequest.provider_response_kind, "rust_model_mount.hosted_provider");
  assert.equal(hostedRequest.hosted_transport_request_ref, "model_mount://hosted_transport_request/js-provider-result");
  assert.equal(hostedRequest.hosted_transport_request_hash, "sha256:hosted-transport-request");
  assert.equal(hostedRequest.hosted_transport_response_hash, "sha256:hosted-transport-response");
  assert.equal(hostedRequest.hosted_transport_status, "rust_hosted_provider_transport_response_bound");
  assert.equal(hostedRequest.provider_auth_evidence_refs.includes("wallet_network_provider_vault_ref_bound"), true);
  assert.equal(hostedRequest.backend_evidence_refs.includes("rust_hosted_provider_invocation_transport_materialized"), true);
  assert.equal(hostedRequest.backend_evidence_refs.includes("rust_hosted_provider_transport_request_bound"), true);
  assert.equal(hostedRequest.backend_evidence_refs.includes("rust_hosted_provider_transport_response_bound"), true);
  const hostedStreamRequest = modelMountProviderResultAdmissionRequestForExecution({
    input: "user: hosted stream",
    instance: { backend_id: "backend.openai-compatible" },
    kind: "responses",
    modelMountProviderExecutionAdmission: {
      record: {
        ...admission.record,
        provider_ref: "provider.openai",
        endpoint_ref: "endpoint.openai",
        model_ref: "model.openai",
        invocation_kind: "responses",
        stream_status: "started",
        provider_auth_evidence_refs: [
          "rust_model_mount_hosted_provider_auth_gate",
          "wallet_network_provider_vault_ref_bound",
          "ctee_hosted_provider_secret_not_exposed",
          "rust_provider_auth_materialization_bound",
        ],
      },
      provider_execution_ref: admission.provider_execution_ref,
      provider_execution_hash: admission.provider_execution_hash,
      receipt_refs: ["receipt://route"],
      evidence_refs: ["rust_model_mount_core"],
    },
    providerResult: {
      output_text: "Rust hosted provider transport response from /responses for model.openai stream",
      provider_response_kind: "rust_model_mount.hosted_provider.stream",
      execution_backend: "rust_model_mount_hosted_provider_stream",
      token_count: { prompt_tokens: 2, completion_tokens: 8, total_tokens: 10 },
      hosted_transport_request_ref: "model_mount://hosted_transport_request/js-provider-stream-result",
      hosted_transport_request_hash: "sha256:hosted-stream-transport-request",
      hosted_transport_response_hash: "sha256:hosted-stream-transport-response",
      hosted_transport_status: "rust_hosted_provider_transport_response_bound",
      provider_auth_evidence_refs: [
        "rust_model_mount_hosted_provider_auth_gate",
        "wallet_network_provider_vault_ref_bound",
        "ctee_hosted_provider_secret_not_exposed",
        "rust_provider_auth_materialization_bound",
      ],
      backend_evidence_refs: [
        "rust_model_mount_hosted_provider_stream_backend",
        "rust_hosted_provider_stream_transport_materialized",
        "rust_hosted_provider_transport_request_bound",
        "rust_hosted_provider_transport_response_bound",
        "hosted_provider_auth_header_materialization_contract_bound",
      ],
    },
    selection: selection({
      endpoint: { api_format: "openai", driver: "openai_compatible" },
      provider: { id: "provider.openai", kind: "openai", driver: "openai_compatible" },
    }),
  });

  assert.equal(hostedStreamRequest.execution_backend, "rust_model_mount_hosted_provider_stream");
  assert.equal(hostedStreamRequest.provider_response_kind, "rust_model_mount.hosted_provider.stream");
  assert.equal(hostedStreamRequest.stream_status, "started");
  assert.equal(hostedStreamRequest.hosted_transport_request_ref, "model_mount://hosted_transport_request/js-provider-stream-result");
  assert.equal(hostedStreamRequest.hosted_transport_request_hash, "sha256:hosted-stream-transport-request");
  assert.equal(hostedStreamRequest.hosted_transport_response_hash, "sha256:hosted-stream-transport-response");
  assert.equal(hostedStreamRequest.hosted_transport_status, "rust_hosted_provider_transport_response_bound");
  assert.equal(hostedStreamRequest.provider_auth_evidence_refs.includes("wallet_network_provider_vault_ref_bound"), true);
  assert.equal(hostedStreamRequest.backend_evidence_refs.includes("rust_hosted_provider_stream_transport_materialized"), true);
  assert.equal(hostedStreamRequest.backend_evidence_refs.includes("rust_hosted_provider_transport_request_bound"), true);
  assert.equal(hostedStreamRequest.backend_evidence_refs.includes("rust_hosted_provider_transport_response_bound"), true);
  assert.throws(
    () =>
      modelMountProviderResultAdmissionRequestForExecution({
        input: "user: hello",
        instance: { backend_id: "backend.instance" },
        kind: "chat.completions",
        modelMountProviderExecutionAdmission: admission,
        providerResult: {
          output_text: "fixture provider answer",
          provider_response_kind: "rust_model_mount.fixture",
          execution_backend: "rust_model_mount_fixture",
        },
        selection: selection({
          endpoint: {
            api_format: "ioi_fixture",
            driver: "fixture",
            provider_id: "provider.fixture",
            backend_id: "backend.fixture",
          },
          provider: {
            id: "provider.fixture",
            kind: "local_folder",
            driver: "fixture",
          },
        }),
      }),
    (error) => error.code === "model_mount_provider_result_token_count_required",
  );
  assert.throws(
    () =>
      modelMountProviderResultAdmissionRequestForExecution({
        input: "user: hello",
        instance: { backend_id: "backend.instance" },
        kind: "chat.completions",
        modelMountProviderExecutionAdmission: admission,
        providerResult: {
          output_text: "fixture provider answer",
          provider_response_kind: "rust_model_mount.fixture",
          execution_backend: "rust_model_mount_fixture",
          token_count: { prompt_tokens: 1, completion_tokens: 2, total_tokens: 4 },
        },
        selection: selection({
          endpoint: {
            api_format: "ioi_fixture",
            driver: "fixture",
            provider_id: "provider.fixture",
            backend_id: "backend.fixture",
          },
          provider: {
            id: "provider.fixture",
            kind: "local_folder",
            driver: "fixture",
          },
        }),
      }),
    (error) => error.code === "model_mount_provider_result_token_count_mismatch",
  );
  assert.throws(
    () =>
      modelMountProviderResultAdmissionRequestForExecution({
        input: "user: hosted",
        instance: { backend_id: "backend.openai-compatible" },
        kind: "chat.completions",
        modelMountProviderExecutionAdmission: {
          record: {
            ...admission.record,
            provider_ref: "provider.openai",
            endpoint_ref: "endpoint.openai",
            model_ref: "model.openai",
          },
          provider_execution_ref: admission.provider_execution_ref,
          provider_execution_hash: admission.provider_execution_hash,
        },
        providerResult: {
          output_text: "hosted provider answer",
          provider_response_kind: "openai.chat",
          execution_backend: "rust_model_mount_native_local_stream",
        },
        selection: selection({
          endpoint: { api_format: "openai", driver: "openai_compatible" },
          provider: { id: "provider.openai", kind: "openai", driver: "openai_compatible" },
        }),
      }),
    (error) =>
      error.code === "model_mount_provider_result_rust_backend_required" &&
      error.details.provider_kind === "openai" &&
      error.details.stream === false,
  );
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

test("model invocation Agentgres transition ignores retired camelCase bridge fields", () => {
  const state = {
    agentgresModelMountingHead() {
      return {
        sequence: 0,
        head_ref: "agentgres://model-mounting/accepted-receipts/head/0",
        state_root: "sha256:state-0",
      };
    },
    planModelMountAcceptedReceiptTransition() {
      return {
        transition: {
          schema_version: "ioi.model_mount.accepted_receipt_transition.v1",
          expected_heads: ["agentgres://model-mounting/accepted-receipts/head/0"],
        },
        operationId: "op_retired",
        operationRef: "agentgres://model-mounting/accepted-receipts/op_retired",
        expectedHeads: ["agentgres://model-mounting/accepted-receipts/head/0"],
        stateRootBefore: "sha256:state-0",
        stateRootAfter: "sha256:state-1",
        resultingHead: "agentgres://model-mounting/accepted-receipts/head/1",
        projectionWatermark: "model-mounting-accepted-receipts:1",
        transitionHash: "sha256:transition-retired",
        evidenceRefs: ["rust_model_mount_accepted_receipt_transition"],
      };
    },
  };

  assert.throws(
    () =>
      modelMountInvocationAgentgresTransitionForReceipt(state, {
        admission: {
          invocation_admission_ref: "model_mount://invocation_admission/test",
          invocation_admission_hash: "sha256:invocation-test",
        },
        admissionRequest: {
          route_decision_ref: "model_mount://route_decision/test",
          input_hash: "sha256:input",
          output_hash: "sha256:output",
        },
        receiptId: "receipt.invoke",
        receiptKind: "model_invocation",
      }),
    /transition\.operation_id/,
  );
});

test("model invocation Agentgres transition rejects retired camelCase head fields", () => {
  const state = {
    agentgresModelMountingHead() {
      return {
        sequence: 0,
        headRef: "agentgres://model-mounting/accepted-receipts/head/0",
        stateRoot: "sha256:state-0",
      };
    },
    planModelMountAcceptedReceiptTransition() {
      throw new Error("transition planner should not be called with retired head fields");
    },
  };

  assert.throws(
    () =>
      modelMountInvocationAgentgresTransitionForReceipt(state, {
        admission: {
          invocation_admission_ref: "model_mount://invocation_admission/test",
          invocation_admission_hash: "sha256:invocation-test",
        },
        admissionRequest: {
          route_decision_ref: "model_mount://route_decision/test",
          input_hash: "sha256:input",
          output_hash: "sha256:output",
        },
        receiptId: "receipt.invoke",
        receiptKind: "model_invocation",
      }),
    /agentgresHead\.head_ref/,
  );
});
