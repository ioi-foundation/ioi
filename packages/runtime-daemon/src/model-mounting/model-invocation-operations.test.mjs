import assert from "node:assert/strict";
import test from "node:test";

import {
  capabilityForInvocationKind,
  invokeModel,
  modelMountInvocationAgentgresTransitionForReceipt,
  modelMountInvocationAdmissionRequestForReceipt,
  modelMountProviderExecutionRequestForInvocation,
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
      const sequence = this.receipts.length + this.appendOperations.length;
      return {
        sequence,
        headRef: `agentgres://model-mounting/operation-log/head/${sequence}`,
        stateRoot: `sha256:state-${sequence}`,
        projectionWatermark: `model-mounting-operation-log:${sequence}`,
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
          expected_heads: request.expectedHeads,
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
          modelMountRouteDecisionRef: "model_mount://route_decision/test",
          workflowGraphId: "workflow.graph",
          workflowNodeId: "workflow.node",
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

function selection() {
  return {
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
    summarizeProviderRequestBodyForTrace: (body) => ({ model: body.model, stream: body.stream === true }),
    ...overrides,
  };
}

test("capabilityForInvocationKind maps model APIs to route capabilities", () => {
  assert.equal(capabilityForInvocationKind("embeddings"), "embeddings");
  assert.equal(capabilityForInvocationKind("rerank"), "rerank");
  assert.equal(capabilityForInvocationKind("responses"), "responses");
  assert.equal(capabilityForInvocationKind("chat.completions"), "chat");
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
  assert.equal(result.receipt.details.routeId, "route.local-first");
  assert.equal(result.receipt.details.modelMountInvocationAdmissionRef, "model_mount://invocation_admission/1");
  assert.equal(result.receipt.details.modelMountInvocationAdmission.route_decision_ref, "model_mount://route_decision/test");
  assert.equal(result.receipt.details.modelMountProviderExecutionRef, "model_mount://provider_execution/1");
  assert.equal(result.receipt.details.modelMountProviderExecution.request_hash.startsWith("sha256:"), true);
  assert.equal(result.receipt.details.modelMountReceiptBindingRef, "sha256:binding-1");
  assert.equal(result.receipt.details.modelMountAcceptedReceiptAppendHash, "sha256:append-1");
  assert.equal(result.receipt.details.modelMountStepModuleInvocation.input.state_root_before, "sha256:state-0");
  assert.equal(result.receipt.details.modelMountStepModuleResult.agentgres_operation_refs[0], "agentgres://model-mounting/operation-log/op_00000001_model_invocation");
  assert.equal(result.receipt.details.modelMountStepModuleResult.state_root_after.startsWith("sha256:"), true);
  assert.equal(result.receipt.details.modelMountAgentgresAdmission.operation_ref, "agentgres://model-mounting/operation-log/op_00000001_model_invocation");
  assert.equal(result.receipt.details.modelMountStepModuleInvocation.module_ref.kind, "model_mount");
  assert.equal(result.receipt.details.modelMountStepModuleResult.workflow_projection.status, "live");
  assert.equal(state.receiptBindingRequests[0].receiptRef, "receipt://receipt.1.model_invocation");
  assert.equal(state.providerExecutionRequests[0].route_decision_ref, "model_mount://route_decision/test");
  assert.equal(state.providerExecutionRequests[0].route_receipt_ref, "receipt://receipt.route");
  assert.equal(state.providerExecutionRequests[0].stream_status, null);
  assert.deepEqual(state.receiptBindingRequests[0].expectedHeads, [
    "agentgres://model-mounting/operation-log/head/0",
  ]);
  assert.deepEqual(result.receipt.details.modelMountInvocationAdmissionReceiptRefs, [
    "receipt://receipt.route",
    "receipt://receipt.1.model_invocation",
    "receipt://receipt.tool",
  ]);
  assert.equal(result.receipt.details.memory.enabled, true);
  assert.equal(result.receipt.details.coalesced, false);
  assert.equal(state.recordedConversations[0].responseId, "resp.custom");
  assert.equal(state.routes.get("route.local-first").lastReceiptId, result.receipt.id);
  assert.equal(state.writes.at(-1)[0], "model-routes");
});

test("invokeModel reuses identical in-flight provider execution and marks coalesced receipts", async () => {
  let resolveProvider;
  let providerCalls = 0;
  const state = fakeState({
    driver: {
      invoke: async () => {
        providerCalls += 1;
        await new Promise((resolve) => {
          resolveProvider = resolve;
        });
        return { outputText: "shared answer" };
      },
    },
  });
  const operation = { authorization: "Bearer token", requiredScope: "model.chat:*", kind: "chat.completions", body: { model: "model.local" } };
  const depSet = deps({ modelInvocationCoalesceKey: () => "coalesce-key" });

  const first = invokeModel(state, operation, depSet);
  const second = invokeModel(state, operation, depSet);
  await Promise.resolve();
  resolveProvider();
  const [firstResult, secondResult] = await Promise.all([first, second]);

  assert.equal(providerCalls, 1);
  assert.equal(firstResult.receipt.kind, "model_invocation");
  assert.equal(secondResult.receipt.kind, "model_invocation_coalesced");
  assert.equal(secondResult.receipt.details.coalesced, true);
  assert.equal(secondResult.receipt.details.coalesceKeyHash, "hash:coalesce-key");
  assert.equal(secondResult.receipt.details.modelMountInvocationAdmissionRef, "model_mount://invocation_admission/2");
  assert.equal(secondResult.receipt.details.modelMountProviderExecutionRef, "model_mount://provider_execution/1");
  assert.equal(secondResult.receipt.details.modelMountReceiptBindingRef, "sha256:binding-2");
  assert.equal(secondResult.receipt.details.modelMountStepModuleResult.agentgres_operation_refs[0], "agentgres://model-mounting/operation-log/op_00000002_model_invocation_coalesced");
  assert.equal(state.inflightModelInvocations.size, 0);
});

test("startModelStream returns native stream invocations with stream-only receipt fields", async () => {
  const stream = { [Symbol.asyncIterator]: async function* noop() {} };
  const state = fakeState({
    driver: {
      supportsStream: () => true,
      async streamInvoke() {
        return {
          stream,
          abort: () => "aborted",
          providerResponseKind: "openai.responses.stream",
          tokenCount: { prompt_tokens: 1, completion_tokens: 0, total_tokens: 1 },
        };
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
  assert.equal(result.providerStream, stream);
  assert.equal(result.invocation.responseId, "resp.stream");
  assert.equal(result.invocation.receipt.details.streamStatus, "started");
  assert.equal(result.invocation.receipt.details.streamSource, "provider_native");
  assert.equal(result.invocation.receipt.details.modelMountInvocationAdmissionRef, "model_mount://invocation_admission/1");
  assert.equal(result.invocation.receipt.details.modelMountProviderExecutionRef, "model_mount://provider_execution/1");
  assert.equal(result.invocation.receipt.details.modelMountInvocationAdmission.stream_status, "started");
  assert.equal(result.invocation.receipt.details.modelMountReceiptBindingRef, "sha256:binding-1");
  assert.equal(result.invocation.receipt.details.modelMountAcceptedReceiptAppend.receipt_ref, "receipt://receipt.1.model_invocation");
  assert.equal(result.invocation.receipt.details.modelMountAgentgresAdmission.operation_ref, "agentgres://model-mounting/operation-log/op_00000002_model_invocation");
  assert.equal(Object.hasOwn(result.invocation.receipt.details, "coalesced"), false);
  assert.equal(Object.hasOwn(result.invocation.receipt.details, "sendOptions"), false);
  assert.equal(state.appendOperations[0].kind, "model.provider_stream_request_shape");
  assert.equal(state.providerExecutionRequests[0].stream_status, "started");
  assert.equal(state.routes.get("route.local-first").lastReceiptId, result.invocation.receipt.id);
});

test("startModelStream falls back to non-stream invocation when provider lacks native streaming", async () => {
  const state = fakeState({
    driver: {
      supportsStream: () => false,
    },
  });

  const result = await startModelStream(
    state,
    {
      authorization: "Bearer token",
      requiredScope: "model.chat:*",
      kind: "chat.completions",
      body: { model: "model.local", stream: true },
    },
    deps(),
  );

  assert.equal(result.native, false);
  assert.equal(result.invocation.fallback, true);
  assert.equal(state.fallbackInvocationArgs.body.stream, false);
});

test("startModelStream fails closed without Rust provider execution admission before stream call", async () => {
  let streamCalls = 0;
  const state = fakeState({
    admitModelMountProviderExecution: undefined,
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
      routeId: "route.local-first",
      providerId: "provider.local",
      endpointId: "endpoint.local",
      selectedModel: "model.local",
      policyHash: "policy",
      inputHash: "input",
      outputHash: "output",
      grantId: "grant://wallet/model-chat",
      toolReceiptIds: ["receipt.tool"],
      providerAuthEvidenceRefs: ["provider.auth"],
      backendEvidenceRefs: ["backend.evidence"],
      responseId: "resp.1",
    },
    receiptId: "receipt.invoke",
    receiptKind: "model_invocation",
    routeReceipt: {
      id: "receipt.route",
      details: {
        modelMountRouteDecisionRef: "model_mount://route_decision/test",
        workflowGraphId: "graph.1",
        workflowNodeId: "node.1",
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
        modelMountRouteDecisionRef: "model_mount://route_decision/test",
        workflowGraphId: "graph.1",
        workflowNodeId: "node.1",
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

test("modelMountInvocationReceiptBindingRequestForReceipt builds model_mount StepModule binding", () => {
  const admissionRequest = modelMountInvocationAdmissionRequestForReceipt({
    body: {},
    capability: "responses",
    kind: "responses",
    receiptDetails: {
      routeId: "route.local-first",
      providerId: "provider.local",
      endpointId: "endpoint.local",
      selectedModel: "model.local",
      policyHash: "sha256:policy",
      inputHash: "sha256:input",
      outputHash: "sha256:output",
      grantId: "grant://wallet/model-chat",
      responseId: "resp.1",
    },
    receiptId: "receipt.invoke",
    receiptKind: "model_invocation",
    routeReceipt: {
      id: "receipt.route",
      details: {
        modelMountRouteDecisionRef: "model_mount://route_decision/test",
        workflowGraphId: "graph.1",
        workflowNodeId: "node.1",
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
      inputHash: "sha256:input",
      outputHash: "sha256:output",
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
      providerAuthEvidenceRefs: ["provider.auth"],
      backendEvidenceRefs: ["backend.evidence"],
    },
    receiptId: "receipt.invoke",
  });

  assert.equal(request.receiptRef, "receipt://receipt.invoke");
  assert.deepEqual(request.expectedHeads, ["agentgres://model-mounting/operation-log/head/0"]);
  assert.equal(request.invocation.module_ref.kind, "model_mount");
  assert.equal(request.invocation.execution.backend, "model_mount");
  assert.equal(request.invocation.input.state_root_before, "sha256:state-0");
  assert.equal(request.invocation.workflow_graph_id, "graph.1");
  assert.equal(request.invocation.workflow_node_id, "node.1");
  assert.deepEqual(request.invocation.authority.authority_grant_refs, ["grant://wallet/model-chat"]);
  assert.deepEqual(request.result.receipt_refs, ["receipt://receipt.invoke"]);
  assert.deepEqual(request.result.agentgres_operation_refs, [
    "agentgres://model-mounting/operation-log/op_00000001_model_invocation",
  ]);
  assert.equal(request.result.resulting_head, "agentgres://model-mounting/operation-log/head/1");
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
