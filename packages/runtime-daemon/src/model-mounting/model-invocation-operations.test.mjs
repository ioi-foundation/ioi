import assert from "node:assert/strict";
import test from "node:test";

import {
  capabilityForInvocationKind,
  invokeModel,
  modelMountInvocationAdmissionRequestForReceipt,
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
  assert.equal(result.invocation.receipt.details.modelMountInvocationAdmission.stream_status, "started");
  assert.equal(Object.hasOwn(result.invocation.receipt.details, "coalesced"), false);
  assert.equal(Object.hasOwn(result.invocation.receipt.details, "sendOptions"), false);
  assert.equal(state.appendOperations[0].kind, "model.provider_stream_request_shape");
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
