import assert from "node:assert/strict";
import test from "node:test";

import {
  conversationState,
  listConversations,
  nextResponseId,
  recordConversationState,
  recordModelStreamCompleted,
} from "./conversation-operations.mjs";

function fakeState() {
  return {
    conversations: new Map(),
    now: "2026-06-04T03:00:00.000Z",
    receiptCounter: 0,
    receiptBindingRequests: [],
    receipts: [],
    writes: [],
    nowIso() {
      return this.now;
    },
    agentgresModelMountingHead() {
      const sequence = this.receipts.length;
      return {
        sequence,
        headRef: `agentgres://model-mounting/operation-log/head/${sequence}`,
        stateRoot: `sha256:state-${sequence}`,
        projectionWatermark: `model-mounting-operation-log:${sequence}`,
      };
    },
    nextReceiptId(kind) {
      this.receiptCounter += 1;
      return `receipt.${this.receiptCounter}.${kind}`;
    },
    admitModelMountInvocation(request) {
      return {
        source: "rust_model_mount_mock",
        backend: "rust_model_mount_live",
        record: {
          ...request,
          invocation_admission_ref: `model_mount://invocation_admission/${this.receiptCounter}`,
          invocation_admission_hash: `sha256:invocation-${this.receiptCounter}`,
        },
        invocation_admission_ref: `model_mount://invocation_admission/${this.receiptCounter}`,
        invocation_admission_hash: `sha256:invocation-${this.receiptCounter}`,
        receipt_refs: request.receipt_refs,
        evidence_refs: ["rust_model_mount_core", `model_mount://invocation_admission/${this.receiptCounter}`],
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
          binding_hash: `sha256:binding-${this.receiptCounter}`,
        },
        accepted_receipt_append: {
          schema_version: "ioi.accepted_receipt_append.v1",
          receipt_ref: request.receiptRef,
          invocation_id: request.invocation.invocation_id,
          receipt_binding_ref: `sha256:binding-${this.receiptCounter}`,
          append_hash: `sha256:append-${this.receiptCounter}`,
        },
        agentgres_admission: {
          schema_version: "ioi.agentgres_admission.v1",
          operation_ref: request.result.agentgres_operation_refs[0],
          expected_heads: request.expectedHeads,
          state_root_before: request.invocation.input.state_root_before,
          state_root_after: request.result.state_root_after,
          resulting_head: request.result.resulting_head,
          admission_hash: `sha256:agentgres-${this.receiptCounter}`,
        },
        projection_record: {
          schema_version: "ioi.step_module_projection.v1",
          component_kind: "ModelInvocationNode",
        },
        receipt_refs: request.result.receipt_refs,
        evidence_refs: ["rust_receipt_binder_core", `sha256:binding-${this.receiptCounter}`],
      };
    },
    receipt(kind, payload) {
      const receipt = { id: `receipt.${kind}.${this.receipts.length + 1}`, kind, ...payload };
      this.receipts.push(receipt);
      return receipt;
    },
    recordConversationState(args) {
      return recordConversationState(this, args, deps);
    },
    writeMap(name, map) {
      this.writes.push([name, [...map.values()].map((record) => ({ ...record }))]);
    },
  };
}

const deps = {
  estimateTokens(input, outputText) {
    return {
      prompt_tokens: String(input).trim().split(/\s+/).filter(Boolean).length,
      completion_tokens: String(outputText).trim().split(/\s+/).filter(Boolean).length,
      total_tokens: String(`${input} ${outputText}`).trim().split(/\s+/).filter(Boolean).length,
    };
  },
  normalizeUsage(usage, fallback) {
    return usage ?? fallback;
  },
  optionalString(value) {
    return typeof value === "string" && value ? value : null;
  },
  randomUUID() {
    return "uuid-1";
  },
  runtimeError({ status, code, message, details }) {
    const error = new Error(message);
    error.status = status;
    error.code = code;
    error.details = details;
    return error;
  },
  stableHash(value) {
    return `hash:${value}`;
  },
};

function selection() {
  return {
    route: { id: "route.local-first" },
    endpoint: {
      id: "endpoint.local",
      modelId: "llama-test",
      providerId: "provider.local",
      backendId: "backend.native",
    },
  };
}

test("nextResponseId uses requested ids, generates fallbacks, and rejects collisions", () => {
  const state = fakeState();
  state.conversations.set("resp_existing", { id: "resp_existing" });

  assert.equal(nextResponseId(state, "resp_requested", deps), "resp_requested");
  assert.equal(nextResponseId(state, null, deps), "resp_uuid-1");
  assert.throws(
    () => nextResponseId(state, "resp_existing", deps),
    (error) => error.status === 409 && error.code === "continuation",
  );
});

test("conversationState returns records and fails closed for missing previous responses", () => {
  const state = fakeState();
  state.conversations.set("resp_1", { id: "resp_1" });

  assert.equal(conversationState(state, "resp_1", deps).id, "resp_1");
  assert.throws(
    () => conversationState(state, "missing", deps),
    (error) => error.status === 404 && error.details.previous_response_id === "missing",
  );
});

test("recordConversationState stores redacted replay metadata and message lineage", () => {
  const state = fakeState();
  const previousState = {
    id: "resp_previous",
    root_response_id: "resp_root",
    messageCount: 4,
  };

  const record = recordConversationState(
    state,
    {
      responseId: "resp_current",
      previousState,
      kind: "responses",
      input: "secret prompt",
      outputText: "public answer",
      selection: selection(),
      instance: { id: "instance.1", backendId: "backend.instance" },
      receipt: { id: "receipt.invocation" },
      routeReceipt: { id: "receipt.route" },
      tokenCount: { total_tokens: 4 },
      streamReceiptId: "receipt.stream",
      continuationSafety: { safe: true },
    },
    deps,
  );

  assert.equal(record.previous_response_id, "resp_previous");
  assert.equal(record.root_response_id, "resp_root");
  assert.equal(record.messageCount, 6);
  assert.equal(record.inputHash, "hash:secret prompt");
  assert.equal(record.outputHash, "hash:public answer");
  assert.equal(record.replay.previous_response_id, "resp_previous");
  assert.equal(record.replay.plaintextPersisted, false);
  assert.equal(Object.hasOwn(record, "previousResponseId"), false);
  assert.equal(Object.hasOwn(record, "rootResponseId"), false);
  assert.equal(Object.hasOwn(record.replay, "previousResponseId"), false);
  assert.equal(state.conversations.get("resp_current"), record);
  assert.equal(state.writes.at(-1)[0], "model-conversations");
});

test("recordModelStreamCompleted emits stream receipt and finalizes conversation state", () => {
  const state = fakeState();
  const invocation = {
    kind: "responses",
    input: "hello model",
    model: "llama-test",
    route: { id: "route.local-first" },
    endpoint: { id: "endpoint.local", modelId: "llama-test", providerId: "provider.local" },
    instance: { id: "instance.1", backendId: "backend.native" },
    receipt: {
      id: "receipt.invocation",
      details: {
        selectedBackend: "backend.native",
        policyHash: "sha256:policy",
        inputHash: "sha256:input",
        providerAuthEvidenceRefs: ["provider.auth"],
      },
    },
    routeReceipt: {
      id: "receipt.route",
      details: {
        model_mount_route_decision_ref: "model_mount://route_decision/test",
        workflow_graph_id: "graph.stream",
        workflow_node_id: "node.stream",
      },
    },
    responseId: "resp_stream",
    previousResponseId: null,
    previousConversationState: null,
    toolReceiptIds: ["receipt.tool"],
  };

  const receipt = recordModelStreamCompleted(
    state,
    {
      invocation,
      streamKind: "responses",
      outputText: "stream answer",
      chunksForwarded: 3,
      finishReason: "stop",
      providerResult: { providerResponseKind: "openai.responses", backendEvidenceRefs: ["backend.ok"] },
      providerStreamShapeSummary: {
        schemaVersion: "ioi.model.provider_stream_shape.v1",
        framesForwarded: 3,
        evidenceRefs: ["model_provider_stream_shape_summary"],
      },
    },
    deps,
  );

  assert.equal(receipt.kind, "model_invocation_stream_completed");
  assert.equal(receipt.id, "receipt.1.model_invocation_stream_completed");
  assert.equal(receipt.details.outputHash, "hash:stream answer");
  assert.equal(receipt.details.previous_response_id, null);
  assert.equal(Object.hasOwn(receipt.details, "previousResponseId"), false);
  assert.deepEqual(receipt.details.toolReceiptIds, ["receipt.tool"]);
  assert.equal(receipt.details.providerStreamShapeSummary.framesForwarded, 3);
  assert.equal(receipt.details.model_mount_invocation_admission_ref, "model_mount://invocation_admission/1");
  assert.equal(receipt.details.model_mount_receipt_binding_ref, "sha256:binding-1");
  assert.equal(receipt.details.model_mount_agentgres_operation_ref, "agentgres://model-mounting/operation-log/op_00000001_model_invocation_stream_completed");
  assert.equal(receipt.details.model_mount_step_module_invocation.input.state_root_before, "sha256:state-0");
  assert.equal(receipt.details.model_mount_step_module_result.resulting_head, "agentgres://model-mounting/operation-log/head/1");
  assert.deepEqual(state.receiptBindingRequests[0].expectedHeads, [
    "agentgres://model-mounting/operation-log/head/0",
  ]);
  assert.equal(invocation.conversationState.id, "resp_stream");
  assert.equal(invocation.conversationState.streamReceiptId, receipt.id);
  assert.equal(Object.hasOwn(invocation.conversationState, "previousResponseId"), false);
  assert.equal(state.conversations.get("resp_stream"), invocation.conversationState);
});

test("recordModelStreamCompleted fails closed without Rust receipt binding", () => {
  const state = fakeState();
  state.bindModelMountInvocationReceipt = undefined;
  const invocation = {
    kind: "responses",
    input: "hello model",
    model: "llama-test",
    route: { id: "route.local-first" },
    endpoint: { id: "endpoint.local", modelId: "llama-test", providerId: "provider.local" },
    instance: { id: "instance.1", backendId: "backend.native" },
    receipt: {
      id: "receipt.invocation",
      details: {
        policyHash: "sha256:policy",
        inputHash: "sha256:input",
      },
    },
    routeReceipt: {
      id: "receipt.route",
      details: {
        model_mount_route_decision_ref: "model_mount://route_decision/test",
      },
    },
    responseId: null,
    toolReceiptIds: [],
  };

  assert.throws(
    () =>
      recordModelStreamCompleted(
        state,
        {
          invocation,
          streamKind: "responses",
          outputText: "stream answer",
        },
        deps,
      ),
    (error) => error.code === "model_mount_stream_completion_receipt_binding_required",
  );
  assert.deepEqual(state.receipts, []);
});

test("listConversations sorts by createdAt", () => {
  const state = fakeState();
  state.conversations.set("late", { id: "late", createdAt: "2026-06-04T03:00:02.000Z" });
  state.conversations.set("early", { id: "early", createdAt: "2026-06-04T03:00:01.000Z" });

  assert.deepEqual(listConversations(state).map((record) => record.id), ["early", "late"]);
});
