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
    transitionRequests: [],
    recordStateCommits: [],
    receipts: [],
    writes: [],
    nowIso() {
      return this.now;
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
          expected_heads: request.acceptedReceiptTransition?.expected_heads ?? [],
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
    commitRuntimeModelMountRecordState(request) {
      this.recordStateCommits.push(request);
      return {
        record_id: request.record_id,
        object_ref: `agentgres://model-mounting/${request.record_dir}/${request.record_id}`,
        content_hash: `sha256:${request.operation_kind}:${request.record_id}`,
        admission_hash: `sha256:admission:${request.operation_kind}:${request.record_id}`,
        commit_hash: `sha256:commit:${request.operation_kind}:${request.record_id}`,
        written_record: request.record,
        storage_record: {
          object_ref: `agentgres://model-mounting/${request.record_dir}/${request.record_id}`,
          content_hash: `sha256:${request.operation_kind}:${request.record_id}`,
          admission: {
            admission_hash: `sha256:admission:${request.operation_kind}:${request.record_id}`,
          },
        },
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

test("recordConversationState fails closed before JS conversation projection mutation", () => {
  const state = fakeState();
  const previousState = {
    id: "resp_previous",
    root_response_id: "resp_root",
    message_count: 4,
  };

  assert.throws(
    () =>
      recordConversationState(
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
        },
        deps,
      ),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_conversation_rust_core_required");
      assert.equal(error.details.operation, "model_conversation_state_write");
      assert.equal(error.details.response_id, "resp_current");
      assert.equal(error.details.previous_response_id, "resp_previous");
      assert.equal(error.details.receipt_id, "receipt.invocation");
      assert.equal(error.details.stream_receipt_id, "receipt.stream");
      assert.ok(error.details.evidence_refs.includes("model_mount_conversation_state_js_facade_retired"));
      return true;
    },
  );

  assert.equal(state.conversations.has("resp_current"), false);
  assert.deepEqual(state.recordStateCommits, []);
  assert.deepEqual(state.writes, []);
});

test("recordModelStreamCompleted fails closed before JS stream receipt or conversation mutation", () => {
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

  assert.throws(
    () =>
      recordModelStreamCompleted(
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
      ),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_conversation_rust_core_required");
      assert.equal(error.details.operation, "model_stream_completion");
      assert.equal(error.details.stream_kind, "responses");
      assert.equal(error.details.invocation_receipt_id, "receipt.invocation");
      assert.equal(error.details.response_id, "resp_stream");
      assert.equal(error.details.chunks_forwarded, 3);
      assert.equal(error.details.has_provider_stream_shape_summary, true);
      assert.ok(error.details.evidence_refs.includes("model_mount_stream_completion_js_facade_retired"));
      return true;
    },
  );

  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.receiptBindingRequests, []);
  assert.deepEqual(state.transitionRequests, []);
  assert.equal(state.conversations.has("resp_stream"), false);
  assert.equal(Object.hasOwn(invocation, "conversationState"), false);
});

test("listConversations sorts by created_at", () => {
  const state = fakeState();
  state.conversations.set("late", { id: "late", created_at: "2026-06-04T03:00:02.000Z" });
  state.conversations.set("early", { id: "early", created_at: "2026-06-04T03:00:01.000Z" });

  assert.deepEqual(listConversations(state).map((record) => record.id), ["early", "late"]);
});
