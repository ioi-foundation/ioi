import assert from "node:assert/strict";
import test from "node:test";

import { ModelMountingState } from "../model-mounting.mjs";

function fakeState() {
  const state = {
    conversations: new Map(),
    agentgresConversationRecords: new Map(),
    stateDir: "/state",
    now: "2026-06-04T03:00:00.000Z",
    receiptCounter: 0,
    receiptBindingRequests: [],
    transitionRequests: [],
    conversationPlanRequests: [],
    streamCompletionPlanRequests: [],
    readProjectionRequests: [],
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
    planModelMountConversationState(request) {
      this.conversationPlanRequests.push(request);
      const record = {
        id: request.response_id,
        object: "ioi.model_mount_conversation_state",
        status: request.status,
        kind: request.kind,
        response_id: request.response_id,
        previous_response_id: request.previous_response_id,
        root_response_id: request.root_response_id,
        message_count: (request.previous_message_count ?? 0) + 1,
        route_id: request.route_ref,
        endpoint_id: request.endpoint_ref,
        provider_id: request.provider_ref,
        selected_model: request.model_ref,
        instance_id: request.instance_ref,
        route_decision_ref: request.route_decision_ref,
        receipt_id: request.invocation_receipt_ref,
        route_receipt_ref: request.route_receipt_ref,
        stream_receipt_ref: request.stream_receipt_ref,
        input_hash: "sha256:input",
        output_hash: "sha256:output",
        token_count: request.token_count,
        continuation: request.continuation_safety,
        receipt_refs: request.receipt_refs,
        evidence_refs: [
          "model_mount_conversation_state_rust_owned",
          "rust_daemon_core_model_conversation_state",
          "agentgres_model_conversation_truth_required",
        ],
        rust_core_boundary: "model_mount.conversation",
        source: request.source,
        conversation_hash: "sha256:conversation-state",
        created_at: request.generated_at,
        updated_at: request.generated_at,
      };
      return {
        source: "rust_daemon_core.model_mount.conversation_state",
        record_dir: "model-conversations",
        record_id: record.id,
        record,
        operation: request.operation,
        operation_kind: "model_mount.conversation.state_write",
        rust_core_boundary: "model_mount.conversation",
        receipt_refs: request.receipt_refs,
        evidence_refs: [
          "model_mount_conversation_state_rust_owned",
          "rust_daemon_core_model_conversation_state",
          "agentgres_model_conversation_truth_required",
        ],
        conversation_hash: "sha256:conversation-state",
      };
    },
    planModelMountStreamCompletion(request) {
      this.streamCompletionPlanRequests.push(request);
      const record = {
        id: request.response_id,
        object: "ioi.model_mount_conversation_state",
        status: "completed",
        kind: request.kind,
        stream_kind: request.stream_kind,
        response_id: request.response_id,
        previous_response_id: request.previous_response_id,
        root_response_id: request.root_response_id,
        message_count: (request.previous_message_count ?? 0) + 1,
        route_id: request.route_ref,
        endpoint_id: request.endpoint_ref,
        provider_id: request.provider_ref,
        selected_model: request.model_ref,
        instance_id: request.instance_ref,
        route_decision_ref: request.route_decision_ref,
        receipt_id: request.invocation_receipt_ref,
        stream_receipt_ref: `receipt://${request.receipt_id}`,
        input_hash: "sha256:input",
        output_hash: "sha256:output",
        token_count: request.provider_usage ?? request.token_count,
        receipt_refs: request.receipt_refs,
        evidence_refs: [
          "model_mount_stream_completion_rust_owned",
          "rust_daemon_core_model_stream_completion",
          "agentgres_model_conversation_truth_required",
        ],
        rust_core_boundary: "model_mount.conversation",
        source: request.source,
        conversation_hash: "sha256:conversation-stream",
        stream_completion_hash: "sha256:stream-completion",
        created_at: request.generated_at,
        updated_at: request.generated_at,
      };
      const receipt = {
        id: request.receipt_id,
        runId: null,
        kind: "model_invocation_stream_completed",
        summary: "responses stream completed through route.local-first to llama-test.",
        redaction: "redacted",
        evidenceRefs: [
          "rust_model_mount_core",
          "model_mount_stream_completion_rust_owned",
        ],
        createdAt: request.generated_at,
        schemaVersion: "ioi.model-mounting.runtime.v1",
        details: {
          rust_daemon_core_receipt_author: "ModelMountCore.plan_model_mount_stream_completion",
          model_mount_route_decision_ref: request.route_decision_ref,
          token_count: request.provider_usage,
          model_mount_receipt_binding_ref: "sha256:binding-stream",
          model_mount_accepted_receipt_append_hash: "sha256:append-stream",
          model_mount_agentgres_operation_ref:
            "agentgres://model-mounting/accepted-receipts/op_00000001_model_invocation_stream_completed",
          model_mount_agentgres_admission_hash: "sha256:agentgres-stream",
          model_mount_agentgres_state_root_before: request.current_state_root,
          model_mount_agentgres_state_root_after: "sha256:state-stream-after",
          model_mount_agentgres_resulting_head:
            "agentgres://model-mounting/accepted-receipts/head/1",
          model_mount_agentgres_admission: {
            operation_ref:
              "agentgres://model-mounting/accepted-receipts/op_00000001_model_invocation_stream_completed",
          },
          model_mount_step_module_invocation: {
            input: { state_root_before: request.current_state_root },
          },
          model_mount_step_module_result: {
            agentgres_operation_refs: [
              "agentgres://model-mounting/accepted-receipts/op_00000001_model_invocation_stream_completed",
            ],
            state_root_after: "sha256:state-stream-after",
            resulting_head: "agentgres://model-mounting/accepted-receipts/head/1",
          },
        },
      };
      return {
        source: "rust_daemon_core.model_mount.stream_completion",
        record_dir: "model-conversations",
        record_id: record.id,
        record,
        receipt,
        operation: request.operation,
        operation_kind: "model_mount.conversation.stream_completion",
        rust_core_boundary: "model_mount.conversation",
        receipt_refs: request.receipt_refs,
        evidence_refs: [
          "model_mount_stream_completion_rust_owned",
          "rust_daemon_core_model_stream_completion",
          "agentgres_model_conversation_truth_required",
        ],
        conversation_hash: "sha256:conversation-stream",
        stream_completion_hash: "sha256:stream-completion",
      };
    },
    commitRuntimeModelMountRecordState(request) {
      this.recordStateCommits.push(request);
      if (request.record_dir === "model-conversations") {
        this.agentgresConversationRecords.set(request.record_id, request.record);
      }
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
      return ModelMountingState.prototype.recordConversationState.call(this, args);
    },
    persistRustAuthoredReceipt(record) {
      this.receipts.push(record);
      return record;
    },
    modelMountCore: {
      planReadProjection(request) {
        state.readProjectionRequests.push({
          projection_kind: request.projection_kind,
          state_dir: request.state_dir,
          state: request.state,
        });
        return {
          projection: rustConversationProjectionFixture([...state.agentgresConversationRecords.values()]),
        };
      },
    },
    writeMap(name, map) {
      this.writes.push([name, [...map.values()].map((record) => ({ ...record }))]);
    },
  };
  return state;
}

function rustConversationProjectionFixture(records = []) {
  return records
    .filter((record) =>
      record?.object === "ioi.model_mount_conversation_state" &&
      record?.rust_core_boundary === "model_mount.conversation" &&
      typeof record?.conversation_hash === "string" &&
      Array.isArray(record?.evidence_refs) &&
      record.evidence_refs.includes("agentgres_model_conversation_truth_required") &&
      (
        record.evidence_refs.includes("model_mount_conversation_state_rust_owned") ||
        record.evidence_refs.includes("model_mount_stream_completion_rust_owned")
      ))
    .sort((left, right) =>
      String(right.created_at ?? "").localeCompare(String(left.created_at ?? "")) ||
      String(right.id ?? "").localeCompare(String(left.id ?? "")));
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

  assert.equal(ModelMountingState.prototype.nextResponseId.call(state, "resp_requested"), "resp_requested");
  assert.match(ModelMountingState.prototype.nextResponseId.call(state, null), /^resp_[0-9a-f-]{36}$/);
  assert.throws(
    () => ModelMountingState.prototype.nextResponseId.call(state, "resp_existing"),
    (error) => error.status === 409 && error.code === "continuation",
  );
});

test("conversationState returns records and fails closed for missing previous responses", () => {
  const state = fakeState();
  state.conversations.set("resp_1", { id: "resp_1" });

  assert.equal(ModelMountingState.prototype.conversationState.call(state, "resp_1").id, "resp_1");
  assert.throws(
    () => ModelMountingState.prototype.conversationState.call(state, "missing"),
    (error) => error.status === 404 && error.details.previous_response_id === "missing",
  );
});

test("recordConversationState commits Rust-authored conversation state through Agentgres", () => {
  const state = fakeState();
  const previousState = {
    id: "resp_previous",
    root_response_id: "resp_root",
    message_count: 4,
    route_id: "route.local-first",
    endpoint_id: "endpoint.local",
    provider_id: "provider.local",
    selected_model: "llama-test",
  };

  const record = ModelMountingState.prototype.recordConversationState.call(
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
      routeReceipt: {
        id: "receipt.route",
        details: { model_mount_route_decision_ref: "model_mount://route_decision/test" },
      },
      tokenCount: { total_tokens: 4 },
      streamReceiptId: "receipt.stream",
    },
  );

  assert.equal(record.id, "resp_current");
  assert.equal(record.previous_response_id, "resp_previous");
  assert.equal(record.root_response_id, "resp_root");
  assert.equal(record.route_id, "route.local-first");
  assert.equal(record.selected_model, "llama-test");
  assert.equal(state.conversations.get("resp_current"), record.record);
  assert.equal(state.conversationPlanRequests.length, 1);
  assert.equal(state.conversationPlanRequests[0].schema_version, "ioi.model_mount.conversation_state.v1");
  assert.equal(state.conversationPlanRequests[0].operation, "model_conversation_state_write");
  assert.deepEqual(state.recordStateCommits.map((commit) => commit.record_dir), ["model-conversations"]);
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.conversation.state_write");
  assert.equal(state.recordStateCommits[0].record.id, "resp_current");
  assert.deepEqual(state.writes, []);
});

test("recordModelStreamCompleted persists Rust-authored stream receipt and conversation record", () => {
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
        model_mount_route_decision_ref: "model_mount://route_decision/test",
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

  const receipt = ModelMountingState.prototype.recordModelStreamCompleted.call(
    state,
    {
      invocation,
      streamKind: "responses",
      outputText: "stream answer",
      providerUsage: { prompt_tokens: 2, completion_tokens: 2, total_tokens: 4 },
      chunksForwarded: 3,
      finishReason: "stop",
      providerResult: { providerResponseKind: "openai.responses", backendEvidenceRefs: ["backend.ok"] },
      providerStreamShapeSummary: {
        schemaVersion: "ioi.model.provider_stream_shape.v1",
        framesForwarded: 3,
        evidenceRefs: ["model_provider_stream_shape_summary"],
      },
    },
  );

  assert.equal(receipt.kind, "model_invocation_stream_completed");
  assert.equal(receipt.details.rust_daemon_core_receipt_author, "ModelMountCore.plan_model_mount_stream_completion");
  assert.equal(receipt.stream_completion_hash, "sha256:stream-completion");
  assert.equal(state.streamCompletionPlanRequests.length, 1);
  assert.equal(state.streamCompletionPlanRequests[0].schema_version, "ioi.model_mount.stream_completion.v1");
  assert.equal(state.streamCompletionPlanRequests[0].operation, "model_stream_completion");
  assert.equal(state.streamCompletionPlanRequests[0].route_decision_ref, "model_mount://route_decision/test");
  assert.equal(state.streamCompletionPlanRequests[0].chunks_forwarded, 3);
  assert.equal(state.receipts.length, 1);
  assert.equal(state.receipts[0].id, receipt.id);
  assert.equal(state.recordStateCommits.length, 1);
  assert.equal(state.recordStateCommits[0].record_dir, "model-conversations");
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.conversation.stream_completion");
  assert.equal(state.conversations.get("resp_stream"), invocation.conversationState);
  assert.equal(invocation.streamCompletionReceipt.id, receipt.id);
  assert.deepEqual(state.receiptBindingRequests, []);
  assert.deepEqual(state.transitionRequests, []);
});

test("listConversations returns Rust-projected admitted conversation states", () => {
  const state = fakeState();
  state.agentgresConversationRecords.set("legacy", {
    id: "legacy",
    object: "ioi.model_mount_conversation_state",
    created_at: "2026-06-04T03:00:03.000Z",
  });
  state.agentgresConversationRecords.set("early", {
    id: "early",
    object: "ioi.model_mount_conversation_state",
    created_at: "2026-06-04T03:00:01.000Z",
    rust_core_boundary: "model_mount.conversation",
    conversation_hash: "sha256:conversation-early",
    evidence_refs: [
      "model_mount_conversation_state_rust_owned",
      "agentgres_model_conversation_truth_required",
    ],
  });
  state.agentgresConversationRecords.set("late", {
    id: "late",
    object: "ioi.model_mount_conversation_state",
    created_at: "2026-06-04T03:00:02.000Z",
    rust_core_boundary: "model_mount.conversation",
    conversation_hash: "sha256:conversation-late",
    evidence_refs: [
      "model_mount_stream_completion_rust_owned",
      "agentgres_model_conversation_truth_required",
    ],
  });

  const conversations = ModelMountingState.prototype.listConversations.call(state);

  assert.deepEqual(conversations.map((record) => record.id), ["late", "early"]);
  assert.equal(state.readProjectionRequests.length, 1);
  assert.equal(state.readProjectionRequests[0].projection_kind, "model_conversation_states");
  assert.equal(state.readProjectionRequests[0].state_dir, state.stateDir);
  assert.deepEqual(state.readProjectionRequests[0].state, {});
  assert.deepEqual(state.writes, []);
});
