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
    receipts: [],
    writes: [],
    nowIso() {
      return this.now;
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
    rootResponseId: "resp_root",
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

  assert.equal(record.rootResponseId, "resp_root");
  assert.equal(record.messageCount, 6);
  assert.equal(record.inputHash, "hash:secret prompt");
  assert.equal(record.outputHash, "hash:public answer");
  assert.equal(record.replay.plaintextPersisted, false);
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
    endpoint: { id: "endpoint.local", providerId: "provider.local" },
    instance: { id: "instance.1", backendId: "backend.native" },
    receipt: { id: "receipt.invocation", details: { selectedBackend: "backend.native" } },
    routeReceipt: { id: "receipt.route" },
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
    },
    deps,
  );

  assert.equal(receipt.kind, "model_invocation_stream_completed");
  assert.equal(receipt.details.outputHash, "hash:stream answer");
  assert.deepEqual(receipt.details.toolReceiptIds, ["receipt.tool"]);
  assert.equal(invocation.conversationState.id, "resp_stream");
  assert.equal(invocation.conversationState.streamReceiptId, receipt.id);
  assert.equal(state.conversations.get("resp_stream"), invocation.conversationState);
});

test("listConversations sorts by createdAt", () => {
  const state = fakeState();
  state.conversations.set("late", { id: "late", createdAt: "2026-06-04T03:00:02.000Z" });
  state.conversations.set("early", { id: "early", createdAt: "2026-06-04T03:00:01.000Z" });

  assert.deepEqual(listConversations(state).map((record) => record.id), ["early", "late"]);
});
