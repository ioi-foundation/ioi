import test from "node:test";
import assert from "node:assert/strict";

import {
  anthropicMessage,
  openAiChatCompletion,
  openAiEmbedding,
  openAiResponse,
} from "./protocol-responses.mjs";
import * as modelMountingFacade from "../model-mounting.mjs";

function invocation(overrides = {}) {
  return {
    model: "route.local-first",
    outputText: "done",
    tokenCount: { prompt_tokens: 2, completion_tokens: 1, total_tokens: 3 },
    receipt: { id: "receipt-1", details: { backend_id: "backend-1" } },
    route: { id: "route-1" },
    endpoint: { id: "endpoint-1" },
    instance: { id: "instance-1", backendId: "backend-1" },
    routeReceipt: {
      id: "route-receipt-1",
      details: {
        model_route_decision: { route_id: "route-1", selected_model: "model-1" },
      },
    },
    toolReceiptIds: ["tool-1"],
    responseId: "resp-1",
    previousResponseId: "resp-0",
    ...overrides,
  };
}

test("OpenAI chat completion preserves provider responses with receipt metadata", () => {
  const response = openAiChatCompletion(invocation({
    providerResponseKind: "chat.completions",
    providerResponse: { id: "provider-chat", choices: [] },
  }), { model: "requested-model" });

  assert.equal(response.id, "provider-chat");
  assert.equal(response.receipt_id, "receipt-1");
  assert.equal(response.route_id, "route-1");
  assert.equal(response.endpoint_id, "endpoint-1");
  assert.equal(response.instance_id, "instance-1");
  assert.equal(response.backend_id, "backend-1");
  assert.equal(response.route_receipt_id, "route-receipt-1");
  assert.deepEqual(response.route_decision, { route_id: "route-1", selected_model: "model-1" });
  assert.equal(response.response_id, "resp-1");
  assert.equal(response.previous_response_id, "resp-0");
  assert.equal(response.output_text, "done");
  assert.equal(response.request_model, "requested-model");
  assert.deepEqual(response.tool_receipt_ids, ["tool-1"]);
});

test("OpenAI response and Anthropic message wrappers expose stable public metadata", () => {
  const response = openAiResponse(invocation());
  assert.equal(response.id, "resp-1");
  assert.equal(response.object, "response");
  assert.equal(response.output_text, "done");
  assert.equal(response.receipt_id, "receipt-1");
  assert.equal(response.backend_id, "backend-1");
  assert.equal(response.route_receipt_id, "route-receipt-1");

  const anthropic = anthropicMessage(invocation());
  assert.equal(anthropic.type, "message");
  assert.equal(anthropic.content[0].text, "done");
  assert.deepEqual(anthropic.usage, {
    input_tokens: 2,
    output_tokens: 1,
    cache_read_input_tokens: 0,
  });
});

test("OpenAI embeddings preserve provider-authored vectors with receipt metadata", () => {
  const response = openAiEmbedding(invocation({
    providerResponseKind: "embeddings",
    providerResponse: {
      object: "list",
      model: "embedding-model",
      data: [
        {
          object: "embedding",
          index: 0,
          embedding: [0.1, -0.2],
        },
      ],
      usage: { prompt_tokens: 1, total_tokens: 1 },
    },
  }), { input: ["alpha"] });

  assert.equal(response.object, "list");
  assert.equal(response.model, "embedding-model");
  assert.equal(response.data.length, 1);
  assert.deepEqual(response.data[0].embedding, [0.1, -0.2]);
  assert.equal(response.receipt_id, "receipt-1");
  assert.equal(response.route_id, "route-1");
});

test("OpenAI embeddings fail closed without Rust/provider-authored vectors", () => {
  assert.throws(
    () => openAiEmbedding(invocation(), { input: ["alpha", "beta"] }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_embedding_provider_response_required");
      assert.equal(error.details.rust_core_boundary, "model_mount.provider_invocation");
      assert.equal(error.details.operation_kind, "model_mount.provider_result.embeddings");
      assert.equal(error.details.provider_response_kind, null);
      assert.equal(error.details.receipt_id, "receipt-1");
      assert.equal(error.details.route_id, "route-1");
      assert.equal(error.details.response_id, "resp-1");
      assert.deepEqual(error.details.evidence_refs, [
        "model_mount_embedding_js_vector_fallback_retired",
        "rust_daemon_core_provider_embedding_required",
      ]);
      assert.equal(Object.hasOwn(error.details, "providerResponseKind"), false);
      assert.equal(Object.hasOwn(error.details, "receiptId"), false);
      return true;
    },
  );
});

test("model-mounting facade does not re-export protocol response helpers", () => {
  assert.equal(Object.hasOwn(modelMountingFacade, "openAiChatCompletion"), false);
  assert.equal(Object.hasOwn(modelMountingFacade, "openAiResponse"), false);
  assert.equal(Object.hasOwn(modelMountingFacade, "openAiEmbedding"), false);
  assert.equal(Object.hasOwn(modelMountingFacade, "openAiCompletion"), false);
  assert.equal(Object.hasOwn(modelMountingFacade, "anthropicMessage"), false);
});
