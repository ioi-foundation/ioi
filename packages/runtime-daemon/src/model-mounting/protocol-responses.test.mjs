import test from "node:test";
import assert from "node:assert/strict";

import {
  anthropicMessage,
  deterministicVector,
  openAiChatCompletion,
  openAiEmbedding,
  openAiResponse,
} from "./protocol-responses.mjs";
import {
  openAiChatCompletion as compatOpenAiChatCompletion,
} from "../model-mounting.mjs";

function invocation(overrides = {}) {
  return {
    model: "route.local-first",
    outputText: "done",
    tokenCount: { prompt_tokens: 2, completion_tokens: 1, total_tokens: 3 },
    receipt: { id: "receipt-1" },
    route: { id: "route-1" },
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
  assert.equal(response.response_id, "resp-1");
  assert.equal(response.previous_response_id, "resp-0");
  assert.equal(response.request_model, "requested-model");
  assert.deepEqual(response.tool_receipt_ids, ["tool-1"]);
});

test("OpenAI response and Anthropic message wrappers expose stable public metadata", () => {
  const response = openAiResponse(invocation());
  assert.equal(response.id, "resp-1");
  assert.equal(response.object, "response");
  assert.equal(response.output_text, "done");
  assert.equal(response.receipt_id, "receipt-1");

  const anthropic = anthropicMessage(invocation());
  assert.equal(anthropic.type, "message");
  assert.equal(anthropic.content[0].text, "done");
  assert.deepEqual(anthropic.usage, {
    input_tokens: 2,
    output_tokens: 1,
    cache_read_input_tokens: 0,
  });
});

test("OpenAI embeddings use deterministic vectors for each input", () => {
  const response = openAiEmbedding(invocation(), { input: ["alpha", "beta"] });

  assert.equal(response.object, "list");
  assert.equal(response.data.length, 2);
  assert.deepEqual(response.data[0].embedding, deterministicVector("alpha"));
  assert.equal(response.data[0].embedding.length, 8);
  assert.equal(response.receipt_id, "receipt-1");
});

test("model-mounting compatibility re-export remains available", () => {
  const response = compatOpenAiChatCompletion(invocation());

  assert.equal(response.object, "chat.completion");
  assert.equal(response.choices[0].message.content, "done");
  assert.equal(response.receipt_id, "receipt-1");
});
