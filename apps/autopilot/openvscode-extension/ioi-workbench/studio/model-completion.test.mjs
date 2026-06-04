import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const {
  createStudioModelStreamHelpers,
  ssePayloadsFromBlock,
  studioDeltaFromSsePayload,
} = require("./model-completion.js");

function helpers() {
  return createStudioModelStreamHelpers({
    firstArray: (value) => Array.isArray(value) ? value : [],
    studioNumberOrNull: (value) => {
      const numeric = Number(value);
      return Number.isFinite(numeric) ? numeric : null;
    },
    uniqueStrings: (values = []) => [...new Set((Array.isArray(values) ? values : []).map((value) => String(value)).filter(Boolean))],
  });
}

test("model completion helpers parse SSE payload blocks and text deltas", () => {
  assert.deepEqual(
    ssePayloadsFromBlock("event: message\ndata: {\"a\":1}\n\ndata: [DONE]\n"),
    ['{"a":1}', "[DONE]"],
  );
  assert.equal(studioDeltaFromSsePayload({ choices: [{ delta: { content: "hello" } }] }), "hello");
  assert.equal(studioDeltaFromSsePayload({ type: "response.output_text.delta", delta: "world" }), "world");
  assert.equal(studioDeltaFromSsePayload({ message: { content: "message" } }), "message");
  assert.equal(studioDeltaFromSsePayload({ response: { output_text: "response" } }), "response");
});

test("model completion stream metadata collects receipts, timings, and stop state", () => {
  const { collectStudioStreamMetadata, studioReasoningDeltaFromSsePayload, studioUsageFromProviderTimings } = helpers();
  const target = {
    receiptIds: new Set(),
    routeId: "route.old",
    model: "old-model",
    providerStream: null,
    provider: null,
    usage: { input_tokens: 2 },
    stopReason: null,
  };

  collectStudioStreamMetadata(target, {
    receipt_id: "receipt_a",
    streamReceiptId: "receipt_stream",
    tool_receipt_ids: ["receipt_tool", "receipt_tool"],
    route_id: "route.local-first",
    model: "qwen/qwen3.5",
    provider_stream: "native",
    provider_id: "provider.llama_cpp",
    timings: {
      prompt_n: 11,
      predicted_n: 7,
      predicted_per_second: 18.5,
      prompt_ms: 100,
      predicted_ms: 300,
    },
    choices: [{ finish_reason: "stop" }],
  });

  assert.deepEqual([...target.receiptIds], ["receipt_a", "receipt_stream", "receipt_tool"]);
  assert.equal(target.routeId, "route.local-first");
  assert.equal(target.model, "qwen/qwen3.5");
  assert.equal(target.providerStream, "native");
  assert.equal(target.provider, "provider.llama_cpp");
  assert.equal(target.stopReason, "stop");
  assert.deepEqual(target.usage, {
    input_tokens: 2,
    prompt_tokens: 11,
    completion_tokens: 7,
    total_tokens: 18,
    tokens_per_second: 18.5,
    prompt_ms: 100,
    completion_ms: 300,
    elapsed_ms: 400,
  });
  assert.equal(studioReasoningDeltaFromSsePayload({ choices: [{ delta: { reasoningContent: " thinking " } }] }), "thinking");
  assert.deepEqual(studioUsageFromProviderTimings(null, target.usage), target.usage);
});
