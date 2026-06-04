import test from "node:test";
import assert from "node:assert/strict";

import {
  chatCompletionRequestBody,
  deterministicOutput,
  deterministicTokenizeText,
  estimateTokens,
  inputText,
  normalizeLimit,
  normalizeUsage,
  outputTextFromChat,
  outputTextFromResponse,
  parseJsonMaybe,
  truncateToEstimatedTokens,
} from "./provider-protocol.mjs";

test("chat completion request body preserves messages and fills model", () => {
  const body = chatCompletionRequestBody({
    messages: [{ role: "system", content: "stay focused" }],
    temperature: 0,
  }, "route.local-first");

  assert.equal(body.model, "route.local-first");
  assert.deepEqual(body.messages, [{ role: "system", content: "stay focused" }]);
  assert.equal(body.temperature, 0);
});

test("chat completion request body converts input payloads to user messages", () => {
  const body = chatCompletionRequestBody({ input: "hello" }, "route.local-first");

  assert.equal(body.model, "route.local-first");
  assert.deepEqual(body.messages, [{ role: "user", content: "hello" }]);
});

test("provider output helpers read chat and responses payload text", () => {
  assert.equal(
    outputTextFromChat({ choices: [{ message: { content: "chat text" } }] }),
    "chat text",
  );
  assert.equal(
    outputTextFromResponse({ output: [{ content: [{ type: "output_text", text: "response text" }] }] }),
    "response text",
  );
});

test("normalize usage maps OpenAI and Responses token names with perf fields", () => {
  const normalized = normalizeUsage({
    input_tokens: 12,
    output_tokens: 5,
    total_tokens: 17,
    tokensPerSecond: 42,
    timeToFirstTokenMs: 9,
  }, {
    prompt_tokens: 1,
    completion_tokens: 1,
    total_tokens: 2,
  });

  assert.deepEqual(normalized, {
    prompt_tokens: 12,
    completion_tokens: 5,
    total_tokens: 17,
    tokens_per_second: 42,
    time_to_first_token_ms: 9,
  });
});

test("parseJsonMaybe parses JSON and truncates invalid text", () => {
  assert.deepEqual(parseJsonMaybe("{\"ok\":true}"), { ok: true });
  assert.deepEqual(parseJsonMaybe("x".repeat(1002)), { text: `${"x".repeat(1000)}...` });
});

test("deterministic fixture helpers remain stable and token-aware", () => {
  const input = inputText({
    messages: [
      { role: "user", content: [{ text: "hello" }], name: "operator" },
      { role: "assistant", content: "world", tool_calls: [{ id: "tool-1" }] },
    ],
  });
  assert.equal(input.includes("user: hello name:operator"), true);
  assert.equal(input.includes("assistant: world"), true);
  assert.equal(input.includes("tool-1"), true);

  assert.match(deterministicOutput({ kind: "chat", input: "hello", modelId: "route.local" }), /^IOI model router fixture response/);
  assert.match(deterministicOutput({ kind: "embeddings", input: "hello", modelId: "route.local" }), /^embedding:route\.local:/);
  assert.deepEqual(estimateTokens("abcdefgh", "abcd"), {
    prompt_tokens: 2,
    completion_tokens: 1,
    total_tokens: 3,
  });

  const tokens = deterministicTokenizeText("hi there");
  assert.deepEqual(tokens.map((token) => token.text), ["hi", " ", "there"]);
  assert.equal(tokens.every((token) => Number.isInteger(token.token_id)), true);
  assert.equal(truncateToEstimatedTokens("abcdefghijkl", 2), "efghijkl");
});

test("normalizeLimit preserves fallback semantics for invalid limits", () => {
  assert.equal(normalizeLimit("9", 80, 200), 9);
  assert.equal(normalizeLimit("0", 80, 200), 80);
  assert.equal(normalizeLimit("-1", 80, 200), 80);
  assert.equal(normalizeLimit("300", 80, 200), 200);
});
