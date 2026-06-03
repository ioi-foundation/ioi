import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createStudioResponseMetrics } = require("./response-metrics.js");

function createMetrics() {
  return createStudioResponseMetrics({
    escapeHtml: (value = "") => String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;"),
    stringValue: (value, fallback = "") => {
      if (value === null || value === undefined) return fallback;
      return typeof value === "string" ? value : String(value);
    },
    normalizeStudioReasoningEffort: (value, fallback = "none") => {
      const text = String(value || "").trim().toLowerCase();
      return ["none", "low", "medium", "high"].includes(text) ? text : fallback;
    },
    normalizeReceiptRefs: (payload = {}) => {
      const refs = [];
      if (Array.isArray(payload.receiptRefs)) refs.push(...payload.receiptRefs);
      if (Array.isArray(payload.receipt_refs)) refs.push(...payload.receipt_refs);
      return refs;
    },
  });
}

test("response metrics use provider usage when available", () => {
  const metrics = createMetrics();
  const row = metrics.studioResponseMetricsFromUsage({
    usage: {
      prompt_tokens: 10,
      completion_tokens: 20,
      total_tokens: 30,
    },
    model: "qwen",
    provider: "local",
    routeId: "route.local",
    reasoningEffort: "HIGH",
    elapsedMs: 2000,
    timeToFirstTokenMs: 150,
    stopReason: "stop",
  });

  assert.equal(row.model, "qwen");
  assert.equal(row.reasoningEffort, "high");
  assert.equal(row.promptTokens, 10);
  assert.equal(row.generatedTokens, 20);
  assert.equal(row.totalTokens, 30);
  assert.equal(row.tokensPerSecond, 10);
  assert.equal(row.estimatedTokens, false);
});

test("response metrics estimate tokens and render escaped rows", () => {
  const metrics = createMetrics();
  const row = metrics.studioResponseMetricsFromUsage({
    usage: {},
    promptText: "12345678",
    generatedText: "123456789",
    model: "<model>",
    provider: "local",
    elapsedMs: 1000,
  });
  const html = metrics.studioResponseMetricsRows({ modelMetrics: row });

  assert.equal(row.promptTokens, 2);
  assert.equal(row.generatedTokens, 3);
  assert.equal(row.totalTokens, 5);
  assert.equal(row.estimatedTokens, true);
  assert.match(html, /data-testid="studio-response-metrics"/);
  assert.match(html, /&lt;model&gt;/);
  assert.match(html, /~2/);
});

test("response metrics split thinking and render badges", () => {
  const metrics = createMetrics();
  const split = metrics.studioSplitReasoningFromText("<think>private chain</think>Final answer");

  assert.deepEqual(split, {
    thinkingText: "private chain",
    answerText: "Final answer",
  });
  assert.match(metrics.studioThinkingRows({ thinkingText: "<hidden>" }), /&lt;hidden&gt;/);
  assert.match(metrics.studioTurnContentRows({ role: "assistant" }, "<b>answer</b>"), /&lt;b&gt;answer&lt;\/b&gt;/);
  assert.match(metrics.studioVerifiedBadge({ receiptRefs: ["receipt_1"] }, "Verified renderer"), /Verified renderer/);
  assert.match(metrics.studioVerifiedBadge({}), /Trace pending/);
});

test("response metrics project response usage aliases", () => {
  const metrics = createMetrics();
  const row = metrics.studioResponseMetricsFromResponse({
    usage: {
      input_tokens: 4,
      output_tokens: 6,
    },
    routeId: "route.provider",
    providerId: "provider.local",
    choices: [{ finish_reason: "length" }],
  }, {
    model: "fallback-model",
    elapsedMs: 3000,
  });

  assert.equal(row.model, "fallback-model");
  assert.equal(row.provider, "provider.local");
  assert.equal(row.routeId, "route.provider");
  assert.equal(row.totalTokens, 10);
  assert.equal(row.stopReason, "length");
});
