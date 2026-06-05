import assert from "node:assert/strict";
import test from "node:test";

import {
  MODEL_ROUTE_DECISION_EVENT_KIND,
  MODEL_ROUTE_DECISION_SCHEMA_VERSION,
  createModelRouteDecision,
  providerRequestBodyForRoute,
  routeDecisionProjectionFromReceipt,
} from "./route-decision.mjs";

test("provider request body resolves auto and strips Autopilot-only route fields", () => {
  const body = providerRequestBodyForRoute(
    {
      route_id: "route.local-first",
      model: "auto",
      stream: true,
      messages: [{ role: "user", content: "hello" }],
      metadata: { workspaceRoot: "/tmp/workspace" },
      model_policy: { deny_fixture_models: true },
      modelPolicy: { denyFixtureModels: true },
      fallback_triggered: true,
      fallbackTriggered: true,
      fallback_reason: "primary_route_unavailable",
      fallbackReason: "legacy_route_unavailable",
      workflow_node_id: "runtime.model-router",
    },
    { modelId: "qwen/qwen3.5-9b", providerId: "provider.llama-cpp", driver: "llama_cpp" },
  );

  assert.equal(body.model, "qwen/qwen3.5-9b");
  assert.equal(body.stream, true);
  assert.deepEqual(body.messages, [{ role: "user", content: "hello" }]);
  assert.equal(body.route_id, undefined);
  assert.equal(body.metadata, undefined);
  assert.equal(body.model_policy, undefined);
  assert.equal(body.modelPolicy, undefined);
  assert.equal(body.fallback_triggered, undefined);
  assert.equal(body.fallbackTriggered, undefined);
  assert.equal(body.fallback_reason, undefined);
  assert.equal(body.fallbackReason, undefined);
  assert.equal(body.workflow_node_id, undefined);
});

test("route decisions use canonical hosted fallback policy constraint", () => {
  const decision = createModelRouteDecision({
    route: { id: "route.local-first", privacy: "local_or_enterprise", fallback: ["endpoint.local"] },
    endpoint: { id: "endpoint.hosted", modelId: "model.hosted", providerId: "provider.hosted" },
    provider: { id: "provider.hosted", kind: "openai", privacyClass: "hosted" },
    policy: { allow_hosted_fallback: true },
    policyHash: "sha256:policy",
    requestedModel: "auto",
  });

  assert.equal(decision.policyConstraints.allow_hosted_fallback, true);
  assert.equal(decision.policyConstraints.allowHostedFallback, undefined);
});

test("route decisions honor canonical fallback request metadata", () => {
  const decision = createModelRouteDecision({
    route: { id: "route.local-first", privacy: "local_or_enterprise", fallback: ["endpoint.local"] },
    endpoint: { id: "endpoint.hosted", modelId: "model.hosted", providerId: "provider.hosted" },
    provider: { id: "provider.hosted", kind: "openai", privacyClass: "hosted" },
    request: {
      fallback_triggered: true,
      fallback_reason: "primary_route_unavailable",
    },
    policyHash: "sha256:policy",
    requestedModel: "auto",
    responseId: "resp-1",
    previousResponseId: "resp-0",
  });

  assert.equal(decision.schema_version, MODEL_ROUTE_DECISION_SCHEMA_VERSION);
  assert.equal(decision.event_kind, MODEL_ROUTE_DECISION_EVENT_KIND);
  assert.equal(typeof decision.decision_id, "string");
  assert.equal(Object.hasOwn(decision, "schemaVersion"), false);
  assert.equal(Object.hasOwn(decision, "eventKind"), false);
  assert.equal(Object.hasOwn(decision, "decisionId"), false);
  assert.equal(decision.response_id, "resp-1");
  assert.equal(decision.previous_response_id, "resp-0");
  assert.equal(Object.hasOwn(decision, "responseId"), false);
  assert.equal(Object.hasOwn(decision, "previousResponseId"), false);
  assert.equal(decision.fallback_allowed, true);
  assert.equal(decision.fallback_triggered, true);
  assert.equal(decision.fallback_reason, "primary_route_unavailable");
  assert.equal(Object.hasOwn(decision, "fallbackAllowed"), false);
  assert.equal(Object.hasOwn(decision, "fallbackTriggered"), false);
  assert.equal(Object.hasOwn(decision, "fallbackReason"), false);
  assert.equal(decision.evidenceRefs.includes("model_route_fallback_selected"), true);
  assert.match(decision.rationale, /primary_route_unavailable/);
});

test("route decisions ignore retired camelCase fallback request aliases", () => {
  const decision = createModelRouteDecision({
    route: { id: "route.local-first", privacy: "local_or_enterprise", fallback: ["endpoint.hosted"] },
    endpoint: { id: "endpoint.hosted", modelId: "model.hosted", providerId: "provider.hosted" },
    provider: { id: "provider.hosted", kind: "openai", privacyClass: "hosted" },
    request: {
      fallbackTriggered: true,
      fallbackReason: "legacy_route_unavailable",
    },
    policyHash: "sha256:policy",
    requestedModel: "auto",
  });

  assert.equal(decision.fallback_triggered, false);
  assert.equal(decision.fallback_reason, null);
  assert.equal(Object.hasOwn(decision, "fallbackTriggered"), false);
  assert.equal(Object.hasOwn(decision, "fallbackReason"), false);
  assert.equal(decision.evidenceRefs.includes("model_route_fallback_selected"), false);
  assert.doesNotMatch(decision.rationale, /legacy_route_unavailable/);
});

test("route decision projections ignore retired legacy model route decision detail", () => {
  assert.deepEqual(routeDecisionProjectionFromReceipt({
    id: "receipt-route",
    createdAt: "2026-06-05T00:00:00.000Z",
    kind: "model_route_selection",
    details: {
      model_route_decision: { routeId: "route.local-first", selectedModel: "model.local" },
    },
  }), {
    routeId: "route.local-first",
    selectedModel: "model.local",
    receiptId: "receipt-route",
    receiptCreatedAt: "2026-06-05T00:00:00.000Z",
    receiptKind: "model_route_selection",
  });

  assert.equal(routeDecisionProjectionFromReceipt({
    id: "receipt-route-legacy",
    kind: "model_route_selection",
    details: {
      modelRouteDecision: { routeId: "route.legacy" },
    },
  }), null);
});

test("provider request body maps Autopilot reasoning off to llama.cpp enable_thinking false", () => {
  const body = providerRequestBodyForRoute(
    {
      model: "qwen/qwen3.5-9b",
      reasoning_effort: "none",
      reasoningEffort: "none",
      chatTemplateKwargs: { enable_thinking: true },
      messages: [{ role: "user", content: "answer directly" }],
    },
    { modelId: "qwen/qwen3.5-9b", providerId: "provider.llama-cpp", driver: "llama_cpp" },
  );

  assert.equal(body.reasoning_effort, "none");
  assert.deepEqual(body.chat_template_kwargs, { enable_thinking: false });
  assert.equal(body.reasoningEffort, undefined);
  assert.equal(body.chatTemplateKwargs, undefined);
});

test("provider request body maps enabled Autopilot reasoning to llama.cpp enable_thinking true", () => {
  const body = providerRequestBodyForRoute(
    {
      model: "qwen/qwen3.5-9b",
      model_policy: { reasoning_effort: "medium" },
      messages: [{ role: "user", content: "think visibly" }],
    },
    { modelId: "qwen/qwen3.5-9b", providerId: "provider.llama-cpp", driver: "llama_cpp" },
  );

  assert.equal(body.reasoning_effort, "medium");
  assert.deepEqual(body.chat_template_kwargs, { enable_thinking: true });
});

test("provider request body coalesces multiple system messages for llama.cpp chat templates", () => {
  const body = providerRequestBodyForRoute(
    {
      model: "qwen/qwen3.5-9b",
      messages: [
        { role: "system", content: "Primary instruction." },
        { role: "system", content: "Workspace context." },
        { role: "user", content: "Create a website." },
      ],
    },
    { modelId: "qwen/qwen3.5-9b", providerId: "provider.llama-cpp", driver: "llama_cpp" },
  );

  assert.deepEqual(body.messages, [
    { role: "system", content: "Primary instruction.\n\nWorkspace context." },
    { role: "user", content: "Create a website." },
  ]);
});

test("provider request body preserves multiple system messages for generic OpenAI-compatible providers", () => {
  const messages = [
    { role: "system", content: "Primary instruction." },
    { role: "system", content: "Workspace context." },
    { role: "user", content: "Create a website." },
  ];
  const body = providerRequestBodyForRoute(
    { model: "gpt-example", messages },
    { modelId: "gpt-example", providerId: "provider.openai", driver: "openai_compatible" },
  );

  assert.deepEqual(body.messages, messages);
});

test("provider request body does not send llama.cpp chat template kwargs to generic providers", () => {
  const body = providerRequestBodyForRoute(
    {
      model: "gpt-example",
      reasoning_effort: "none",
      chatTemplateKwargs: { enable_thinking: false },
      messages: [{ role: "user", content: "hello" }],
    },
    { modelId: "gpt-example", providerId: "provider.openai", driver: "openai_compatible" },
  );

  assert.equal(body.reasoning_effort, "none");
  assert.equal(body.chat_template_kwargs, undefined);
  assert.equal(body.chatTemplateKwargs, undefined);
});
