import assert from "node:assert/strict";
import test from "node:test";

import {
  providerRequestBodyForRoute,
  routeDecisionProjectionFromReceipt,
  workflowContextFromRouteRequest,
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

test("route decision workflow context ignores retired request aliases", () => {
  assert.deepEqual(workflowContextFromRouteRequest({
    workflow_graph_id: "graph-1",
    workflow_node_id: "node-1",
    workflow_node_type: "model-router",
    workflowGraphId: "graph-legacy",
    workflowNodeId: "node-legacy",
    node_id: "node-snake-legacy",
    nodeId: "node-camel-legacy",
    workflowNodeType: "type-legacy",
    node: "node-type-legacy",
  }), {
    workflow_graph_id: "graph-1",
    workflow_node_id: "node-1",
    workflow_node_type: "model-router",
  });
  assert.deepEqual(workflowContextFromRouteRequest({
    workflowGraphId: "graph-legacy",
    workflowNodeId: "node-legacy",
    node_id: "node-snake-legacy",
    nodeId: "node-camel-legacy",
    workflowNodeType: "type-legacy",
    node: "node-type-legacy",
  }), {
    workflow_graph_id: null,
    workflow_node_id: null,
    workflow_node_type: null,
  });
});

test("route decision projections ignore retired legacy model route decision detail", () => {
  assert.deepEqual(routeDecisionProjectionFromReceipt({
    id: "receipt-route",
    createdAt: "2026-06-05T00:00:00.000Z",
    kind: "model_route_selection",
    details: {
      model_route_decision: { route_id: "route.local-first", selected_model: "model.local" },
    },
  }), {
    route_id: "route.local-first",
    selected_model: "model.local",
    receipt_id: "receipt-route",
    receipt_created_at: "2026-06-05T00:00:00.000Z",
    receipt_kind: "model_route_selection",
  });
  const projection = routeDecisionProjectionFromReceipt({
    id: "receipt-route",
    createdAt: "2026-06-05T00:00:00.000Z",
    kind: "model_route_selection",
    details: {
      model_route_decision: { route_id: "route.local-first", selected_model: "model.local" },
    },
  });
  assert.equal(Object.hasOwn(projection, "receiptId"), false);
  assert.equal(Object.hasOwn(projection, "receiptCreatedAt"), false);
  assert.equal(Object.hasOwn(projection, "receiptKind"), false);

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

test("provider request body ignores retired reasoning effort aliases", () => {
  const body = providerRequestBodyForRoute(
    {
      model: "qwen/qwen3.5-9b",
      reasoningEffort: "none",
      thinkingEffort: "none",
      messages: [{ role: "user", content: "answer directly" }],
    },
    { modelId: "qwen/qwen3.5-9b", providerId: "provider.llama-cpp", driver: "llama_cpp" },
  );

  assert.equal(body.reasoning_effort, undefined);
  assert.equal(body.chat_template_kwargs, undefined);
  assert.equal(body.reasoningEffort, undefined);
  assert.equal(body.thinkingEffort, undefined);
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

test("provider request body ignores retired modelPolicy reasoning alias", () => {
  const body = providerRequestBodyForRoute(
    {
      model: "qwen/qwen3.5-9b",
      modelPolicy: { reasoning_effort: "none" },
      messages: [{ role: "user", content: "answer directly" }],
    },
    { modelId: "qwen/qwen3.5-9b", providerId: "provider.llama-cpp", driver: "llama_cpp" },
  );

  assert.equal(body.reasoning_effort, undefined);
  assert.equal(body.chat_template_kwargs, undefined);
  assert.equal(body.modelPolicy, undefined);
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
