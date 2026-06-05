import assert from "node:assert/strict";
import test from "node:test";

import {
  MODEL_ROUTE_DECISION_EVENT_KIND,
  MODEL_ROUTE_DECISION_SCHEMA_VERSION,
  createModelRouteDecision,
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

test("route decisions use canonical hosted fallback policy constraint", () => {
  const decision = createModelRouteDecision({
    route: {
      id: "route.local-first",
      privacy: "local_or_enterprise",
      fallback: ["endpoint.local"],
      providerEligibility: ["provider.hosted"],
      deniedProviders: ["provider.blocked"],
      maxLatencyMs: 8000,
    },
    endpoint: { id: "endpoint.hosted", modelId: "model.hosted", providerId: "provider.hosted" },
    provider: { id: "provider.hosted", kind: "openai", privacyClass: "hosted" },
    policy: { allow_hosted_fallback: true, max_cost_usd: 0.5 },
    policyHash: "sha256:policy",
    requestedModel: "auto",
  });

  assert.equal(decision.policy_constraints.route_privacy, "local_or_enterprise");
  assert.equal(decision.policy_constraints.requested_privacy, null);
  assert.deepEqual(decision.policy_constraints.provider_eligibility, ["provider.hosted"]);
  assert.deepEqual(decision.policy_constraints.denied_providers, ["provider.blocked"]);
  assert.equal(decision.policy_constraints.max_cost_usd, 0.5);
  assert.equal(decision.policy_constraints.max_latency_ms, 8000);
  assert.equal(decision.policy_constraints.allow_hosted_fallback, true);
  assert.equal(decision.policy_constraints.local_only, false);
  assert.equal(Object.hasOwn(decision, "policyConstraints"), false);
  assert.equal(Object.hasOwn(decision.policy_constraints, "routePrivacy"), false);
  assert.equal(Object.hasOwn(decision.policy_constraints, "requestedPrivacy"), false);
  assert.equal(Object.hasOwn(decision.policy_constraints, "providerEligibility"), false);
  assert.equal(Object.hasOwn(decision.policy_constraints, "deniedProviders"), false);
  assert.equal(Object.hasOwn(decision.policy_constraints, "maxCostUsd"), false);
  assert.equal(Object.hasOwn(decision.policy_constraints, "maxLatencyMs"), false);
  assert.equal(Object.hasOwn(decision.policy_constraints, "allowHostedFallback"), false);
  assert.equal(Object.hasOwn(decision.policy_constraints, "localOnly"), false);
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
    workflow: {
      workflowGraphId: "graph-1",
      workflowNodeId: "node-1",
      workflowNodeType: "model-router",
    },
    evaluatedCandidates: [
      { status: "accepted", endpointId: "endpoint.hosted", providerId: "provider.hosted", reason: null },
      { status: "rejected", endpointId: "endpoint.local", providerId: "provider.local", reason: "privacy_mismatch" },
    ],
  });

  assert.equal(decision.schema_version, MODEL_ROUTE_DECISION_SCHEMA_VERSION);
  assert.equal(decision.event_kind, MODEL_ROUTE_DECISION_EVENT_KIND);
  assert.equal(typeof decision.decision_id, "string");
  assert.equal(Object.hasOwn(decision, "schemaVersion"), false);
  assert.equal(Object.hasOwn(decision, "eventKind"), false);
  assert.equal(Object.hasOwn(decision, "decisionId"), false);
  assert.equal(decision.route_id, "route.local-first");
  assert.equal(decision.requested_model, "auto");
  assert.equal(decision.requested_model_mode, "auto");
  assert.equal(decision.auto_resolved, true);
  assert.equal(decision.selected_model, "model.hosted");
  assert.equal(decision.upstream_model, "model.hosted");
  assert.equal(decision.never_send_auto_upstream, true);
  assert.equal(decision.endpoint_id, "endpoint.hosted");
  assert.equal(decision.provider_id, "provider.hosted");
  assert.equal(decision.provider_kind, "openai");
  assert.equal(decision.reasoning_effort, "provider_default");
  assert.equal(decision.local_remote_placement, "remote");
  assert.equal(decision.privacy_posture, "local_or_enterprise");
  assert.equal(decision.cost_estimate_usd, 0.01);
  assert.equal(decision.cost_estimate_source, "hosted_default");
  assert.equal(decision.fallback_model, null);
  assert.equal(decision.fallback_endpoint_id, "endpoint.local");
  assert.equal(Object.hasOwn(decision, "routeId"), false);
  assert.equal(Object.hasOwn(decision, "requestedModel"), false);
  assert.equal(Object.hasOwn(decision, "requestedModelMode"), false);
  assert.equal(Object.hasOwn(decision, "autoResolved"), false);
  assert.equal(Object.hasOwn(decision, "selectedModel"), false);
  assert.equal(Object.hasOwn(decision, "upstreamModel"), false);
  assert.equal(Object.hasOwn(decision, "neverSendAutoUpstream"), false);
  assert.equal(Object.hasOwn(decision, "endpointId"), false);
  assert.equal(Object.hasOwn(decision, "providerId"), false);
  assert.equal(Object.hasOwn(decision, "providerKind"), false);
  assert.equal(Object.hasOwn(decision, "reasoningEffort"), false);
  assert.equal(Object.hasOwn(decision, "localRemotePlacement"), false);
  assert.equal(Object.hasOwn(decision, "privacyPosture"), false);
  assert.equal(Object.hasOwn(decision, "costEstimateUsd"), false);
  assert.equal(Object.hasOwn(decision, "costEstimateSource"), false);
  assert.equal(Object.hasOwn(decision, "fallbackModel"), false);
  assert.equal(Object.hasOwn(decision, "fallbackEndpointId"), false);
  assert.equal(decision.response_id, "resp-1");
  assert.equal(decision.previous_response_id, "resp-0");
  assert.equal(Object.hasOwn(decision, "responseId"), false);
  assert.equal(Object.hasOwn(decision, "previousResponseId"), false);
  assert.equal(decision.workflow_graph_id, "graph-1");
  assert.equal(decision.workflow_node_id, "node-1");
  assert.equal(decision.workflow_node_type, "model-router");
  assert.equal(Object.hasOwn(decision, "workflowGraphId"), false);
  assert.equal(Object.hasOwn(decision, "workflowNodeId"), false);
  assert.equal(Object.hasOwn(decision, "workflowNodeType"), false);
  assert.equal(decision.policy_hash, "sha256:policy");
  assert.equal(Object.hasOwn(decision, "policyHash"), false);
  assert.equal(decision.fallback_allowed, true);
  assert.equal(decision.fallback_triggered, true);
  assert.equal(decision.fallback_reason, "primary_route_unavailable");
  assert.equal(decision.evaluated_candidate_count, 2);
  assert.equal(decision.rejected_candidates.length, 1);
  assert.equal(decision.rejected_candidates[0].endpoint_id, "endpoint.local");
  assert.equal(decision.rejected_candidates[0].provider_id, "provider.local");
  assert.equal(decision.rejected_candidates[0].reason, "privacy_mismatch");
  assert.equal(Object.hasOwn(decision, "fallbackAllowed"), false);
  assert.equal(Object.hasOwn(decision, "fallbackTriggered"), false);
  assert.equal(Object.hasOwn(decision, "fallbackReason"), false);
  assert.equal(Object.hasOwn(decision, "evaluatedCandidateCount"), false);
  assert.equal(Object.hasOwn(decision, "rejectedCandidates"), false);
  assert.equal(decision.evidence_refs.includes("model_route_fallback_selected"), true);
  assert.equal(Object.hasOwn(decision, "evidenceRefs"), false);
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
  assert.equal(decision.evidence_refs.includes("model_route_fallback_selected"), false);
  assert.equal(Object.hasOwn(decision, "evidenceRefs"), false);
  assert.doesNotMatch(decision.rationale, /legacy_route_unavailable/);
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
    workflowGraphId: "graph-1",
    workflowNodeId: "node-1",
    workflowNodeType: "model-router",
  });
  assert.deepEqual(workflowContextFromRouteRequest({
    workflowGraphId: "graph-legacy",
    workflowNodeId: "node-legacy",
    node_id: "node-snake-legacy",
    nodeId: "node-camel-legacy",
    workflowNodeType: "type-legacy",
    node: "node-type-legacy",
  }), {
    workflowGraphId: null,
    workflowNodeId: null,
    workflowNodeType: null,
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
