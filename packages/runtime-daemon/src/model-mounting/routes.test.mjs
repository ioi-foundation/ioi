import assert from "node:assert/strict";
import test from "node:test";

import {
  endpointIdsForExplicitModel,
  routeSelectionReceipt,
  selectRoute,
  testRoute,
  upsertRouteRecord,
} from "./routes.mjs";

function normalizeScopes(value, fallback = []) {
  return Array.isArray(value) ? value : fallback;
}

function safeId(value) {
  return String(value).replace(/[^a-z0-9_.-]+/gi, "-").toLowerCase();
}

function runtimeError({ status, code, message, details }) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  error.details = details;
  return error;
}

function captureError(fn) {
  try {
    fn();
  } catch (error) {
    return error;
  }
  throw new Error("Expected function to throw.");
}

test("model mounting route helpers normalize route records", () => {
  assert.deepEqual(upsertRouteRecord({
    role: "Research Route",
    provider_eligibility: ["local_folder"],
    denied_providers: ["openai"],
    max_cost_usd: "0.5",
    max_latency_ms: "1500",
    last_selected_model: "local:auto",
    last_receipt_id: "receipt-1",
  }, { normalizeScopes, safeId }), {
    id: "route.research-route",
    role: "Research Route",
    description: "Operator-defined model route.",
    privacy: "local_or_enterprise",
    quality: "adaptive",
    maxCostUsd: 0.5,
    maxLatencyMs: 1500,
    providerEligibility: ["local_folder"],
    fallback: [],
    deniedProviders: ["openai"],
    status: "active",
    lastSelectedModel: "local:auto",
    lastReceiptId: "receipt-1",
  });
});

test("model mounting route helpers order explicit model endpoints by route fallback", () => {
  const endpoints = new Map([
    ["endpoint.b", { id: "endpoint.b", modelId: "model.local", status: "mounted" }],
    ["endpoint.a", { id: "endpoint.a", modelId: "model.local", status: "mounted" }],
    ["endpoint.c", { id: "endpoint.c", modelId: "model.other", status: "mounted" }],
  ]);

  assert.deepEqual(endpointIdsForExplicitModel({
    endpoints,
    modelId: "model.local",
    mountEndpoint: () => ({ id: "mounted.new" }),
    normalizeScopes,
    route: { fallback: ["endpoint.a"] },
  }), ["endpoint.a", "endpoint.b"]);
});

test("model mounting route helpers mount explicit models with no existing endpoint", () => {
  const mounted = [];

  assert.deepEqual(endpointIdsForExplicitModel({
    endpoints: new Map(),
    modelId: "model.new",
    mountEndpoint: (body) => {
      mounted.push(body);
      return { id: "endpoint.new" };
    },
    normalizeScopes,
    route: { fallback: [] },
  }), ["endpoint.new"]);
  assert.deepEqual(mounted, [{ model_id: "model.new" }]);
});

test("model mounting route helpers select policy-allowed endpoints after rejected candidates", () => {
  const routes = new Map([["route.local-first", {
    id: "route.local-first",
    fallback: ["endpoint.hosted", "endpoint.local"],
    deniedProviders: [],
    providerEligibility: [],
    privacy: "local_or_enterprise",
    maxCostUsd: 1,
  }]]);
  const endpoints = new Map([
    ["endpoint.hosted", {
      id: "endpoint.hosted",
      providerId: "provider.hosted",
      modelId: "model.hosted",
      capabilities: ["chat"],
    }],
    ["endpoint.local", {
      id: "endpoint.local",
      providerId: "provider.local",
      modelId: "model.local",
      capabilities: ["chat"],
    }],
  ]);
  const providers = new Map([
    ["provider.hosted", { id: "provider.hosted", kind: "openai", privacyClass: "hosted" }],
    ["provider.local", { id: "provider.local", kind: "local_folder", privacyClass: "local_private" }],
  ]);

  const selection = selectRoute({
    endpoint: (id) => endpoints.get(id),
    endpointIdsForExplicitModel: () => [],
    isAutoModelSelector: () => true,
    isFixtureEndpointCandidate: () => false,
    modelId: "auto",
    policy: {},
    provider: (id) => providers.get(id),
    route: (id) => routes.get(id),
    routes,
    runtimeError,
    truthy: Boolean,
  });

  assert.equal(selection.endpoint.id, "endpoint.local");
  assert.deepEqual(selection.evaluatedCandidates.map((candidate) => candidate.reason), [
    "hosted_fallback_not_allowed",
    "policy_allowed",
  ]);
});

test("model mounting route helpers report blocker details when no endpoint satisfies policy", () => {
  const routes = new Map([["route.local-first", {
    id: "route.local-first",
    fallback: ["endpoint.local"],
    deniedProviders: [],
    providerEligibility: ["ollama"],
    privacy: "local_or_enterprise",
    maxCostUsd: 1,
  }]]);
  const endpoints = new Map([["endpoint.local", {
    id: "endpoint.local",
    providerId: "provider.local",
    modelId: "model.local",
    capabilities: ["chat"],
  }]]);
  const providers = new Map([["provider.local", {
    id: "provider.local",
    kind: "local_folder",
    privacyClass: "local_private",
  }]]);

  const error = captureError(() => selectRoute({
    endpoint: (id) => endpoints.get(id),
    endpointIdsForExplicitModel: () => [],
    isAutoModelSelector: () => true,
    isFixtureEndpointCandidate: () => false,
    modelId: "auto",
    policy: {},
    provider: (id) => providers.get(id),
    route: (id) => routes.get(id),
    routes,
    runtimeError,
    truthy: Boolean,
  }));

  assert.equal(error.status, 424);
  assert.equal(error.details.evaluatedCandidates[0].reason, "provider_not_eligible_for_route");
});

test("model mounting route helpers preserve route-selection receipt metadata", () => {
  const created = [];
  const receipt = routeSelectionReceipt({
    body: {
      model: "model.local",
      model_policy: { privacy: "local_only" },
      workflow_node_id: "node-1",
    },
    capability: "chat",
    evidenceRefs: ["extra"],
    previousResponseId: "resp-0",
    receipt: (kind, payload) => {
      const record = { id: "receipt-route", kind, ...payload };
      created.push(record);
      return record;
    },
    responseId: "resp-1",
    routeDecision: {
      MODEL_ROUTE_DECISION_SCHEMA_VERSION: "v1",
      MODEL_ROUTE_DECISION_EVENT_KIND: "model_route_decision",
      workflowContextFromRouteRequest: () => ({ workflowNodeId: "node-1" }),
      createModelRouteDecision: ({ evaluatedCandidates }) => ({
        decisionId: "decision-1",
        evaluatedCandidates,
      }),
    },
    selection: {
      route: { id: "route.local-first" },
      endpoint: { id: "endpoint.local", modelId: "model.local", providerId: "provider.local" },
      provider: { id: "provider.local" },
      evaluatedCandidates: [{ endpointId: "endpoint.local", status: "selected" }],
    },
    stableHash: () => "policy-hash",
  });

  assert.equal(receipt.kind, "model_route_selection");
  assert.equal(created[0].details.modelRouteDecisionId, "decision-1");
  assert.equal(created[0].details.workflowNodeId, "node-1");
  assert.deepEqual(created[0].evidenceRefs, ["model_router", "route.local-first", "endpoint.local", "extra"]);
});

test("model mounting route helpers test routes through state compatibility methods", () => {
  const writes = [];
  const routes = new Map([["route.local-first", {
    id: "route.local-first",
    fallback: ["endpoint.local"],
    deniedProviders: [],
    providerEligibility: [],
    privacy: "local_or_enterprise",
    maxCostUsd: 1,
  }]]);
  const selection = {
    route: routes.get("route.local-first"),
    endpoint: { id: "endpoint.local", modelId: "model.local", providerId: "provider.local" },
    provider: { id: "provider.local" },
  };
  const receipt = { id: "receipt-route-test" };
  const state = {
    routes,
    route(routeId) {
      return routes.get(routeId);
    },
    selectRoute(input) {
      assert.deepEqual(input, {
        modelId: "model.local",
        routeId: "route.local-first",
        capability: "chat",
        policy: { privacy: "local_only" },
      });
      return selection;
    },
    routeSelectionReceipt(receiptSelection, payload) {
      assert.equal(receiptSelection, selection);
      assert.deepEqual(payload, {
        body: {
          model: "model.local",
          model_policy: { privacy: "local_only" },
          route_id: "route.local-first",
        },
        capability: "chat",
      });
      return receipt;
    },
    writeMap(dir, map) {
      writes.push({ dir, map });
    },
  };

  const result = testRoute(state, "route.local-first", {
    model: "model.local",
    model_policy: { privacy: "local_only" },
  });

  assert.equal(result.receipt, receipt);
  assert.equal(result.route.lastSelectedModel, "model.local");
  assert.equal(result.route.lastReceiptId, "receipt-route-test");
  assert.equal(routes.get("route.local-first"), result.route);
  assert.equal(writes.length, 1);
  assert.equal(writes[0].dir, "model-routes");
  assert.equal(writes[0].map, routes);
});
