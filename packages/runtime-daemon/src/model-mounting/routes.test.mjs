import assert from "node:assert/strict";
import test from "node:test";

import {
  endpointIdsForExplicitModel,
  endpointIdsForExplicitModelForState,
  modelMountRouteDecisionRequestForSelection,
  routeSelectionReceipt,
  routeSelectionReceiptForState,
  selectRoute,
  selectRouteForState,
  testRoute,
  upsertRoute,
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

function admitModelMountRouteDecision(request) {
  return {
    source: "rust_model_mount_mock",
    backend: "rust_model_mount_live",
    record: {
      ...request,
      route_decision_ref: "model_mount://route_decision/test",
      route_decision_hash: "sha256:test",
    },
    route_decision_ref: "model_mount://route_decision/test",
    route_decision_hash: "sha256:test",
    receipt_refs: request.receipt_refs,
    evidence_refs: ["rust_model_mount_core", "model_mount://route_decision/test"],
  };
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

test("model mounting route helpers ignore retired hosted fallback policy alias", () => {
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
  const base = {
    endpoint: (id) => endpoints.get(id),
    endpointIdsForExplicitModel: () => [],
    isAutoModelSelector: () => true,
    isFixtureEndpointCandidate: () => false,
    modelId: "auto",
    provider: (id) => providers.get(id),
    route: (id) => routes.get(id),
    routes,
    runtimeError,
    truthy: Boolean,
  };

  assert.equal(selectRoute({ ...base, policy: { allow_hosted_fallback: true } }).endpoint.id, "endpoint.hosted");
  assert.equal(selectRoute({ ...base, policy: { allowHostedFallback: true } }).endpoint.id, "endpoint.local");
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
    admitModelMountRouteDecision,
    nextReceiptId: () => "receipt-route",
    previousResponseId: "resp-0",
    receipt: (kind, payload) => {
      const record = { id: payload.id ?? "receipt-route", kind, ...payload };
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
  assert.equal(receipt.id, "receipt-route");
  assert.equal(created[0].details.model_route_decision_schema_version, "v1");
  assert.equal(created[0].details.model_route_decision_event_kind, "model_route_decision");
  assert.equal(created[0].details.model_route_decision_id, "decision-1");
  assert.equal(created[0].details.model_route_decision.decisionId, "decision-1");
  assert.equal(created[0].details.model_mount_route_decision_ref, "model_mount://route_decision/test");
  assert.equal(created[0].details.model_mount_route_decision_hash, "sha256:test");
  assert.equal(created[0].details.model_mount_route_decision.route_ref, "route.local-first");
  assert.deepEqual(created[0].details.model_mount_route_decision_receipt_refs, ["receipt://receipt-route"]);
  assert.equal(Object.hasOwn(created[0].details, "modelRouteDecisionSchemaVersion"), false);
  assert.equal(Object.hasOwn(created[0].details, "modelRouteDecisionEventKind"), false);
  assert.equal(Object.hasOwn(created[0].details, "modelRouteDecisionId"), false);
  assert.equal(Object.hasOwn(created[0].details, "modelRouteDecision"), false);
  assert.equal(Object.hasOwn(created[0].details, "modelMountRouteDecisionRef"), false);
  assert.equal(Object.hasOwn(created[0].details, "modelMountRouteDecision"), false);
  assert.equal(created[0].details.workflowNodeId, "node-1");
  assert.deepEqual(created[0].evidenceRefs, [
    "model_router",
    "rust_model_mount_core",
    "route.local-first",
    "endpoint.local",
    "model_mount://route_decision/test",
    "extra",
  ]);
});

test("model mounting route receipt fails closed without Rust admission", () => {
  const error = captureError(() =>
    routeSelectionReceipt({
      body: { model: "auto" },
      capability: "chat",
      nextReceiptId: () => "receipt-route",
      receipt: () => ({ id: "receipt-route" }),
      routeDecision: {
        MODEL_ROUTE_DECISION_SCHEMA_VERSION: "v1",
        MODEL_ROUTE_DECISION_EVENT_KIND: "model_route_decision",
        workflowContextFromRouteRequest: () => ({}),
        createModelRouteDecision: () => ({ decisionId: "decision-1" }),
      },
      selection: {
        route: { id: "route.local-first" },
        endpoint: { id: "endpoint.local", modelId: "model.local", providerId: "provider.local" },
        provider: { id: "provider.local" },
      },
      stableHash: () => "policy-hash",
    }),
  );

  assert.equal(error.code, "model_mount_route_decision_admission_required");
});

test("model mounting route receipt requires a precomputed receipt id", () => {
  const error = captureError(() =>
    routeSelectionReceipt({
      body: { model: "auto" },
      capability: "chat",
      admitModelMountRouteDecision,
      receipt: () => ({ id: "receipt-route" }),
      routeDecision: {
        MODEL_ROUTE_DECISION_SCHEMA_VERSION: "v1",
        MODEL_ROUTE_DECISION_EVENT_KIND: "model_route_decision",
        workflowContextFromRouteRequest: () => ({}),
        createModelRouteDecision: () => ({ decisionId: "decision-1" }),
      },
      selection: {
        route: { id: "route.local-first" },
        endpoint: { id: "endpoint.local", modelId: "model.local", providerId: "provider.local" },
        provider: { id: "provider.local" },
      },
      stableHash: () => "policy-hash",
    }),
  );

  assert.equal(error.code, "model_mount_route_decision_receipt_id_required");
});

test("model mounting route request resolves auto before Rust admission", () => {
  const request = modelMountRouteDecisionRequestForSelection({
    body: {
      model: "auto",
      authority_grant_refs: ["grant://model-route"],
      custody_ref: "ctee://custody/private-workspace",
      privacy_profile: "private_workspace_ctee",
    },
    capability: "chat",
    modelRouteDecision: { decisionId: "decision-1" },
    policy: { privacy: "private_workspace_ctee" },
    policyHash: "policy-hash",
    receiptId: "receipt-route",
    selection: {
      route: { id: "route.local-first" },
      endpoint: { id: "endpoint.local", modelId: "model.local", providerId: "provider.local" },
      provider: { id: "provider.local", privacyClass: "local_private" },
    },
    workflow: { workflowGraphId: "graph-1", workflowNodeId: "node-1" },
  });

  assert.equal(request.schema_version, "ioi.model_mount.route_decision.v1");
  assert.equal(request.model_ref, "model.local");
  assert.equal(request.policy_hash, "sha256:policy-hash");
  assert.deepEqual(request.receipt_refs, ["receipt://receipt-route"]);
  assert.deepEqual(request.authority_grant_refs, ["grant://model-route"]);
  assert.equal(request.custody_ref, "ctee://custody/private-workspace");
  assert.equal(request.privacy_profile, "private_workspace_ctee");
  assert.equal(request.node_plaintext_allowed, false);
  assert.equal(request.workflow_graph_ref, "graph-1");
  assert.equal(request.workflow_node_ref, "node-1");
});

test("model mounting route state operations preserve delegate wiring", () => {
  const writes = [];
  const receipts = [];
  const state = {
    routes: new Map(),
    endpoints: new Map([["endpoint.local", {
      id: "endpoint.local",
      modelId: "model.local",
      providerId: "provider.local",
      capabilities: ["chat"],
      status: "mounted",
    }]]),
    providers: new Map([["provider.local", {
      id: "provider.local",
      kind: "local_folder",
      privacyClass: "local_private",
    }]]),
    endpoint(endpointId) {
      return this.endpoints.get(endpointId);
    },
    endpointIdsForExplicitModel(route, modelId) {
      return endpointIdsForExplicitModelForState(this, route, modelId, { normalizeScopes });
    },
    mountEndpoint(body) {
      const endpoint = { id: `endpoint.${body.model_id}`, modelId: body.model_id, providerId: "provider.local", capabilities: ["chat"], status: "mounted" };
      this.endpoints.set(endpoint.id, endpoint);
      return endpoint;
    },
    admitModelMountRouteDecision: admitModelMountRouteDecision,
    nextReceiptId: () => "receipt-route",
    provider(providerId) {
      return this.providers.get(providerId);
    },
    receipt(kind, payload) {
      const record = { id: `receipt-${kind}`, kind, ...payload };
      receipts.push(record);
      return record;
    },
    route(routeId) {
      return this.routes.get(routeId);
    },
    writeMap(dir, map) {
      writes.push({ dir, map });
    },
  };

  const route = upsertRoute(state, {
    role: "Review",
    fallback: ["endpoint.local"],
  }, { normalizeScopes, safeId });
  assert.equal(route.id, "route.review");
  assert.equal(state.routes.get(route.id), route);
  assert.equal(writes.at(-1).dir, "model-routes");
  assert.deepEqual(endpointIdsForExplicitModelForState(state, route, "missing-model", { normalizeScopes }), ["endpoint.missing-model"]);

  const selection = selectRouteForState(state, {
    modelId: "auto",
    routeId: route.id,
    capability: "chat",
    policy: {},
  }, {
    isAutoModelSelector: () => true,
    isFixtureEndpointCandidate: () => false,
    runtimeError,
    truthy: Boolean,
  });
  assert.equal(selection.endpoint.id, "endpoint.local");
  assert.equal(selection.evaluatedCandidates.at(-1).reason, "policy_allowed");

  const receipt = routeSelectionReceiptForState(state, selection, {
    body: { model: "auto" },
    capability: "chat",
  }, {
    routeDecision: {
      MODEL_ROUTE_DECISION_SCHEMA_VERSION: "v1",
      MODEL_ROUTE_DECISION_EVENT_KIND: "model_route_decision",
      workflowContextFromRouteRequest: () => ({}),
      createModelRouteDecision: () => ({ decisionId: "decision-1" }),
    },
    stableHash: () => "policy-hash",
  });
  assert.equal(receipt.kind, "model_route_selection");
  assert.equal(receipts.at(-1).details.model_route_decision_id, "decision-1");
  assert.equal(Object.hasOwn(receipts.at(-1).details, "modelRouteDecisionId"), false);
  assert.equal(receipts.at(-1).details.model_mount_route_decision_ref, "model_mount://route_decision/test");
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
