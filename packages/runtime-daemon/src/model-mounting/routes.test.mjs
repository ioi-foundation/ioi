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
  persistModelRouteSelectionState,
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
  const receiptId = String(request.receipt_refs[0] ?? "receipt://receipt-route").replace(/^receipt:\/\//, "");
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
    accepted_receipt_record: {
      id: receiptId,
      runId: null,
      kind: "model_route_selection",
      summary: "Route route.local-first selected model.local.",
      redaction: "none",
      evidenceRefs: [
        "model_router",
        "rust_model_mount_core",
        "rust_daemon_core_model_route_selection_receipt",
        "route.local-first",
        "endpoint.local",
        "model_mount://route_decision/test",
      ],
      createdAt: "unix:1",
      details: {
        rust_daemon_core_receipt_author: "ModelMountCore.admit_route_decision",
        route_id: "route.local-first",
        selected_model: "model.local",
        endpoint_id: "endpoint.local",
        provider_id: "provider.local",
        capability: request.capability,
        policy_hash: request.policy_hash,
        response_id: null,
        previous_response_id: null,
        model_route_decision_schema_version: request.schema_version,
        model_route_decision_event_kind: "model_route_decision",
        model_route_decision_id: request.idempotency_key,
        model_route_decision: {
          decision_id: request.idempotency_key,
          route_id: "route.local-first",
          selected_model: "model.local",
        },
        model_mount_route_decision_schema_version: request.schema_version,
        model_mount_route_decision_ref: "model_mount://route_decision/test",
        model_mount_route_decision_hash: "sha256:test",
        model_mount_route_decision_source: "rust_model_mount_mock",
        model_mount_route_decision_backend: "rust_model_mount_live",
        model_mount_route_decision_receipt_refs: request.receipt_refs,
        model_mount_route_decision: {
          ...request,
          route_decision_ref: "model_mount://route_decision/test",
          route_decision_hash: "sha256:test",
        },
        workflow_graph_id: request.workflow_graph_ref ?? null,
        workflow_node_id: request.workflow_node_ref ?? null,
        workflow_node_type: null,
      },
      schemaVersion: "ioi.model-mounting.runtime.v1",
    },
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

test("model mounting route upsert rejects retired request aliases before state write", () => {
  const calls = [];
  const state = {
    routes: new Map(),
    writeMap(...args) {
      calls.push(["writeMap", ...args]);
    },
  };
  const error = captureError(() =>
    upsertRoute(
      state,
      {
        role: "Research Route",
        maxCostUsd: "0.5",
        maxLatencyMs: "1500",
        providerEligibility: ["local_folder"],
        deniedProviders: ["openai"],
        lastSelectedModel: "local:auto",
        lastReceiptId: "receipt-1",
      },
      {
        normalizeScopes(...args) {
          calls.push(["normalizeScopes", ...args]);
          return [];
        },
        safeId(...args) {
          calls.push(["safeId", ...args]);
          return "route";
        },
      },
    ),
  );

  assert.equal(error.status, 400);
  assert.equal(error.code, "model_mount_route_upsert_request_aliases_retired");
  assert.deepEqual(error.details.retired_aliases, [
    "maxCostUsd",
    "maxLatencyMs",
    "providerEligibility",
    "deniedProviders",
    "lastSelectedModel",
    "lastReceiptId",
  ]);
  assert.deepEqual(error.details.canonical_fields, [
    "max_cost_usd",
    "max_latency_ms",
    "provider_eligibility",
    "denied_providers",
    "last_selected_model",
    "last_receipt_id",
  ]);
  assert.equal(Object.hasOwn(error.details, "maxCostUsd"), false);
  assert.equal(Object.hasOwn(error.details, "providerEligibility"), false);
  assert.deepEqual(calls, []);
  assert.equal(state.routes.size, 0);
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
    model_id: "auto",
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
    model_id: "auto",
    provider: (id) => providers.get(id),
    route: (id) => routes.get(id),
    routes,
    runtimeError,
    truthy: Boolean,
  };

  assert.equal(selectRoute({ ...base, policy: { allow_hosted_fallback: true } }).endpoint.id, "endpoint.hosted");
  assert.equal(selectRoute({ ...base, policy: { allowHostedFallback: true } }).endpoint.id, "endpoint.local");
});

test("model mounting route helpers ignore retired cost and fixture-deny policy aliases", () => {
  const routes = new Map([["route.local-first", {
    id: "route.local-first",
    fallback: ["endpoint.fixture", "endpoint.hosted"],
    deniedProviders: [],
    providerEligibility: [],
    privacy: "hosted_allowed",
    maxCostUsd: 0.01,
  }]]);
  const endpoints = new Map([
    ["endpoint.fixture", {
      id: "endpoint.fixture",
      providerId: "provider.fixture",
      modelId: "model.fixture",
      capabilities: ["chat"],
      estimatedCostUsd: 0,
    }],
    ["endpoint.hosted", {
      id: "endpoint.hosted",
      providerId: "provider.hosted",
      modelId: "model.hosted",
      capabilities: ["chat"],
      estimatedCostUsd: 0.05,
    }],
  ]);
  const providers = new Map([
    ["provider.fixture", { id: "provider.fixture", kind: "local_folder", privacyClass: "local_private" }],
    ["provider.hosted", { id: "provider.hosted", kind: "openai", privacyClass: "hosted" }],
  ]);
  const base = {
    endpoint: (id) => endpoints.get(id),
    endpointIdsForExplicitModel: () => [],
    isAutoModelSelector: () => true,
    isFixtureEndpointCandidate: (endpoint) => endpoint.id === "endpoint.fixture",
    model_id: "auto",
    provider: (id) => providers.get(id),
    route: (id) => routes.get(id),
    routes,
    runtimeError,
    truthy: Boolean,
  };

  assert.equal(
    selectRoute({ ...base, policy: { deny_fixture_models: true, max_cost_usd: 0.1 } }).endpoint.id,
    "endpoint.hosted",
  );
  assert.equal(
    selectRoute({ ...base, policy: { denyFixtureModels: true, maxCostUsd: 0.1 } }).endpoint.id,
    "endpoint.fixture",
  );
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
    model_id: "auto",
    policy: {},
    provider: (id) => providers.get(id),
    route: (id) => routes.get(id),
    routes,
    runtimeError,
    truthy: Boolean,
  }));

  assert.equal(error.status, 424);
  assert.equal(error.details.route_id, "route.local-first");
  assert.equal(error.details.evaluated_candidates[0].reason, "provider_not_eligible_for_route");
  assert.equal(Object.hasOwn(error.details, "routeId"), false);
  assert.equal(Object.hasOwn(error.details, "evaluatedCandidates"), false);
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
    persistRustAuthoredReceipt: (record) => {
      created.push(record);
      return record;
    },
    responseId: "resp-1",
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
  assert.equal(created[0].details.rust_daemon_core_receipt_author, "ModelMountCore.admit_route_decision");
  assert.equal(created[0].details.model_route_decision_schema_version, "ioi.model_mount.route_decision.v1");
  assert.equal(created[0].details.model_route_decision_event_kind, "model_route_decision");
  assert.equal(created[0].details.model_route_decision_id, "model_route_decision:receipt-route");
  assert.equal(created[0].details.model_route_decision.decision_id, "model_route_decision:receipt-route");
  assert.equal(Object.hasOwn(created[0].details.model_route_decision, "decisionId"), false);
  assert.equal(created[0].details.route_id, "route.local-first");
  assert.equal(created[0].details.selected_model, "model.local");
  assert.equal(created[0].details.endpoint_id, "endpoint.local");
  assert.equal(created[0].details.provider_id, "provider.local");
  assert.equal(created[0].details.policy_hash, "sha256:policy-hash");
  assert.equal(created[0].details.model_mount_route_decision_ref, "model_mount://route_decision/test");
  assert.equal(created[0].details.model_mount_route_decision_hash, "sha256:test");
  assert.equal(created[0].details.model_mount_route_decision.route_ref, "route.local-first");
  assert.deepEqual(created[0].details.model_mount_route_decision_receipt_refs, ["receipt://receipt-route"]);
  assert.equal(Object.hasOwn(created[0].details, "modelRouteDecisionSchemaVersion"), false);
  assert.equal(Object.hasOwn(created[0].details, "modelRouteDecisionEventKind"), false);
  assert.equal(Object.hasOwn(created[0].details, "modelRouteDecisionId"), false);
  assert.equal(Object.hasOwn(created[0].details, "modelRouteDecision"), false);
  assert.equal(Object.hasOwn(created[0].details, "routeId"), false);
  assert.equal(Object.hasOwn(created[0].details, "selectedModel"), false);
  assert.equal(Object.hasOwn(created[0].details, "endpointId"), false);
  assert.equal(Object.hasOwn(created[0].details, "providerId"), false);
  assert.equal(Object.hasOwn(created[0].details, "policyHash"), false);
  assert.equal(Object.hasOwn(created[0].details, "responseId"), false);
  assert.equal(Object.hasOwn(created[0].details, "previousResponseId"), false);
  assert.equal(Object.hasOwn(created[0].details, "modelMountRouteDecisionRef"), false);
  assert.equal(Object.hasOwn(created[0].details, "modelMountRouteDecision"), false);
  assert.equal(created[0].details.workflow_node_id, "node-1");
  assert.equal(Object.hasOwn(created[0].details, "workflowNodeId"), false);
  assert.deepEqual(created[0].evidenceRefs, [
    "model_router",
    "rust_model_mount_core",
    "rust_daemon_core_model_route_selection_receipt",
    "route.local-first",
    "endpoint.local",
    "model_mount://route_decision/test",
  ]);
});

test("model mounting route receipt rejects retired request aliases before receipt allocation", () => {
  const calls = [];
  const error = captureError(() =>
    routeSelectionReceipt({
      body: {
        modelId: "model.local",
        modelPolicy: { privacy: "local_only" },
        workflowGraphId: "graph-1",
        workflowNodeId: "node-1",
        nodeId: "node-alias",
        node_id: "node-snake-alias",
        workflowNodeType: "Model Router",
      },
      nextReceiptId: () => {
        calls.push("nextReceiptId");
        return "receipt-route";
      },
      receipt: () => ({ id: "receipt-route" }),
    }),
  );

  assert.equal(error.status, 400);
  assert.equal(error.code, "model_mount_route_selection_request_aliases_retired");
  assert.deepEqual(error.details.retired_aliases, [
    "modelId",
    "modelPolicy",
    "workflowGraphId",
    "workflowNodeId",
    "nodeId",
    "node_id",
    "workflowNodeType",
  ]);
  assert.deepEqual(error.details.canonical_fields, [
    "model",
    "model_id",
    "model_policy",
    "workflow_graph_id",
    "workflow_node_id",
    "workflow_node_type",
    "authority_grant_refs",
    "authority_receipt_refs",
    "custody_ref",
    "privacy_profile",
    "node_plaintext_allowed",
  ]);
  assert.equal(Object.hasOwn(error.details, "modelId"), false);
  assert.equal(Object.hasOwn(error.details, "modelPolicy"), false);
  assert.deepEqual(calls, []);
});

test("model mounting route receipt rejects retired authority request aliases before receipt allocation", () => {
  const calls = [];
  const error = captureError(() =>
    routeSelectionReceipt({
      body: {
        authorityGrantRefs: ["grant://model-route"],
        authorityReceiptRefs: ["receipt://wallet/model-route"],
        custodyRef: "ctee://custody/private-workspace",
        privacyProfile: "private_workspace_ctee",
        nodePlaintextAllowed: true,
      },
      nextReceiptId: () => {
        calls.push("nextReceiptId");
        return "receipt-route";
      },
      receipt: () => ({ id: "receipt-route" }),
    }),
  );

  assert.equal(error.status, 400);
  assert.equal(error.code, "model_mount_route_selection_request_aliases_retired");
  assert.deepEqual(error.details.retired_aliases, [
    "authorityGrantRefs",
    "authorityReceiptRefs",
    "custodyRef",
    "privacyProfile",
    "nodePlaintextAllowed",
  ]);
  assert.equal(Object.hasOwn(error.details, "authorityGrantRefs"), false);
  assert.equal(Object.hasOwn(error.details, "privacyProfile"), false);
  assert.deepEqual(calls, []);
});

test("model mounting route receipt fails closed without Rust admission", () => {
  const error = captureError(() =>
    routeSelectionReceipt({
      body: { model: "auto" },
      capability: "chat",
      nextReceiptId: () => "receipt-route",
      receipt: () => ({ id: "receipt-route" }),
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

test("model mounting route receipt rejects Rust admission results without Rust-authored receipt record", () => {
  const error = captureError(() =>
    routeSelectionReceipt({
      body: { model: "auto" },
      capability: "chat",
      admitModelMountRouteDecision: (request) => {
        const { accepted_receipt_record, ...result } = admitModelMountRouteDecision(request);
        void accepted_receipt_record;
        return result;
      },
      nextReceiptId: () => "receipt-route",
      persistRustAuthoredReceipt: () => {
        throw new Error("must not persist");
      },
      selection: {
        route: { id: "route.local-first" },
        endpoint: { id: "endpoint.local", modelId: "model.local", providerId: "provider.local" },
        provider: { id: "provider.local" },
      },
      stableHash: () => "policy-hash",
    }),
  );

  assert.equal(error.code, "model_mount_route_selection_rust_receipt_required");
  assert.equal(error.details.missing, "accepted_receipt_record");
  assert.ok(error.details.evidence_refs.includes("rust_daemon_core_model_route_selection_receipt_required"));
});

test("model mounting route receipt requires a precomputed receipt id", () => {
  const error = captureError(() =>
    routeSelectionReceipt({
      body: { model: "auto" },
      capability: "chat",
      admitModelMountRouteDecision,
      receipt: () => ({ id: "receipt-route" }),
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
    policy: { privacy: "private_workspace_ctee" },
    policyHash: "policy-hash",
    receiptId: "receipt-route",
    selection: {
      route: { id: "route.local-first" },
      endpoint: { id: "endpoint.local", modelId: "model.local", providerId: "provider.local" },
      provider: { id: "provider.local", privacyClass: "local_private" },
    },
    workflow: { workflow_graph_id: "graph-1", workflow_node_id: "node-1" },
  });

  assert.equal(request.schema_version, "ioi.model_mount.route_decision.v1");
  assert.equal(request.idempotency_key, "model_route_decision:receipt-route");
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

test("model mounting route request rejects retired authority aliases before Rust admission request build", () => {
  const error = captureError(() =>
    modelMountRouteDecisionRequestForSelection({
      body: {
        authorityGrantRefs: ["grant://model-route"],
        authorityReceiptRefs: ["receipt://wallet/model-route"],
        custodyRef: "ctee://custody/private-workspace",
        privacyProfile: "private_workspace_ctee",
        nodePlaintextAllowed: true,
      },
    }),
  );

  assert.equal(error.status, 400);
  assert.equal(error.code, "model_mount_route_selection_request_aliases_retired");
  assert.deepEqual(error.details.retired_aliases, [
    "authorityGrantRefs",
    "authorityReceiptRefs",
    "custodyRef",
    "privacyProfile",
    "nodePlaintextAllowed",
  ]);
});

test("model mounting route request ignores retired policy privacy profile alias", () => {
  const request = modelMountRouteDecisionRequestForSelection({
    body: { model: "auto" },
    capability: "chat",
    policy: { privacyProfile: "private_workspace_ctee" },
    policyHash: "policy-hash",
    receiptId: "receipt-route",
    selection: {
      route: { id: "route.local-first", privacy: "local_or_enterprise" },
      endpoint: { id: "endpoint.local", modelId: "model.local", providerId: "provider.local" },
      provider: { id: "provider.local", privacyClass: "local_private" },
    },
    workflow: {},
  });

  assert.equal(request.privacy_profile, "local_or_enterprise");
  assert.equal(Object.hasOwn(request, "privacyProfile"), false);
});

test("model mounting route selection operations preserve delegate wiring without route state mutation", () => {
  const writes = [];
  const receipts = [];
  const route = {
    id: "route.review",
    role: "Review",
    fallback: ["endpoint.local"],
    deniedProviders: [],
    providerEligibility: [],
    privacy: "local_or_enterprise",
    maxCostUsd: 1,
  };
  const state = {
    routes: new Map([[route.id, route]]),
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
    persistRustAuthoredReceipt(record) {
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

  assert.deepEqual(endpointIdsForExplicitModelForState(state, route, "missing-model", { normalizeScopes }), ["endpoint.missing-model"]);

  const selection = selectRouteForState(state, {
    model_id: "auto",
    route_id: route.id,
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
    stableHash: () => "policy-hash",
  });
  assert.equal(receipt.kind, "model_route_selection");
  assert.equal(receipts.at(-1).details.model_route_decision_id, "model_route_decision:receipt-route");
  assert.equal(Object.hasOwn(receipts.at(-1).details, "modelRouteDecisionId"), false);
  assert.equal(receipts.at(-1).details.model_mount_route_decision_ref, "model_mount://route_decision/test");
});

test("model mounting public route control facades fail closed before selection, receipts, or state mutation", () => {
  const calls = [];
  const routes = new Map([["route.local-first", {
    id: "route.local-first",
    fallback: ["endpoint.local"],
    deniedProviders: [],
    providerEligibility: [],
    privacy: "local_or_enterprise",
    maxCostUsd: 1,
  }]]);
  const state = {
    routes,
    route(routeId) {
      calls.push(["route", routeId]);
      return routes.get(routeId);
    },
    selectRoute() {
      calls.push(["selectRoute"]);
    },
    routeSelectionReceipt() {
      calls.push(["routeSelectionReceipt"]);
    },
    receipt() {
      calls.push(["receipt"]);
    },
    writeMap(dir, map) {
      calls.push(["writeMap", dir, map]);
    },
  };

  const upsertError = captureError(() =>
    upsertRoute(state, { role: "Review", fallback: ["endpoint.local"] }, { normalizeScopes, safeId }),
  );
  assert.equal(upsertError.status, 501);
  assert.equal(upsertError.code, "model_mount_route_control_rust_core_required");
  assert.equal(upsertError.details.rust_core_boundary, "model_mount.route_control");
  assert.equal(upsertError.details.operation_kind, "model_mount.route.write");
  assert.equal(upsertError.details.route_id, "route.review");

  const testError = captureError(() =>
    testRoute(state, "route.local-first", {
      model: "model.local",
      model_policy: { privacy: "local_only" },
    }),
  );
  assert.equal(testError.status, 501);
  assert.equal(testError.code, "model_mount_route_control_rust_core_required");
  assert.equal(testError.details.operation_kind, "model_mount.route.test");
  assert.equal(testError.details.route_id, "route.local-first");
  assert.deepEqual(calls, []);
  assert.equal(routes.has("route.review"), false);
  assert.equal(routes.get("route.local-first").lastReceiptId, undefined);
});

test("model mounting route selection state persistence fails closed before JS route map mutation", () => {
  const routes = new Map([["route.local-first", {
    id: "route.local-first",
    fallback: ["endpoint.local"],
    deniedProviders: [],
    providerEligibility: [],
    privacy: "local_or_enterprise",
    maxCostUsd: 1,
  }]]);
  const state = {
    routes,
  };

  const error = captureError(() =>
    persistModelRouteSelectionState(
      state,
      routes.get("route.local-first"),
      "model.local",
      "receipt-route-test",
      "model_mount.route.invocation_selection",
    ),
  );

  assert.equal(error.status, 501);
  assert.equal(error.code, "model_mount_route_control_rust_core_required");
  assert.equal(error.details.rust_core_boundary, "model_mount.route_control");
  assert.equal(error.details.operation_kind, "model_mount.route.invocation_selection");
  assert.equal(error.details.route_id, "route.local-first");
  assert.equal(error.details.receipt_id, "receipt-route-test");
  assert.equal(error.details.selected_model, "model.local");
  assert.equal(Object.hasOwn(error.details, "routeId"), false);
  assert.equal(Object.hasOwn(error.details, "receiptId"), false);
  assert.equal(Object.hasOwn(error.details, "selectedModel"), false);
  assert.equal(routes.get("route.local-first").lastReceiptId, undefined);
});

test("model mounting route helpers test route rejects retired request aliases before route lookup", () => {
  const calls = [];
  const state = {
    route(routeId) {
      calls.push(["route", routeId]);
      return { id: routeId };
    },
    selectRoute() {
      calls.push(["selectRoute"]);
    },
    routeSelectionReceipt() {
      calls.push(["routeSelectionReceipt"]);
    },
  };

  const error = captureError(() =>
    testRoute(state, "route.local-first", {
      modelId: "model.local",
      modelPolicy: { privacy: "local_only" },
      workflowGraphId: "graph-1",
      workflowNodeId: "node-1",
      nodeId: "node-alias",
      node_id: "node-snake-alias",
      workflowNodeType: "Model Router",
    }),
  );

  assert.equal(error.status, 400);
  assert.equal(error.code, "model_mount_route_selection_request_aliases_retired");
  assert.deepEqual(error.details.retired_aliases, [
    "modelId",
    "modelPolicy",
    "workflowGraphId",
    "workflowNodeId",
    "nodeId",
    "node_id",
    "workflowNodeType",
  ]);
  assert.deepEqual(calls, []);
});
