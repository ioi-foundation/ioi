import assert from "node:assert/strict";
import test from "node:test";

import { ModelMountingState } from "../model-mounting.mjs";
import {
  assertCanonicalRouteSelectionRequest,
  testRoute,
  throwModelRouteSelectionRustCoreRequired,
  upsertRoute,
} from "./routes.mjs";

function captureError(fn) {
  try {
    fn();
  } catch (error) {
    return error;
  }
  throw new Error("Expected function to throw.");
}

function routeControlRequiredForTest(requests = []) {
  return (operationKind, details = {}) => {
    const request = {
      schema_version: "ioi.model_mount.route_control_required.v1",
      operation: "model_mount.route_control",
      operation_kind: operationKind,
      source: "runtime-daemon.model_mounting.route_control",
      evidence_refs: [
        "model_mount_route_control_js_facade_retired",
        "rust_daemon_core_route_control_required",
        "agentgres_route_truth_required",
      ],
      details,
    };
    requests.push(request);
    const recordDetails = {
      operation: request.operation,
      ...details,
      operation_kind: operationKind,
      rust_core_boundary: "model_mount.route_control",
      source: request.source,
      evidence_refs: request.evidence_refs,
    };
    return {
      source: "rust_model_mount_route_control_required_command",
      backend: "rust_model_mount_route_control_required",
      status: "rust_core_required",
      status_code: 501,
      code: "model_mount_route_control_rust_core_required",
      message: "Model route control requires Rust daemon-core ownership.",
      rust_core_boundary: "model_mount.route_control",
      operation: request.operation,
      operation_kind: operationKind,
      details: recordDetails,
      evidence_refs: request.evidence_refs,
      record: {
        schema_version: "ioi.model_mount.route_control_required_result.v1",
        object: "ioi.model_mount_route_control_required",
        status: "rust_core_required",
        status_code: 501,
        code: "model_mount_route_control_rust_core_required",
        message: "Model route control requires Rust daemon-core ownership.",
        rust_core_boundary: "model_mount.route_control",
        operation: request.operation,
        operation_kind: operationKind,
        source: request.source,
        evidence_refs: request.evidence_refs,
        details: recordDetails,
        generated_at: "rust_model_mount_core",
      },
    };
  };
}

test("model mounting route upsert rejects retired request aliases before Rust-required boundary", () => {
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

test("model mounting route upsert fails closed without JS route-record normalization", () => {
  const calls = [];
  const routes = new Map();
  const routeControlRequiredRequests = [];
  const error = captureError(() =>
    upsertRoute(
      {
        routes,
        routeControlRequired: routeControlRequiredForTest(routeControlRequiredRequests),
        writeMap(...args) {
          calls.push(["writeMap", ...args]);
        },
      },
      {
        role: "Research Route",
        fallback: ["endpoint.local"],
        provider_eligibility: ["local_folder"],
      },
      {
        normalizeScopes(...args) {
          calls.push(["normalizeScopes", ...args]);
          return [];
        },
        safeId(...args) {
          calls.push(["safeId", ...args]);
          return "route.research-route";
        },
      },
    ),
  );

  assert.equal(error.status, 501);
  assert.equal(error.code, "model_mount_route_control_rust_core_required");
  assert.equal(error.details.rust_core_boundary, "model_mount.route_control");
  assert.equal(error.details.operation_kind, "model_mount.route.write");
  assert.equal(error.details.route_id, "route:Research Route");
  assert.deepEqual(calls, []);
  assert.equal(routes.size, 0);
  assert.equal(routeControlRequiredRequests.length, 1);
  assert.equal(routeControlRequiredRequests[0].operation_kind, "model_mount.route.write");
  assert.equal(routeControlRequiredRequests[0].details.route_id, "route:Research Route");
});

test("model mounting route selection rejects retired request aliases before Rust boundary", () => {
  const error = captureError(() =>
    assertCanonicalRouteSelectionRequest({
      modelId: "model.local",
      modelPolicy: { privacy: "local_only" },
      workflowGraphId: "graph-1",
      workflowNodeId: "node-1",
      nodeId: "node-alias",
      node_id: "node-snake-alias",
      workflowNodeType: "Model Router",
      authorityGrantRefs: ["grant://model-route"],
      authorityReceiptRefs: ["receipt://wallet/model-route"],
      custodyRef: "ctee://custody/private-workspace",
      privacyProfile: "private_workspace_ctee",
      nodePlaintextAllowed: true,
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
    "authorityGrantRefs",
    "authorityReceiptRefs",
    "custodyRef",
    "privacyProfile",
    "nodePlaintextAllowed",
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
  assert.equal(Object.hasOwn(error.details, "privacyProfile"), false);
});

test("mounted route selection facades fail closed before JS endpoint policy evaluation", () => {
  const calls = [];
  const routeControlRequiredRequests = [];
  const state = {
    routeControlRequired: routeControlRequiredForTest(routeControlRequiredRequests),
    routes: new Map([["route.local-first", { id: "route.local-first" }]]),
    endpoints: new Map([["endpoint.local", { id: "endpoint.local" }]]),
    providers: new Map([["provider.local", { id: "provider.local" }]]),
    route(routeId) {
      calls.push(["route", routeId]);
      return this.routes.get(routeId);
    },
    endpoint(endpointId) {
      calls.push(["endpoint", endpointId]);
      return this.endpoints.get(endpointId);
    },
    provider(providerId) {
      calls.push(["provider", providerId]);
      return this.providers.get(providerId);
    },
    mountEndpoint(body) {
      calls.push(["mountEndpoint", body]);
      return { id: "endpoint.created" };
    },
  };

  const selectError = captureError(() =>
    ModelMountingState.prototype.selectRoute.call(state, {
      modelId: "auto",
      routeId: "route.local-first",
      capability: "chat",
      policy: { allow_hosted_fallback: true },
    }),
  );
  assert.equal(selectError.status, 501);
  assert.equal(selectError.code, "model_mount_route_control_rust_core_required");
  assert.equal(selectError.details.operation_kind, "model_mount.route.select");
  assert.equal(selectError.details.model_id, "auto");
  assert.equal(selectError.details.route_id, "route.local-first");
  assert.equal(selectError.details.capability, "chat");
  assert.deepEqual(calls, []);
  assert.equal(routeControlRequiredRequests[0].operation_kind, "model_mount.route.select");
  assert.equal(routeControlRequiredRequests[0].details.route_id, "route.local-first");

  const explicitError = captureError(() =>
    ModelMountingState.prototype.endpointIdsForExplicitModel.call(
      state,
      { id: "route.local-first", fallback: ["endpoint.local"] },
      "model.local",
    ),
  );
  assert.equal(explicitError.status, 501);
  assert.equal(explicitError.code, "model_mount_route_control_rust_core_required");
  assert.equal(explicitError.details.operation_kind, "model_mount.route.explicit_model_endpoints");
  assert.equal(explicitError.details.model_id, "model.local");
  assert.deepEqual(calls, []);
  assert.equal(routeControlRequiredRequests[1].operation_kind, "model_mount.route.explicit_model_endpoints");
  assert.equal(routeControlRequiredRequests[1].details.model_id, "model.local");
});

test("model mounting public route control facades fail closed before selection, receipts, or state mutation", () => {
  const calls = [];
  const routeControlRequiredRequests = [];
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
    routeControlRequired: routeControlRequiredForTest(routeControlRequiredRequests),
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
    upsertRoute(state, { role: "Review", fallback: ["endpoint.local"] }),
  );
  assert.equal(upsertError.status, 501);
  assert.equal(upsertError.code, "model_mount_route_control_rust_core_required");
  assert.equal(upsertError.details.rust_core_boundary, "model_mount.route_control");
  assert.equal(upsertError.details.operation_kind, "model_mount.route.write");
  assert.equal(upsertError.details.route_id, "route:Review");

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
  assert.equal(routeControlRequiredRequests.length, 2);
  assert.equal(routeControlRequiredRequests[0].operation_kind, "model_mount.route.write");
  assert.equal(routeControlRequiredRequests[1].operation_kind, "model_mount.route.test");
});

test("model mounting route-selection receipt helper is retired behind Rust core", () => {
  const routeControlRequiredRequests = [];
  const error = captureError(() =>
    throwModelRouteSelectionRustCoreRequired(
      routeControlRequiredForTest(routeControlRequiredRequests)("model_mount.route.selection_update", {
        route_id: "route.local-first",
        selected_model: "model.local",
        receipt_id: "receipt-route-test",
        route_selection_boundary: "model_mount.route_selection",
      }),
    ),
  );

  assert.equal(error.status, 501);
  assert.equal(error.code, "model_mount_route_control_rust_core_required");
  assert.equal(error.details.rust_core_boundary, "model_mount.route_control");
  assert.equal(error.details.route_selection_boundary, "model_mount.route_selection");
  assert.equal(error.details.operation_kind, "model_mount.route.selection_update");
  assert.equal(error.details.route_id, "route.local-first");
  assert.equal(error.details.receipt_id, "receipt-route-test");
  assert.equal(error.details.selected_model, "model.local");
  assert.equal(Object.hasOwn(error.details, "routeId"), false);
  assert.equal(Object.hasOwn(error.details, "receiptId"), false);
  assert.equal(Object.hasOwn(error.details, "selectedModel"), false);
  assert.equal(routeControlRequiredRequests.length, 1);
  assert.equal(routeControlRequiredRequests[0].operation_kind, "model_mount.route.selection_update");
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
