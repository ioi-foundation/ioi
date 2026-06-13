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

function routeControlPlannerForTest(requests = []) {
  return (request) => {
    requests.push(request);
    const routeId = request.route_id ?? request.body?.id ?? `route:${request.body?.role ?? "default"}`;
    const endpoint = request.endpoints?.[0] ?? {
      id: "endpoint.local",
      providerId: "provider.local",
      modelId: request.body?.model ?? request.body?.model_id ?? "model.local",
    };
    const provider = request.providers?.[0] ?? { id: endpoint.providerId ?? "provider.local", kind: "local_folder" };
    const route = request.current_route ?? { id: routeId };
    const routeDecisionRef = `model_mount://route_decision/${routeId}`;
    let record;
    if (request.operation_kind === "model_mount.route.test") {
      record = {
        id: `route_test:${routeId}:test`,
        object: "ioi.model_mount_route_test",
        route_id: routeId,
        model: request.body?.model ?? null,
        receipt_refs: ["receipt://route-control/test"],
        evidence_refs: ["model_mount_route_control_rust_owned"],
      };
    } else if (request.operation_kind === "model_mount.route.select") {
      record = {
        id: `route_selection:${routeId}:test`,
        object: "ioi.model_mount_route_selection",
        route_id: routeId,
        selected_model: endpoint.modelId ?? endpoint.model_id,
        endpoint_id: endpoint.id,
        provider_id: provider.id,
        receipt_refs: ["receipt://route-control/select"],
        evidence_refs: ["model_mount_route_control_rust_owned"],
        route,
        endpoint,
        provider,
        route_decision: {
          route_decision_ref: routeDecisionRef,
          route_ref: routeId,
          endpoint_ref: endpoint.id,
          provider_ref: provider.id,
          model_ref: endpoint.modelId ?? endpoint.model_id,
        },
        accepted_receipt_record: {
          id: "receipt.route-selection",
          kind: "model_route_selection",
          details: {
            model_mount_route_decision_ref: routeDecisionRef,
            route_id: routeId,
            endpoint_id: endpoint.id,
            provider_id: provider.id,
            selected_model: endpoint.modelId ?? endpoint.model_id,
          },
        },
      };
    } else if (request.operation_kind === "model_mount.route.explicit_model_endpoints") {
      record = {
        id: `route_endpoint_resolution:${routeId}:test`,
        object: "ioi.model_mount_explicit_model_endpoints",
        route_id: routeId,
        model_id: request.body?.model_id,
        endpoint_ids: [endpoint.id],
        endpoints: [endpoint],
        receipt_refs: ["receipt://route-control/explicit-endpoints"],
        evidence_refs: ["model_mount_route_control_rust_owned"],
      };
    } else {
      record = {
        id: routeId,
        role: request.body?.role ?? "default",
        fallback: request.body?.fallback ?? [],
        providerEligibility: request.body?.provider_eligibility ?? [],
        maxCostUsd: request.body?.max_cost_usd ?? 0.25,
        maxLatencyMs: request.body?.max_latency_ms ?? 30000,
        receiptRefs: ["receipt://route-control/write"],
        routeControl: {
          rust_core_boundary: "model_mount.route_control",
          evidence_refs: ["model_mount_route_control_rust_owned"],
        },
      };
    }
    const recordDir = request.operation_kind === "model_mount.route.test"
      ? "model-route-tests"
      : request.operation_kind === "model_mount.route.select"
        ? "model-route-selections"
        : request.operation_kind === "model_mount.route.explicit_model_endpoints"
          ? "model-route-endpoint-resolutions"
          : "model-routes";
    return {
      source: "rust_model_mount_route_control_command",
      backend: "rust_model_mount_route_control",
      plan: {
        schema_version: "ioi.model_mount.route_control_plan.v1",
        object: "ioi.model_mount_route_control_plan",
        status: "planned",
        rust_core_boundary: "model_mount.route_control",
        operation_kind: request.operation_kind,
        source: request.source,
        record_dir: recordDir,
        record_id: record.id,
        record,
        receipt_refs: record.receipt_refs ?? record.receiptRefs,
        evidence_refs: ["model_mount_route_control_rust_owned", "rust_daemon_core_route_control_plan"],
        control_hash: `hash:${record.id}`,
      },
      record_dir: recordDir,
      record_id: record.id,
      record,
      operation_kind: request.operation_kind,
      rust_core_boundary: "model_mount.route_control",
      receipt_refs: record.receipt_refs ?? record.receiptRefs,
      evidence_refs: ["model_mount_route_control_rust_owned", "rust_daemon_core_route_control_plan"],
      control_hash: `hash:${record.id}`,
    };
  };
}

function recordStateCommitForTest(commits = []) {
  return (request) => {
    commits.push(request);
    return {
      record_id: request.record_id,
      object_ref: `agentgres://model-mounting/${request.record_dir}/${request.record_id}`,
      content_hash: `content:${request.record_id}`,
      admission_hash: `admission:${request.record_id}`,
      commit_hash: `commit:${request.record_id}`,
      written_record: request.record,
      storage_record: {
        object_ref: `agentgres://model-mounting/${request.record_dir}/${request.record_id}`,
        content_hash: `content:${request.record_id}`,
        admission: { admission_hash: `admission:${request.record_id}` },
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

test("model mounting route upsert commits Rust-planned route record without JS normalization", () => {
  const calls = [];
  const routes = new Map();
  const routeControlPlans = [];
  const recordStateCommits = [];
  const result = upsertRoute(
    {
      routes,
      nowIso: () => "2026-06-13T00:00:00.000Z",
      planRouteControl: routeControlPlannerForTest(routeControlPlans),
      commitRuntimeModelMountRecordState: recordStateCommitForTest(recordStateCommits),
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
  );

  assert.equal(result.status, "committed");
  assert.equal(result.operation_kind, "model_mount.route.write");
  assert.equal(result.rust_core_boundary, "model_mount.route_control");
  assert.equal(result.route.id, "route:Research Route");
  assert.equal(result.route.fallback[0], "endpoint.local");
  assert.deepEqual(calls, []);
  assert.equal(routes.get("route:Research Route").id, "route:Research Route");
  assert.equal(routeControlPlans.length, 1);
  assert.equal(routeControlPlans[0].operation_kind, "model_mount.route.write");
  assert.equal(routeControlPlans[0].body.role, "Research Route");
  assert.equal(recordStateCommits.length, 1);
  assert.equal(recordStateCommits[0].record_dir, "model-routes");
  assert.equal(recordStateCommits[0].record_id, "route:Research Route");
  assert.deepEqual(recordStateCommits[0].receipt_refs, ["receipt://route-control/write"]);
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

test("mounted route selection uses Rust planning and Agentgres commits before JS endpoint policy evaluation", () => {
  const calls = [];
  const routeControlPlans = [];
  const recordStateCommits = [];
  const receiptCommits = [];
  const endpoint = {
    id: "endpoint.local",
    providerId: "provider.local",
    modelId: "model.local",
    status: "mounted",
    capabilities: ["chat"],
  };
  const provider = {
    id: "provider.local",
    kind: "local_folder",
    capabilities: ["chat"],
  };
  const state = {
    nowIso: () => "2026-06-13T00:00:00.000Z",
    planRouteControl: routeControlPlannerForTest(routeControlPlans),
    commitRuntimeModelMountRecordState: recordStateCommitForTest(recordStateCommits),
    persistRustAuthoredReceipt(receipt) {
      receiptCommits.push(receipt);
      return { id: receipt.id, committed: true };
    },
    routes: new Map([["route.local-first", {
      id: "route.local-first",
      fallback: ["endpoint.local"],
      providerEligibility: ["local_folder"],
    }]]),
    endpoints: new Map([["endpoint.local", endpoint]]),
    providers: new Map([["provider.local", provider]]),
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

  const selection = ModelMountingState.prototype.selectRoute.call(state, {
    modelId: "model.local",
    routeId: "route.local-first",
    capability: "chat",
    policy: { privacy: "local_only" },
  });

  assert.equal(selection.route.id, "route.local-first");
  assert.equal(selection.endpoint.id, "endpoint.local");
  assert.equal(selection.provider.id, "provider.local");
  assert.equal(selection.route_decision.route_decision_ref, "model_mount://route_decision/route.local-first");
  assert.equal(selection.routeReceipt.kind, "model_route_selection");
  assert.equal(selection.route_control.record_dir, "model-route-selections");
  assert.equal(selection.route_control.commit.record_id, "route_selection:route.local-first:test");
  assert.equal(selection.route_control.receipt_commit.committed, true);

  const endpointIds = ModelMountingState.prototype.endpointIdsForExplicitModel.call(
    state,
    { id: "route.local-first", fallback: ["endpoint.local"] },
    "model.local",
  );
  assert.deepEqual(endpointIds, ["endpoint.local"]);
  assert.deepEqual(calls, []);
  assert.equal(routeControlPlans.length, 2);
  assert.equal(routeControlPlans[0].operation_kind, "model_mount.route.select");
  assert.equal(routeControlPlans[0].body.model, "model.local");
  assert.equal(routeControlPlans[0].body.model_policy.privacy, "local_only");
  assert.equal(routeControlPlans[0].current_route.id, "route.local-first");
  assert.deepEqual(routeControlPlans[0].endpoints, [endpoint]);
  assert.deepEqual(routeControlPlans[0].providers, [provider]);
  assert.equal(routeControlPlans[1].operation_kind, "model_mount.route.explicit_model_endpoints");
  assert.equal(routeControlPlans[1].body.model_id, "model.local");
  assert.deepEqual(recordStateCommits.map((commit) => commit.record_dir), [
    "model-route-selections",
    "model-route-endpoint-resolutions",
  ]);
  assert.equal(receiptCommits[0].id, "receipt.route-selection");
});

test("model mounting public route control uses Rust planning and Agentgres record commits", () => {
  const calls = [];
  const routeControlPlans = [];
  const recordStateCommits = [];
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
    nowIso: () => "2026-06-13T00:00:00.000Z",
    planRouteControl: routeControlPlannerForTest(routeControlPlans),
    commitRuntimeModelMountRecordState: recordStateCommitForTest(recordStateCommits),
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

  const upsertResult = upsertRoute(state, { role: "Review", fallback: ["endpoint.local"] });
  assert.equal(upsertResult.status, "committed");
  assert.equal(upsertResult.operation_kind, "model_mount.route.write");
  assert.equal(upsertResult.route.id, "route:Review");

  const testResult = testRoute(state, "route.local-first", {
    model: "model.local",
    model_policy: { privacy: "local_only" },
  });
  assert.equal(testResult.status, "committed");
  assert.equal(testResult.operation_kind, "model_mount.route.test");
  assert.equal(testResult.route_test.route_id, "route.local-first");
  assert.equal(testResult.route_test.model, "model.local");
  assert.deepEqual(calls, []);
  assert.equal(routes.has("route:Review"), true);
  assert.equal(routes.get("route.local-first").lastReceiptId, undefined);
  assert.equal(routeControlPlans.length, 2);
  assert.equal(routeControlPlans[0].operation_kind, "model_mount.route.write");
  assert.equal(routeControlPlans[1].operation_kind, "model_mount.route.test");
  assert.equal(recordStateCommits.length, 2);
  assert.deepEqual(recordStateCommits.map((commit) => commit.record_dir), [
    "model-routes",
    "model-route-tests",
  ]);
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
