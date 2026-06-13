import { commitModelMountRecordState } from "./record-state-commits.mjs";

const MODEL_MOUNT_ROUTE_CONTROL_SCHEMA_VERSION = "ioi.model_mount.route_control.v1";

const RETIRED_ROUTE_SELECTION_REQUEST_ALIASES = [
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
];

const CANONICAL_ROUTE_SELECTION_REQUEST_FIELDS = [
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
];

const RETIRED_ROUTE_UPSERT_REQUEST_ALIASES = [
  "maxCostUsd",
  "maxLatencyMs",
  "providerEligibility",
  "deniedProviders",
  "lastSelectedModel",
  "lastReceiptId",
];

const CANONICAL_ROUTE_UPSERT_REQUEST_FIELDS = [
  "max_cost_usd",
  "max_latency_ms",
  "provider_eligibility",
  "denied_providers",
  "last_selected_model",
  "last_receipt_id",
];

export function upsertRoute(state, body = {}, deps = {}) {
  void deps;
  assertCanonicalRouteUpsertRequestBody(body);
  const routeId = routeIdFromUpsertBody(body);
  const plan = routeControlPlanForState(state, "model_mount.route.write", {
    body,
    route_id: routeId,
    current_route: routeId ? state?.routes?.get?.(routeId) ?? null : null,
  });
  const commit = commitRouteControlPlan(state, plan, {
    unconfiguredCode: "model_mount_route_control_record_state_commit_unconfigured",
    unconfiguredMessage:
      "Model route control requires Rust Agentgres record-state commit before public route truth can return.",
  });
  if (plan.record_dir === "model-routes" && state?.routes?.set) {
    state.routes.set(plan.record_id, plan.record);
  }
  return routeControlResponse(plan, commit, { route: plan.record });
}

export function testRoute(state, routeId, body = {}) {
  assertCanonicalRouteSelectionRequestBody(body);
  const plan = routeControlPlanForState(state, "model_mount.route.test", {
    body,
    route_id: routeId,
    current_route: state?.routes?.get?.(routeId) ?? null,
  });
  const commit = commitRouteControlPlan(state, plan, {
    unconfiguredCode: "model_mount_route_test_record_state_commit_unconfigured",
    unconfiguredMessage:
      "Model route test requires Rust Agentgres record-state commit before public route-test truth can return.",
  });
  return routeControlResponse(plan, commit, { route_test: plan.record });
}

export function throwModelRouteSelectionRustCoreRequired(record = {}) {
  const details = record.details && typeof record.details === "object" && !Array.isArray(record.details)
    ? record.details
    : {};
  throwModelRouteControlRustCoreRequired({
    ...record,
    details: {
      ...details,
      route_selection_boundary: details.route_selection_boundary ?? "model_mount.route_selection",
    },
  });
}

export function assertCanonicalRouteSelectionRequest(body = {}) {
  assertCanonicalRouteSelectionRequestBody(body);
}

export function throwModelRouteControlRustCoreRequired(record = {}) {
  const details = record.details && typeof record.details === "object" && !Array.isArray(record.details)
    ? record.details
    : {};
  const evidenceRefs = Array.isArray(details.evidence_refs)
    ? details.evidence_refs
    : Array.isArray(record.evidence_refs)
      ? record.evidence_refs
      : [
          "model_mount_route_control_js_facade_retired",
          "rust_daemon_core_route_control_required",
          "agentgres_route_truth_required",
        ];
  const error = new Error(record.message ?? "Model route control requires Rust daemon-core ownership.");
  error.status = record.status_code ?? 501;
  error.code = record.code ?? "model_mount_route_control_rust_core_required";
  error.details = {
    ...details,
    rust_core_boundary: details.rust_core_boundary ?? record.rust_core_boundary ?? "model_mount.route_control",
    evidence_refs: evidenceRefs,
  };
  throw error;
}

export function routeControlRequiredForState(state, operation_kind, details = {}) {
  return state.routeControlRequired(operation_kind, details);
}

function routeControlPlanForState(state, operation_kind, { body = {}, route_id = null, current_route = null } = {}) {
  if (!state || typeof state.planRouteControl !== "function") {
    const error = new Error("Model route control requires Rust daemon-core route-control planning.");
    error.status = 500;
    error.code = "model_mount_route_control_planner_unconfigured";
    error.details = {
      operation_kind,
      route_id,
      rust_core_boundary: "model_mount.route_control",
    };
    throw error;
  }
  return state.planRouteControl({
    schema_version: MODEL_MOUNT_ROUTE_CONTROL_SCHEMA_VERSION,
    operation_kind,
    source: "runtime-daemon.model_mounting.route_control",
    route_id,
    generated_at: typeof state.nowIso === "function" ? state.nowIso() : null,
    body,
    current_route,
  });
}

export function commitRouteControlPlan(state, plan, options = {}) {
  return commitModelMountRecordState(state, {
    recordDir: plan.record_dir,
    record: plan.record,
    operation_kind: plan.operation_kind,
    receipt_refs: plan.receipt_refs,
    invalidCode: "model_mount_route_control_record_state_commit_invalid",
    ...options,
  });
}

function routeControlResponse(plan, commit, payload = {}) {
  return {
    object: "ioi.model_mount_route_control",
    status: "committed",
    operation_kind: plan.operation_kind,
    rust_core_boundary: plan.rust_core_boundary,
    record_dir: plan.record_dir,
    record_id: plan.record_id,
    record: plan.record,
    commit,
    receipt_refs: plan.receipt_refs,
    evidence_refs: plan.evidence_refs,
    control_hash: plan.control_hash,
    ...payload,
  };
}

function routeIdFromUpsertBody(body = {}) {
  if (typeof body.id === "string" && body.id.trim()) return body.id.trim();
  if (typeof body.role === "string" && body.role.trim()) return `route:${body.role.trim()}`;
  return null;
}

function assertCanonicalRouteSelectionRequestBody(body = {}) {
  const presentAliases = RETIRED_ROUTE_SELECTION_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (presentAliases.length === 0) return;
  const error = new Error("Model route-selection request uses retired compatibility aliases.");
  error.status = 400;
  error.code = "model_mount_route_selection_request_aliases_retired";
  error.details = {
    retired_aliases: presentAliases,
    canonical_fields: CANONICAL_ROUTE_SELECTION_REQUEST_FIELDS,
  };
  throw error;
}

function assertCanonicalRouteUpsertRequestBody(body = {}) {
  const presentAliases = RETIRED_ROUTE_UPSERT_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (presentAliases.length === 0) return;
  const error = new Error(
    "Model route upsert request aliases are retired; use canonical snake_case route fields.",
  );
  error.status = 400;
  error.code = "model_mount_route_upsert_request_aliases_retired";
  error.details = {
    retired_aliases: presentAliases,
    canonical_fields: CANONICAL_ROUTE_UPSERT_REQUEST_FIELDS,
  };
  throw error;
}
