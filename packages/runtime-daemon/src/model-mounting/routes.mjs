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
  void state;
  void deps;
  assertCanonicalRouteUpsertRequestBody(body);
  throwModelRouteControlRustCoreRequired(
    routeControlRequiredForState(state, "model_mount.route.write", {
      route_id: routeIdFromUpsertBody(body),
    }),
  );
}

export function testRoute(state, routeId, body = {}) {
  void state;
  assertCanonicalRouteSelectionRequestBody(body);
  throwModelRouteControlRustCoreRequired(
    routeControlRequiredForState(state, "model_mount.route.test", {
      route_id: routeId,
    }),
  );
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
