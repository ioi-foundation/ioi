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

export function isAutoModelSelector(modelId) {
  return typeof modelId === "string" && modelId.trim().toLowerCase() === "auto";
}

export function upsertRouteRecord(body = {}, { normalizeScopes, safeId } = {}) {
  assertCanonicalRouteUpsertRequestBody(body);
  const id = body.id ?? `route.${safeId(body.role ?? "custom")}`;
  return {
    id,
    role: body.role ?? "custom",
    description: body.description ?? "Operator-defined model route.",
    privacy: body.privacy ?? "local_or_enterprise",
    quality: body.quality ?? "adaptive",
    maxCostUsd: Number(body.max_cost_usd ?? 0.25),
    maxLatencyMs: Number(body.max_latency_ms ?? 30000),
    providerEligibility: normalizeScopes(body.provider_eligibility, []),
    fallback: normalizeScopes(body.fallback, []),
    deniedProviders: normalizeScopes(body.denied_providers, []),
    status: body.status ?? "active",
    lastSelectedModel: body.last_selected_model ?? null,
    lastReceiptId: body.last_receipt_id ?? null,
  };
}

export function upsertRoute(state, body = {}, deps = {}) {
  const { normalizeScopes, safeId } = deps;
  const route = upsertRouteRecord(body, { normalizeScopes, safeId });
  throwModelRouteControlRustCoreRequired("model_mount.route.write", {
    route_id: route.id,
  });
}

export function endpointIdsForExplicitModel({
  endpoints,
  modelId,
  mountEndpoint,
  normalizeScopes,
  route,
} = {}) {
  const matchingEndpoints = [...endpoints.values()].filter(
    (candidate) => candidate.status !== "unmounted" && candidate.modelId === modelId,
  );
  const routeFallbackMatches = normalizeScopes(route.fallback, []).filter((endpointId) =>
    matchingEndpoints.some((endpoint) => endpoint.id === endpointId),
  );
  const ordered = [...routeFallbackMatches];
  for (const endpoint of matchingEndpoints) {
    if (!ordered.includes(endpoint.id)) ordered.push(endpoint.id);
  }
  if (ordered.length > 0) return ordered;
  return [mountEndpoint({ model_id: modelId }).id];
}

export function endpointIdsForExplicitModelForState(state, route, modelId, deps = {}) {
  const { normalizeScopes } = deps;
  return endpointIdsForExplicitModel({
    endpoints: state.endpoints,
    modelId,
    mountEndpoint: (body) => state.mountEndpoint(body),
    normalizeScopes,
    route,
  });
}

export function selectRoute({
  endpoint,
  endpointIdsForExplicitModel: endpointIdsForExplicitModelFn,
  isAutoModelSelector: isAutoModelSelectorFn = isAutoModelSelector,
  isFixtureEndpointCandidate,
  model_id,
  policy,
  provider,
  route: getRoute,
  route_id,
  routes,
  runtimeError,
  truthy,
  capability = "chat",
} = {}) {
  const route = routes.get(route_id ?? "route.local-first") ?? getRoute("route.local-first");
  const explicitModelId = isAutoModelSelectorFn(model_id) ? null : model_id;
  const fallback = explicitModelId
    ? endpointIdsForExplicitModelFn(route, explicitModelId)
    : route.fallback.length > 0
      ? route.fallback
      : [];
  const evaluatedCandidates = [];
  for (const endpointId of fallback) {
    const candidateEndpoint = endpoint(endpointId);
    const candidateProvider = provider(candidateEndpoint.providerId);
    const candidate = {
      endpointId,
      providerId: candidateProvider.id,
      providerKind: candidateProvider.kind,
      modelId: candidateEndpoint.modelId,
      status: "rejected",
      reason: null,
    };
    if (route.deniedProviders.includes(candidateProvider.kind)) {
      candidate.reason = "provider_denied_by_route";
      evaluatedCandidates.push(candidate);
      continue;
    }
    if (route.providerEligibility.length > 0 && !route.providerEligibility.includes(candidateProvider.kind)) {
      candidate.reason = "provider_not_eligible_for_route";
      evaluatedCandidates.push(candidate);
      continue;
    }
    if (truthy(policy?.deny_fixture_models) && isFixtureEndpointCandidate(candidateEndpoint, candidateProvider)) {
      candidate.reason = "fixture_model_denied_by_product_policy";
      evaluatedCandidates.push(candidate);
      continue;
    }
    if (policy?.privacy === "local_only" && candidateProvider.privacyClass !== "local_private") {
      candidate.reason = "policy_requires_local_only";
      evaluatedCandidates.push(candidate);
      continue;
    }
    if (
      candidateProvider.privacyClass === "hosted" &&
      route.privacy === "local_or_enterprise" &&
      !truthy(policy?.allow_hosted_fallback)
    ) {
      candidate.reason = "hosted_fallback_not_allowed";
      evaluatedCandidates.push(candidate);
      continue;
    }
    const costCeiling = Number(policy?.max_cost_usd ?? route.maxCostUsd ?? Infinity);
    const estimatedCost = Number(candidateEndpoint.estimatedCostUsd ?? candidateProvider.estimatedCostUsd ?? (candidateProvider.privacyClass === "hosted" ? 0.01 : 0));
    if (Number.isFinite(costCeiling) && estimatedCost > costCeiling) {
      candidate.reason = "estimated_cost_exceeds_policy";
      evaluatedCandidates.push(candidate);
      continue;
    }
    if (!candidateEndpoint.capabilities.includes(capability) && capability !== "chat") {
      candidate.reason = "capability_unavailable";
      evaluatedCandidates.push(candidate);
      continue;
    }
    evaluatedCandidates.push({ ...candidate, status: "selected", reason: "policy_allowed" });
    return { route, endpoint: candidateEndpoint, provider: candidateProvider, evaluatedCandidates };
  }
  throw runtimeError({
    status: 424,
    code: "external_blocker",
    message: "No model endpoint satisfied the route policy.",
    details: { route_id: route.id, capability, policy, evaluated_candidates: evaluatedCandidates },
  });
}

export function selectRouteForState(state, { model_id, route_id, capability, policy }, deps = {}) {
  const {
    isAutoModelSelector,
    isFixtureEndpointCandidate,
    runtimeError,
    truthy,
  } = deps;
  return selectRoute({
    capability,
    endpoint: (endpointId) => state.endpoint(endpointId),
    endpointIdsForExplicitModel: (route, explicitModelId) =>
      state.endpointIdsForExplicitModel(route, explicitModelId),
    isFixtureEndpointCandidate,
    model_id,
    policy,
    provider: (providerId) => state.provider(providerId),
    route: (id) => state.route(id),
    route_id,
    routes: state.routes,
    runtimeError,
    truthy,
  });
}

export function routeSelectionReceipt({
  body = {},
  capability = "chat",
  evidenceRefs = [],
  admitModelMountRouteDecision,
  nextReceiptId,
  persistRustAuthoredReceipt,
  previousResponseId = null,
  responseId = null,
  selection,
  stableHash,
} = {}) {
  assertCanonicalRouteSelectionRequestBody(body);
  const policy = body.model_policy ?? {};
  const requestedModel = body.model ?? body.model_id ?? null;
  const workflow = workflowContextFromRouteSelectionRequest(body);
  const policyHash = stableHash(policy);
  if (typeof nextReceiptId !== "function") {
    throw routeDecisionReceiptIdRequiredError();
  }
  const receiptId = nextReceiptId("model_route_selection");
  if (typeof admitModelMountRouteDecision !== "function") {
    throw routeDecisionRustAdmissionRequiredError();
  }
  const modelMountRouteDecision = admitModelMountRouteDecision(
    modelMountRouteDecisionRequestForSelection({
      body,
      capability,
      policy,
      policyHash,
      previousResponseId,
      receiptId,
      responseId,
      selection,
      workflow,
    }),
  );
  void evidenceRefs;
  void requestedModel;
  void responseId;
  void previousResponseId;
  if (typeof persistRustAuthoredReceipt !== "function") {
    throw routeDecisionAcceptedReceiptRequiredError("persist_rust_authored_receipt");
  }
  if (!modelMountRouteDecision.accepted_receipt_record) {
    throw routeDecisionAcceptedReceiptRequiredError("accepted_receipt_record");
  }
  return persistRustAuthoredReceipt(modelMountRouteDecision.accepted_receipt_record);
}

export function routeSelectionReceiptForState(state, selection, options = {}, deps = {}) {
  const {
    stableHash,
  } = deps;
  return routeSelectionReceipt({
    admitModelMountRouteDecision: (request) => state.admitModelMountRouteDecision(request),
    ...options,
    nextReceiptId: (kind) => state.nextReceiptId(kind),
    persistRustAuthoredReceipt: (record) => state.persistRustAuthoredReceipt(record),
    selection,
    stableHash,
  });
}

export function testRoute(state, routeId, body = {}) {
  assertCanonicalRouteSelectionRequestBody(body);
  throwModelRouteControlRustCoreRequired("model_mount.route.test", {
    route_id: routeId,
  });
}

export function persistModelRouteSelectionState(
  state,
  routeRecord,
  selectedModel,
  receiptId,
  operation_kind = "model_mount.route.selection_update",
) {
  throwModelRouteControlRustCoreRequired(operation_kind, {
    route_id: routeRecord?.id ?? null,
    selected_model: selectedModel ?? null,
    receipt_id: receiptId ?? null,
  });
}

export function modelMountRouteDecisionRequestForSelection({
  body = {},
  capability = "chat",
  policy = {},
  policyHash,
  previousResponseId = null,
  receiptId = null,
  responseId = null,
  selection,
  workflow = {},
} = {}) {
  assertCanonicalRouteSelectionRequestBody(body);
  return {
    schema_version: "ioi.model_mount.route_decision.v1",
    route_ref: requiredRef("route_ref", selection?.route?.id),
    provider_ref: requiredRef("provider_ref", selection?.provider?.id ?? selection?.endpoint?.providerId),
    endpoint_ref: requiredRef("endpoint_ref", selection?.endpoint?.id),
    model_ref: requiredRef("model_ref", selection?.endpoint?.modelId),
    capability: requiredRef("capability", capability),
    policy_hash: policyHashRef(policyHash),
    idempotency_key: `model_route_decision:${requiredRef("receipt_id", receiptId)}`,
    receipt_refs: [`receipt://${requiredRef("receiptId", receiptId)}`],
    authority_grant_refs: normalizeRefs(body.authority_grant_refs),
    authority_receipt_refs: normalizeRefs(body.authority_receipt_refs),
    custody_ref: optionalRef(
      body.custody_ref ??
        selection?.endpoint?.custodyRef ??
        selection?.endpoint?.custody_ref ??
        selection?.provider?.custodyRef ??
        selection?.provider?.custody_ref,
    ),
    privacy_profile: optionalRef(
      body.privacy_profile ??
        policy.privacy_profile ??
        policy.privacy ??
        selection?.route?.privacy ??
        selection?.provider?.privacyClass,
    ),
    node_plaintext_allowed: Boolean(
      body.node_plaintext_allowed ??
        selection?.endpoint?.nodePlaintextAllowed ??
        selection?.provider?.nodePlaintextAllowed ??
        false,
    ),
    workflow_graph_ref: optionalRef(workflow.workflow_graph_id),
    workflow_node_ref: optionalRef(workflow.workflow_node_id),
  };
}

export function workflowContextFromRouteSelectionRequest(body = {}) {
  return {
    workflow_graph_id: optionalString(body.workflow_graph_id),
    workflow_node_id: optionalString(body.workflow_node_id),
    workflow_node_type: optionalString(body.workflow_node_type),
  };
}

function routeDecisionRustAdmissionRequiredError() {
  const error = new Error("Model route decisions require Rust model_mount admission before receipt creation.");
  error.status = 502;
  error.code = "model_mount_route_decision_admission_required";
  return error;
}

function routeDecisionReceiptIdRequiredError() {
  const error = new Error("Model route decisions require a precomputed receipt id before Rust admission.");
  error.status = 500;
  error.code = "model_mount_route_decision_receipt_id_required";
  return error;
}

function routeDecisionAcceptedReceiptRequiredError(field) {
  const error = new Error("Model route selection receipts must be authored by Rust daemon core.");
  error.status = 502;
  error.code = "model_mount_route_selection_rust_receipt_required";
  error.details = {
    missing: field,
    rust_core_boundary: "model_mount.route_selection_receipt",
    evidence_refs: [
      "model_mount_route_selection_js_receipt_creation_retired",
      "rust_daemon_core_model_route_selection_receipt_required",
      "agentgres_model_route_selection_truth_required",
    ],
  };
  return error;
}

export function throwModelRouteControlRustCoreRequired(operation_kind, details = {}) {
  const error = new Error("Model route control requires Rust daemon-core ownership.");
  error.status = 501;
  error.code = "model_mount_route_control_rust_core_required";
  error.details = {
    rust_core_boundary: "model_mount.route_control",
    operation_kind,
    ...details,
    evidence_refs: [
      "model_mount_route_control_js_facade_retired",
      "rust_daemon_core_route_control_required",
      "agentgres_route_truth_required",
    ],
  };
  throw error;
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

function requiredRef(field, value) {
  const normalized = optionalRef(value);
  if (!normalized) {
    const error = new Error(`Model route decision missing ${field}.`);
    error.status = 500;
    error.code = "model_mount_route_decision_ref_missing";
    error.details = { field };
    throw error;
  }
  return normalized;
}

function optionalRef(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

function optionalString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

function normalizeRefs(value) {
  return Array.isArray(value)
    ? value.map(optionalRef).filter(Boolean)
    : [];
}

function uniqueRefs(values) {
  const refs = [];
  for (const value of values) {
    const ref = optionalRef(value);
    if (ref && !refs.includes(ref)) refs.push(ref);
  }
  return refs;
}

function policyHashRef(value) {
  const normalized = requiredRef("policy_hash", value);
  return normalized.startsWith("sha256:") ? normalized : `sha256:${normalized}`;
}
