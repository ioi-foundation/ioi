export function upsertRouteRecord(body = {}, { normalizeScopes, safeId } = {}) {
  const id = body.id ?? `route.${safeId(body.role ?? "custom")}`;
  return {
    id,
    role: body.role ?? "custom",
    description: body.description ?? "Operator-defined model route.",
    privacy: body.privacy ?? "local_or_enterprise",
    quality: body.quality ?? "adaptive",
    maxCostUsd: Number(body.max_cost_usd ?? body.maxCostUsd ?? 0.25),
    maxLatencyMs: Number(body.max_latency_ms ?? body.maxLatencyMs ?? 30000),
    providerEligibility: normalizeScopes(body.provider_eligibility ?? body.providerEligibility, []),
    fallback: normalizeScopes(body.fallback, []),
    deniedProviders: normalizeScopes(body.denied_providers ?? body.deniedProviders, []),
    status: body.status ?? "active",
    lastSelectedModel: body.last_selected_model ?? body.lastSelectedModel ?? null,
    lastReceiptId: body.last_receipt_id ?? body.lastReceiptId ?? null,
  };
}

export function upsertRoute(state, body = {}, deps = {}) {
  const { normalizeScopes, safeId } = deps;
  const route = upsertRouteRecord(body, { normalizeScopes, safeId });
  state.routes.set(route.id, route);
  state.writeMap("model-routes", state.routes);
  return route;
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
  isAutoModelSelector,
  isFixtureEndpointCandidate,
  modelId,
  policy,
  provider,
  route: getRoute,
  routeId,
  routes,
  runtimeError,
  truthy,
  capability = "chat",
} = {}) {
  const route = routes.get(routeId ?? "route.local-first") ?? getRoute("route.local-first");
  const explicitModelId = isAutoModelSelector(modelId) ? null : modelId;
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
    if (truthy(policy?.deny_fixture_models ?? policy?.denyFixtureModels) && isFixtureEndpointCandidate(candidateEndpoint, candidateProvider)) {
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
    const costCeiling = Number(policy?.max_cost_usd ?? policy?.maxCostUsd ?? route.maxCostUsd ?? Infinity);
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
    details: { routeId: route.id, capability, policy, evaluatedCandidates },
  });
}

export function selectRouteForState(state, { modelId, routeId, capability, policy }, deps = {}) {
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
    isAutoModelSelector,
    isFixtureEndpointCandidate,
    modelId,
    policy,
    provider: (providerId) => state.provider(providerId),
    route: (id) => state.route(id),
    routeId,
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
  previousResponseId = null,
  receipt,
  responseId = null,
  routeDecision,
  selection,
  stableHash,
} = {}) {
  const policy = body.model_policy ?? body.modelPolicy ?? {};
  const requestedModel = body.model ?? body.model_id ?? body.modelId ?? null;
  const workflow = routeDecision.workflowContextFromRouteRequest(body);
  const policyHash = stableHash(policy);
  if (typeof nextReceiptId !== "function") {
    throw routeDecisionReceiptIdRequiredError();
  }
  const receiptId = nextReceiptId("model_route_selection");
  const modelRouteDecision = routeDecision.createModelRouteDecision({
    route: selection.route,
    endpoint: selection.endpoint,
    provider: selection.provider,
    capability,
    policy,
    requestedModel,
    request: body,
    policyHash,
    workflow,
    responseId,
    previousResponseId,
    evaluatedCandidates: selection.evaluatedCandidates ?? [],
  });
  if (typeof admitModelMountRouteDecision !== "function") {
    throw routeDecisionRustAdmissionRequiredError();
  }
  const modelMountRouteDecision = admitModelMountRouteDecision(
    modelMountRouteDecisionRequestForSelection({
      body,
      capability,
      modelRouteDecision,
      policy,
      policyHash,
      previousResponseId,
      receiptId,
      responseId,
      selection,
      workflow,
    }),
  );
  const rustEvidenceRefs = uniqueRefs([
    modelMountRouteDecision.route_decision_ref,
    ...(Array.isArray(modelMountRouteDecision.evidence_refs) ? modelMountRouteDecision.evidence_refs : []),
  ]);
  const payload = {
    summary: `Route ${selection.route.id} selected ${selection.endpoint.modelId}.`,
    redaction: "none",
    evidenceRefs: uniqueRefs([
      "model_router",
      "rust_model_mount_core",
      selection.route.id,
      selection.endpoint.id,
      ...rustEvidenceRefs,
      ...evidenceRefs,
    ]),
    details: {
      route_id: selection.route.id,
      selected_model: selection.endpoint.modelId,
      endpoint_id: selection.endpoint.id,
      provider_id: selection.endpoint.providerId,
      capability,
      policy_hash: policyHash,
      response_id: responseId,
      previous_response_id: previousResponseId,
      model_route_decision_schema_version: routeDecision.MODEL_ROUTE_DECISION_SCHEMA_VERSION,
      model_route_decision_event_kind: routeDecision.MODEL_ROUTE_DECISION_EVENT_KIND,
      model_route_decision_id: modelRouteDecision.decision_id,
      model_route_decision: modelRouteDecision,
      model_mount_route_decision_schema_version: "ioi.model_mount.route_decision.v1",
      model_mount_route_decision_ref: modelMountRouteDecision.route_decision_ref,
      model_mount_route_decision_hash: modelMountRouteDecision.route_decision_hash,
      model_mount_route_decision_source: modelMountRouteDecision.source,
      model_mount_route_decision_backend: modelMountRouteDecision.backend,
      model_mount_route_decision_receipt_refs: modelMountRouteDecision.receipt_refs ?? [],
      model_mount_route_decision: modelMountRouteDecision.record,
      workflow_graph_id: workflow.workflowGraphId ?? null,
      workflow_node_id: workflow.workflowNodeId ?? null,
      workflow_node_type: workflow.workflowNodeType ?? null,
    },
  };
  if (receiptId) payload.id = receiptId;
  return receipt("model_route_selection", payload);
}

export function routeSelectionReceiptForState(state, selection, options = {}, deps = {}) {
  const {
    routeDecision,
    stableHash,
  } = deps;
  return routeSelectionReceipt({
    admitModelMountRouteDecision: (request) => state.admitModelMountRouteDecision(request),
    ...options,
    nextReceiptId: (kind) => state.nextReceiptId(kind),
    receipt: (kind, payload) => state.receipt(kind, payload),
    routeDecision,
    selection,
    stableHash,
  });
}

export function testRoute(state, routeId, body = {}) {
  const route = state.route(routeId);
  const capability = body.capability ?? "chat";
  const selection = state.selectRoute({
    modelId: body.model ?? body.model_id ?? body.modelId,
    routeId,
    capability,
    policy: body.model_policy ?? body.modelPolicy ?? {},
  });
  const receipt = state.routeSelectionReceipt(selection, { body: { ...body, route_id: routeId }, capability });
  const updatedRoute = {
    ...route,
    lastSelectedModel: selection.endpoint.modelId,
    lastReceiptId: receipt.id,
  };
  state.routes.set(routeId, updatedRoute);
  state.writeMap("model-routes", state.routes);
  return { route: updatedRoute, selection, receipt };
}

export function modelMountRouteDecisionRequestForSelection({
  body = {},
  capability = "chat",
  modelRouteDecision = {},
  policy = {},
  policyHash,
  previousResponseId = null,
  receiptId = null,
  responseId = null,
  selection,
  workflow = {},
} = {}) {
  return {
    schema_version: "ioi.model_mount.route_decision.v1",
    route_ref: requiredRef("route_ref", selection?.route?.id),
    provider_ref: requiredRef("provider_ref", selection?.provider?.id ?? selection?.endpoint?.providerId),
    endpoint_ref: requiredRef("endpoint_ref", selection?.endpoint?.id),
    model_ref: requiredRef("model_ref", selection?.endpoint?.modelId),
    capability: requiredRef("capability", capability),
    policy_hash: policyHashRef(policyHash),
    idempotency_key: `model_route_decision:${requiredRef("decision_id", modelRouteDecision.decision_id)}`,
    receipt_refs: [`receipt://${requiredRef("receiptId", receiptId)}`],
    authority_grant_refs: normalizeRefs(body.authority_grant_refs ?? body.authorityGrantRefs),
    authority_receipt_refs: normalizeRefs(body.authority_receipt_refs ?? body.authorityReceiptRefs),
    custody_ref: optionalRef(
      body.custody_ref ??
        body.custodyRef ??
        selection?.endpoint?.custodyRef ??
        selection?.endpoint?.custody_ref ??
        selection?.provider?.custodyRef ??
        selection?.provider?.custody_ref,
    ),
    privacy_profile: optionalRef(
      body.privacy_profile ??
        body.privacyProfile ??
        policy.privacy_profile ??
        policy.privacyProfile ??
        policy.privacy ??
        selection?.route?.privacy ??
        selection?.provider?.privacyClass,
    ),
    node_plaintext_allowed: Boolean(
      body.node_plaintext_allowed ??
        body.nodePlaintextAllowed ??
        selection?.endpoint?.nodePlaintextAllowed ??
        selection?.provider?.nodePlaintextAllowed ??
        false,
    ),
    workflow_graph_ref: optionalRef(workflow.workflowGraphId),
    workflow_node_ref: optionalRef(workflow.workflowNodeId),
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
