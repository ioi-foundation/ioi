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
      !truthy(policy?.allow_hosted_fallback ?? policy?.allowHostedFallback)
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

export function routeSelectionReceipt({
  body = {},
  capability = "chat",
  evidenceRefs = [],
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
  return receipt("model_route_selection", {
    summary: `Route ${selection.route.id} selected ${selection.endpoint.modelId}.`,
    redaction: "none",
    evidenceRefs: ["model_router", selection.route.id, selection.endpoint.id, ...evidenceRefs],
    details: {
      routeId: selection.route.id,
      selectedModel: selection.endpoint.modelId,
      endpointId: selection.endpoint.id,
      providerId: selection.endpoint.providerId,
      capability,
      policyHash,
      responseId,
      previousResponseId,
      modelRouteDecisionSchemaVersion: routeDecision.MODEL_ROUTE_DECISION_SCHEMA_VERSION,
      modelRouteDecisionEventKind: routeDecision.MODEL_ROUTE_DECISION_EVENT_KIND,
      modelRouteDecisionId: modelRouteDecision.decisionId,
      modelRouteDecision,
      ...workflow,
    },
  });
}
