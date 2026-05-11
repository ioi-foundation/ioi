import crypto from "node:crypto";

export const MODEL_ROUTE_DECISION_SCHEMA_VERSION = "ioi.model-route-decision.v1";
export const MODEL_ROUTE_DECISION_EVENT_KIND = "ModelRouteDecision";

export function isAutoModelSelector(modelId) {
  return typeof modelId === "string" && modelId.trim().toLowerCase() === "auto";
}

export function createModelRouteDecision({
  route,
  endpoint,
  provider,
  capability = "chat",
  policy = {},
  requestedModel = null,
  request = {},
  policyHash,
  workflow = {},
  responseId = null,
  previousResponseId = null,
  evaluatedCandidates = [],
} = {}) {
  const autoResolved = isAutoModelSelector(requestedModel);
  const costEstimate = estimatedCostUsd(endpoint, provider);
  const fallback = fallbackFor(route, endpoint);
  const policyConstraints = routePolicyConstraints(route, policy);
  const placement = localRemotePlacement(provider);
  const privacyPosture = privacyPostureFor(route, provider, policy);
  const reasoningEffort = reasoningEffortFor(policy, request);
  const selectedModel = endpoint?.modelId ?? null;
  const decision = {
    schemaVersion: MODEL_ROUTE_DECISION_SCHEMA_VERSION,
    object: "ioi.model_route_decision",
    eventKind: MODEL_ROUTE_DECISION_EVENT_KIND,
    decisionId: stableHash({
      routeId: route?.id ?? null,
      endpointId: endpoint?.id ?? null,
      providerId: provider?.id ?? null,
      capability,
      requestedModel,
      policyHash,
      workflow,
      responseId,
      previousResponseId,
    }),
    routeId: route?.id ?? null,
    capability,
    requestedModel,
    requestedModelMode: autoResolved ? "auto" : requestedModel ? "explicit" : "route_default",
    autoResolved,
    selectedModel,
    upstreamModel: selectedModel,
    neverSendAutoUpstream: !autoResolved || selectedModel !== "auto",
    endpointId: endpoint?.id ?? null,
    providerId: provider?.id ?? null,
    providerKind: provider?.kind ?? null,
    providerLabel: provider?.label ?? null,
    reasoningEffort,
    localRemotePlacement: placement,
    privacyPosture,
    costEstimateUsd: costEstimate.value,
    costEstimateSource: costEstimate.source,
    fallbackModel: fallback.model,
    fallbackEndpointId: fallback.endpointId,
    fallbackAllowed: Boolean(fallback.endpointId),
    rationale: routeRationale({ route, endpoint, provider, policy, requestedModel, autoResolved, placement, costEstimate }),
    policyConstraints,
    evaluatedCandidateCount: evaluatedCandidates.length,
    rejectedCandidates: evaluatedCandidates
      .filter((candidate) => candidate.status === "rejected")
      .map((candidate) => ({
        endpointId: candidate.endpointId,
        providerId: candidate.providerId,
        reason: candidate.reason,
      })),
    workflowGraphId: workflow.workflowGraphId ?? null,
    workflowNodeId: workflow.workflowNodeId ?? null,
    workflowNodeType: workflow.workflowNodeType ?? null,
    responseId,
    previousResponseId,
    policyHash,
    evidenceRefs: [
      "model_router",
      route?.id,
      endpoint?.id,
      provider?.id,
      autoResolved ? "model_auto_resolved_before_provider_invocation" : null,
    ].filter(Boolean),
  };
  return decision;
}

export function routeDecisionProjectionFromReceipt(receipt) {
  const decision = receipt?.details?.modelRouteDecision;
  if (!decision || typeof decision !== "object") return null;
  return {
    ...decision,
    receiptId: receipt.id,
    receiptCreatedAt: receipt.createdAt,
    receiptKind: receipt.kind,
  };
}

export function providerRequestBodyForRoute(body = {}, endpoint = {}) {
  if (!isAutoModelSelector(body.model)) return body;
  return { ...body, model: endpoint.modelId };
}

export function workflowContextFromRouteRequest(body = {}) {
  return {
    workflowGraphId: optionalString(body.workflow_graph_id ?? body.workflowGraphId),
    workflowNodeId: optionalString(body.workflow_node_id ?? body.workflowNodeId ?? body.node_id ?? body.nodeId),
    workflowNodeType: optionalString(body.workflow_node_type ?? body.workflowNodeType ?? body.node),
  };
}

function reasoningEffortFor(policy = {}, request = {}) {
  const value =
    policy.reasoning_effort ??
    policy.reasoningEffort ??
    request.reasoning_effort ??
    request.reasoningEffort ??
    request.thinking ??
    request.thinking_effort ??
    request.thinkingEffort;
  if (typeof value === "string" && value.trim()) return value.trim();
  return "provider_default";
}

function localRemotePlacement(provider = {}) {
  switch (provider.privacyClass) {
    case "local_private":
      return "local";
    case "workspace":
      return "workspace";
    case "remote_confidential":
      return "remote_confidential";
    case "hosted":
      return "remote";
    default:
      return "unknown";
  }
}

function privacyPostureFor(route = {}, provider = {}, policy = {}) {
  if (policy.privacy) return String(policy.privacy);
  if (route.privacy) return String(route.privacy);
  if (provider.privacyClass) return String(provider.privacyClass);
  return "unspecified";
}

function estimatedCostUsd(endpoint = {}, provider = {}) {
  const endpointCost = Number(endpoint.estimatedCostUsd);
  if (Number.isFinite(endpointCost)) return { value: endpointCost, source: "endpoint" };
  const providerCost = Number(provider.estimatedCostUsd);
  if (Number.isFinite(providerCost)) return { value: providerCost, source: "provider" };
  return {
    value: provider.privacyClass === "hosted" ? 0.01 : 0,
    source: provider.privacyClass === "hosted" ? "hosted_default" : "local_default",
  };
}

function fallbackFor(route = {}, selectedEndpoint = {}) {
  const fallbackEndpointId = Array.isArray(route.fallback)
    ? route.fallback.find((endpointId) => endpointId !== selectedEndpoint.id) ?? null
    : null;
  return {
    endpointId: fallbackEndpointId,
    model: fallbackEndpointId ? null : null,
  };
}

function routePolicyConstraints(route = {}, policy = {}) {
  return {
    routePrivacy: route.privacy ?? null,
    requestedPrivacy: policy.privacy ?? null,
    providerEligibility: Array.isArray(route.providerEligibility) ? [...route.providerEligibility] : [],
    deniedProviders: Array.isArray(route.deniedProviders) ? [...route.deniedProviders] : [],
    maxCostUsd: Number(policy.max_cost_usd ?? policy.maxCostUsd ?? route.maxCostUsd ?? 0),
    maxLatencyMs: Number(policy.max_latency_ms ?? policy.maxLatencyMs ?? route.maxLatencyMs ?? 0),
    allowHostedFallback: truthy(policy.allow_hosted_fallback ?? policy.allowHostedFallback),
    localOnly: policy.privacy === "local_only" || route.privacy === "local_only",
  };
}

function routeRationale({ route = {}, endpoint = {}, provider = {}, policy = {}, requestedModel, autoResolved, placement, costEstimate }) {
  if (autoResolved) {
    return `model=auto resolved to ${endpoint.modelId} through ${route.id} before provider invocation.`;
  }
  if (requestedModel) {
    return `Explicit model ${requestedModel} resolved to ${endpoint.modelId} on ${provider.kind}.`;
  }
  if (policy.privacy === "local_only" || route.privacy === "local_only") {
    return `Local-only policy selected ${endpoint.modelId} on ${provider.kind}.`;
  }
  return `${route.id} selected ${endpoint.modelId} on ${provider.kind} with ${placement} placement and estimated cost ${costEstimate.value}.`;
}

function truthy(value) {
  return value === true || value === "true" || value === 1 || value === "1";
}

function optionalString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

function stableHash(value) {
  return crypto.createHash("sha256").update(stableStringify(value)).digest("hex");
}

function stableStringify(value) {
  if (typeof value === "string") return value;
  if (!value || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`)
    .join(",")}}`;
}
