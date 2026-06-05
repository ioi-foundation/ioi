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
  const fallbackTriggered = truthy(request.fallback_triggered);
  const fallbackReason = optionalString(request.fallback_reason);
  const decision = {
    schema_version: MODEL_ROUTE_DECISION_SCHEMA_VERSION,
    object: "ioi.model_route_decision",
    event_kind: MODEL_ROUTE_DECISION_EVENT_KIND,
    decision_id: stableHash({
      route_id: route?.id ?? null,
      endpoint_id: endpoint?.id ?? null,
      provider_id: provider?.id ?? null,
      capability,
      requested_model: requestedModel,
      policyHash,
      workflow,
      response_id: responseId,
      previous_response_id: previousResponseId,
    }),
    route_id: route?.id ?? null,
    capability,
    requested_model: requestedModel,
    requested_model_mode: autoResolved ? "auto" : requestedModel ? "explicit" : "route_default",
    auto_resolved: autoResolved,
    selected_model: selectedModel,
    upstream_model: selectedModel,
    never_send_auto_upstream: !autoResolved || selectedModel !== "auto",
    endpoint_id: endpoint?.id ?? null,
    provider_id: provider?.id ?? null,
    provider_kind: provider?.kind ?? null,
    provider_label: provider?.label ?? null,
    reasoning_effort: reasoningEffort,
    local_remote_placement: placement,
    privacy_posture: privacyPosture,
    cost_estimate_usd: costEstimate.value,
    cost_estimate_source: costEstimate.source,
    fallback_model: fallback.model,
    fallback_endpoint_id: fallback.endpointId,
    fallback_allowed: Boolean(fallback.endpointId),
    fallback_triggered: fallbackTriggered,
    fallback_reason: fallbackReason,
    rationale: routeRationale({
      route,
      endpoint,
      provider,
      policy,
      requestedModel,
      autoResolved,
      placement,
      costEstimate,
      fallbackTriggered,
      fallbackReason,
    }),
    policy_constraints: policyConstraints,
    evaluated_candidate_count: evaluatedCandidates.length,
    rejected_candidates: evaluatedCandidates
      .filter((candidate) => candidate.status === "rejected")
      .map((candidate) => ({
        endpoint_id: candidate.endpointId,
        provider_id: candidate.providerId,
        reason: candidate.reason,
      })),
    workflowGraphId: workflow.workflowGraphId ?? null,
    workflowNodeId: workflow.workflowNodeId ?? null,
    workflowNodeType: workflow.workflowNodeType ?? null,
    response_id: responseId,
    previous_response_id: previousResponseId,
    policyHash,
    evidenceRefs: [
      "model_router",
      route?.id,
      endpoint?.id,
      provider?.id,
      autoResolved ? "model_auto_resolved_before_provider_invocation" : null,
      fallbackTriggered ? "model_route_fallback_selected" : null,
    ].filter(Boolean),
  };
  return decision;
}

export function routeDecisionProjectionFromReceipt(receipt) {
  const decision = receipt?.details?.model_route_decision;
  if (!decision || typeof decision !== "object") return null;
  return {
    ...decision,
    receiptId: receipt.id,
    receiptCreatedAt: receipt.createdAt,
    receiptKind: receipt.kind,
  };
}

export function providerRequestBodyForRoute(body = {}, endpoint = {}) {
  const requestBody = { ...body };
  if (isAutoModelSelector(requestBody.model)) {
    requestBody.model = endpoint.modelId;
  }
  stripAutopilotOnlyProviderFields(requestBody);
  applyProviderNativeReasoningControls(requestBody, body, endpoint);
  normalizeProviderNativeMessages(requestBody, endpoint);
  return requestBody;
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

function stripAutopilotOnlyProviderFields(body = {}) {
  for (const key of [
    "route_id",
    "routeId",
    "model_policy",
    "modelPolicy",
    "metadata",
    "workflow_graph_id",
    "workflowGraphId",
    "workflow_node_id",
    "workflowNodeId",
    "workflow_node_type",
    "workflowNodeType",
    "fallback_triggered",
    "fallbackTriggered",
    "fallback_reason",
    "fallbackReason",
    "send_options",
    "sendOptions",
    "memory",
    "integrations",
    "ephemeral_mcp",
    "ephemeralMcp",
    "reasoningEffort",
    "thinkingEffort",
    "chat_template_kwargs",
    "chatTemplateKwargs",
  ]) {
    delete body[key];
  }
}

function applyProviderNativeReasoningControls(requestBody = {}, originalBody = {}, endpoint = {}) {
  if (!isLlamaCppEndpoint(endpoint)) return;
  const policy = originalBody.model_policy ?? originalBody.modelPolicy ?? {};
  const effort = normalizeReasoningEffortValue(
    originalBody.reasoning_effort ??
      originalBody.reasoningEffort ??
      originalBody.thinking ??
      originalBody.thinking_effort ??
      originalBody.thinkingEffort ??
      policy.reasoning_effort ??
      policy.reasoningEffort ??
      policy.thinking,
  );
  if (!effort) return;
  requestBody.reasoning_effort = effort;
  requestBody.chat_template_kwargs = {
    ...(originalBody.chat_template_kwargs && typeof originalBody.chat_template_kwargs === "object" ? originalBody.chat_template_kwargs : {}),
    enable_thinking: !["none", "off", "false", "disabled"].includes(effort),
  };
}

function normalizeProviderNativeMessages(requestBody = {}, endpoint = {}) {
  if (!isLlamaCppEndpoint(endpoint) || !Array.isArray(requestBody.messages)) return;
  const systemMessages = requestBody.messages.filter((message) => String(message?.role ?? "").toLowerCase() === "system");
  if (systemMessages.length <= 1) return;
  const systemContent = systemMessages
    .map((message) => messageContentToProviderText(message.content))
    .filter(Boolean)
    .join("\n\n");
  const nonSystemMessages = requestBody.messages.filter((message) => String(message?.role ?? "").toLowerCase() !== "system");
  requestBody.messages = systemContent
    ? [{ role: "system", content: systemContent }, ...nonSystemMessages]
    : nonSystemMessages;
}

function messageContentToProviderText(content) {
  if (typeof content === "string") return content.trim();
  if (Array.isArray(content)) {
    return content
      .map((part) => {
        if (typeof part === "string") return part;
        if (typeof part?.text === "string") return part.text;
        if (typeof part?.content === "string") return part.content;
        return "";
      })
      .filter(Boolean)
      .join("\n")
      .trim();
  }
  if (content && typeof content === "object") {
    if (typeof content.text === "string") return content.text.trim();
    if (typeof content.content === "string") return content.content.trim();
  }
  return "";
}

function isLlamaCppEndpoint(endpoint = {}) {
  const haystack = `${endpoint.driver ?? ""} ${endpoint.apiFormat ?? ""} ${endpoint.providerId ?? ""} ${endpoint.backendId ?? ""}`.toLowerCase();
  return haystack.includes("llama_cpp") || haystack.includes("llama-cpp");
}

function normalizeReasoningEffortValue(value) {
  if (value === true) return "medium";
  if (value === false) return "none";
  const normalized = typeof value === "string" ? value.trim().toLowerCase().replace(/[\s-]+/g, "_") : "";
  if (!normalized) return "";
  if (["none", "off", "false", "disabled", "disable"].includes(normalized)) return "none";
  if (["low", "medium", "high", "xhigh"].includes(normalized)) return normalized;
  return normalized;
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
    route_privacy: route.privacy ?? null,
    requested_privacy: policy.privacy ?? null,
    provider_eligibility: Array.isArray(route.providerEligibility) ? [...route.providerEligibility] : [],
    denied_providers: Array.isArray(route.deniedProviders) ? [...route.deniedProviders] : [],
    max_cost_usd: Number(policy.max_cost_usd ?? policy.maxCostUsd ?? route.maxCostUsd ?? 0),
    max_latency_ms: Number(policy.max_latency_ms ?? policy.maxLatencyMs ?? route.maxLatencyMs ?? 0),
    allow_hosted_fallback: truthy(policy.allow_hosted_fallback),
    local_only: policy.privacy === "local_only" || route.privacy === "local_only",
  };
}

function routeRationale({
  route = {},
  endpoint = {},
  provider = {},
  policy = {},
  requestedModel,
  autoResolved,
  placement,
  costEstimate,
  fallbackTriggered,
  fallbackReason,
}) {
  if (fallbackTriggered) {
    return `Fallback route ${route.id} selected ${endpoint.modelId} after ${fallbackReason ?? "primary route rejection"}.`;
  }
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
