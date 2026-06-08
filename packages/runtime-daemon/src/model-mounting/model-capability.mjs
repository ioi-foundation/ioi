export const MODEL_CAPABILITY_SCHEMA_VERSION = "ioi.model-capability.v1";

const ACTIVE_PROVIDER_STATUSES = new Set(["available", "configured", "running"]);
const HOSTED_PROVIDER_KINDS = new Set(["openai", "anthropic", "gemini", "custom_http"]);

export function modelCapabilities({
  routes = [],
  endpoints = [],
  providers = [],
  artifacts = [],
  instances = [],
} = {}) {
  const endpointById = new Map(endpoints.map((endpoint) => [endpoint.id, endpoint]));
  const providerById = new Map(providers.map((provider) => [provider.id, provider]));
  const artifactByModelId = new Map(artifacts.map((artifact) => [artifact.modelId, artifact]));
  const loadedEndpointIds = new Set(
    instances.filter((instance) => instance.status === "loaded").map((instance) => instance.endpointId),
  );

  return routes.map((route) =>
    modelCapabilityForRoute(route, {
      artifactByModelId,
      endpointById,
      loadedEndpointIds,
      providerById,
    }),
  );
}

function modelCapabilityForRoute(route, context) {
  const candidates = route.fallback.map((endpointId, index) =>
    candidateReadiness(route, endpointId, index, context),
  );
  const readyCandidates = candidates.filter((candidate) => candidate.ready);
  const missingVaultCount = candidates.filter((candidate) => candidate.vault_required && !candidate.vault_ready).length;
  const selectedCandidate = readyCandidates[0] ?? candidates[0] ?? null;
  const credentialStatus = readinessStatus(route, candidates, readyCandidates);
  const available = route.status === "active" && readyCandidates.length > 0;
  const capability = selectedCandidate?.capability ?? "chat";

  return {
    schema_version: MODEL_CAPABILITY_SCHEMA_VERSION,
    object: "ioi.model_capability",
    id: `model-capability:${route.id}`,
    route_id: route.id,
    role: route.role,
    model_role: route.role,
    capability,
    primitive_capability: `prim:model.${capability}`,
    authority_scope_requirements: [`route.use:${route.id}`, `model.${capability}:*`],
    policy_target: modelPolicyTarget(route.id),
    privacy_tier: route.privacy,
    provider_priority: route.providerEligibility,
    fallback_policy: {
      allowed: route.fallback.length > 1,
      endpoint_ids: route.fallback,
      denied_providers: route.deniedProviders,
      selected_endpoint_id: selectedCandidate?.endpoint_id ?? null,
      deterministic_order: true,
    },
    fallback_evidence: candidates.map((candidate) => candidate.evidence),
    cost_estimate_visibility: {
      visible: true,
      max_cost_usd: route.maxCostUsd,
      max_latency_ms: route.maxLatencyMs,
      source: "model_route_policy",
    },
    credential_readiness: {
      status: credentialStatus,
      reason: readinessReason(route, candidates, readyCandidates),
      evidence_refs: compactEvidence(candidates.flatMap((candidate) => candidate.evidence_refs)),
    },
    vault_readiness: {
      status: missingVaultCount === 0 ? "ready" : "missing",
      required_count: candidates.filter((candidate) => candidate.vault_required).length,
      configured_count: candidates.filter((candidate) => candidate.vault_required && candidate.vault_ready).length,
      missing_count: missingVaultCount,
    },
    byok_required: candidates.some((candidate) => candidate.vault_required),
    receipt_behavior: {
      receipt_required: true,
      required_receipt_types: ["model_route_selection", "model_invocation"],
    },
    workflow_availability: {
      available,
      reason: available ? "At least one route candidate is executable." : "No executable model route candidate is ready.",
      config_fields: ["model_ref", "route_id", "model_binding"],
      evidence_refs: compactEvidence(candidates.flatMap((candidate) => candidate.evidence_refs)),
    },
    agent_availability: {
      available,
      reason: available ? "Agent runtime can request this route capability." : "Agent runtime must resolve model readiness first.",
      evidence_refs: compactEvidence(candidates.flatMap((candidate) => candidate.evidence_refs)),
    },
    candidates,
  };
}

function candidateReadiness(route, endpointId, priority, { artifactByModelId, endpointById, providerById, loadedEndpointIds }) {
  const endpoint = endpointById.get(endpointId) ?? null;
  const provider = endpoint ? providerById.get(endpoint.providerId) ?? null : null;
  const artifact = endpoint ? artifactByModelId.get(endpoint.modelId) ?? null : null;
  const vaultRequired = providerRequiresVault(provider);
  const vaultReady = !vaultRequired || Boolean(provider?.secretConfigured || provider?.vaultBoundary?.configured);
  const providerReady = provider ? ACTIVE_PROVIDER_STATUSES.has(String(provider.status)) : false;
  const endpointReady = endpoint ? endpoint.status === "mounted" || loadedEndpointIds.has(endpoint.id) : false;
  const ready = route.status === "active" && endpointReady && providerReady && vaultReady;
  const reason = readinessCandidateReason({ endpoint, endpointReady, provider, providerReady, vaultRequired, vaultReady });
  const evidenceRefs = compactEvidence([
    endpoint?.lastReceiptId,
    provider?.lastReceiptId,
    artifact?.lastReceiptId,
    ...(endpoint?.evidenceRefs ?? []),
    ...(provider?.evidenceRefs ?? []),
  ]);

  return {
    endpoint_id: endpointId,
    priority,
    model_id: endpoint?.modelId ?? null,
    provider_id: provider?.id ?? null,
    provider_kind: provider?.kind ?? null,
    capability: firstCapability(endpoint?.capabilities ?? artifact?.capabilities),
    privacy_tier: endpoint?.privacyClass ?? provider?.privacyClass ?? route.privacy,
    status: ready ? "ready" : "blocked",
    ready,
    vault_required: vaultRequired,
    vault_ready: vaultReady,
    reason,
    evidence_refs: evidenceRefs,
    evidence: {
      endpoint_id: endpointId,
      provider_id: provider?.id ?? null,
      status: ready ? "ready" : "blocked",
      reason,
      vault_required: vaultRequired,
      vault_ready: vaultReady,
    },
  };
}

function providerRequiresVault(provider) {
  if (!provider) return false;
  return Boolean(provider.vaultBoundary?.required) || HOSTED_PROVIDER_KINDS.has(String(provider.kind));
}

function modelPolicyTarget(routeId) {
  return routeId.startsWith("route.") ? `model.${routeId}` : `model.route.${routeId}`;
}

function readinessStatus(route, candidates, readyCandidates) {
  if (route.status !== "active") return "disabled";
  if (readyCandidates.length > 0) return "ready";
  if (candidates.some((candidate) => candidate.vault_required && !candidate.vault_ready)) return "missing";
  return "degraded";
}

function readinessReason(route, candidates, readyCandidates) {
  if (route.status !== "active") return "Model route is disabled.";
  if (readyCandidates.length > 0) return "Route has an executable candidate.";
  return candidates[0]?.reason ?? "Route has no configured fallback candidates.";
}

function readinessCandidateReason({ endpoint, endpointReady, provider, providerReady, vaultRequired, vaultReady }) {
  if (!endpoint) return "Route fallback endpoint is not registered.";
  if (!provider) return "Endpoint provider is not registered.";
  if (!providerReady) return `Provider status is ${provider.status}.`;
  if (vaultRequired && !vaultReady) return "Provider requires wallet vault credentials.";
  if (!endpointReady) return `Endpoint status is ${endpoint.status}.`;
  return "Endpoint, provider, and credential posture are ready.";
}

function firstCapability(capabilities) {
  return Array.isArray(capabilities) && capabilities.length > 0 ? String(capabilities[0]) : "chat";
}

function compactEvidence(values) {
  return [...new Set(values.filter((value) => typeof value === "string" && value.trim()))];
}
